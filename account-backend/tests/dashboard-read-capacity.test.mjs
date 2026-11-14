import test from 'node:test';
import assert from 'node:assert/strict';
import {dashboardReadDatabase,dashboardReadRequest} from '../src/dashboard-read-db.js';
import {recoveryProtected} from '../src/recovery-control.js';
import {publicSourceCacheKey,publicSourceStatus,invalidatePublicSourceStatus} from '../src/public-source-status-cache.js';
import {capacityFixture,capacitySessions,fixtureId} from './helpers/capacity-db.mjs';
import {seedOutage} from '../../scripts/nvd_capacity_fixture.mjs';
import * as cvie from '../src/cvie.js';
import worker from '../src/index.js';
import {evidenceContext} from '../src/cvie-records.js';
import {ownedProductSql} from '../src/shared-scopes.js';

test('dashboard capability rejects mutations, disguised CTE writes and foreign batches before reaching D1',async()=>{
 let touched=0;const db=dashboardReadDatabase({prepare:()=>{touched++;throw Error('Unexpected D1 access');}});
 for(const sql of ['UPDATE users SET email=email','WITH x AS (SELECT 1) DELETE FROM users RETURNING id','SELECT 1; DELETE FROM users','PRAGMA writable_schema=1','/* safe */ WITH x AS (SELECT 1) INSERT INTO users SELECT * FROM x'])assert.throws(()=>db.prepare(sql),/read-only SELECT/);
 assert.throws(()=>db.batch([{}]),/capabilities/);assert.equal(touched,0);
 assert.equal(db.prepare('WITH x AS (SELECT 1) SELECT * FROM x').run,undefined);assert.equal(db.withSession,undefined);assert.equal(db.exec,undefined);
 for(const path of ['/v1/cvie/sync','/v1/cvie/directory','/v1/inventory','/v1/acknowledge/token','/v1/team/organizations/other'])assert.equal(dashboardReadRequest(new Request('https://api.cveharbor.com'+path)),false);
 assert.equal(dashboardReadRequest(new Request('https://api.cveharbor.com/v1/cvie',{method:'POST'})),false);
 assert.equal(dashboardReadRequest(new Request('https://confirm.cveharbor.com/v1/cvie')),false);
});

test('replica reads are anchored to this request authentication; every authority check is fresh primary',async()=>{
 const calls=[];let counter=0;
 const original={withSession(constraint){const mark='server-'+(++counter);const prepare=sql=>({bind(){return this;},first:async()=>{calls.push([constraint,sql]);return {id:'owner'};},all:async()=>{calls.push([constraint,sql]);return {results:[]};}});return {prepare,getBookmark:()=>mark,batch:rows=>Promise.all(rows.map(r=>r.all()))};}};
 const db=dashboardReadDatabase(original),auth='SELECT users.id FROM sessions JOIN users ON users.id=sessions.user_id JOIN user_totp ON user_totp.user_id=users.id';
 await db.prepare('SELECT write_hold FROM operations_control').first();await db.prepare(auth).first();
 await db.prepare('WITH x AS (SELECT 1) SELECT * FROM x').all();
 await db.batch([db.prepare('SELECT * FROM cvie_sources'),db.prepare('SELECT * FROM inventory_customers')]);
 await db.prepare('SELECT * FROM team_members').all();await db.prepare(auth).first();await db.prepare('SELECT * FROM cvie_sources').all();
 assert.deepEqual(calls.map(c=>c[0]),['first-primary','first-primary','server-2','server-3','server-3','first-primary','first-primary','server-6']);
 const second=dashboardReadDatabase(original);await second.prepare('SELECT * FROM cvie_sources').all();assert.equal(calls.at(-1)[0],'first-primary','No bookmark crosses requests');
});

test('transient routing failures create a fresh session; stale replicas cannot supply authorization',async()=>{
 const constraints=[];let retries=0,revoked=false;
 const db=dashboardReadDatabase({withSession(constraint){constraints.push(constraint);return {getBookmark:()=> 'authenticated-snapshot',prepare:sql=>({async first(){
  if(sql.includes('sessions'))return constraint==='first-primary'&&revoked?null:{id:'owner'};
  if(retries++===0)throw Error('D1 DB is overloaded. Requests queued for too long.');
  return {saved:true};
 }})};}},{sleep:async()=>{},random:()=>0});
 const auth='SELECT users.id FROM sessions JOIN users JOIN user_totp';
 assert.equal((await db.prepare(auth).first()).id,'owner');await db.prepare('SELECT * FROM cvie_shared_advisories').first();
 assert.deepEqual(constraints,['first-primary','authenticated-snapshot','first-primary']);
 await db.prepare('SELECT * FROM cvie_sources').first();assert.equal(constraints.at(-1),'first-primary','An overloaded replica is avoided for the rest of this request');
 revoked=true;assert.equal(await db.prepare(auth).first(),null);assert.equal(constraints.at(-1),'first-primary');
});

test('whole Worker dashboard reads make zero writes and honor revocation, ownership and maintenance',async()=>{
 const f=capacityFixture({owners:50,customers:50,environments:100,assets:5000}),tokens=capacitySessions(f.sql),seed=await seedOutage(f,cvie),env={...seed.env,RECOVERY_CONTROL_REQUIRED:'true'};
 const paths=['/v1/me','/v1/cvie?scope=inventory','/v1/cvie/advisories?scope=inventory','/v1/workspace/summary','/v1/workspace/items?view=environments','/v1/workspace/trend','/v1/customer-score-history?customer_id='+fixtureId(1),'/v1/inventory/software-history?customer_id='+fixtureId(1),'/v1/finding-assignments'];
 const call=(path,token=tokens[0])=>worker.fetch(new Request('https://api.cveharbor.com'+path,{headers:{Cookie:'cvh_session='+token,Origin:'https://cveharbor.com'}}),env,{waitUntil:()=>assert.fail('Read started background work')});
 try{
  const before=f.sql.prepare('SELECT total_changes() n').get().n;
  for(const path of paths){const r=await call(path);assert.equal(r.status,200,path+' '+await r.text());}
  assert.equal(f.sql.prepare('SELECT total_changes() n').get().n,before);assert.equal(f.sql.prepare('SELECT count(*) n FROM operations_leases').get().n,0);
  const other=await(await call('/v1/workspace/items?view=environments',tokens[1])).json();assert.ok(other.items.every(i=>i.customer_id===fixtureId(2)));
  f.sql.exec("UPDATE user_totp SET enabled=0 WHERE user_id='owner-0'");for(const path of paths)assert.equal((await call(path)).status,401,path);
  f.sql.exec("UPDATE user_totp SET enabled=1 WHERE user_id='owner-0'; DELETE FROM sessions WHERE user_id='owner-0'");for(const path of paths)assert.equal((await call(path)).status,401,path);
  f.sql.exec('UPDATE operations_control SET write_hold=1');for(const path of paths)assert.equal((await call(path,tokens[1])).status,503,path);
  f.sql.exec('DROP TABLE operations_control');assert.equal((await call('/v1/cvie',tokens[1])).status,503);
 }finally{f.close();}
});

test('dashboard read tracking cannot start writes or background work; mutations keep their leases',async()=>{
 const f=capacityFixture();let context,lease;
 try{
  const app=recoveryProtected({async fetch(req,env,ctx){context=ctx;await env.DB.prepare('DELETE FROM users').run();}});
  await assert.rejects(app.fetch(new Request('https://api.cveharbor.com/v1/cvie'),{DB:f.DB,RECOVERY_CONTROL_REQUIRED:'true'},{}),/read-only SELECT/);assert.equal(context,undefined);
  const write=recoveryProtected({async fetch(){lease=f.sql.prepare('SELECT count(*) n FROM operations_leases').get().n;return new Response('ok');}});
  await write.fetch(new Request('https://api.cveharbor.com/v1/cvie/sync',{method:'POST'}),{DB:f.DB,RECOVERY_CONTROL_REQUIRED:'true'});assert.equal(lease,1);
 }finally{f.close();}
});

test('only public source metadata shares a cache identity across read capabilities',async()=>{
 const env={DB:{}},key=publicSourceCacheKey(env),read={DB:{},CVIE_PUBLIC_CACHE_KEY:key};let loads=0;
 assert.deepEqual(Object.keys(key),[]);assert.equal(key.prepare,undefined);
 assert.deepEqual(await publicSourceStatus(env,100,()=>{loads++;return {public:true};}),{public:true});
 await publicSourceStatus(read,101,()=>{loads++;return {};});assert.equal(loads,1);
 invalidatePublicSourceStatus(env);await publicSourceStatus(read,102,()=>{loads++;return {};});assert.equal(loads,2);
});


test('CVIE status reuses only its own scoped products and retains counts and source outage evidence',async()=>{
 const f=capacityFixture({owners:50,customers:50,environments:100,assets:1000}),tokens=capacitySessions(f.sql),seed=await seedOutage(f,cvie);
 const owned=ownedProductSql(seed.env,'p.*','all');let productReads=0;
 const binding={prepare(sql){if(sql===owned)productReads++;return f.DB.prepare(sql);}};
 const env={...seed.env,DB:binding,RECOVERY_CONTROL_REQUIRED:'true'};
 try{
  f.sql.exec("UPDATE cvie_shared_scopes SET status='retrying',error='Fictional NVD outage',next_attempt_at=9999999999999");
  const response=await worker.fetch(new Request('https://api.cveharbor.com/v1/cvie',{headers:{Cookie:'cvh_session='+tokens[0]}}),env,{});
  assert.equal(response.status,200);const body=await response.json();
  assert.equal(productReads,1);assert.equal(body.products.length,1);assert.equal(body.products[0].history_count,200);assert.equal(body.products[0].status,'retrying');
  assert.equal(body.evidence.sources.find(s=>s.id==='nvd').status,'unavailable');
  assert.equal(body.account_id,'owner-0');
  await assert.rejects(evidenceContext(seed.env,'owner-0','all',[{id:'other',user_id:'owner-1'}]),/current account/);
 }finally{f.close();}
});
