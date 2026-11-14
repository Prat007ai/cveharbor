import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {CapacityAuthorityCoordinator,coordinatedAuthority,BATCH_SQL,AUTHORITY_SQL} from './capacity_authority_coordinator.mjs';
import {capacityFixture,capacitySessions} from '../account-backend/tests/helpers/capacity-db.mjs';
import {capacitySessionBinding} from '../account-backend/tests/helpers/capacity-sessions.mjs';
import {coordinatorConfig} from './capacity_authority_deploy.mjs';
import {validateCloudRun} from './inventory_capacity_cloud.mjs';
import worker from '../account-backend/src/index.js';

const request=hash=>new Request('https://capacity-authority.invalid/check',{method:'POST',body:JSON.stringify({token_hash:hash})});
const hash=token=>createHash('sha256').update(token).digest('hex');
function setup(){
 const f=capacityFixture({owners:50,customers:50,environments:100,assets:1000}),tokens=capacitySessions(f.sql),prepare=f.DB.prepare.bind(f.DB);
 let batches=0;f.DB.prepare=sql=>{if(sql===BATCH_SQL)batches++;return prepare(sql);};
 const native=capacitySessionBinding(f),coordinator=new CapacityAuthorityCoordinator({}, {DB:native});
 return {f,tokens,native,coordinator,batches:()=>batches};
}
test('50 simultaneous current checks execute one primary query and preserve each result position',async()=>{
 const {f,tokens,coordinator,batches}=setup();
 try{
  const responses=await Promise.all(tokens.map(t=>coordinator.fetch(request(hash(t)))));
  const rows=await Promise.all(responses.map(r=>r.json()));
  assert.equal(batches(),1);assert.equal(rows.reduce((n,r)=>n+r.native_queries,0),1);
  rows.forEach((r,i)=>{assert.equal(r.row.id,'owner-'+i);assert.equal(r.row.sid,'load-session-'+i);assert.equal(r.row.write_hold,0);assert.ok(r.bookmark);assert.equal(r.batch_size,50);});
  assert.equal(new Set(rows.map(r=>r.bookmark)).size,1);
 }finally{f.close();}
});
test('requests cannot reuse an earlier authority result after revocation, expiry, MFA changes or a hold',async()=>{
 const {f,tokens,coordinator,batches}=setup();
 try{
  await coordinator.fetch(request(hash(tokens[0])));
  f.sql.prepare('DELETE FROM sessions WHERE user_id=?').run('owner-0');
  f.sql.prepare('UPDATE sessions SET expires_at=0 WHERE user_id=?').run('owner-1');
  f.sql.prepare('UPDATE user_totp SET enabled=0 WHERE user_id=?').run('owner-2');
  const rows=await Promise.all(tokens.slice(0,4).map(t=>coordinator.fetch(request(hash(t))).then(r=>r.json())));
  assert.equal(batches(),2);for(const r of rows.slice(0,3))assert.equal(r.row.id,null);assert.equal(rows[3].row.id,'owner-3');
  f.sql.exec('UPDATE operations_control SET write_hold=1');
  const held=await(await coordinator.fetch(request(hash(tokens[3])))).json();assert.equal(held.row.write_hold,1);assert.equal(batches(),3);
 }finally{f.close();}
});
test('malformed requests, missing control state and database failures cannot authorize',async()=>{
 const {f,tokens,coordinator,batches}=setup();
 try{
  for(const req of [new Request('https://capacity-authority.invalid/'),request('invalid'),new Request('https://capacity-authority.invalid/check',{method:'POST',body:'{'}),new Request('https://capacity-authority.invalid/check',{method:'POST',body:JSON.stringify({token_hash:hash(tokens[0]),sql:'SELECT 1'})})])assert.ok((await coordinator.fetch(req)).status>=400);
  assert.equal(batches(),0);
  f.sql.exec('DELETE FROM operations_control');assert.equal((await coordinator.fetch(request(hash(tokens[0])))).status,503);
  const failed=new CapacityAuthorityCoordinator({}, {DB:{withSession(){throw Error('private DB detail');}}});
  const response=await failed.fetch(request(hash(tokens[0])));assert.equal(response.status,503);assert.doesNotMatch(await response.text(),/private|DB detail/);
 }finally{f.close();}
});
test('the adapter intercepts only the exact audited primary query and returns its native result shape',async()=>{
 const {f,tokens,coordinator,native,batches}=setup();
 try{
  const db=coordinatedAuthority(native,coordinator),session=db.withSession('first-primary');
  const row=await session.prepare(AUTHORITY_SQL).bind(hash(tokens[0]),Math.floor(Date.now()/1000)).first();
  assert.equal(row.id,'owner-0');assert.ok(session.getBookmark());assert.equal(batches(),1);
  assert.equal((await db.withSession('first-primary').prepare('SELECT write_hold FROM operations_control').first()).write_hold,0);
  await db.withSession(session.getBookmark()).prepare(AUTHORITY_SQL).bind(hash(tokens[0]),Math.floor(Date.now()/1000)).first();
  assert.equal(batches(),1,'Anchored/native and maintenance-only queries are not redirected');
 }finally{f.close();}
});
test('full application keeps customer isolation and live denial while coalescing 50 dashboard authority reads',async()=>{
 const {f,tokens,coordinator,native,batches}=setup(),env={DB:coordinatedAuthority(native,coordinator),RECOVERY_CONTROL_REQUIRED:'true'};
 const call=i=>worker.fetch(new Request('https://api.cveharbor.com/v1/inventory/page?resource=customers',{headers:{Cookie:'cvh_session='+tokens[i]}}),env,{});
 try{
  const responses=await Promise.all(tokens.map((_,i)=>call(i)));assert.equal(batches(),1);
  for(let i=0;i<50;i++){assert.equal(responses[i].status,200);const body=await responses[i].json();assert.equal(body.items.length,1);assert.equal(body.items[0].name,'Customer '+i);}
  f.sql.prepare('DELETE FROM sessions WHERE user_id=?').run('owner-0');assert.equal((await call(0)).status,401);
  f.sql.exec('UPDATE operations_control SET write_hold=1');assert.equal((await call(1)).status,503);
  assert.equal(f.sql.prepare('SELECT count(*) n FROM operations_leases').get().n,0);
 }finally{f.close();}
});


test('coordinator infrastructure is restricted to the existing protected main-only caller and explicit mode and fictional database',()=>{
 const env={GITHUB_REPOSITORY:'Prat007ai/cveharbor',GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_RUN_ATTEMPT:'1',GITHUB_WORKFLOW_REF:'Prat007ai/cveharbor/.github/workflows/inventory-capacity-cloud.yml@refs/heads/main',GITHUB_RUN_ID:'12345678901',GITHUB_SHA:'a'.repeat(40),CAPACITY_REVIEWED_COMMIT:'a'.repeat(40),CLOUDFLARE_ACCOUNT_ID:'9706b4d98ad72884e67fd1eb875c8a61',CLOUDFLARE_API_TOKEN:'fictional',CAPACITY_AUTHORITY_COORDINATOR:'true'};
 const config=coordinatorConfig(env);assert.equal(config.workers_dev,false);assert.equal(config.preview_urls,false);assert.deepEqual(config.routes,[]);assert.equal(config.d1_databases[0].database_id,'b4a226d7-35e8-469f-abfe-2a2eee0a96de');assert.equal(config.durable_objects.bindings.length,1);validateCloudRun(env);
 for(const change of [{GITHUB_REF:'refs/heads/feature'},{GITHUB_RUN_ATTEMPT:'2'},{GITHUB_EVENT_NAME:'push'},{CAPACITY_REVIEWED_COMMIT:'b'.repeat(40)},{CAPACITY_AUTHORITY_COORDINATOR:undefined},{CLOUDFLARE_ACCOUNT_ID:'aa99b9b15e0492302e4f6484b8d27bc2'},{GITHUB_WORKFLOW_REF:'Prat007ai/cveharbor/.github/workflows/unapproved.yml@refs/heads/main'}])assert.throws(()=>coordinatorConfig({...env,...change}));
 assert.throws(()=>validateCloudRun({...env,GITHUB_WORKFLOW_REF:'Prat007ai/cveharbor/.github/workflows/unapproved.yml@refs/heads/main'}));
});


test('a queued check observes revocation before execution and larger bursts use bounded batches',async()=>{
 const {f,tokens,coordinator,batches}=setup();
 try{
  const queued=coordinator.fetch(request(hash(tokens[0])));
  f.sql.prepare('DELETE FROM sessions WHERE user_id=?').run('owner-0');
  assert.equal((await(await queued).json()).row.id,null);
  const responses=await Promise.all(Array.from({length:200},()=>coordinator.fetch(request(hash(tokens[1])))));
  const rows=await Promise.all(responses.map(r=>r.json()));assert.equal(batches(),3);
  assert.equal(rows.reduce((n,r)=>n+r.native_queries,0),2);assert.ok(rows.every(r=>r.row.id==='owner-1'&&r.batch_size<=128));
 }finally{f.close();}
});


test('requests arriving during an in-flight primary query wait for a newer check',async()=>{
 let queries=0,release,started;const ready=new Promise(resolve=>started=resolve),hold=new Promise(resolve=>release=resolve);
 const db={withSession(constraint){
  assert.equal(constraint,'first-primary');let bookmark;
  return {getBookmark:()=>bookmark,prepare(sql){
   assert.equal(sql,BATCH_SQL);
   return {bind(hashes){return {async all(){
    const number=++queries;bookmark='snapshot-'+number;
    const results=JSON.parse(hashes).map((_,i)=>({request_index:i,write_hold:0,revision:0,id:number===1?'owner':null,expires_at:9999999999}));
    if(number===1){started();await hold;}return {results};
   }};}};
  }};
 }};
 const coordinator=new CapacityAuthorityCoordinator({}, {DB:db});
 const first=coordinator.fetch(request('a'.repeat(64)));await ready;
 const later=coordinator.fetch(request('a'.repeat(64)));release();
 const [before,after]=await Promise.all([first.then(r=>r.json()),later.then(r=>r.json())]);
 assert.equal(queries,2);assert.equal(before.row.id,'owner');assert.equal(after.row.id,null);assert.notEqual(before.bookmark,after.bookmark);
});
