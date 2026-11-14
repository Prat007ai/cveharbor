import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {cachedRead,rememberRead,READ_CACHE_TTL,READ_CACHE_ENTRIES,deterministicRead,stableReadBindings} from '../src/versioned-read-cache.js';
import {capacityFixture,capacitySessions,fixtureId} from './helpers/capacity-db.mjs';
import {dashboardReadDatabase} from '../src/dashboard-read-db.js';
import worker from '../src/index.js';
import {inventoryPage} from '../src/inventory-pages.js';

test('data results require exact database/version/query/bindings and expire with bounded storage',()=>{
 const key={},query='owner-a/page',value={success:true,results:[{name:'Before'}],meta:{served_by_primary:true,rows_read:250,duration:4}};
 rememberRead(key,'v1',query,value,100);
 for(const args of [[{},'v1',query],[key,'v2',query],[key,'v1','owner-b/page'],[key,null,query]])assert.equal(cachedRead(...args,101),null);
 const hit=cachedRead(key,'v1',query,101);assert.equal(hit.value.meta.rows_read,0);assert.equal(hit.value.meta.served_by_primary,undefined);
 hit.value.results[0].name='Modified';assert.equal(cachedRead(key,'v1',query,102).value.results[0].name,'Before');
 assert.equal(cachedRead(key,'v1',query,100+READ_CACHE_TTL),null);
 rememberRead(key,'v1','large',{text:'x'.repeat(256*1024)},100);assert.equal(cachedRead(key,'v1','large',101),null);
 for(let i=0;i<=READ_CACHE_ENTRIES;i++)rememberRead(key,'v1','query-'+i,{i},100);
 assert.equal(cachedRead(key,'v1','query-0',101),null);assert.equal(cachedRead(key,'v1','query-'+READ_CACHE_ENTRIES,101).value.i,READ_CACHE_ENTRIES);
 rememberRead(key,'v1','failure',{success:false,error:'failed'},100);assert.equal(cachedRead(key,'v1','failure',101),null);
 assert.equal(deterministicRead("SELECT datetime('now')"),false);assert.equal(deterministicRead('SELECT current_timestamp'),false);
 for(const args of [[new ArrayBuffer(1)],[NaN],[Infinity],[Date.now()],['2026-11-13T00:00:00.001Z']])assert.equal(stableReadBindings(args),false);
 assert.equal(stableReadBindings(['owner',null,250]),true);
});

function sessionFixture(f){
 const calls=[];const revision=()=>String(f.sql.prepare('SELECT total_changes() n').get().n).padStart(16,'0');
 const binding={withSession(constraint){let bookmark=constraint.startsWith('first-')?null:constraint;
  const prepare=sql=>{let args=[];const s={bind(...a){args=a;return s;}};
   for(const method of ['first','all'])s[method]=async()=>{calls.push({sql,constraint,args});const value=await f.DB.prepare(sql).bind(...args)[method]();bookmark=revision();return value;};return s;};
  return {prepare,getBookmark:()=>bookmark,batch:rows=>Promise.all(rows.map(r=>r.all()))};
 }};return {binding,calls};
}

test('real inventory requests reuse unchanged pages only after fresh primary checks and invalidate on every write',async()=>{
 const f=capacityFixture({owners:50,customers:50,environments:100,assets:1000}),tokens=capacitySessions(f.sql),observed=sessionFixture(f),env={DB:observed.binding,RECOVERY_CONTROL_REQUIRED:'true',AGENT_INVENTORY_SCHEMA:'1'};
 f.sql.exec(fs.readFileSync(new URL('../agent-schema.sql',import.meta.url),'utf8'));
 const call=(i=0)=>worker.fetch(new Request('https://api.cveharbor.com/v1/inventory/page?resource=assets&customer_id='+fixtureId(i+1),{headers:{Cookie:'cvh_session='+tokens[i]}}),env,{});
 try{
  const a=await call();assert.equal(a.status,200);const original=await a.json();assert.equal(observed.calls.length,2);
  observed.calls.length=0;assert.deepEqual(await(await call()).json(),original);assert.equal(observed.calls.length,2);assert.ok(observed.calls.every(c=>c.constraint==='first-primary'));
  observed.calls.length=0;const other=await(await call(1)).json();assert.notDeepEqual(other.items,original.items);assert.equal(observed.calls.length,2);
  f.sql.prepare('UPDATE inventory_assets SET notes=? WHERE id=?').run('Changed',original.items[0].id);
  observed.calls.length=0;const changed=await(await call()).json();assert.equal(changed.items[0].notes,'Changed');assert.equal(observed.calls.length,3);
  // Agent mappings and metadata do not bump the inventory revision. Such
  // pages must stay live, and a manual cached page cannot hide a new mapping.
  const asset=original.items[1];
  f.sql.prepare("INSERT INTO inventory_agents(id,user_id,customer_id,environment_id,token_hash,hostname,agent_version,created_at,state) VALUES('fixture-device','owner-0',?,?,'fictional-hash','TEST','1',0,'active')").run(fixtureId(1),asset.environment_id);
  f.sql.prepare("INSERT INTO inventory_agent_assets VALUES(?,'fixture-device','fixture-product',1)").run(asset.id);
  const linked=await(await call()).json();assert.equal(linked.items.find(x=>x.id===asset.id).agent_device_id,'fixture-device');
  f.sql.exec("UPDATE inventory_agents SET primary_ip='192.0.2.10',state='suspended'");
  const refreshed=await(await call()).json();assert.equal(refreshed.items.find(x=>x.id===asset.id).agent_primary_ip,'192.0.2.10');assert.equal(refreshed.items.find(x=>x.id===asset.id).agent_state,'suspended');
  f.sql.exec("DELETE FROM inventory_agent_assets");await call();
  // Transfer away: the trigger bumps only the new owner. A revision-only cache
  // would leak this asset; the primary ownership guard must reject that hit.
  const revision=f.sql.prepare("SELECT revision FROM inventory_capacity_revisions WHERE user_id='owner-0'").get().revision;
  f.sql.prepare('UPDATE inventory_assets SET user_id=? WHERE id=?').run('owner-1',original.items[0].id);
  assert.equal(f.sql.prepare("SELECT revision FROM inventory_capacity_revisions WHERE user_id='owner-0'").get().revision,revision);
  const transferred=await(await call()).json();assert.ok(!transferred.items.some(x=>x.id===original.items[0].id));
  f.sql.exec('UPDATE operations_control SET revision=revision+1');observed.calls.length=0;
  await call();assert.ok(observed.calls.some(c=>c.sql.endsWith(' AS packed')),'Control revision invalidates saved pages');
  f.sql.prepare('UPDATE inventory_environments SET user_id=? WHERE id=?').run('owner-1',transferred.items[0].environment_id);
  const movedEnvironment=await(await call()).json();assert.ok(!movedEnvironment.items.some(x=>x.environment_id===transferred.items[0].environment_id));
  f.sql.exec("UPDATE user_totp SET enabled=0 WHERE user_id='owner-0'");assert.equal((await call()).status,401);
  f.sql.exec("UPDATE user_totp SET enabled=1 WHERE user_id='owner-0'");
  f.sql.exec("DELETE FROM sessions WHERE user_id='owner-0'");assert.equal((await call()).status,401);
  f.sql.exec('UPDATE operations_control SET write_hold=1');assert.equal((await call(1)).status,503);
 }finally{f.close();}
});

test('dashboard cache never reuses primary authority, crosses bindings, or returns data after failed authentication',async()=>{
 const f=capacityFixture(),observed=sessionFixture(f),auth='SELECT id FROM users WHERE id=?',actualAuth='SELECT users.id FROM sessions JOIN users ON users.id=sessions.user_id JOIN user_totp ON user_totp.user_id=users.id';
 capacitySessions(f.sql,1);
 try{
  const read=async()=>{const db=dashboardReadDatabase(observed.binding);await db.prepare(actualAuth).first();return db.prepare('SELECT name FROM inventory_customers WHERE user_id=?').bind('owner-0').all();};
  const first=await read();observed.calls.length=0;assert.deepEqual(await read(),JSON.parse(JSON.stringify(first)));assert.equal(observed.calls.length,1);assert.equal(observed.calls[0].constraint,'first-primary');
  const db=dashboardReadDatabase(observed.binding);await db.prepare(actualAuth).first();await db.prepare(auth).bind('owner-0').first();assert.equal(observed.calls.at(-1).constraint,'first-primary');
  f.sql.exec('DELETE FROM sessions');assert.equal(await db.prepare(actualAuth).first(),null);
  await db.prepare('SELECT name FROM inventory_customers WHERE user_id=?').bind('owner-0').all();assert.equal(observed.calls.at(-1).constraint,'first-primary','Failed auth clears the cache version; the handler rejects the request');
 }finally{f.close();}
});


test('the existing memory budget retains bounded pages for all 50 fictional customers',async t=>{
 t.mock.timers.enable({apis:['Date'],now:Date.now()});
 const f=capacityFixture({owners:50,customers:50,environments:100,assets:50000});
 f.sql.exec(fs.readFileSync(new URL('../agent-schema.sql',import.meta.url),'utf8'));
 let packedReads=0,ownershipChecks=0;
 const DB={prepare(sql){if(sql.endsWith(' AS packed'))packedReads++;if(sql.includes(' AS owned_count'))ownershipChecks++;return f.DB.prepare(sql);}};
 const env={DB,AGENT_INVENTORY_SCHEMA:'1',INVENTORY_READ_CACHE_IDENTITY:{},INVENTORY_READ_CONTROL_REVISION:'1'};
 const page=(owner,cursor=null)=>inventoryPage(new Request('https://api.cveharbor.com/v1/inventory/page?'+new URLSearchParams({customer_id:fixtureId(owner+1),...(cursor?{cursor}:{})})),env,{id:'owner-'+owner});
 const first=[];
 try{
  for(let owner=0;owner<50;owner++){let cursor=null,count=0;do{const result=await page(owner,cursor);if(!cursor)first[owner]=result;count+=result.items.length;cursor=result.next_cursor;}while(cursor);assert.equal(count,1000);}
  assert.equal(packedReads,200);packedReads=0;
  for(let round=0;round<2;round++){t.mock.timers.tick(4000);for(let owner=0;owner<50;owner++)assert.deepEqual(await page(owner),first[owner]);}
  assert.equal(packedReads,0,'Freshly validated pages stay reusable within the existing memory budget');assert.equal(ownershipChecks,100,'Every reused page still validates current ownership');
 }finally{f.close();}
});
