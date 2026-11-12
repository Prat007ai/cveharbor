import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture,user,question,provider} from './helpers/ai-db.mjs';
import {assist,allowance} from '../src/ai-allowance.js';
import {adminRoute} from '../src/ai-admin.js';
import {ALLOWANCE,RESERVATION,period} from '../src/ai-pricing.js';
const admin=(f,path,method='GET',data={},actor='admin')=>adminRoute(new Request('https://api.cveharbor.com/v1/ai/admin'+path,{method}),f.env,user(actor),path,data);
const enable=f=>admin(f,'/personal/accounts','POST',{org:'owner',enabled:true});
test('personal workspace starts paused, owner activates, and organization allowance remains independent',async()=>{
 const f=fixture({personal:true}),p=provider();try{
  await assert.rejects(assist(f.env,user('owner'),'owner',question('personal-request-001','private-a'),p.fetcher,true),/paused/);
  assert.equal(p.calls.length,0);
  await assert.rejects(admin(f,'/personal/accounts','POST',{org:'owner',enabled:true},'owner'),/administrator/);
  await enable(f);
  const q=question('same-identifier-001','private-a');const result=await assist(f.env,user('owner'),'owner',q,p.fetcher,true);
  assert.equal(result.state,'settled');assert.equal((await allowance(f.db,'north')).spent_usd,0);
  assert.equal((await assist(f.env,user('owner'),'owner',q,p.fetcher,true)).replayed,true);assert.equal(p.calls.length,2);
  const report=await admin(f,'/personal/usage');assert.equal(report.scope,'personal');assert.equal(report.requests.length,1);assert.ok(report.totals.spent>0);
  assert.equal((await admin(f,'/usage')).requests.length,0);
 }finally{f.store.close();}
});
test('personal scope rejects another user and another customer before inference',async()=>{
 const f=fixture({personal:true}),p=provider();try{await enable(f);
  for(const [actor,account,customer]of [['staff','owner','private-a'],['owner','owner','private-b'],['owner','owner','customer-a']])await assert.rejects(assist(f.env,user(actor),account,question('scope-identifier-001',customer),p.fetcher,true),/unavailable/);
  assert.equal(p.calls.length,0);
 }finally{f.store.close();}
});
test('personal hard stop shares one balance across customers and preserves ambiguous charges',async()=>{
 const f=fixture({personal:true}),p=provider({failInference:true});try{await enable(f);
  f.store.prepare('INSERT INTO ai_personal_months(org,month,spent) VALUES(?,?,?)').run('owner',period(),ALLOWANCE-RESERVATION);
  const result=await assist(f.env,user('owner'),'owner',question('held-personal-001','private-a'),p.fetcher,true);assert.equal(result.state,'held');
  assert.equal((await assist(f.env,user('owner'),'owner',question('blocked-personal-001','private-a'),p.fetcher,true)).state,'blocked');assert.equal(p.calls.length,2);
  const usage={input_tokens:88,output_tokens:172,cached_input_tokens:0,reasoning_tokens:0};
  await admin(f,'/personal/reconcile','POST',{request_id:result.request_id,evidence:'Fictional provider receipt',usage});
  assert.equal((await admin(f,'/personal/usage')).requests.find(r=>r.id===result.request_id).state,'settled');
  await assert.rejects(admin(f,'/personal/reconcile','POST',{request_id:result.request_id,evidence:'Fictional provider receipt',usage}),/already reconciled/);
 }finally{f.store.close();}
});
test('customer revocation during personal inference records cost and suppresses the answer',async()=>{
 const f=fixture({personal:true}),p=provider({hook:()=>f.store.exec("DELETE FROM inventory_customers WHERE id='private-a'")});try{await enable(f);
  await assert.rejects(assist(f.env,user('owner'),'owner',question('revoke-personal-001','private-a'),p.fetcher,true),/unavailable/);
  assert.equal(f.store.prepare('SELECT state FROM ai_personal_requests').get().state,'settled');
 }finally{f.store.close();}
});
test('personal accounting retains recovery freezes and does not permit self activation',async()=>{
 const f=fixture({personal:true});try{await enable(f);f.store.exec('UPDATE operations_control SET database_frozen=1');
  await assert.rejects(admin(f,'/personal/accounts','POST',{org:'staff',enabled:true}),/recovery write hold/);
  await assert.rejects(assist(f.env,user('owner'),'owner',question('freeze-personal-001','private-a'),provider().fetcher,true),/recovery write hold/);
 }finally{f.store.close();}
});
