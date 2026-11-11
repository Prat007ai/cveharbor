import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture,user,question,provider} from './helpers/ai-db.mjs';
import {assist,allowance} from '../src/ai-allowance.js';
import {PRICE,USD,ALLOWANCE,RESERVATION,charge,period,priceCurrent} from '../src/ai-pricing.js';
import {adminRoute} from '../src/ai-admin.js';
const request=(url,method='GET')=>new Request('https://api.cveharbor.com/v1/ai/admin'+url,{method});
test.beforeEach(t=>t.mock.timers.enable({apis:['Date'],now:Date.parse('2026-11-11T18:00:00Z')}));

test('all staff and customers share exactly one organization allowance; no prompt storage',async()=>{
 const {env,store,db}=fixture(),p=provider();
 const a=await assist(env,user('owner'),'north',question(),p.fetcher);
 const b=await assist(env,user('staff'),'north',question('fictional-request-00002','customer-b'),p.fetcher);
 const c=await assist(env,user('other'),'south',question('fictional-request-00003','customer-c'),p.fetcher);
 assert.equal(a.state,'settled');assert.equal(b.state,'settled');assert.equal(c.state,'settled');
 const cost=88*PRICE.input+172*PRICE.output;
 assert.equal((await allowance(db,'north')).spent_usd,2*cost/USD);
 assert.equal((await allowance(db,'south')).spent_usd,cost/USD);
 assert.equal(store.prepare('SELECT COUNT(*) n FROM ai_months').get().n,2);
 assert.ok(!JSON.stringify(store.prepare('SELECT * FROM ai_requests').all()).includes(question().question));
 assert.equal(JSON.parse(p.calls[1].options.body).max_completion_tokens,1024);
 assert.equal(JSON.parse(p.calls[1].options.body).store,false);
});
test('last available reservation cannot be double spent under concurrent requests; blocked sends nothing',async()=>{
 const {env,store}=fixture(),p=provider({failInference:true});
 store.prepare('INSERT INTO ai_months(org,month,spent) VALUES(?,?,?)').run('north',period(),ALLOWANCE-RESERVATION);
 const results=await Promise.all(Array.from({length:15},(_,i)=>assist(env,user('owner'),'north',question('concurrent-request-'+String(i).padStart(3,'0')),p.fetcher)));
 assert.equal(results.filter(r=>r.state==='held').length,1);
 assert.equal(results.filter(r=>r.state==='blocked').length,14);
 assert.equal(p.calls.length,2);
 const balance=store.prepare('SELECT * FROM ai_months').get();assert.equal(balance.spent+balance.reserved,ALLOWANCE);
 await assert.rejects(async()=>store.prepare('UPDATE ai_months SET spent=spent+1').run(),/CHECK/);
});
test('same idempotency key is never dispatched twice, including across months or different payloads',async()=>{
 const {env,store}=fixture(),p=provider();
 const results=await Promise.all(Array.from({length:8},()=>assist(env,user('owner'),'north',question(),p.fetcher)));
 assert.equal(p.calls.length,2);assert.equal(results.filter(r=>r.replayed).length,7);
 await assert.rejects(assist(env,user('owner'),'north',{...question(),question:'Different'},p.fetcher),/identifier/);
 assert.equal(store.prepare('SELECT COUNT(*) n FROM ai_requests').get().n,1);
});
test('authorization, disabled organizations, malformed input and price bounds fail before Azure',async()=>{
 const {env}=fixture(),p=provider();
 await assert.rejects(assist(env,user('staff'),'north',question(),p.fetcher),/unavailable/);
 await assert.rejects(assist(env,user('owner'),'south',question(),p.fetcher),/unavailable/);
 await assert.rejects(assist(env,user('owner'),'north',{...question(),question:'😀'.repeat(1600)},p.fetcher),/6,000/);
 env.CVEHARBOR_AI_ENABLED='false';await assert.rejects(assist(env,user('owner'),'north',question(),p.fetcher),/paused/);
 assert.equal(p.calls.length,0);
 assert.equal(priceCurrent(Date.parse('2026-12-12T00:00:00Z')),false);
 assert.equal(period(Date.parse('2027-01-01T00:00:00Z')),'2027-01');
 assert.throws(()=>charge({input_tokens:32769,output_tokens:1}));
 assert.throws(()=>charge({input_tokens:1,output_tokens:1025}));
 assert.throws(()=>charge({input_tokens:1,output_tokens:1,cached_input_tokens:2}));
 assert.equal(charge({input_tokens:100,output_tokens:100,cached_input_tokens:80,reasoning_tokens:99}),20*PRICE.input+80*PRICE.cached+100*PRICE.output);
});
test('authentication failure releases; ambiguous inference and missing usage retain reservations',async()=>{
 const {env,store}=fixture();
 assert.equal((await assist(env,user('owner'),'north',question(),provider({failAuth:true}).fetcher)).state,'released');
 assert.equal(store.prepare('SELECT reserved FROM ai_months').get().reserved,0);
 for(const opts of [{failInference:true},{usage:{}},{model:'unreviewed-model'}]){
  const r=await assist(env,user('owner'),'north',question('ambiguous-'+crypto.randomUUID()),provider(opts).fetcher);assert.equal(r.state,'held');
 }
 assert.equal(store.prepare('SELECT reserved FROM ai_months').get().reserved,RESERVATION*3);
 assert.equal(store.prepare("SELECT enabled FROM ai_organizations WHERE org='north'").get().enabled,0);
});

test('failed settlement retains funds and a retry cannot issue another paid request',async()=>{
 const {env,store}=fixture();
 const p=provider({hook:()=>store.exec("CREATE TRIGGER fictional_settlement_failure BEFORE UPDATE ON ai_requests WHEN NEW.state='settled' BEGIN SELECT RAISE(ABORT,'Fictional storage failure'); END;")});
 const first=await assist(env,user('owner'),'north',question(),p.fetcher);
 assert.equal(first.state,'held');
 assert.equal(store.prepare('SELECT reserved FROM ai_months').get().reserved,RESERVATION);
 assert.equal((await assist(env,user('owner'),'north',question(),p.fetcher)).replayed,true);
 assert.equal(p.calls.length,2);
});

test('stalled pre-dispatch recovery cancels safely and blocks a delayed provider dispatch',async()=>{
 const {env,store}=fixture(),p=provider();let resume,ready;
 const started=new Promise(resolve=>ready=resolve),paused=new Promise(resolve=>resume=resolve);
 const fetcher=async(url,options)=>{const result=await p.fetcher(url,options);ready();await paused;return result;};
 const pending=assist(env,user('owner'),'north',question(),fetcher);await started;
 const row=store.prepare('SELECT id FROM ai_requests').get();
 const payload={request_id:row.id,evidence:'Fictional recovery review: never dispatched',usage:{input_tokens:0,output_tokens:0}};
 await assert.rejects(adminRoute(request('/reconcile','POST'),env,user('admin'),'/reconcile',payload),/already reconciled/);
 // Fixture-only clock aging: production immutable transition guards remain in place.
 store.exec('DROP TRIGGER ai_request_transition');
 store.prepare('UPDATE ai_requests SET updated_at=unixepoch()-600 WHERE id=?').run(row.id);
 await adminRoute(request('/reconcile','POST'),env,user('admin'),'/reconcile',payload);
 resume();await pending;
 assert.equal(p.calls.length,1);assert.equal(store.prepare('SELECT state FROM ai_requests').get().state,'released');
 assert.equal(store.prepare('SELECT reserved FROM ai_months').get().reserved,0);
});
test('revocation before dispatch prevents inference; after dispatch suppresses answer but records cost',async()=>{
 const f=fixture(),p=provider();
 const revoke=async(url,options)=>{const result=await p.fetcher(url,options);f.store.exec("DELETE FROM team_visible_customers WHERE actor='owner'");return result;};
 assert.equal((await assist(f.env,user('owner'),'north',question(),revoke)).state,'released');assert.equal(p.calls.length,1);
 const g=fixture(),late=provider({hook:()=>g.store.exec("DELETE FROM team_visible_customers WHERE actor='owner'")});
 await assert.rejects(assist(g.env,user('owner'),'north',question(),late.fetcher),/unavailable/);
 assert.equal(g.store.prepare('SELECT state FROM ai_requests').get().state,'settled');
});
test('UTC month resets lazily without deleting history or freeing uncertain old reservations',async()=>{
 const {db,store}=fixture();
 store.prepare('INSERT INTO ai_months(org,month,spent,reserved) VALUES(?,?,?,?)').run('north','2026-11',10*USD,2*USD);
 assert.equal((await allowance(db,'north',Date.parse('2026-11-30T23:59:59Z'))).available_usd,8);
 assert.equal((await allowance(db,'north',Date.parse('2026-12-01T00:00:00Z'))).available_usd,20);
 assert.equal(store.prepare("SELECT reserved FROM ai_months WHERE month='2026-11'").get().reserved,2*USD);
});
test('organization Owners cannot access platform reports or grant themselves dashboard access',async()=>{
 const {env}=fixture();
 await assert.rejects(adminRoute(request('/usage'),env,user('owner'),'/usage',{}),/administrator/);
 await assert.rejects(adminRoute(request('/access','POST'),env,user('owner'),'/access',{action:'grant',email:'owner@example.test'}),/administrator/);
 await adminRoute(request('/access','POST'),env,user('admin'),'/access',{action:'grant',email:'staff@example.test'});
 const report=await adminRoute(request('/usage'),env,user('staff'),'/usage',{});assert.equal(report.totals.organizations,2);assert.equal(report.platform_owner,false);
 await assert.rejects(adminRoute(request('/access','POST'),env,user('staff'),'/access',{action:'grant',email:'owner@example.test'}),/administrator/);
 await adminRoute(request('/access','POST'),env,user('admin'),'/access',{action:'revoke',email:'staff@example.test'});
 await assert.rejects(adminRoute(request('/usage'),env,user('staff'),'/usage',{}),/administrator/);
});
test('report totals include held/blocked/failed requests; owner reconciles once with evidence',async()=>{
 const {env,store}=fixture();
 const r=await assist(env,user('owner'),'north',question(),provider({failInference:true}).fetcher);
 const before=await adminRoute(request('/usage'),env,user('admin'),'/usage',{});assert.equal(before.totals.reserved,RESERVATION);
 const payload={request_id:r.request_id,evidence:'Fictional Azure usage export record 123',usage:{input_tokens:88,output_tokens:172}};
 await adminRoute(request('/reconcile','POST'),env,user('admin'),'/reconcile',payload);
 await assert.rejects(adminRoute(request('/reconcile','POST'),env,user('admin'),'/reconcile',payload),/already reconciled/);
 const after=await adminRoute(request('/usage?org=north'),env,user('admin'),'/usage',{});
 assert.equal(after.totals.reserved,0);assert.equal(after.totals.spent,charge(payload.usage));assert.equal(after.users.length,1);
 assert.equal(store.prepare("SELECT COUNT(*) n FROM ai_audit WHERE action='reconcile usage'").get().n,1);
 assert.throws(()=>store.exec('DELETE FROM ai_requests'),/Retain/);
});
test('recovery freeze prevents new accounting and access mutations',async()=>{
 const {env,store}=fixture(),p=provider();store.exec('UPDATE operations_control SET database_frozen=1');
 await assert.rejects(assist(env,user('owner'),'north',question(),p.fetcher),/recovery write hold/);
 await assert.rejects(adminRoute(request('/access','POST'),env,user('admin'),'/access',{action:'grant',email:'staff@example.test'}),/recovery write hold/);
 assert.equal(p.calls.length,0);
});
