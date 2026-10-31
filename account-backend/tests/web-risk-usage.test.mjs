import test from 'node:test';
import assert from 'node:assert/strict';
import {reserveLookup,usageReport} from '../src/web-risk-usage.js';
function database(start=0){
 const state={count:start,accounts:new Map()};
 return {state,prepare(sql){return {bind(...args){return {
  async run(){
   if(sql.includes('SET reserved=reserved+1')){if(state.count>=150000)return {meta:{changes:0}};state.count++;return {meta:{changes:1}}}
   if(sql.includes('INSERT INTO web_risk_account_usage'))state.accounts.set(args[1],(state.accounts.get(args[1])||0)+1);
   return {meta:{changes:1}};
  },
  async first(){if(sql.includes('SELECT reserved FROM'))return {reserved:state.count};if(sql.includes('SELECT reserved,warning_sent_at'))return {reserved:state.count,warning_sent_at:null};if(sql.includes('SELECT requests FROM'))return {requests:state.accounts.get(args[1])||0};return null}
 }}}}};
}
test('hard stop at 150000 and does not charge blocked requests',async()=>{
 const db=database(149999),env={DB:db};
 const first=await reserveLookup(env,'tenant-a');
 const blocked=await reserveLookup(env,'tenant-b');
 assert.equal(first.allowed,true);assert.equal(blocked.allowed,false);
 assert.equal(blocked.reason,'monthly_limit');
 assert.equal(db.state.count,150000);
 assert.equal(db.state.accounts.get('tenant-a'),1);
 assert.equal(db.state.accounts.has('tenant-b'),false);
});
test('concurrent reservations never pass the cap',async()=>{
 const db=database(149990),env={DB:db};
 const result=await Promise.all(Array.from({length:30},(_,i)=>reserveLookup(env,'account-'+i)));
 assert.equal(result.filter(x=>x.allowed).length,10);
 assert.equal(db.state.count,150000);
});
test('account scoped usage report and fail closed',async()=>{
 const db=database(15);db.state.accounts.set('one',9);db.state.accounts.set('two',6);
 const view=await usageReport({DB:db},'one','2026-10');
 assert.equal(view.account_used,9);assert.equal(view.global_used,15);
 assert.deepEqual((await reserveLookup({},'one')).allowed,false);
});

test('warning test sends to configured recipient without touching Web Risk usage',async()=>{
 const {sendWarningTest}=await import('../src/web-risk-usage.js');
 const events=[],db={prepare(sql){return {bind(...args){return {
  async first(){if(sql.includes('SELECT window_start'))return null;return {count:1}},
  async run(){events.push({sql,args});return {meta:{changes:1}}}
 }}}}};
 const messages=[];
 const sender=async(_url,options)=>{messages.push(JSON.parse(options.body));return new Response(JSON.stringify({data:{succeeded:1,failed:0}}),{status:200})};
 const result=await sendWarningTest({DB:db,WEB_RISK_ALERT_TEST_ENABLED:'true',SMTP2GO_API_KEY:'fake',EMAIL_FROM:'alerts@cveharbor.com',WEB_RISK_BILLING_ALERT_EMAIL:'alert@example.com'},'account1',sender);
 assert.equal(result.ok,true);
 assert.equal(messages[0].to[0],'alert@example.com');
 assert.ok(messages[0].subject.includes('[TEST]'));
 assert.equal(events.some(x=>x.sql.includes('web_risk_usage')),false);
});
test('warning test is disabled by default',async()=>{
 const {sendWarningTest}=await import('../src/web-risk-usage.js');
 const result=await sendWarningTest({},'account1',()=>{throw Error('must not send')});
 assert.equal(result.ok,false);assert.equal(result.status,503);
});
