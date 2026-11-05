import test from 'node:test';
import assert from 'node:assert/strict';
import {waitBackend} from '../scripts/release.mjs';
import {safeFailure} from '../scripts/errors.mjs';
const env={CF_STAGING_APPROVED_COMMIT:'a'.repeat(40)};
const good={ready:true,schema_ready:true,feed_version:'b'.repeat(64),mail_capture:true,mfa_configured:true,monitor_webhook_configured:true,native_schedules:false,held:false,release:env.CF_STAGING_APPROVED_COMMIT};
function clock(){let time=0;const waits=[];return {now:()=>time,sleep:async ms=>{waits.push(ms);time+=ms;},advance:ms=>{time+=ms;},waits};}
test('only stale release retries GET; matching release returns immediately without waits',async()=>{
 for(const stale of [0,2,6])for(const legacy of [false,true]){
  const c=clock(),observed=[];let requests=0;
  const result=await waitBackend(env,async(_url,init)=>{assert.equal(init.method,'GET');assert.equal(init.redirect,'manual');requests++;const body={...good,release:requests<=stale?'c'.repeat(40):good.release};if(legacy){delete body.mfa_configured;delete body.monitor_webhook_configured;}return Response.json(body);},{...c,bootstrap:true,record:e=>observed.push(structuredClone(e))});
  assert.equal(result.attempts,stale+1);assert.equal(requests,stale+1);assert.deepEqual(c.waits,Array(stale).fill(5000));
  assert.equal(observed.at(-1).checks.release_matches,true);assert.equal(observed.at(-1).attempt,stale+1);
 }
});
test('persistent release mismatch stops after seven requests and six waits with safe evidence',async()=>{
 const c=clock();let requests=0;
 await assert.rejects(waitBackend(env,async()=>{requests++;return Response.json({...good,release:'private-stale-identity',extra:'private-response'});},c),e=>{
  const f=safeFailure(e);assert.equal(f.check,'release_matches');assert.equal(f.retry_exhausted,true);assert.equal(f.attempts,7);assert.equal(f.retry_window_ms,60000);assert.doesNotMatch(JSON.stringify(f),/private-/);return true;
 });
 assert.equal(requests,7);assert.equal(c.waits.length,6);
});
test('other failures stop on the first request even when release is stale',async()=>{
 for(const patch of [{ready:false},{schema_ready:false},{feed_version:null},{mail_capture:false},{mfa_configured:false},{monitor_webhook_configured:false},{native_schedules:true},{held:true}]){
  const c=clock();let requests=0;
  await assert.rejects(waitBackend(env,async()=>{requests++;return Response.json({...good,release:'c'.repeat(40),...patch});},c));
  assert.equal(requests,1);assert.deepEqual(c.waits,[]);
 }
 for(const mode of ['network','json','403','302','429','503']){
  const c=clock();let requests=0;
  await assert.rejects(waitBackend(env,async()=>{requests++;if(mode==='network')throw Error('private-network');if(mode==='json')return new Response('private-html');return Response.json({...good,release:'c'.repeat(40)},{status:Number(mode)});},c));
  assert.equal(requests,1);assert.deepEqual(c.waits,[]);
 }
});
test('a different failure on a later request stops immediately rather than exhausting retries',async()=>{
 const c=clock();let requests=0;
 await assert.rejects(waitBackend(env,async()=>Response.json({...good,release:'c'.repeat(40),mail_capture:++requests===1}),c),e=>safeFailure(e).check==='mail_capture');
 assert.equal(requests,2);assert.deepEqual(c.waits,[5000]);
});
test('total deadline bounds slow probes and rejects success after the window',async()=>{
 for(const match of [false,true]){
  const c=clock();let requests=0;
  await assert.rejects(waitBackend(env,async()=>{requests++;c.advance(requests===1?29000:26000);return Response.json({...good,release:match&&requests===2?good.release:'c'.repeat(40)});},c),e=>safeFailure(e).retry_exhausted===true);
  assert.equal(requests,2);assert.deepEqual(c.waits,[5000]);
 }
});
