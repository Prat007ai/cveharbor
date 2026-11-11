import test from 'node:test';
import assert from 'node:assert/strict';
import {verifyAfterDeployment} from './organization_ai_health.mjs';
function scenario(states){let reads=0,waits=0;return {
 fetcher:async url=>url.endsWith('/release-readiness')?Response.json(states[Math.min(reads++,states.length-1)]):url.endsWith('/health')?Response.json({accounts:'configured'}):new Response('',{status:401}),
 wait:async()=>{waits++;},counts:()=>({reads,waits})};}
const ready=release=>({ready:true,held:false,schema_ready:true,release});
test('waits for the exact approved build while only its healthy predecessor is serving',async()=>{
 const s=scenario([ready('old'),ready('old'),ready('new')]);
 await verifyAfterDeployment({expectedRelease:'new',predecessor:'old',...s});
 assert.deepEqual(s.counts(),{reads:3,waits:2});
});
test('never accepts a predecessor that remains deployed',async()=>{
 const s=scenario([ready('old')]);
 await assert.rejects(verifyAfterDeployment({expectedRelease:'new',predecessor:'old',...s}),/different Worker build/);
 assert.deepEqual(s.counts(),{reads:13,waits:12});
});
test('unexpected builds, schema failures and recovery holds fail without retry',async()=>{
 for(const state of [ready('unexpected'),{...ready('old'),schema_ready:false},{...ready('old'),held:true,ready:false}]){
  const s=scenario([state]);
  await assert.rejects(verifyAfterDeployment({expectedRelease:'new',predecessor:'old',...s}));
  assert.deepEqual(s.counts(),{reads:1,waits:0});
 }
});
