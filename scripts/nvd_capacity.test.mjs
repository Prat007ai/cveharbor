import test from 'node:test';
import assert from 'node:assert/strict';
import {outageAdapter,seedOutage} from './nvd_capacity_fixture.mjs';
import {capacityFixture} from '../account-backend/tests/helpers/capacity-db.mjs';
import * as cvie from '../account-backend/src/cvie.js';
test('outage adapter limits reads and keeps source injection behind a run-only control key',async()=>{
 let reads=0,steps=0;
 const adapter=outageAdapter({fetch:()=>{reads++;return Response.json({});}},async(env,fetcher,now)=>{steps++;assert.equal(now,361000);const r=await fetcher();assert.equal(r.status,503);assert.equal(r.headers.get('Retry-After'),'300');return {retrying:true};},1000,'fictional-key');
 const req=(path,options)=>new Request('https://example.test'+path,options);
 assert.equal((await adapter.fetch(req('/v1/inventory/page'),{})).status,200);
 for(const path of ['/v1/inventory','/v1/cvie/directory','/v1/cvie/sync'])assert.equal((await adapter.fetch(req(path),{})).status,405);
 assert.equal((await adapter.fetch(req('/v1/inventory/page',{method:'DELETE'}),{})).status,405);
 assert.equal((await adapter.fetch(req('/__outage/step?mode=503',{method:'POST'}),{})).status,404);
 assert.equal(reads,1);assert.equal(steps,0);
 const response=await adapter.fetch(req('/__outage/step?mode=503',{method:'POST',headers:{'X-Outage-Control':'fictional-key'}}),{});
 assert.equal((await response.json()).calls,1);assert.equal(steps,1);
});
test('50 test accounts share saved evidence and one unavailable provider request',async()=>{
 const fixture=capacityFixture({owners:50,customers:50,environments:100,assets:1000});
 try{
  const now=Date.now(),seed=await seedOutage(fixture,cvie,now);let calls=0;
  assert.equal(fixture.sql.prepare('SELECT count(*) n FROM cvie_shared_scopes').get().n,1);
  const fetcher=async()=>{calls++;return new Response('',{status:503});};
  await Promise.all(Array.from({length:50},()=>cvie.runCvieStep(seed.env,fetcher,now)));
  assert.equal(calls,1);await cvie.runCvieStep(seed.env,fetcher,now+60000);assert.equal(calls,1);
  assert.equal(fixture.sql.prepare('SELECT count(*) n FROM cvie_shared_advisories').get().n,200);
  for(const id of ['owner-0','owner-49']){
   const r=await cvie.cvieRoute(new Request('https://example.test/v1/cvie?scope=inventory'),seed.env,{id});const state=await r.json();assert.equal(state.products.length,1);assert.equal(state.products[0].status,'retrying');
  }
 }finally{fixture.close();}
});
