import test from 'node:test';
import assert from 'node:assert/strict';
import {outageAdapter,seedOutage} from './nvd_capacity_fixture.mjs';
import {capacityFixture} from '../account-backend/tests/helpers/capacity-db.mjs';
import * as cvie from '../account-backend/src/cvie.js';
import http from 'node:http';
import {outageRehearsal} from './nvd_capacity_rehearsal.mjs';
test('outage adapter limits reads and keeps source injection behind a run-only control key',async()=>{
 let reads=0,steps=0;
 const adapter=outageAdapter({fetch:()=>{reads++;return Response.json({});}},async(env,fetcher,now)=>{steps++;assert.equal(now,361000);const r=await fetcher();assert.equal(r.status,503);assert.equal(r.headers.get('Retry-After'),'300');return {retrying:true};},1000,'fictional-key');
 const req=(path,options)=>new Request('https://example.test'+path,options);
 assert.equal((await adapter.fetch(req('/v1/inventory/page'),{})).status,200);
 for(const path of ['/v1/inventory','/v1/cvie/directory','/v1/cvie/sync'])assert.equal((await adapter.fetch(req(path),{})).status,405);
 assert.equal((await adapter.fetch(req('/v1/inventory/page',{method:'DELETE'}),{})).status,405);
 assert.equal((await adapter.fetch(req('/__outage/step?mode=503',{method:'POST'}),{})).status,404);
 assert.equal((await adapter.fetch(req('/__outage/routing',{method:'POST'}),{})).status,404);
 assert.equal(reads,1);assert.equal(steps,0);
 const response=await adapter.fetch(req('/__outage/step?mode=503',{method:'POST',headers:{'X-Outage-Control':'fictional-key'}}),{});
 assert.equal((await response.json()).calls,1);assert.equal(steps,1);
});

test('routing diagnostic returns only version presence and location metadata, never the bookmark or customer data',async()=>{
 const calls=[];const env={DB:{withSession(constraint){calls.push(constraint);return {getBookmark:()=> 'fictional-private-bookmark',prepare(sql){assert.equal(sql,'SELECT 1 AS routing_probe');return {all:async()=>({results:[{routing_probe:1}],meta:{served_by_primary:constraint==='first-primary',served_by_region:'WNAM',duration:1}})};}};}}};
 const adapter=outageAdapter({fetch:()=>assert.fail('Not an application read')},()=>assert.fail('No provider call'),1,'fictional-key');
 const r=await adapter.fetch(new Request('https://example.test/__outage/routing',{method:'POST',headers:{'X-Outage-Control':'fictional-key'}}),env);
 const body=await r.json();assert.equal(body.bookmark_present,true);assert.equal(body.unchanged_read_bookmark,true);assert.equal(body.anchored.primary,false);assert.deepEqual(calls,['first-primary','fictional-private-bookmark','first-unconstrained','first-primary']);assert.doesNotMatch(JSON.stringify(body),/fictional|private/);
});
test('failed customer reads and browser probes cannot suppress either outage phase or produce success',async()=>{
 const calls={timeout:0,'503':0};let receipt;
 const server=http.createServer((req,res)=>{
  const url=new URL(req.url,'http://localhost');
  if(url.pathname==='/__outage/step'){
   const mode=url.searchParams.get('mode');res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({calls:calls[mode]++===0?1:0,elapsed_ms:1}));
  }else{res.writeHead(503);res.end('{}');}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try{
  await assert.rejects(outageRehearsal({base:'http://127.0.0.1:'+server.address().port,tokens:Array(50).fill('fictional'),controlKey:'fictional',site:'.',seconds:0,browserProbe:async()=>{throw Error('Fictional browser failure');},onProgress:r=>{receipt=structuredClone(r);}}));
  assert.deepEqual(receipt.phases.map(p=>p.mode),['timeout','503']);
  assert.equal(receipt.errors.filter(e=>e.component==='browser').length,2);
  assert.equal(receipt.errors.filter(e=>e.session!==undefined).length,100);
  assert.ok(receipt.phases.every(p=>p.nvd_attempts===1&&p.cooldown_attempts===0));
 }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
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
