import test from 'node:test';
import assert from 'node:assert/strict';
import {DB} from './helpers/d1.mjs';
import {subscribeProducts,cvieRoute,runCvieStep} from '../src/cvie.js';
import {sourceHealth} from '../src/cvie-records.js';
import {publicSourceStatus,invalidatePublicSourceStatus,PUBLIC_STATUS_TTL} from '../src/public-source-status-cache.js';
import worker from '../src/index.js';
const NOW=Date.parse('2026-11-01T18:00:00Z');
const route=(env,user='a',path='/v1/cvie/progress')=>cvieRoute(new Request('https://api.cveharbor.com'+path),env,{id:user});
test('the new progress route requires an authenticated session',async()=>{
 const response=await worker.fetch(new Request('https://api.cveharbor.com/v1/cvie/progress'),{DB:new DB()},{waitUntil(){}});
 assert.equal(response.status,401);
});
test('warm progress polls use two read statements, omit advisory matching and never cross accounts',async()=>{
 const env={DB:new DB()};await subscribeProducts(env,'a',[{name:'Apache Tomcat'}]);await subscribeProducts(env,'b',[{name:'PHP'}]);
 await runCvieStep(env,()=>Response.json({startIndex:0,totalResults:0,vulnerabilities:[]}),Date.now());
 const sql=[],prepare=env.DB.prepare.bind(env.DB);env.DB.prepare=query=>{sql.push(query);return prepare(query);};
 const first=await (await route(env)).json();assert.equal(first.products[0].name,'Apache Tomcat');assert.ok(first.products[0].progress);
 assert.equal(first.evidence.sources.length,3);
 env.DB.executions=0;sql.length=0;
 for(let i=0;i<100;i++){
  const state=await (await route(env,i%2?'a':'b')).json();
  assert.equal(state.products.length,1);assert.equal(state.products[0].name,i%2?'Apache Tomcat':'PHP');
 }
 assert.equal(env.DB.executions,200);
 assert.ok(sql.every(s=>!s.includes('cvie_advisories')||s.includes('FROM cvie_provider_budget')),'progress avoids the advisory tables except the existing readiness existence check');
 assert.ok(sql.every(s=>!s.includes('cvie_disclosures')&&!s.includes('verified_matches')));
 assert.ok(sql.every(s=>!/^\s*(INSERT|UPDATE|DELETE)/i.test(s)));
 assert.equal((await route(env)).headers.get('Cache-Control'),'no-store','private responses remain uncached');
 const empty=await (await route(env,'nonexistent')).json();assert.deepEqual(empty.products,[]);
 assert.equal(empty.evidence.sources.filter(s=>s.id==='nvd').length,1,'cached public metadata never acquires account-specific NVD status');
});
test('public metadata cache shares concurrent loads, clones results and expires after thirty seconds',async()=>{
 const env={DB:new DB()};let reads=0;
 const load=async()=>{reads++;return {sources:[{id:'cve_program',status:'current'}]};};
 const results=await Promise.all(Array.from({length:100},()=>publicSourceStatus(env,NOW,load)));
 assert.equal(reads,1);results[0].sources.unshift({id:'private-nvd'});
 assert.deepEqual((await publicSourceStatus(env,NOW+1,load)).sources.map(s=>s.id),['cve_program']);
 await publicSourceStatus(env,NOW+PUBLIC_STATUS_TTL,load);assert.equal(reads,2);
 invalidatePublicSourceStatus(env);await publicSourceStatus(env,NOW+PUBLIC_STATUS_TTL+1,load);assert.equal(reads,3);
 const other={DB:new DB()};await publicSourceStatus(other,NOW,load);assert.equal(reads,4,'different database bindings never share entries');
});
test('a failed public metadata read is retried and cache invalidation fences an older in-flight load',async()=>{
 const env={DB:new DB()};
 await assert.rejects(publicSourceStatus(env,NOW,()=>{throw Error('Temporary source query failure');}));
 let resolve;const old=publicSourceStatus(env,NOW,()=>new Promise(r=>{resolve=r;}));await Promise.resolve();
 invalidatePublicSourceStatus(env);
 assert.equal((await publicSourceStatus(env,NOW,()=>({revision:'new'}))).revision,'new');
 resolve({revision:'old'});await old;
 assert.equal((await publicSourceStatus(env,NOW,()=>({revision:'unexpected'}))).revision,'new');
});
test('public status caching reduces repeated queue aggregates without hiding source refreshes indefinitely',async()=>{
 const env={DB:new DB()};await sourceHealth(env,NOW);env.DB.executions=0;
 for(let i=0;i<100;i++)await sourceHealth(env,NOW+1);
 assert.equal(env.DB.executions,0);
 await sourceHealth(env,NOW+PUBLIC_STATUS_TTL);assert.ok(env.DB.executions>0);
});
