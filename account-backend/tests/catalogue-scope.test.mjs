import test from 'node:test';
import assert from 'node:assert/strict';
import {DB} from './helpers/d1.mjs';
import worker from '../src/index.js';
import {catalogueProducts,catalogueRevision} from '../src/catalogue-selection.js';
import {subscribeProducts,syncAccountProducts,runCvieStep,cvieRoute} from '../src/cvie.js';
const q=(e,s,...a)=>e.DB.prepare(s).bind(...a),NOW=Date.now(),CPE='cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*';
async function setup(shared=false){
 const e={DB:new DB(),CVIE_SHARED_SCANS_ENABLED:String(shared)};
 const tokens={a:'a'.repeat(64),b:'b'.repeat(64)};
 for(const id of ['a','b']){const hash=await catalogueRevision(tokens[id]);e.DB.sql.prepare('INSERT INTO sessions VALUES(?,?,?,?)').run(id,id,hash,Math.floor(Date.now()/1000)+3600);e.DB.sql.prepare('INSERT INTO user_totp VALUES(?,1)').run(id)}
 // Saving never needs a provider call for these contract tests.
 await q(e,"UPDATE cvie_provider_budget SET next_request_at=?",NOW+86400000).run();
 const request=async(method='GET',body,id='a')=>{
  const pending=[];const r=await worker.fetch(new Request('https://api.cveharbor.com/v1/technology-catalogue',{method,headers:{Origin:'https://cveharbor.com',Cookie:'cvh_session='+tokens[id],'Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{})}),e,{waitUntil:p=>pending.push(p)});
  await Promise.all(pending);return {status:r.status,...await r.json()};
 };
 const state=(scope='catalogue',id='a')=>cvieRoute(new Request('https://api.cveharbor.com/v1/cvie/progress?scope='+scope),e,{id}).then(r=>r.json());
 return {e,request,state};
}
test('save exact defaults, selected custom products, reload, no-op writes and revision conflicts',async()=>{
 const {e,request,state}=await setup();const initial=await request();assert.equal(initial.revision,'none');
 const data={defaults:['Windows Server OS','.NET Core'],products:[{name:'Maria DB',version:'',enabled:false}],revision:initial.revision};
 const saved=await request('PUT',data);assert.equal(saved.saved,true);assert.equal(saved.cvie.ready,true);
 assert.deepEqual((await state()).products.map(p=>p.name).sort(),['.NET Core','Windows Server OS']);
 assert.deepEqual((await request()).defaults,data.defaults);
 const before=(await q(e,'SELECT total_changes() AS n').first()).n;
 assert.equal((await request('PUT',{...data,revision:saved.revision})).unchanged,true);
 assert.equal((await q(e,'SELECT total_changes() AS n').first()).n,before,'identical save makes zero writes');
 assert.equal((await request('PUT',{defaults:[],products:[],revision:'stale'})).status,409);
 assert.deepEqual((await request()).defaults,data.defaults);
 const add=await request('PUT',{defaults:[...data.defaults,'WordPress / Plugins'],products:[],revision:saved.revision});assert.equal(add.saved,true);
 assert.equal((await state()).products.length,3);
 await request('PUT',{defaults:[],products:[],revision:add.revision});assert.equal((await state()).products.length,0);
 assert.deepEqual((await request()).defaults,[]);await syncAccountProducts(e,'a');assert.equal((await state()).products.length,0);
 assert.ok((await q(e,'SELECT COUNT(*) n FROM cvie_products').first()).n>=3,'historical product state is retained');
});
test('catalogue scope cannot include inventory/watchlist or another user; saved preferences do not alter either',async()=>{
 const {e,request,state}=await setup(true);
 e.DB.sql.exec("INSERT INTO inventory_assets VALUES('a','WordPress');INSERT INTO user_stack VALUES('a','PHP')");
 await syncAccountProducts(e,'a');await request('PUT',{defaults:['.NET Core'],products:[]});await request('PUT',{defaults:['PHP'],products:[]},'b');
 assert.deepEqual((await state()).products.map(p=>p.name),['.NET Core']);
 assert.deepEqual((await state('catalogue','b')).products.map(p=>p.name),['PHP']);
 assert.deepEqual((await state('inventory')).products.map(p=>p.name),['WordPress']);
 assert.deepEqual((await state('stack')).products.map(p=>p.name),['PHP']);
 await request('PUT',{defaults:[],products:[]});
 assert.equal((await state()).products.length,0);assert.equal((await state('inventory')).products.length,1);assert.equal((await state('catalogue','b')).products.length,1);
 assert.equal((await q(e,'SELECT COUNT(*) n FROM inventory_assets').first()).n,1);assert.equal((await q(e,'SELECT COUNT(*) n FROM user_stack').first()).n,1);
 assert.equal((await worker.fetch(new Request('https://api.cveharbor.com/v1/technology-catalogue'),e,{})).status,401);
});
test('bulk changes preserve custom PHP details and keep a single catalogue registration',async()=>{
 const {request,state}=await setup();
 const php={name:'PHP',version:'8.4.26',vendor:'PHP',category:'applications'};
 let saved=await request();
 for(const enabled of [true,false,true]){
  const product={...php,enabled};
  saved=await request('PUT',{defaults:enabled?['PHP']:[],products:[product],revision:saved.revision});
  assert.equal(saved.saved,true);
  assert.deepEqual((await request()).products,[product]);
  assert.deepEqual((await state()).products.map(p=>p.name),enabled?['PHP']:[]);
 }
});
test('stale synchronization cannot restore removed catalogue jobs or erase a newer selection',async()=>{
 const {e,request,state}=await setup();await request('PUT',{defaults:['PHP'],products:[]});
 const old=(await q(e,'SELECT preferences_json FROM user_technology_catalogue WHERE user_id=?','a').first()).preferences_json;
 await request('PUT',{defaults:['.NET Core'],products:[]});
 await subscribeProducts(e,'a',catalogueProducts(JSON.parse(old)),'catalogue',old);
 assert.deepEqual((await state()).products.map(p=>p.name),['.NET Core']);
 assert.deepEqual((await q(e,"SELECT p.name FROM cvie_products p JOIN cvie_subscriptions s ON s.product_id=p.id WHERE s.origin='catalogue'").all()).results.map(p=>p.name),['.NET Core']);
});
test('private in-flight pages are invalidated after removal; shared requests required by another account survive',async()=>{
 for(const shared of [false,true]){
  const {e,request,state}=await setup(shared);
  const data={defaults:[],products:[{name:'Apache Tomcat',version:'',cpe:CPE}]};
  await request('PUT',data);if(shared)await request('PUT',data,'b');
  await q(e,'UPDATE cvie_provider_budget SET next_request_at=0').run();
  let calls=0;
  const result=await runCvieStep(e,async()=>{calls++;await request('PUT',{defaults:[],products:[]});return Response.json({startIndex:0,totalResults:0,vulnerabilities:[]})},NOW,'a');
  assert.equal(calls,1);assert.equal((await state()).products.length,0);
  if(!shared){assert.equal(result.cancelled,true);assert.equal((await q(e,'SELECT last_success_at FROM cvie_products').first()).last_success_at,null)}
  else {assert.equal((await state('catalogue','b')).products.length,1);assert.equal((await q(e,'SELECT COUNT(*) n FROM cvie_shared_scopes').first()).n,1);await request('PUT',{defaults:[],products:[]},'b')}
  assert.equal((await runCvieStep(e,()=>{throw Error('Obsolete scan scheduled')},NOW+10000)).idle,true);
 }
});
test('historical advisory queries exclude inventory and watchlist records from catalogue pages',async()=>{
 for(const shared of [false,true]){
  const {e,request}=await setup(shared);
  e.DB.sql.exec("INSERT INTO inventory_assets VALUES('a','WordPress');INSERT INTO user_stack VALUES('a','PHP')");
  await syncAccountProducts(e,'a');await request('PUT',{defaults:['.NET Core'],products:[]});
  const products=(await q(e,"SELECT * FROM cvie_products WHERE user_id='a'").all()).results;
  for(const [i,p] of products.entries()){
   const record={id:'CVE-2026-'+(88000+i),published:new Date(NOW-86400000).toISOString(),summary:p.name,severity:'high',cvss:8.1,sources:[]};
   await q(e,'INSERT INTO cvie_advisories VALUES(?,?,?,?,?)',p.id,record.id,record.published,JSON.stringify(record),'retained').run();
  }
  const records=async scope=>(await (await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie/advisories?scope='+scope),e,{id:'a'})).json()).advisories;
  assert.deepEqual((await records('catalogue')).flatMap(r=>r.cvie_products),['.NET Core']);
  assert.deepEqual((await records('inventory')).flatMap(r=>r.cvie_products),['WordPress']);
  assert.deepEqual((await records('stack')).flatMap(r=>r.cvie_products),['PHP']);
  await request('PUT',{defaults:[],products:[]});assert.deepEqual(await records('catalogue'),[]);
  assert.equal((await runCvieStep(e,()=>{throw Error('Catalogue scheduled unrelated product')},NOW,'a','catalogue')).idle,true);
 }
});
