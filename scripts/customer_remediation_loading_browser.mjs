// Isolated browser fixtures only. Every request is intercepted; no cloud access or writes.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
const {chromium}=await import(process.env.CVEHARBOR_PLAYWRIGHT_MODULE||'playwright-core');
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||'/usr/bin/google-chrome',args:['--no-sandbox']});
const features={storage:'d1',version:2,shared_records_available:true,customer_records_available:true,assignments_available:true,assignment_email_enabled:true};
const inventory=account=>({customers:[{id:account+'-north',name:account+' North'},{id:account+'-south',name:account+' South'}],environments:[],assets:[]});
const record=(account,customer)=>({id:'CVE-2026-81001',status:'Open',owner:account+' fictional owner',updated:'2026-11-05T12:00:00Z',scope:customer==='unassigned'?null:{customer_id:customer,customer_name:customer}});
const headers={'Access-Control-Allow-Origin':'http://127.0.0.1:8080','Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS'};
let account='a',populated=false,override=null,gate=null,writes=0;
const diagnostics=[],uncaught=[];
try{
 const context=await browser.newContext({serviceWorkers:'block'});context.setDefaultTimeout(10000);
 await context.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.hostname==='api.cveharbor.com'){
   if(req.method()==='OPTIONS')return route.fulfill({status:204,headers});
   if(req.method()!=='GET'){writes++;return route.fulfill({status:400,headers,json:{error:'No writes in loading tests'}});}
   const owner=account;let response={status:200,headers,json:{}};
   if(url.pathname==='/v1/me')response.json={authenticated:!!owner,email:owner+'@example.test'};
   if(url.pathname==='/v1/remediations/features')response.json=features;
   if(url.pathname==='/v1/inventory')response.json=inventory(owner);
   if(url.pathname==='/v1/remediations')response.json={remediations:populated?[record(owner,url.searchParams.get('customer_id')==='all'?owner+'-north':url.searchParams.get('customer_id'))]:[]};
   if(url.pathname==='/v1/stack')response.json={stack:[]};
   if(url.pathname==='/v1/alerts')response.json={enabled:false};
   if(override?.match(url)){response={headers,...override.response};}
   const held=gate;
   if(held?.match(url)){
    held.requests++;held.started();await held.promise;
    if(held.response)response={headers,...held.response};
   }
   if(response.abort)await route.abort(response.abort);else await route.fulfill(response);
   if(held?.match(url)){held.completed++;held.finished();}return;
  }
  if(url.hostname!=='127.0.0.1')return route.abort();
  const file=path.resolve('public','.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));
  if(!file.startsWith(path.resolve('public')+path.sep)||!fs.existsSync(file))return route.fulfill({status:404,body:''});
  return route.fulfill({body:fs.readFileSync(file),contentType:{'.html':'text/html','.js':'application/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml'}[path.extname(file)]||'application/octet-stream'});
 });
 const page=await context.newPage();page.on('pageerror',e=>uncaught.push(e.message));
 page.on('console',m=>{if(m.text().startsWith('Remediation tracker load failed'))diagnostics.push(m.text());});
 async function settled(kind='ready'){
  await page.waitForFunction(expected=>{
   const rows=document.getElementById('remediationRows'),save=document.getElementById('remediationSave');
   return rows?.closest('table')?.getAttribute('aria-busy')==='false'&&
    (expected==='ready'?!save.disabled:rows.textContent.includes('Records unavailable'));
  },kind);
 }
 async function pending(){
  await page.waitForFunction(()=>document.getElementById('remediationRows')?.closest('table')?.getAttribute('aria-busy')==='true');
  assert.match(await page.locator('#remediationStorage').textContent(),/Loading/);
  assert.doesNotMatch(await page.locator('#remediationStorage').textContent(),/unavailable|retry/i);
  for(const id of ['remediationSave','remediationAssign','remediationImport'])assert.equal(await page.locator('#'+id).isDisabled(),true,id);
 }
 function hold(match,response){
  let release,started,finished;const promise=new Promise(r=>release=r),seen=new Promise(r=>started=r),done=new Promise(r=>finished=r);
  gate={match,response,promise,started,finished,requests:0,completed:0};
  return {seen,done,release(){gate=null;release();}};
 }
 const endpoint=p=>url=>url.pathname==='/v1/'+p;
 const customer=c=>url=>url.pathname==='/v1/remediations'&&url.searchParams.get('customer_id')===c;
 async function open(){await page.goto('http://127.0.0.1:8080/remediation/');}
 async function accountEvent(value){account=value;await page.evaluate(a=>window.dispatchEvent(new CustomEvent('cveharbor:account-state',{detail:{authenticated:!!a,email:a+'@example.test'}})),value);}
 async function painted(){await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));}
 async function blockedSubmit(){
  const before=writes;
  await page.locator('#remediationCve').fill('CVE-2026-99999');await page.locator('#remediationOwner').fill('Fictional engineer');
  await page.evaluate(()=>document.getElementById('remediationForm').dispatchEvent(new Event('submit',{cancelable:true,bubbles:true})));
  assert.equal(writes,before);assert.equal(await page.evaluate(()=>localStorage.getItem('cveharbor.remediation.v1')),null);
 }
 for(const resource of ['remediations/features','inventory','remediations']){
  const held=hold(endpoint(resource));await open();await held.seen;await pending();await blockedSubmit();held.release();await settled();
  assert.equal(await page.locator('#remediationTotal').textContent(),'0');
 }
 assert.equal(diagnostics.length,0,'ordinary delayed loading is not a diagnostic failure');
 console.log('PASS delayed features/inventory/records, empty success, pending write guards');

 for(const resource of ['remediations/features','inventory','remediations']){
  override={match:endpoint(resource),response:{status:503,json:{error:'PRIVATE_RESPONSE_BODY@example.test'}}};
  await open();await settled('failed');await blockedSubmit();assert.equal(await page.locator('#remediationRefresh').isEnabled(),true);
  assert.match(diagnostics.at(-1),/request/);assert.doesNotMatch(diagnostics.at(-1),/PRIVATE_RESPONSE|example\.test/);
  override=null;await page.locator('#remediationRefresh').click();await settled();
 }
 override={match:endpoint('remediations'),response:{abort:'failed'}};
 await open();await settled('failed');assert.match(diagnostics.at(-1),/request/);await blockedSubmit();
 override=null;await page.locator('#remediationRefresh').click();await settled();
 const malformed=[
  ['remediations/features',{status:200,body:'invalid JSON PRIVATE'}],
  ['remediations/features',{status:200,json:{storage:'d1',version:2,shared_records_available:'yes'}}],
  ['inventory',{status:200,json:{customers:[],environments:{},assets:[]}}],
  ['inventory',{status:200,json:{customers:[null],environments:[],assets:[]}}],
  ['remediations',{status:200,body:'invalid JSON PRIVATE'}],
  ['remediations',{status:200,json:{}}],
  ['remediations',{status:200,json:{remediations:{}}}],
  ['remediations',{status:200,json:{remediations:[null]}}],
  ['remediations',{status:200,json:{remediations:[{id:'not-a-cve'}]}}],
 ];
 for(const [resource,response] of malformed){
  override={match:endpoint(resource),response};await open();await settled('failed');
  assert.match(diagnostics.at(-1),/response-validation/);assert.doesNotMatch(diagnostics.at(-1),/PRIVATE/);
  assert.notEqual(await page.locator('#remediationTotal').textContent(),'0');
  override=null;await page.locator('#remediationRefresh').click();await settled();
 }
 console.log('PASS HTTP failures, malformed JSON/shapes, sanitized diagnostics and recovery');

 populated=true;await open();await settled();
 const decorate=await page.evaluate(()=>{window.__savedDecorate=window.CVEHARBOR_CUSTOMER_REMEDIATION.decorate;window.CVEHARBOR_CUSTOMER_REMEDIATION.decorate=()=>{throw Error('PRIVATE_RENDER_EXCEPTION@example.test');};return true;});assert.ok(decorate);
 await page.locator('#remediationRefresh').click();await settled('failed');
 assert.match(diagnostics.at(-1),/rendering/);assert.doesNotMatch(diagnostics.at(-1),/PRIVATE_RENDER|example\.test/);await blockedSubmit();
 await page.evaluate(()=>window.CVEHARBOR_CUSTOMER_REMEDIATION.decorate=window.__savedDecorate);
 await page.locator('#remediationRefresh').click();await settled();assert.equal(await page.locator('#remediationTotal').textContent(),'1');

 for(const staleFailure of [false,true]){
  const held=hold(customer('a-north'),staleFailure?{status:500,json:{error:'PRIVATE_STALE'}}:undefined);
  await page.locator('#remediationCustomerFilter').selectOption('a-north');await held.seen;await pending();
  await page.locator('#remediationCustomerFilter').selectOption('a-south');await settled();
  const before=diagnostics.length;held.release();await held.done;
  await painted();
  assert.equal(await page.locator('#remediationSave').isEnabled(),true);
  assert.match(await page.locator('#remediationRows').textContent(),/a-south/);
  assert.doesNotMatch(await page.locator('#remediationRows').textContent(),/a-north/);assert.equal(diagnostics.length,before);
 }
 const staleSuccess=hold(customer('a-north'));
 await page.locator('#remediationCustomerFilter').selectOption('a-north');await staleSuccess.seen;
 override={match:customer('a-south'),response:{status:500,json:{error:'PRIVATE_CURRENT'}}};
 await page.locator('#remediationCustomerFilter').selectOption('a-south');await settled('failed');
 assert.doesNotMatch(diagnostics.at(-1),/a-south|PRIVATE_CURRENT/);
 staleSuccess.release();await staleSuccess.done;await painted();
 assert.equal(await page.locator('#remediationSave').isDisabled(),true);assert.match(await page.locator('#remediationRows').textContent(),/Records unavailable/);
 override=null;await page.locator('#remediationRefresh').click();await settled();
 await page.locator('#remediationCustomerFilter').selectOption('unassigned');await settled();assert.match(await page.locator('#remediationRows').textContent(),/Unassigned Records/);
 console.log('PASS populated rendering/recovery, out-of-order customer success/failure and Unassigned filtering');

 // An obsolete initialization (including inventory) must not clear the next account's controls.
 for(const resource of ['remediations/features','inventory','remediations'])for(const staleFailure of [false,true]){
  account='a';const held=hold(endpoint(resource),staleFailure?{status:503,json:{error:'PRIVATE_OLD_ACCOUNT'}}:undefined);
  await open();await held.seen;await pending();
  gate=null;await accountEvent('b');await settled();const before=diagnostics.length;
  held.release();await held.done;
  await painted();
  assert.equal(await page.locator('#remediationSave').isEnabled(),true);
  assert.match(await page.locator('#remediationCustomerFilter').textContent(),/b North/);
  assert.doesNotMatch(await page.locator('#remediationCustomerFilter').textContent(),/a North/);
  assert.match(await page.locator('#remediationRows').textContent(),/b fictional owner/);assert.equal(diagnostics.length,before);
 }
 for(const resource of ['remediations/features','inventory','remediations'])for(const staleFailure of [false,true]){
  account='a';const held=hold(endpoint(resource),staleFailure?{status:500,json:{error:'PRIVATE_SIGNED_OUT'}}:undefined);
  await open();await held.seen;await accountEvent(null);const before=diagnostics.length;held.release();await held.done;
  await painted();await page.waitForFunction(()=>document.getElementById('remediationStorage').textContent.includes('local to this browser'));
  assert.equal(await page.locator('#remediationCustomerFilter').count(),0);assert.doesNotMatch(await page.locator('#remediationRows').textContent(),/fictional owner/);
  assert.equal(diagnostics.length,before);assert.equal(await page.locator('#remediationRefresh').isDisabled(),true);
 }
 assert.equal(writes,0);assert.deepEqual(uncaught,[]);
 console.log('PASS pending sign-out/account switches, stale errors ignored, no writes or uncaught exceptions');
}finally{await browser.close();}
