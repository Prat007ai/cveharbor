// Actual browser + actual legacy Worker handlers + isolated SQLite/Cache fixtures.
// No production customer writes or outbound vendor/email traffic.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {DB} from '../account-backend/tests/helpers/d1.mjs';
import {handler} from '../account-backend/src/lifecycle.js';
let chromium;try{({chromium}=await import('playwright-core'));}catch{({chromium}=await import('/opt/codex/cua_node/lib/node_modules/playwright/index.mjs'));}
const db=new DB();db.sql.exec(fs.readFileSync('account-backend/lifecycle-schema.sql','utf8'));
const cache=new Map(),env={DB:db,DIRECTORY_CACHE:{async match(k){return cache.get(k)?.clone()},async put(k,r){cache.set(k,r.clone())}}};
const server=spawn('python',['-m','http.server','8776','--bind','127.0.0.1','--directory','public'],{stdio:'ignore'});
const nativeFetch=globalThis.fetch;let sourceCalls=0,owner='a';
globalThis.fetch=async url=>{
 sourceCalls++;assert.ok(String(url).startsWith('https://endoflife.date/api/'));
 if(String(url).endsWith('/drupal.json'))return Response.json([{cycle:'10',latest:'10.6.8',eol:'2026-12-09'},{cycle:'11',latest:'11.2.1',eol:false}]);
 return new Response('',{status:404});
};
let browser;
try{
 browser=await chromium.launch({executablePath:['/usr/bin/chromium','/usr/bin/google-chrome','/usr/bin/chromium-browser'].find(p=>fs.existsSync(p)),headless:true,args:['--no-sandbox']});const page=await browser.newPage();
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());if(url.hostname==='127.0.0.1')return route.continue();
  if(url.hostname==='api.cveharbor.com'){
   if(url.pathname==='/v1/me')return route.fulfill({json:{authenticated:true,email:owner+'@example.test'}});
   if(url.pathname==='/v1/monitoring/status')return route.fulfill({json:{ready:false}});
   if(url.pathname.startsWith('/v1/lifecycle')){
    try{const r=await handler(new Request(url,{method:req.method()}),env,{id:owner},url.pathname,req.postDataJSON()||{});return route.fulfill({status:r.status,body:await r.text(),contentType:'application/json'});}catch(e){return route.fulfill({status:e.status||500,json:{error:e.message}});}
   }
   return route.fulfill({json:{}});
  }return route.fulfill({status:204,body:''});
 });
 await page.setViewportSize({width:1440,height:1000});await page.goto('http://127.0.0.1:8776/lifecycle/');
 await page.waitForFunction(()=>window.CVEHARBOR_LIFECYCLE_MONITOR&&window.CVEHARBOR_DIRECTORY_SEARCH);
 await page.evaluate(()=>window.dispatchEvent(new CustomEvent('cveharbor:account-state',{detail:{authenticated:true,email:'a@example.test'}})));
 await page.waitForFunction(()=>!document.getElementById('lifecycleWatchSave').disabled);
 await page.locator('#lifecycleProductSearch').fill('Durpal CMS');
 await page.getByRole('button',{name:/Did you mean: Drupal/}).click();
 await page.waitForFunction(()=>document.getElementById('lifecycleCycle').options.length===3);
 assert.equal(await page.locator('#lifecycleProduct').inputValue(),'drupal');
 await page.locator('#lifecycleCycle').selectOption('10');await page.locator('#lifecycleInstalled').fill('10.6.1');await page.locator('#lifecycleWatchSave').click();
 await page.waitForFunction(()=>document.getElementById('lifecycleWatches').textContent.includes('10.6.1'));
 assert.match(await page.locator('#lifecycleWatches').textContent(),/2026-12-09/);assert.equal(sourceCalls,1);
 await page.reload();await page.waitForFunction(()=>document.getElementById('lifecycleWatches').textContent.includes('10.6.1'));assert.equal(sourceCalls,1,'reload reads shared cache, not vendor');
 // Failed lookup still allows the private name/version to be saved with no URL/date.
 db.sql.prepare("UPDATE cvie_provider_budget SET next_request_at=0 WHERE provider='lifecycle-directory'").run();
 await page.locator('#lifecycleProductSearch').fill('Unlisted Customer Engine');await page.locator('#lifecycleAddUnlisted').click();
 await page.locator('#lifecycleCustomCycle').fill('2');await page.locator('#lifecycleInstalled').fill('2.1.4');await page.locator('#lifecycleWatchSave').click();
 await page.waitForFunction(()=>document.getElementById('lifecycleWatches').textContent.includes('Unlisted Customer Engine'));
 assert.match(await page.locator('#lifecycleLookupStatus').textContent(),/No matching release history/);
 for(const response of cache.values())assert.doesNotMatch(await response.clone().text(),/Unlisted Customer Engine|2\.1\.4|example\.test/);
 const privateRow=db.sql.prepare("SELECT * FROM lifecycle_watches WHERE product='Unlisted Customer Engine'").get();assert.equal(privateRow.user_id,'a');assert.equal(privateRow.custom_eol_date,'');assert.equal(privateRow.installed_version,'2.1.4');
 // Cached identity can resolve a saved unresolved row, without replacing its version.
 db.sql.prepare("UPDATE lifecycle_watches SET product='Drupal CMS',slug='',cycle='11' WHERE id=?").run(privateRow.id);await page.reload();
 await page.waitForFunction(()=>document.getElementById('lifecycleWatches').textContent.includes('Drupal CMS'));
 const unresolved=page.locator('#lifecycleWatches article').filter({hasText:'Drupal CMS'});await unresolved.getByRole('button',{name:'Find product and release'}).click();
 await unresolved.getByRole('button',{name:'Use this product and release'}).click();await page.waitForFunction(()=>!document.getElementById('lifecycleWatches').textContent.includes('Drupal CMS'));
 assert.equal(db.sql.prepare('SELECT installed_version FROM lifecycle_watches WHERE id=?').get(privateRow.id).installed_version,'2.1.4');
 owner='b';await page.evaluate(()=>window.dispatchEvent(new CustomEvent('cveharbor:account-state',{detail:{authenticated:true,email:'b@example.test'}})));
 await page.waitForFunction(()=>document.getElementById('lifecycleWatchCount').textContent==='0 monitored');
 for(const width of [390,768,1440,2560]){
  await page.setViewportSize({width,height:1000});const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1);assert.equal(overflow,false,'no horizontal overflow at '+width);
 }
 fs.mkdirSync('work',{recursive:true});await page.setViewportSize({width:1440,height:1000});await page.locator('#lifecycleProductSearch').fill('.NET');await page.evaluate(()=>scrollTo(0,0));await page.screenshot({path:'work/lifecycle-directory-desktop.png',fullPage:true});
 assert.deepEqual(errors,[]);console.log('PASS Chromium lifecycle directory: typo suggestion, exact selection, real legacy saves, cached reload, unknown-product persistence, resolution, tenant isolation and responsive layouts.');
}finally{globalThis.fetch=nativeFetch;await browser?.close();server.kill();db.sql.close();}
