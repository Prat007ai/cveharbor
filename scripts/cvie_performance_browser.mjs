// Fictional large snapshots only. No live accounts, AI calls or external requests.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createRequire} from 'node:module';
import {securityFixture} from './customer_security_fixture.mjs';
const require=createRequire(new URL('../staging/package.json',import.meta.url)),{chromium}=require('playwright-core');
const root=path.resolve(process.env.INVENTORY_TEST_SITE||'public');
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
try{for(const width of [1440,390]){
 const fixture=securityFixture();let progress=1;
 const records=Array.from({length:10000},(_,i)=>({id:'CVE-2026-'+(100000+i),categories:['Unrelated product'],cvie_products:['Unrelated product'],affected:'Unrelated product before 2.0',summary:'Fictional advisory',published:'2026-11-01',severity:'medium',sources:[]}));
 const excluded=Array.from({length:30000},(_,i)=>({id:records[i%10000].id,product:'Excluded '+i%3}));
 const products=()=>Array.from({length:132},(_,i)=>({id:'p'+i,name:i?'Unrelated product '+i:'PHP',status:'scanning',last_success_at:1,progress:{windows_complete:progress,windows_total:100}}));
 const page=await browser.newPage({viewport:{width,height:1000}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.addInitScript(()=>{window.longTasks=[];new PerformanceObserver(list=>window.longTasks.push(...list.getEntries().map(e=>e.duration))).observe({type:'longtask',buffered:true});});
 await page.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.hostname==='api.cveharbor.com'){
   assert.ok(req.method()==='GET'||(url.pathname==='/v1/cvie/sync'&&req.method()==='POST'),'Unexpected mutation '+url.pathname);
   let body,status=200;
   if(url.pathname==='/v1/cvie'||url.pathname==='/v1/cvie/progress')body={ready:true,account_id:'fixture',products:products(),evidence:{sources:[]},excluded_product_cves:excluded};
   else if(url.pathname==='/v1/cvie/advisories')body={account_id:'fixture',advisories:records,next:null};
   else if(url.pathname==='/v1/finding-assignments')body={ready:true,assignments:[]};
   else if(url.pathname==='/v1/preferences')body={defaults:['PHP'],products:[]};
   else{const result=await fixture.request(url.href,{method:req.method()});body=await result.json();status=result.status;}
   return route.fulfill({status,json:body,headers:{'Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true'}});
  }
  if(url.hostname!=='cveharbor.com')return route.abort();
  if(url.pathname==='/data.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_DATA='+JSON.stringify({advisories:fixture.advisories})});
  if(url.pathname==='/catalog.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_CATALOG={advisories:[]}'});
  const file=path.resolve(root,'.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));assert.ok(file.startsWith(root+path.sep));
  try{return route.fulfill({body:await fs.readFile(file),contentType:({'.html':'text/html','.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.json':'application/json'})[path.extname(file)]||'application/octet-stream'});}catch{return route.fulfill({status:404,body:''});}
 });
 for(const section of ['customer-dashboard','customer-reports','environments','vulnerabilities']){
  if(section==='environments')fixture.inventory.assets.push(...Array.from({length:102},(_,i)=>({id:'large'+i,environment_id:'e1',name:'FICTIONAL-'+i,technology:'Fictional app '+i,version:'1.0.0'})));
  const start=Date.now();await page.goto('https://cveharbor.com/'+section+'/');
  await page.waitForFunction(()=>window.CVEHARBOR_CVIE?.ready&&!window.CVEHARBOR_CVIE.loading);
  if(section.startsWith('customer-'))await page.waitForSelector('#customerDashStatus[data-ready="true"]');
  const readyMs=Date.now()-start;
  const history=page.locator('select[aria-label="CVIE vulnerability history"]:visible').first();await history.focus();
  await history.evaluate(el=>{window.savedHistory=el;window.longTasks=[];});
  progress++;
  const refreshStart=Date.now();await page.evaluate(()=>window.CVEHARBOR_CVIE.refresh(false,true));
  assert.equal(await page.evaluate(()=>window.savedHistory.isConnected&&document.activeElement===window.savedHistory),true,'progress must preserve focused History');
  const progressMs=Date.now()-refreshStart;
  const selectStart=Date.now();
  if(section.startsWith('customer-')){
   await page.selectOption('#customerDashFilter','c1');await page.selectOption('#customerDashEnvironment','e1');
   assert.equal(await page.locator('#customerDashEnvironment').inputValue(),'e1');
   await page.selectOption('#customerDashFilter','c2');assert.equal(await page.locator('#customerDashFilter').inputValue(),'c2');
  }else if(section==='environments'){
   await page.selectOption('#inventoryMatchCustomer','c1');await page.selectOption('#inventoryMatchCustomer','c2');assert.equal(await page.locator('#inventoryMatchCustomer').inputValue(),'c2');
   await page.waitForFunction(()=>document.getElementById('inventoryMatchCount').textContent==='2 potential matches');
   assert.match(await page.locator('#inventoryMatchResults').innerText(),/Other Customer/);assert.doesNotMatch(await page.locator('#inventoryMatchResults').innerText(),/Fixture Harbor/);
   assert.equal(await page.evaluate(async()=>{const before=window.CVEHARBOR_CVIE.records;await window.CVEHARBOR_CVIE.refresh();return window.CVEHARBOR_CVIE.records===before;}),true,'unchanged full refresh preserves matching snapshot');
  }else if(section==='vulnerabilities'){
   // The filter can be below the catalogue feed; selectOption exercises its actual handler.
   await page.locator('#technologyFilter').selectOption('all');
  }
  const selectionMs=Date.now()-selectStart;
  assert.ok(selectionMs<2000,'customer/filter interaction must not stall for seconds');
  const maxTask=await page.evaluate(()=>Math.max(0,...window.longTasks));
  assert.ok(maxTask<1000,'progress and filters must not cause a one-second browser task');
  // Follow an actual menu link, verifying route and successful document response.
  const nav=page.locator('a[href="/workspace/"]:visible').first();
  if(await nav.count()){await nav.click();await page.waitForURL('**/workspace/');assert.match(await page.title(),/Workspace/);}
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({width,section,records:records.length,exclusions:excluded.length,readyMs,progressMs,selectionMs,maxInteractionTaskMs:Math.round(maxTask)}));
 }
 await page.close();
}}finally{await browser.close();}

