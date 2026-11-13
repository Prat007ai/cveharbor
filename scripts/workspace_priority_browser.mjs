// All data and requests are fictional; exercise the actual Workspace UI.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {workspaceFixture} from './workspace_fixture.mjs';
const {chromium}=await import(process.env.CVEHARBOR_PLAYWRIGHT_MODULE||'playwright-core');
const root=path.resolve(process.env.INVENTORY_TEST_SITE||'.');
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
try{for(const width of [1440,390]){
 const fixture=workspaceFixture(),page=await browser.newPage({viewport:{width,height:1000}}),errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 const inventory={customers:[{id:'large',name:'Large fixture'},{id:'empty',name:'Empty fixture'}],environments:[{id:'env',customer_id:'large',name:'Production'}],assets:Array.from({length:102},(_,i)=>({id:'a'+i,environment_id:'env',name:'HOST'+i,technology:'Fictional product '+i,version:'1.0.0'}))};
 const advisories=Array.from({length:5000},(_,i)=>({id:'CVE-2026-'+(100000+i),categories:['Fictional product '+i%102],affected:'Fictional product '+i%102+' before 2.0.0',severity:'high',sources:[]}));
 await page.addInitScript(()=>{window.longTasks=[];new PerformanceObserver(l=>window.longTasks.push(...l.getEntries().map(e=>e.duration))).observe({type:'longtask',buffered:true});});
 await page.route('**/*',async route=>{
  const req=route.request(),u=new URL(req.url());assert.equal(req.method(),'GET','No mutations or paid AI calls');
  if(u.hostname==='api.cveharbor.com'){
   let r;if(u.pathname==='/v1/inventory')r={status:200,body:inventory};
   else if(u.pathname==='/v1/team/organizations')r={status:200,body:{organizations:[]}};
   else r=await fixture.request(u.href);
   return route.fulfill({status:r.status,json:r.body,headers:{'Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true'}});
  }
  if(u.hostname!=='cveharbor.com')return route.abort();
  if(u.pathname==='/workspace-intelligence.json')return route.fulfill({json:{items:[]}});
  if(u.pathname==='/data.js'||u.pathname==='/catalog.js')return route.fulfill({contentType:'text/javascript',body:'window.'+(u.pathname==='/data.js'?'CVEHARBOR_DATA':'CVEHARBOR_CATALOG')+'='+JSON.stringify({advisories:u.pathname==='/data.js'?advisories:[]})});
  const file=path.resolve(root,'.'+u.pathname+(u.pathname.endsWith('/')?'index.html':''));assert.ok(file.startsWith(root+path.sep));
  try{return route.fulfill({body:await fs.readFile(file),contentType:({'.html':'text/html','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.json':'application/json'})[path.extname(file)]||'application/octet-stream'});}catch{return route.fulfill({status:404,body:''});}
 });
 await page.goto('https://cveharbor.com/workspace/');await page.waitForSelector('body.workspace-authenticated');
 await page.getByRole('button',{name:'Review customer priorities',exact:true}).click();
 const chooser=page.locator('#workspaceAccess > .finding-ai select'),panel=page.locator('#workspaceAccess > .finding-ai');
 await chooser.waitFor();await page.evaluate(()=>{window.longTasks=[];});
 const start=Date.now();await chooser.selectOption('large');const selectionMs=Date.now()-start;
 // A subsequent selection must remain usable while the first calculation yields.
 await chooser.selectOption('empty');await panel.getByText(/0 saved software entries/).waitFor();
 assert.doesNotMatch(await panel.innerText(),/102 saved/);
 await chooser.selectOption('large');await panel.getByText(/102 saved software entries/).waitFor({timeout:30000});
 const maxTask=await page.evaluate(()=>Math.max(0,...window.longTasks));
 assert.ok(selectionMs<500,'selection handler should yield immediately');assert.ok(maxTask<500,'assessment must not monopolize the browser for seconds');
 await chooser.selectOption('empty');await panel.getByText(/0 saved software entries/).waitFor();
 assert.equal(await panel.locator('.finding-ai-priority').count(),0);assert.deepEqual(errors,[]);
 console.log(JSON.stringify({width,assets:102,advisories:5000,selectionMs,maxTaskMs:Math.round(maxTask),cancelledSelectionIsolated:true}));await page.close();
}}finally{await browser.close();}
