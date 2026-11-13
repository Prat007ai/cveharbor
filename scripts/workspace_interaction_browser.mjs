// All data and requests are fictional; exercise the actual Workspace UI.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createRequire} from 'node:module';
import {workspaceFixture} from './workspace_fixture.mjs';
const require=createRequire(new URL('../staging/package.json',import.meta.url));
const {chromium}=process.env.CVEHARBOR_PLAYWRIGHT_MODULE?await import(process.env.CVEHARBOR_PLAYWRIGHT_MODULE):require('playwright-core');
const root=path.resolve(process.env.INVENTORY_TEST_SITE||'.');
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
try{for(const width of [1440,390]){
 const fixture=workspaceFixture(),page=await browser.newPage({viewport:{width,height:1000}}),errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 const inventory={customers:Array.from({length:50},(_,i)=>({id:i===49?'empty':i?'c'+i:'large',name:'Customer '+i})),environments:Array.from({length:100},(_,i)=>({id:'e'+i,customer_id:i<2?'large':'c'+Math.min(48,Math.floor(i/2)),name:'Environment '+i})),assets:Array.from({length:50000},(_,i)=>({id:'a'+i,environment_id:'e'+Math.floor(i/500),name:'HOST'+i,technology:'Fictional product '+i%102,version:'1.0.0'}))};
 const assetRequests=[];let slowItemRequested=false,releaseItem;const lateItem=new Promise(resolve=>releaseItem=resolve);

 const advisories=Array.from({length:5000},(_,i)=>({id:'CVE-2026-'+(100000+i),categories:['Fictional product '+i%102],affected:'Fictional product '+i%102+' before 2.0.0',severity:'high',sources:[]}));
 await page.addInitScript(()=>{window.longTasks=[];new PerformanceObserver(l=>window.longTasks.push(...l.getEntries().map(e=>e.duration))).observe({type:'longtask',buffered:true});});
 await page.route('**/*',async route=>{
  const req=route.request(),u=new URL(req.url());assert.equal(req.method(),'GET','No mutations or paid AI calls');
  if(u.hostname==='api.cveharbor.com'){
   let r;if(u.pathname==='/v1/inventory/status')r={status:200,body:{ready:true,pagination:true}};
   else if(u.pathname==='/v1/inventory/page'){
    const resource=u.searchParams.get('resource'),customer=u.searchParams.get('customer_id');
    if(resource==='assets'){assetRequests.push(customer);assert.ok(customer,'Never fetch all customers software to show the chooser');await new Promise(resolve=>setTimeout(resolve,150));}
    const envs=new Set(inventory.environments.filter(e=>!customer||e.customer_id===customer).map(e=>e.id));
    const items=inventory[resource].filter(row=>!customer||resource==='customers'?true:resource==='environments'?row.customer_id===customer:envs.has(row.environment_id));
    r={status:200,body:{resource,items,revision:1,complete:true,next_cursor:null}};
   }
   else if(u.pathname==='/v1/workspace/items'&&u.searchParams.get('view')==='activity'){slowItemRequested=true;await lateItem;r={status:503,body:{error:'Late old view error'}};}
   else if(u.pathname==='/v1/inventory')throw Error('Unexpected full inventory read');
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
 const chooserStart=Date.now();await page.getByRole('button',{name:'Review customer priorities',exact:true}).click();
 const chooser=page.locator('#workspaceAccess > .finding-ai select'),panel=page.locator('#workspaceAccess > .finding-ai');
 await chooser.waitFor();const chooserMs=Date.now()-chooserStart;assert.deepEqual(assetRequests,[],'Customer chooser loads before software');await page.evaluate(()=>{window.longTasks=[];});
 const start=Date.now();await chooser.selectOption('large');const selectionMs=Date.now()-start;
 // A subsequent selection must remain usable while the first calculation yields.
 await chooser.selectOption('empty');await panel.getByText(/0 saved software entries/).waitFor();
 assert.doesNotMatch(await panel.innerText(),/1000 saved/);
 const readyStart=Date.now();await chooser.selectOption('large');await panel.getByText(/1000 saved software entries/).waitFor({timeout:30000});const readyMs=Date.now()-readyStart;
 const maxTask=await page.evaluate(()=>Math.max(0,...window.longTasks));
 assert.ok(selectionMs<500,'selection handler should yield immediately');assert.ok(maxTask<500,'assessment must not monopolize the browser for seconds');
 await chooser.selectOption('empty');await panel.getByText(/0 saved software entries/).waitFor();
 assert.equal(await panel.locator('.finding-ai-priority').count(),0);
 // Overview navigation remains independent of priority assessment and a slow prior response.
 await page.locator('#ws-activity-tab').click();await page.waitForTimeout(50);assert.ok(slowItemRequested);
 await page.locator('#ws-environments-tab').click();await page.locator('#wsActivityPanel').getByText('Registered entry 1',{exact:true}).waitFor();
 releaseItem();await page.waitForTimeout(200);
 assert.doesNotMatch(await page.locator('#wsActivityPanel').innerText(),/Could not load records/,'An old tab failure cannot replace the current view');
 assert.equal(await page.locator('#ws-environments-tab').getAttribute('aria-selected'),'true');
 assert.deepEqual(errors,[]);
 console.log(JSON.stringify({width,customers:50,environments:100,chooserMs,readyMs,assets:50000,advisories:5000,selectionMs,maxTaskMs:Math.round(maxTask),cancelledSelectionIsolated:true}));await page.close();
}}finally{await browser.close();}
