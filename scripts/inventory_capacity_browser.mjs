// Browser integration with actual paginated route and SQLite. All external
// traffic is intercepted; synthetic data only, no credentials or inference.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import {createRequire} from 'node:module';
import {capacityFixture,fixtureId} from '../account-backend/tests/helpers/capacity-db.mjs';
import {inventoryRoute} from '../account-backend/src/inventory.js';
import {securityFixture} from './customer_security_fixture.mjs';
const require=createRequire(new URL('../staging/package.json',import.meta.url));
const {chromium}=require('playwright-core'),root=path.resolve(process.env.INVENTORY_TEST_SITE||'.');
// The fixture replaces the CDN. Load its bounded static inputs before timing
// browser work so shared-runner filesystem contention is not a network model.
// API latency remains the explicit 50ms delay below, including every page.
const staticFiles=new Map();
for(const entry of await fs.readdir(root,{withFileTypes:true})){
 if(entry.isFile()&&/\.(js|css|json|svg|ico)$/.test(entry.name)&&!['data.js','catalog.js'].includes(entry.name)){
  const file=path.join(root,entry.name);staticFiles.set(file,await fs.readFile(file));
 }
}
for(const section of ['customer-reports','customer-dashboard']){
 const file=path.join(root,section,'index.html');staticFiles.set(file,await fs.readFile(file));
}
// Finish the heavy synchronous seed before launching Chrome. The four browser
// scenarios only read this database; rebuilding/updating 50,000 rows with Chrome
// already running competes with its startup on small shared CI runners.
const env=capacityFixture({assets:50000});
env.sql.exec("UPDATE inventory_assets SET technology='PHP',version='8.4.1'");
// No external request can escape the fixture. Loopback static traffic bypasses
// this rejecting proxy; HTTPS fixture requests are fulfilled through CDP below.
const rejectProxy=http.createServer((req,res)=>{res.writeHead(502);res.end();});
rejectProxy.on('connect',(req,socket)=>socket.destroy());
await new Promise(resolve=>rejectProxy.listen(0,'127.0.0.1',resolve));
const browser=await chromium.launch({headless:true,args:['--proxy-server=http://127.0.0.1:'+rejectProxy.address().port,'--proxy-bypass-list=127.0.0.1'],executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
try{
 for(const width of [1440,390])for(const section of ['customer-reports','customer-dashboard']){
  const fixture=securityFixture(),page=await browser.newPage({viewport:{width,height:1000}}),errors=[];let pages=0;
  // Serve static fixture bytes through ordinary loopback HTTP. Intercepting
  // every script/CSS request over the browser-control protocol adds test-runner
  // scheduling delay that real CDN requests do not have.
  const types={'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json'};
  const server=http.createServer((req,res)=>{
   const url=new URL(req.url,'http://localhost');let bytes,type;
   if(url.pathname==='/data.js'||url.pathname==='/catalog.js'){
    bytes='window.'+(url.pathname==='/data.js'?'CVEHARBOR_DATA':'CVEHARBOR_CATALOG')+'='+JSON.stringify({advisories:url.pathname==='/data.js'?fixture.advisories:[]});type='text/javascript';
   }else{
    const file=path.resolve(root,'.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));
    if(file.startsWith(root+path.sep)){bytes=staticFiles.get(file);type=types[path.extname(file)]||'application/octet-stream';}
   }
   res.writeHead(bytes?200:404,{'Content-Type':type||'text/plain'});res.end(bytes||'');
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const site='http://127.0.0.1:'+server.address().port;
  page.on('pageerror',error=>errors.push(error.message));
  await page.addInitScript(()=>{
   window.capacityLongTasks=[];
   new PerformanceObserver(list=>{for(const task of list.getEntries())window.capacityLongTasks.push({start:Math.round(task.startTime),duration:Math.round(task.duration)});}).observe({type:'longtask',buffered:true});
   new MutationObserver(()=>{
    const select=document.querySelector('#customerDashFilter');
    if(window.capacityMenuReady===undefined&&select?.options.length===51&&!select.disabled&&!document.querySelector('#customerDashAccess')?.hidden)window.capacityMenuReady=performance.now();
   }).observe(document,{subtree:true,childList:true,attributes:true});
  });
  // Playwright page.route enables Fetch interception with urlPattern='*',
  // including requests excluded by its JS regex. Match HTTPS in Chrome itself
  // so local scripts/styles never wait for browser-control round trips.
  const cdp=await page.context().newCDPSession(page),cancelledRequests=new Set();
  await cdp.send('Network.enable');
  cdp.on('Network.loadingFailed',event=>{if(event.canceled)cancelledRequests.add(event.requestId);});
  const handle=async route=>{
   const request=route.request(),url=new URL(request.url());
   if(url.hostname==='api.cveharbor.com'){
    await new Promise(resolve=>setTimeout(resolve,50));
    let result;
    if(url.pathname==='/v1/inventory/page'||url.pathname==='/v1/inventory/status'){
     if(url.pathname.endsWith('/page'))pages++;
     try{result=await inventoryRoute(new Request(url),env,{id:'owner-0'},url.pathname);}catch(error){result=new Response(JSON.stringify({error:error.message}),{status:error.status||500});}
    }else result=await fixture.request(url.href,{method:request.method(),body:request.postData()});
    return route.fulfill({status:result.status,headers:{'Access-Control-Allow-Origin':site,'Access-Control-Allow-Credentials':'true'},json:await result.json()});
   }
   if(url.hostname!=='cveharbor.com')return route.abort();
   if(url.pathname==='/data.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_DATA='+JSON.stringify({advisories:fixture.advisories})});
   if(url.pathname==='/catalog.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_CATALOG={advisories:[]}'});
   const file=path.resolve(root,'.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));assert.ok(file.startsWith(root+path.sep));
   try{return route.fulfill({body:staticFiles.get(file)||await fs.readFile(file),contentType:({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json'})[path.extname(file)]||'application/octet-stream'});}catch{return route.fulfill({status:404,body:''});}
  };
  cdp.on('Fetch.requestPaused',event=>{
   const route={request:()=>({url:()=>event.request.url,method:()=>event.request.method,postData:()=>event.request.postData}),
    abort:()=>cdp.send('Fetch.failRequest',{requestId:event.requestId,errorReason:'BlockedByClient'}),
    fulfill:async options=>{
     const headers={...(options.json!==undefined?{'Content-Type':'application/json'}:{}),...(options.contentType?{'Content-Type':options.contentType}:{}),...options.headers};
     const body=options.json!==undefined?JSON.stringify(options.json):options.body||'';
     await cdp.send('Fetch.fulfillRequest',{requestId:event.requestId,responseCode:options.status||200,responseHeaders:Object.entries(headers).map(([name,value])=>({name,value})),body:Buffer.from(body).toString('base64')});
    }};
   void handle(route).catch(error=>{
    // Rapid customer changes intentionally abort stale requests. Chrome removes
    // their interception IDs before the simulated API latency has elapsed.
    if(page.isClosed()||cancelledRequests.has(event.networkId))return;
    errors.push('Fixture transport: '+error.message);void route.abort().catch(()=>{});
   });
  });
  await cdp.send('Fetch.enable',{patterns:[{urlPattern:'https://*',requestStage:'Request'}]});
  try{
   await cdp.send('Profiler.enable');await cdp.send('Profiler.setSamplingInterval',{interval:10000});await cdp.send('Profiler.start');
   const start=Date.now();await page.goto(site+'/'+section+'/'+(section==='customer-reports'?'?customer='+fixtureId(50):''));
   await page.waitForFunction(()=>Number.isFinite(window.capacityMenuReady));const menuReady=Math.round(await page.evaluate(()=>window.capacityMenuReady));
   const {profile}=await cdp.send('Profiler.stop');await cdp.send('Profiler.disable');
   console.log(JSON.stringify({phase:'menu',section,width,menu_ready_ms:menuReady,runner_observed_ms:Date.now()-start,page_requests:pages,navigation:await page.evaluate(()=>performance.getEntriesByType('navigation').map(({domInteractive,domContentLoadedEventEnd,loadEventEnd})=>({domInteractive,domContentLoadedEventEnd,loadEventEnd}))),errors}));
   if(menuReady>=1500){
    const nodes=new Map(profile.nodes.map(n=>[n.id,n.callFrame])),timings=new Map();
    for(let i=0;i<(profile.samples||[]).length;i++){const frame=nodes.get(profile.samples[i]),key=(frame?.functionName||'(anonymous)')+' '+(frame?.url?.split('/').at(-1)||'');timings.set(key,(timings.get(key)||0)+(profile.timeDeltas?.[i]||0));}
    console.log(JSON.stringify({phase:'slow_menu_diagnostics',cpu_samples:[...timings].sort((a,b)=>b[1]-a[1]).slice(0,15).map(([frame,us])=>({frame,ms:Math.round(us/1000)})),resources:await page.evaluate(()=>performance.getEntriesByType('resource').map(r=>({path:new URL(r.name).pathname,start:Math.round(r.startTime),duration:Math.round(r.duration),transfer:r.transferSize}))),long_tasks:await page.evaluate(()=>window.capacityLongTasks)}));
   }
   assert.ok(menuReady<1500,`${section} ${width}px customer menu took ${menuReady}ms (budget 1500ms)`);
   if(section==='customer-dashboard')await page.selectOption('#customerDashFilter',fixtureId(50));
   await page.waitForSelector('#customerDashStatus[data-ready="true"]',{timeout:120000});
   assert.match(await page.locator('.customer-finding-pages').first().textContent(),/of 2000 filtered findings/);
   assert.equal(await page.locator('.customer-vulnerability-table tbody tr').count(),50);
   const ready=Date.now()-start,at=Date.now();await page.selectOption('#customerDashFilter',fixtureId(1));
   await page.waitForFunction(()=>document.querySelector('#customerDashStatus').dataset.assessing==='false');
   assert.match(await page.locator('.customer-finding-pages').first().textContent(),/of 2000 filtered findings/);
   const selection=Date.now()-at;assert.ok(selection<1200,`${section} ${width}px customer selection took ${selection}ms (budget 1200ms)`);
   await page.locator('.customer-vulnerability-table').evaluate(el=>{for(let p=el;p;p=p.parentElement)if(p.tagName==='DETAILS')p.open=true;});
   await page.getByRole('button',{name:'Next findings',exact:true}).click();
   await page.waitForFunction(()=>document.querySelector('.customer-finding-pages')?.textContent.includes('Showing 51–100'));
   await page.evaluate(ids=>{const select=document.querySelector('#customerDashFilter');for(const id of ids){select.value=id;select.dispatchEvent(new Event('change'));}},[fixtureId(50),fixtureId(2),fixtureId(1)]);
   await page.waitForFunction(()=>document.querySelector('#customerDashStatus').dataset.assessing==='false'&&document.querySelector('.customer-finding-pages'));
   assert.equal(await page.locator('#customerDashFilter').inputValue(),fixtureId(1));
   if(section==='customer-reports'){await page.evaluate(()=>{URL.createObjectURL=blob=>{blob.text().then(text=>window.capacityCsv=text);return 'blob:fixture';};URL.revokeObjectURL=()=>{};HTMLAnchorElement.prototype.click=()=>{};});
   await page.locator('#customerReportCsv').click();await page.waitForFunction(()=>window.capacityCsv);
   const csv=await page.evaluate(()=>window.capacityCsv);assert.equal(csv.trim().split('\r\n').length,2001);assert.match(csv,/Customer 0/);assert.doesNotMatch(csv,/Customer 49/);}
   fixture.setAuthenticated(false);await page.evaluate(()=>window.dispatchEvent(new Event('focus')));await page.waitForFunction(()=>document.querySelector('#customerDashAccess').hidden);assert.equal(await page.locator('.customer-vulnerability-table').count(),0);
   assert.deepEqual(errors,[]);console.log(JSON.stringify({section,width,menu_ready_ms:menuReady,customers:50,environments:100,software_entries:50000,page_requests:pages,ready_ms:ready,selection_ms:selection,errors}));
  }finally{await page.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
 }
}finally{await browser.close();rejectProxy.closeAllConnections();await new Promise(resolve=>rejectProxy.close(resolve));env.close();}
