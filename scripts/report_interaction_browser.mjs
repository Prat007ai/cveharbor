// Fictional reports only. All requests are fulfilled locally or rejected.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createRequire} from 'node:module';
import {securityFixture} from './customer_security_fixture.mjs';
const require=createRequire(new URL('../staging/package.json',import.meta.url)),{chromium}=require('playwright-core');
const root=path.resolve(process.env.INVENTORY_TEST_SITE||'.');
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
try{for(const width of [1440,390]){
 const fixture=securityFixture();let revision=1;
 fixture.inventory.assets=Array.from({length:200},(_,i)=>({id:'a'+i,environment_id:i<100?'e1':i<180?'e2':'e3',name:'HOST-'+i,technology:'Windows Server',version:'10.0.20348.5761'}));
 const affected=Array.from({length:10},(_,i)=>'Windows Server 2022 for x64-based Systems (installation option '+i+')').join('; ');
 const records=()=>Array.from({length:2500},(_,i)=>({id:'CVE-2026-'+(100000+i),categories:['Windows Server'],cvie_products:['Windows Server'],affected,summary:'Fictional Windows Server vulnerability '+revision+'. '+('An authenticated deployment check is required. '.repeat(30)),severity:i%3?'high':'critical',sources:[{label:'Fictional vendor',url:'https://example.test/'+i}]}));
 const page=await browser.newPage({viewport:{width,height:1000}}),errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.addInitScript(()=>{
  window.reportTasks=[];window.reportGaps=[];let last=performance.now();
  setInterval(()=>{const now=performance.now();window.reportGaps.push(now-last);last=now;},20);
  new PerformanceObserver(list=>window.reportTasks.push(...list.getEntries().map(x=>({start:x.startTime,duration:x.duration})))).observe({type:'longtask',buffered:true});
 });
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url());
  if(url.hostname==='api.cveharbor.com'){
   assert.ok(request.method()==='GET'||url.pathname==='/v1/cvie/sync','Unexpected mutation');
   let body,status=200;
   if(url.pathname==='/v1/cvie'||url.pathname==='/v1/cvie/progress')body={ready:true,account_id:'fixture',products:Array.from({length:132},(_,i)=>({id:'p'+i,name:i?'Product '+i:'Windows Server',status:'scanning',last_success_at:revision,progress:{windows_complete:revision,windows_total:100}})),evidence:{sources:[]}};
   else if(url.pathname==='/v1/cvie/advisories')body={account_id:'fixture',advisories:records(),next:null};
   else if(url.pathname==='/v1/finding-assignments')body={ready:true,assignments:[]};
   else{const result=await fixture.request(url.href,{method:request.method()});body=await result.json();status=result.status;}
   return route.fulfill({status,json:body});
  }
  if(url.hostname!=='cveharbor.com')return route.abort();
  if(url.pathname==='/data.js'||url.pathname==='/catalog.js')return route.fulfill({contentType:'text/javascript',body:'window.'+(url.pathname==='/data.js'?'CVEHARBOR_DATA':'CVEHARBOR_CATALOG')+'={advisories:[]}'});
  const file=path.resolve(root,'.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));assert.ok(file.startsWith(root+path.sep));
  try{return route.fulfill({body:await fs.readFile(file),contentType:({'.html':'text/html','.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.json':'application/json'})[path.extname(file)]||'application/octet-stream'});}catch{return route.fulfill({status:404,body:''});}
 });
 await page.goto('https://cveharbor.com/customer-reports/');
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE?.ready&&!window.CVEHARBOR_CVIE.loading&&document.querySelector('#customerDashStatus')?.dataset.ready==='true');
 const cdp=await page.context().newCDPSession(page);
 if(process.env.REPORT_PROFILE==='true'){await cdp.send('Profiler.enable');await cdp.send('Profiler.start');}
 await page.evaluate(()=>{window.reportTasks=[];window.reportGaps=[];});
 const start=Date.now();await page.selectOption('#customerDashFilter','c1');
 await page.waitForFunction(()=>document.querySelector('#customerDashStatus').dataset.assessing==='false');
 const initialMs=Date.now()-start;
 revision++;
 const refreshing=page.evaluate(()=>window.CVEHARBOR_CVIE.refresh());
 const switchStart=Date.now();await page.selectOption('#customerDashEnvironment','e1');
 await refreshing;
 await page.waitForFunction(()=>document.querySelector('#customerDashStatus').dataset.assessing==='false');
 const switchMs=Date.now()-switchStart;
 if(process.env.REPORT_PROFILE==='true'){const {profile}=await cdp.send('Profiler.stop');await fs.writeFile('verification/report-'+width+'.cpuprofile',JSON.stringify(profile));}
 const metrics=await page.evaluate(()=>({maxTask:Math.round(Math.max(0,...window.reportTasks.map(x=>x.duration))),maxGap:Math.round(Math.max(0,...window.reportGaps)),nodes:document.querySelectorAll('*').length}));
 console.log(JSON.stringify({width,initialMs,switchMs,...metrics}));
 assert.match(await page.locator('#customerReportBody').innerText(),/5000/);
 assert.equal(await page.locator('#customerDashEnvironment').inputValue(),'e1');
 // A late CVIE response must finish in the newest selected customer/scope.
 revision++;
 const nextRefresh=page.evaluate(()=>window.CVEHARBOR_CVIE.refresh());
 await page.selectOption('#customerDashFilter','c2');
 await page.selectOption('#customerDashEnvironment','e3');
 await nextRefresh;
 await page.waitForFunction(()=>document.querySelector('#customerDashStatus').dataset.assessing==='false'&&!window.CVEHARBOR_CVIE.loading&&document.querySelector('#customerReportBody .customer-report-details')?.textContent.includes('Other Customer'));
 const finalReport=await page.locator('#customerReportBody').innerText();
 assert.match(finalReport,/Other Customer/);assert.doesNotMatch(finalReport,/Fixture Harbor/);
 assert.equal(await page.locator('#customerDashEnvironment').inputValue(),'e3');
 assert.equal(await page.evaluate(async()=>{const before=document.querySelector('#customerReportBody').firstChild;await window.CVEHARBOR_CVIE.refresh(false,true);return before===document.querySelector('#customerReportBody').firstChild;}),true,'progress-only updates preserve the current report');
 assert.deepEqual(errors,[]);
 if(process.env.REPORT_BASELINE!=='true'){
  assert.ok(metrics.maxGap<500,'Report work must yield to customer input within 500ms');
  assert.ok(switchMs<1200,'Environment selection during incoming CVIE results must settle within 1.2 seconds');
 }
 await page.close();
}}finally{await browser.close();}
