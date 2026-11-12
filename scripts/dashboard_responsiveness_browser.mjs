// Fictional accounts and advisories. All browser requests are intercepted locally.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createRequire} from 'node:module';
import {securityFixture} from './customer_security_fixture.mjs';
const require=createRequire(new URL('../staging/package.json',import.meta.url));
const {chromium}=require('playwright-core');
const root=path.resolve(process.env.INVENTORY_TEST_SITE||'.');
const screenshots=path.resolve(process.env.INVENTORY_SCREENSHOTS||'../evidence/dashboard-responsive-screens');
await fs.mkdir(screenshots,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
try{
 for(const width of [1440,390]){
  const fixture=securityFixture();
  fixture.inventory.assets=Array.from({length:152},(_,i)=>({id:'a'+i,environment_id:'e1',name:'FICTIONAL-WEB',technology:['Windows Server','WinSCP 6.1.1','.NET Runtime','PHP','VMware Tools'][i%5],version:'6.1.1'}));
  fixture.advisories.push(...Array.from({length:5000},(_,i)=>({id:'CVE-2026-'+(100000+i),categories:['Unrelated product'],affected:'Unrelated product before 2.0',summary:'Fictional advisory',sources:[{url:'https://example.test/advisory/'+i,label:'Fixture'}]})));
  const page=await browser.newPage({viewport:{width,height:1000}}),errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.route('**/*',async route=>{
   const request=route.request(),url=new URL(request.url());
   if(url.hostname==='api.cveharbor.com'){
    assert.ok(!url.pathname.includes('/ai/')||request.method()==='GET');
    const result=await fixture.request(url.href,{method:request.method(),body:request.postData()});
    return route.fulfill({status:result.status,headers:{'Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true'},json:await result.json()});
   }
   if(url.hostname!=='cveharbor.com')return route.abort();
   if(url.pathname==='/data.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_DATA='+JSON.stringify({advisories:fixture.advisories})});
   if(url.pathname==='/catalog.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_CATALOG={advisories:[]}'});
   const filename=path.resolve(root,'.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));assert.ok(filename.startsWith(root+path.sep));
   try{
    let body=await fs.readFile(filename);
    if(url.pathname==='/inventory-assessment.js')body=Buffer.concat([body,Buffer.from('\nwindow.matchCalls=0;const originalCandidate=window.CVEHARBOR_INVENTORY_MATCH.candidate;window.CVEHARBOR_INVENTORY_MATCH.candidate=(...args)=>{window.matchCalls++;return originalCandidate(...args)};')]);
    return route.fulfill({body,contentType:({'.html':'text/html','.js':'text/javascript','.mjs':'text/javascript','.css':'text/css'})[path.extname(filename)]||'application/octet-stream'});
   }catch{return route.fulfill({status:404,body:''});}
  });
  const started=Date.now();await page.goto('https://cveharbor.com/customer-dashboard/');
  await page.waitForSelector('#customerDashStatus[data-ready="true"]');
  await page.waitForFunction(()=>!window.CVEHARBOR_CVIE.loading);
  const readyMs=Date.now()-started;
  const calls=await page.evaluate(()=>window.matchCalls);
  assert.ok(calls>0);
  const selectionStart=Date.now();
  await page.selectOption('#customerDashFilter','c1');await page.selectOption('#customerDashEnvironment','e1');
  assert.equal(await page.evaluate(()=>window.matchCalls),calls,'unchanged customer/environment selection must reuse matching work');
  assert.match(await page.locator('#customerDashMetrics').innerText(),/152/);
  assert.match(await page.locator('#customerDashboardServers').innerText(),/FICTIONAL-WEB/);
  await page.selectOption('#customerDashFilter','c2');assert.doesNotMatch(await page.locator('#customerDashboardServers').innerText(),/FICTIONAL-WEB/);
  await page.selectOption('#customerDashFilter','c1');
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({width,readyMs,selectionMs:Date.now()-selectionStart,candidateCalls:calls}));
  await page.screenshot({path:path.join(screenshots,'dashboard-'+width+'.png')});await page.close();
 }
}finally{await browser.close();}
