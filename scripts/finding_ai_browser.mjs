// Fictional evidence and accounts; every request is intercepted. No paid AI calls.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createRequire} from 'node:module';
import {securityFixture} from './customer_security_fixture.mjs';
import {workspaceFixture} from './workspace_fixture.mjs';
const require=createRequire(new URL('../staging/package.json',import.meta.url));
const {chromium}=require('playwright-core');
const root=path.resolve(process.env.INVENTORY_TEST_SITE||'.'),screens=path.resolve(process.env.INVENTORY_SCREENSHOTS||'../evidence/finding-ai-screens');await fs.mkdir(screens,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
try{for(const width of [1440,390]){
 const f=securityFixture(),workspace=workspaceFixture(),page=await browser.newPage({viewport:{width,height:1000}}),errors=[];let posts=0,enabled=true;
 f.inventory.assets=Array.from({length:152},(_,i)=>({id:'a'+i,environment_id:'e1',name:'PRIVATE-HOST',technology:'PHP',version:'8.4.1',notes:'PRIVATE-NOTES'}));
 const modern={id:'server',environment_id:'e1',name:'DEMO-SERVER2022',technology:'Windows Server',version:'10.0.20348.5761'};
 f.inventory.assets.push(modern);
 f.advisories.push({id:'CVE-2019-0708',categories:['Windows'],title:'Legacy Remote Desktop Services issue',affected:'Windows Server: 2008 R2 for x64-based Systems Service Pack 1 (Core installation); 2008 for x64-based Systems Service Pack 2',severity:'critical',known_exploited:true,sources:[{url:'https://example.test/legacy'}]});
 const noLegacy=async()=>assert.equal(await page.getByRole('button',{name:/View CVE-2019-0708 details/}).count(),0,'Incompatible finding must not enter counts, tables or priorities');
 page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url());
  if(url.hostname==='api.cveharbor.com'){
   let payload,status=200;
   if(url.pathname.endsWith('/allowance'))payload={enabled,available_usd:20};
   else if(url.pathname.endsWith('/assistance')){
    posts++;const body=request.postDataJSON();assert.ok(Buffer.byteLength(body.question)<6000);assert.equal(body.customer,'c1');assert.doesNotMatch(body.question,/PRIVATE-HOST|PRIVATE-NOTES|Fixture Harbor/);assert.match(body.question,/8\.4\.1/);assert.match(body.question,/example\.test/);
    payload={answer:'Applicability\nFictional evidence. <img src=x onerror=alert(1)>\nRecommended fix\nReview vendor instructions.\nVerify the result\nRecheck the installed version.',request_id:'fictional-receipt',state:'settled',allowance:{available_usd:19.99}};
   }else if(url.pathname.startsWith('/v1/workspace/')){const result=await workspace.request(url.href);payload=result.body;status=result.status;}
   else if(url.pathname==='/v1/team/organizations/north/customers')payload={name:'Fixture Organization',customers:f.inventory.customers};
   else if(url.pathname==='/v1/team/organizations/north/customers/c1')payload={customer:{name:'Fixture Harbor',role:'Viewer'},assets:f.inventory.assets,environments:f.inventory.environments.filter(e=>e.customer_id==='c1')};
   else{const result=await f.request(url.href,{method:request.method(),body:request.postData()});payload=await result.json();status=result.status;}
   return route.fulfill({status,headers:{'Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true'},json:payload});
  }
  if(url.hostname!=='cveharbor.com')return route.abort();
  if(url.pathname==='/data.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_DATA='+JSON.stringify({advisories:f.advisories})});
  if(url.pathname==='/catalog.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_CATALOG={advisories:[]}'});
  const filename=path.resolve(root,'.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));assert.ok(filename.startsWith(root+path.sep));
  try{return route.fulfill({body:await fs.readFile(filename),contentType:({'.html':'text/html','.js':'text/javascript','.css':'text/css'})[path.extname(filename)]||'application/octet-stream'});}catch{return route.fulfill({status:404,body:''});}
 });
 await page.goto('https://cveharbor.com/customer-dashboard/?customer=c1');await page.waitForSelector('#customerDashStatus[data-ready="true"]');
 await noLegacy();assert.equal(await page.evaluate(()=>window.CVEHARBOR_INVENTORY_MATCH.evaluate([{id:'server',technology:'Windows Server',version:'10.0.20348.5761'}],window.CVEHARBOR_DATA.advisories).total),0);
 await page.locator('.finding-ai-priority').first().click();
 assert.equal(posts,0,'opening evidence must not spend allowance');
 const dialog=page.locator('dialog[open]');await dialog.locator('.finding-ai-generate').evaluate(button=>{button.click();button.click();});
 await dialog.locator('.finding-ai-answer:not([hidden])').waitFor();assert.equal(posts,1);assert.equal(await dialog.locator('.finding-ai-answer img').count(),0);assert.ok(await dialog.locator('.finding-ai-generate').isDisabled());
 await page.screenshot({path:path.join(screens,'guide-'+width+'.png')});
 await dialog.getByRole('button',{name:'Close vulnerability details'}).click();enabled=false;
 await page.locator('.finding-ai-priority').first().click();await page.locator('dialog[open] .finding-ai-generate').click();await page.waitForFunction(()=>document.querySelector('dialog[open] .finding-ai-status').textContent.includes('paused'));assert.equal(posts,1);
 await page.goto('https://cveharbor.com/customer-reports/?customer=c1');await page.waitForSelector('#customerDashStatus[data-ready="true"]');
 await noLegacy();
 assert.equal(await page.locator('.customer-print-document').count(),0,'hidden print document must be lazy');
 const started=Date.now();await page.selectOption('#customerDashFilter','c2');await page.selectOption('#customerDashFilter','c1');const selectionMs=Date.now()-started;
 assert.equal(await page.locator('.customer-print-document').count(),0);
 await page.evaluate(()=>window.dispatchEvent(new Event('beforeprint')));assert.equal(await page.locator('.customer-print-document').count(),1);assert.match(await page.locator('.customer-print-document').textContent(),/Fixture Harbor/);
 assert.doesNotMatch(await page.locator('.customer-print-document').textContent(),/CVE-2019-0708/);
 await page.evaluate(()=>window.dispatchEvent(new Event('afterprint')));await page.selectOption('#customerDashFilter','c2');await page.evaluate(()=>window.dispatchEvent(new Event('beforeprint')));assert.doesNotMatch(await page.locator('.customer-print-document').textContent(),/PRIVATE-HOST/);await page.evaluate(()=>window.dispatchEvent(new Event('afterprint')));
 enabled=true;await page.goto('https://cveharbor.com/customer-dashboard/?org=north&customer=c1');await page.locator('.finding-ai-priority').first().click();await page.locator('dialog[open] .finding-ai-generate').click();await page.locator('dialog[open] .finding-ai-answer:not([hidden])').waitFor();assert.equal(posts,2);
 await noLegacy();
 await page.goto('https://cveharbor.com/workspace/');await page.waitForSelector('body.workspace-authenticated');
 await page.getByRole('button',{name:'Review customer priorities',exact:true}).click();await page.locator('#workspaceAccess > .finding-ai select').selectOption('c1');
 await noLegacy();
 assert.equal(posts,2,'workspace assessment must not send paid requests');assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),true);
 await page.screenshot({path:path.join(screens,'workspace-'+width+'.png'),fullPage:true});
 await page.locator('#workspaceAccess .finding-ai-priority').first().click();await page.locator('dialog[open] .finding-ai-generate').click();await page.locator('dialog[open] .finding-ai-answer:not([hidden])').waitFor();assert.equal(posts,3);
 modern.version='2008 R2';await page.goto('https://cveharbor.com/customer-dashboard/?customer=c1');await page.waitForSelector('#customerDashStatus[data-ready="true"]');assert.ok(await page.getByRole('button',{name:/View CVE-2019-0708 details/}).count(),'An actually matching legacy release remains visible');
 assert.deepEqual(errors,[]);console.log(JSON.stringify({width,reportSelectionMs:selectionMs,aiRequests:posts,privacy:true,printScope:true}));await page.close();
}}finally{await browser.close();}
