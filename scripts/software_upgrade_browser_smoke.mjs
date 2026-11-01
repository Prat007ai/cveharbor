// Fully intercepted synthetic fixtures: no production requests, writes, or emails.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {securityFixture} from './customer_security_fixture.mjs';
const {chromium}=await import(process.env.CVEHARBOR_PLAYWRIGHT_MODULE||'playwright');
const fixture=securityFixture(),directory=process.env.CVEHARBOR_REVIEW_DIR||'work/upgrade-browser';
let activeScan=false;
Object.assign(fixture.inventory.assets.find(a=>a.id==='a1'),{technology:'WordPress',version:'6.6.1'});
fixture.inventory.assets.find(a=>a.id==='a4').asset_type='Software';
fixture.advisories.splice(0,fixture.advisories.length,
 {id:'CVE-2026-70001',title:'WordPress core issue',summary:'Synthetic core upgrade regression',affected:'WordPress before 6.6.2',categories:['WordPress / Plugins'],severity:'high'},
 {id:'CVE-2026-70002',title:'WordPress core remaining issue',summary:'Synthetic remaining exposure',affected:'WordPress before 6.8.0',categories:['WordPress / Plugins'],severity:'high'},
 {id:'CVE-2026-70003',title:'Autoptimize plugin issue',summary:'Synthetic plugin upgrade regression',affected:'Autoptimize before 3.2.0',categories:['WordPress / Plugins'],severity:'high'});

fs.mkdirSync(directory,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||undefined,args:['--no-sandbox']});
try{
 const context=await browser.newContext({viewport:{width:1440,height:1080},reducedMotion:'reduce',timezoneId:'America/Toronto',serviceWorkers:'block'});
 await context.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.hostname==='api.cveharbor.com'){
   const headers={'Access-Control-Allow-Origin':'http://127.0.0.1:8080','Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS'};
   if(req.method()==='OPTIONS')return route.fulfill({status:204,headers});
   if(url.pathname==='/v1/plugin-monitor/refresh')return route.fulfill({status:200,headers,contentType:'application/json',body:JSON.stringify({status:'unverified',reason:'Synthetic pending check'})});
   // Supply the same synthetic product/source snapshot to lightweight polling.
   const fixtureUrl=url.pathname==='/v1/cvie/progress'?req.url().replace('/cvie/progress','/cvie'):req.url();
   const result=await fixture.request(fixtureUrl,{method:req.method(),body:req.postData()});
   const body=await result.json();
   if(['/v1/cvie','/v1/cvie/progress'].includes(url.pathname)){
    if(activeScan)body.products[0].status='scanning';
    body.evidence.sources.reverse(); // API order need not match presentation order.
   }
   return route.fulfill({status:result.status,headers,contentType:'application/json',body:JSON.stringify(body)});
  }
  if(url.hostname!=='127.0.0.1')return route.abort();
  const filename=path.resolve('public','.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));
  if(!filename.startsWith(path.resolve('public')+path.sep))return route.abort();
  if(url.pathname==='/data.js')return route.fulfill({contentType:'application/javascript',body:'window.CVEHARBOR_DATA='+JSON.stringify({advisories:fixture.advisories})});
  if(url.pathname==='/catalog.js')return route.fulfill({contentType:'application/javascript',body:'window.CVEHARBOR_CATALOG={advisories:[]}'});
  if(!fs.existsSync(filename))return route.fulfill({status:404,body:''});
  const type={'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml','.png':'image/png','.webp':'image/webp'}[path.extname(filename)]||'application/octet-stream';
  return route.fulfill({contentType:type,body:fs.readFileSync(filename)});
 });
 const errors=[];
 const report=await context.newPage(),dashboard=await context.newPage(),inventory=await context.newPage();
 for(const p of [report,dashboard,inventory])p.on('pageerror',e=>errors.push(e.message));
 for(const [p,route] of [[report,'customer-reports'],[dashboard,'customer-dashboard']]){
  await p.goto('http://127.0.0.1:8080/'+route+'/?customer=c1');
  await p.waitForSelector('.customer-vulnerability-table',{state:'attached'});await p.selectOption('#customerDashEnvironment','e1');
 }
 assert.match(await report.locator('.customer-vulnerability-table').innerText(),/70001/);
 await inventory.goto('http://127.0.0.1:8080/environments/');
 await inventory.evaluate(()=>window.dispatchEvent(new CustomEvent('cveharbor:account-state',{detail:{authenticated:true,email:'fixture@example.test'}})));
 await inventory.waitForSelector('.inventory-asset');
 async function edit(name,version){
  const row=inventory.locator('.inventory-asset').filter({has:inventory.locator('.inventory-technology-name',{hasText:name})}).first();
  await row.getByRole('button',{name:'Edit',exact:true}).click();
  await inventory.locator('#inventoryVersion').fill(version);
  await inventory.locator('#inventoryAssetSave').click();
  await inventory.waitForFunction(()=>document.querySelector('#inventoryMessage').textContent.includes('Technology updated'));
 }
 await edit('WordPress','6.6.2');
 for(const p of [report,dashboard])await p.waitForFunction(()=>!document.querySelector('.customer-vulnerability-table').textContent.includes('70001'));
 assert.match(await report.locator('.customer-vulnerability-table').innerText(),/70002/);
 await edit('Autoptimize','3.2.0');
 for(const p of [report,dashboard]){
  await p.waitForFunction(()=>!document.querySelector('.customer-vulnerability-table').textContent.includes('70003'));
  await p.waitForFunction(()=>document.querySelector('.customer-upgrade-history').textContent.includes('3.2.0'));
  await p.locator('.customer-upgrade-history > summary').click();
  assert.match(await p.locator('.customer-upgrade-history').innerText(),/6\.6\.1.*6\.6\.2/s);
 }
 for(const width of [1440,768,390]){
  await report.setViewportSize({width,height:1080});
  assert.ok(await report.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  await report.screenshot({path:directory+'/history-'+width+'.png',fullPage:true});
 }
 await report.pdf({path:directory+'/upgrade-history.pdf',printBackground:true,preferCSSPageSize:true});
 assert.equal(fixture.upgrades.length,2);assert.equal(fixture.writes.filter(x=>x.path.startsWith('inventory/assets/')).length,2);
 assert.equal(fixture.writes.filter(x=>!x.path.startsWith('inventory/assets/')).length,0);
 assert.deepEqual(errors,[]);
 console.log('PASS actual inventory Edit → save → cross-tab report/dashboard refresh, WordPress/plugin fixed-range removal, retained current finding, history, PDF and responsive layout.');
}finally{await browser.close()}
