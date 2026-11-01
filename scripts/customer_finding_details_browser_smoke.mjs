// Fully intercepted synthetic fixtures: no production requests, writes, or emails.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {securityFixture} from './customer_security_fixture.mjs';
const {chromium}=await import(process.env.CVEHARBOR_PLAYWRIGHT_MODULE||'playwright');
const fixture=securityFixture(),directory=process.env.CVEHARBOR_REVIEW_DIR||'work/finding-details-browser';
let activeScan=false;
Object.assign(fixture.advisories[0],{summary:'Full advisory detail. '.repeat(40)+'Final sentence.',cvss:9.8,epss:0.1065,remediation:'Install the vendor-fixed release.',action:'Verify the installed package.'});
fs.mkdirSync(directory,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||undefined,args:['--no-sandbox']});
try{
 const context=await browser.newContext({viewport:{width:1440,height:1080},reducedMotion:'reduce',timezoneId:'America/Toronto',serviceWorkers:'block'});
 await context.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.hostname==='api.cveharbor.com'){
   const headers={'Access-Control-Allow-Origin':'http://127.0.0.1:8080','Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS'};
   if(req.method()==='OPTIONS')return route.fulfill({status:204,headers});
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
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 for(const route of ['customer-dashboard','customer-reports']){
  await page.goto('http://127.0.0.1:8080/'+route+'/?customer=c1');
  await page.waitForSelector('.customer-cve-detail',{state:'attached'});
  await page.selectOption('#customerDashEnvironment','e1');
  if(route==='customer-dashboard')await page.locator('#customerFindingsSection > summary').click();
  const trigger=page.locator('.customer-vulnerability-table .customer-cve-detail').first();
  const status=page.locator('.customer-vulnerability-table .customer-finding-status-select').first();
  const ticket=page.locator('.customer-vulnerability-table .customer-ticket-input').first();
  if(route==='customer-dashboard'){await status.selectOption('Fix in Progress');await ticket.fill('DRAFT-123')}
  const writes=fixture.writes.length;
  await trigger.focus();await page.keyboard.press('Enter');
  const dialog=page.locator('.customer-finding-dialog');await dialog.waitFor({state:'visible'});
  assert.match(await dialog.innerText(),/Final sentence/);
  assert.match(await dialog.innerText(),/9.8/);
  assert.match(await dialog.innerText(),/WEB01/);
  assert.doesNotMatch(await dialog.innerText(),/OTHER01|STAGE01|DRAFT-123/);
  assert.equal(await dialog.locator('input,select,.remediation-detail-assign').count(),0);
  assert.equal(await page.evaluate(()=>document.activeElement.closest('dialog')?.classList.contains('customer-finding-dialog')),true);
  await page.keyboard.press('Shift+Tab');
  assert.equal(await page.evaluate(()=>document.activeElement.closest('dialog')?.classList.contains('customer-finding-dialog')),true,'native modal traps focus');
  await page.keyboard.press('Escape');assert.equal(await dialog.count(),0);
  assert.equal(await trigger.evaluate(el=>el===document.activeElement),true,'Escape restores focus');
  if(route==='customer-dashboard'){assert.equal(await status.inputValue(),'Fix in Progress');assert.equal(await ticket.inputValue(),'DRAFT-123')}
  for(const width of [390,768,1440]){
   await page.setViewportSize({width,height:1000});await trigger.click();
   await dialog.waitFor({state:'visible'});
   const rect=await dialog.boundingBox();assert.ok(rect.x>=0&&rect.x+rect.width<=width+1,'modal fits viewport');
   assert.equal(await dialog.evaluate(el=>el.scrollWidth<=el.clientWidth+1),true,'no horizontal modal overflow');
   await page.screenshot({path:directory+'/'+route+'-'+width+'.png'});
   await dialog.locator('.close-dialog').click();
  }
  assert.equal(fixture.writes.length,writes,'reading details never saves or sends email');
 }
 assert.deepEqual(errors,[]);
 console.log('PASS: CVE dialog keyboard, focus restoration, preserved drafts, desktop/tablet/mobile and read-only report');
 await context.close();
}finally{await browser.close()}
