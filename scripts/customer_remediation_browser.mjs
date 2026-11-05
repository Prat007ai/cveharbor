// Real browser + in-memory Worker/SQLite; every request intercepted, no cloud writes.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {customerRemediationFixture,customerA,customerB} from './customer_remediation_fixture.mjs';
import {fixtureCve} from '../account-backend/tests/helpers/assignment-db.mjs';
const {chromium}=await import(process.env.CVEHARBOR_PLAYWRIGHT_MODULE||'playwright-core');
const f=await customerRemediationFixture(),native=globalThis.fetch;globalThis.fetch=f.fetcher;
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||'/usr/bin/google-chrome',args:['--no-sandbox']});
const output='work/customer-remediation-review';fs.mkdirSync(output,{recursive:true});
let page;const errors=[];
try{
 const context=await browser.newContext({serviceWorkers:'block',acceptDownloads:true});context.setDefaultTimeout(15000);
 await context.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.hostname==='api.cveharbor.com'){
   const headers={'Access-Control-Allow-Origin':'http://127.0.0.1:8080','Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS'};
   if(req.method()==='OPTIONS')return route.fulfill({status:204,headers});
   const r=await f.call(url.pathname.slice(3)+url.search,req.method(),req.postData()?JSON.parse(req.postData()):undefined);
   return route.fulfill({status:r.status,headers:{...Object.fromEntries(r.headers),...headers},body:await r.text()});
  }
  if(url.hostname!=='127.0.0.1')return route.abort();
  const file=path.resolve('public','.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));
  if(!file.startsWith(path.resolve('public')+path.sep)||!fs.existsSync(file))return route.fulfill({status:404,body:''});
  return route.fulfill({body:fs.readFileSync(file),contentType:{'.html':'text/html','.js':'application/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml'}[path.extname(file)]||'application/octet-stream'});
 });
 page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));await page.setViewportSize({width:1440,height:1000});
 await page.goto('http://127.0.0.1:8080/remediation/?customer_id='+encodeURIComponent(customerA));
 await page.waitForFunction(()=>document.getElementById('remediationTotal').textContent==='0');
 assert.equal(await page.locator('.rt-stat').count(),4);assert.equal(await page.locator('.rt-tool').count(),4);
 assert.equal(await page.locator('#remediationCustomer').inputValue(),customerA);
 assert.doesNotMatch(await page.locator('#remediationCustomerFilter').textContent(),/Private Other/);
 async function save(owner,status='Open'){
  await page.locator('#remediationCve').fill(fixtureCve);await page.locator('#remediationOwner').fill(owner);await page.locator('#remediationStatus').selectOption(status);await page.locator('#remediationSave').click();await page.waitForFunction(()=>document.getElementById('remediationTotal').textContent==='1');
 }
 await save('North engineer');
 await page.locator('#remediationCustomerFilter').selectOption(customerB);await page.waitForFunction(()=>document.getElementById('remediationTotal').textContent==='0');
 await save('South engineer','Investigating');assert.equal(await page.locator('#remediationProgress').textContent(),'1');
 await page.reload();await page.waitForFunction(()=>document.getElementById('remediationTotal').textContent==='1');assert.equal(await page.locator('#remediationCustomerFilter').inputValue(),customerB);assert.match(await page.locator('#remediationRows').textContent(),/South engineer/);assert.doesNotMatch(await page.locator('#remediationRows').textContent(),/North engineer/);
 await page.locator('#remediationCustomerFilter').selectOption(customerA);await page.waitForFunction(()=>document.getElementById('remediationOpen').textContent==='1');
 await page.locator('#remediationRows').getByRole('button',{name:/^Edit /}).click();
 const dialog=page.locator('dialog.shared-record');await dialog.getByLabel('Owner',{exact:true}).fill('North patched');await dialog.locator('.shared-fields select').selectOption('Remediated');await dialog.getByLabel('Reason for status change',{exact:true}).fill('Fictional customer North patch verified');await dialog.getByRole('button',{name:'Save status and details'}).click();
 await page.waitForFunction(()=>document.getElementById('remediationResolved').textContent==='1');await dialog.getByRole('button',{name:'Close',exact:true}).click();
 await page.locator('#remediationCustomerFilter').selectOption('all');await page.waitForFunction(()=>document.getElementById('remediationTotal').textContent==='3');
 await page.locator('#remediationCustomerFilter').selectOption('unassigned');await page.waitForFunction(()=>document.getElementById('remediationTotal').textContent==='1');assert.match(await page.locator('#remediationRows').textContent(),/Unassigned Records/);
 await page.locator('#remediationCustomerFilter').selectOption('all');await page.waitForFunction(()=>document.getElementById('remediationTotal').textContent==='3');
 await page.locator('#remediationCve').fill('CVE-2026-99999');await page.locator('#remediationOwner').fill('Unassigned engineer');await page.locator('#remediationSave').click();
 assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediations').get().n,3);assert.equal(await page.locator('#remediationCustomer').inputValue(),'');
 await page.locator('#remediationCustomer').selectOption('unassigned');await page.locator('#remediationSave').click();await page.waitForFunction(()=>document.getElementById('remediationTotal').textContent==='4');
 await page.locator('#remediationCustomerFilter').selectOption(customerB);await page.waitForFunction(()=>document.getElementById('remediationProgress').textContent==='1');
 const south=(await(await f.call('/remediations?customer_id='+encodeURIComponent(customerB))).json()).remediations[0];
 await page.getByRole('button',{name:'Assign '+south.id+' by email',exact:true}).click();await page.locator('#remediationAssignEmail').fill('south-browser-reviewer@example.test');await page.locator('#remediationAssignConfirm').check();await page.locator('#remediationSendAssignment').click();await page.locator('#remediationConfirmSend').click();await page.locator('#remediationSuccessDialog').waitFor({state:'visible'});await page.locator('#remediationSuccessClose').click();
 assert.equal(f.DB.sql.prepare('SELECT cve_id FROM remediation_assignment_requests').get().cve_id,south.id);
 const downloadEvent=page.waitForEvent('download');await page.locator('#remediationExport').click();const download=await downloadEvent;const csv=fs.readFileSync(await download.path(),'utf8');assert.match(csv,/Customer South/);assert.doesNotMatch(csv,/Customer North/);
 for(const width of [1440,390]){await page.setViewportSize({width,height:1000});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await page.screenshot({path:output+'/tracker-'+width+'.png',fullPage:true});}
 await page.goto('http://127.0.0.1:8080/environments/');
 const northLink=page.locator('.inventory-customer').filter({hasText:'Customer North'}).getByRole('link',{name:'Remediation Tracker',exact:true});await northLink.waitFor();assert.equal(await northLink.getAttribute('href'),'/remediation/?customer_id='+encodeURIComponent(customerA));await northLink.click();await page.locator('#remediationCustomerFilter').waitFor();assert.equal(await page.locator('#remediationCustomerFilter').inputValue(),customerA);
 await page.goto('http://127.0.0.1:8080/customer-dashboard/');await page.locator('#customerDashFilter').selectOption(customerB);assert.equal(await page.locator('#customerRemediationLink').getAttribute('href'),'/remediation/?customer_id='+encodeURIComponent(customerB));
 assert.deepEqual(errors,[]);console.log('PASS customer selector, preserved cards/tools, independent same-CVE creates, switching, reload, edit/history, unassigned and scoped CSV.');
}catch(error){if(page)console.error(JSON.stringify({errors,url:page.url(),message:await page.locator('#remediationMessage').textContent(),total:await page.locator('#remediationTotal').textContent()}));throw error;}finally{await browser.close();globalThis.fetch=native;f.DB.sql.close();}
