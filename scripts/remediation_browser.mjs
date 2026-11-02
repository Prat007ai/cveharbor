// All requests are intercepted. Review fixtures and email submissions never reach production.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {remediationFixture} from './remediation_fixture.mjs';
const {chromium}=await import(process.env.CVEHARBOR_PLAYWRIGHT_MODULE||'playwright-core');
const fixture=remediationFixture(),directory='work/remediation-review';fs.mkdirSync(directory,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||'/usr/bin/google-chrome',args:['--no-sandbox']});
try{
 const context=await browser.newContext({reducedMotion:'reduce',timezoneId:'UTC',serviceWorkers:'block',acceptDownloads:true});
 await context.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  const headers={'Access-Control-Allow-Origin':'http://127.0.0.1:8080','Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS'};
  if(url.hostname==='api.cveharbor.com'){
   if(req.method()==='OPTIONS')return route.fulfill({status:204,headers});
   const r=await fixture.request(req.url(),req.method(),req.postData());return route.fulfill({status:r.status,json:r.body,headers});
  }
  if(url.hostname!=='127.0.0.1')return route.abort();
  const file=path.resolve('public','.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));
  if(!file.startsWith(path.resolve('public')+path.sep)||!fs.existsSync(file))return route.fulfill({status:404,body:''});
  const contentType={'.html':'text/html','.js':'application/javascript','.json':'application/json','.css':'text/css','.svg':'image/svg+xml'}[path.extname(file)]||'application/octet-stream';return route.fulfill({contentType,body:fs.readFileSync(file)});
 });
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));await page.setViewportSize({width:1600,height:1000});await page.goto('http://127.0.0.1:8080/remediation/');await page.waitForFunction(()=>document.getElementById('remediationTotal').textContent==='6');
 assert.ok(fixture.seen.every(r=>r.method==='GET'),'page load is read-only');
 assert.equal(await page.locator('#remediationOpen').innerText(),'2');assert.equal(await page.locator('#remediationProgress').innerText(),'1');assert.equal(await page.locator('#remediationResolved').innerText(),'1');
 assert.equal(await page.locator('.command-nav-link[aria-current="page"]').getAttribute('href'),'/remediation/');
 assert.deepEqual(await page.locator('.rt-tool').evaluateAll(nodes=>nodes.map(n=>n.getAttribute('href'))),['/admin-tools/','/vulnerabilities/','/customer-reports/','/account/']);
 const measurements=[];
 for(const width of [1600,1672,1280,1024,820,768,390,320]){
  await page.setViewportSize({width,height:1000});await page.evaluate(()=>new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))));
  const layout=await page.evaluate(()=>({width:innerWidth,page:document.documentElement.scrollWidth,nav:document.querySelector('.command-sidebar').getBoundingClientRect().width,overflow:[...document.querySelectorAll('.rt-panel,.rt-stat,.rt-tool')].filter(n=>n.scrollWidth>n.clientWidth+1).length}));
  assert.ok(layout.page<=width+1,'no horizontal page overflow at '+width);assert.equal(layout.overflow,0);if(width>820)assert.equal(layout.nav,74);measurements.push(layout);
  if([1600,390].includes(width))await page.screenshot({path:directory+'/remediation-'+width+'.png',fullPage:true});
 }
 await page.setViewportSize({width:1600,height:1000});
 await page.locator('#remediationCve').fill('CVE-2026-99999');await page.locator('#remediationSave').click();
 assert.equal(await page.locator('#remediationOwnerError').isVisible(),true);assert.equal(await page.locator('#remediationOwner').getAttribute('aria-invalid'),'true');assert.ok(fixture.seen.every(r=>r.method==='GET'));
 await page.locator('#remediationOwner').fill('   ');await page.locator('#remediationSave').click();assert.ok(fixture.seen.every(r=>r.method==='GET'));
 await page.locator('#remediationOwner').fill('Review engineer');await page.locator('#remediationStatus').selectOption('Investigating');await page.locator('#remediationDue').fill('2026-12-01');await page.locator('#remediationNotes').fill('=SAFE CSV fixture');await page.locator('#remediationSave').click();await page.waitForFunction(()=>document.getElementById('remediationTotal').textContent==='7');
 assert.equal(await page.locator('#remediationProgress').innerText(),'2');
 await page.getByRole('button',{name:'Edit CVE-2026-99999',exact:true}).click();assert.equal(await page.locator('#remediationDue').inputValue(),'2026-12-01');
 await page.locator('#remediationOwner').fill('');const puts=fixture.seen.filter(r=>r.method==='PUT').length;await page.locator('#remediationSave').click();assert.equal(fixture.seen.filter(r=>r.method==='PUT').length,puts);
 await page.locator('#remediationOwner').fill('Updated engineer');await page.locator('#remediationStatus').selectOption('Remediated');await page.locator('#remediationSave').click();await page.waitForFunction(()=>document.getElementById('remediationResolved').textContent==='2');
 await page.locator('#remediationViewAll').click();assert.equal(await page.locator('#remediationRows tr').count(),7);assert.match(await page.locator('#remediationRows').innerText(),/Unassigned/);
 await page.getByRole('button',{name:'Edit CVE-2026-81005',exact:true}).click();assert.equal(await page.locator('#remediationOwner').inputValue(),'');await page.locator('#remediationSave').click();assert.equal(await page.locator('#remediationOwnerError').isVisible(),true);
 await page.getByRole('button',{name:'Assign CVE-2026-99999 by email',exact:true}).click();await page.locator('#remediationAssignEmail').fill('external@example.net');await page.locator('#remediationAssignNotes').fill('Verify affected versions.');await page.locator('#remediationAssignConfirm').check();await page.locator('#remediationSendAssignment').click();await page.locator('#remediationConfirmSend').click();await page.waitForFunction(()=>document.getElementById('remediationSuccessDialog').open);await page.locator('#remediationSuccessClose').click();assert.match(await page.locator('#remediationRows').textContent(),/external@example.net/);
 const downloadEvent=page.waitForEvent('download');await page.locator('#remediationExport').click();const download=await downloadEvent;assert.equal(download.suggestedFilename(),'cveharbor-remediation.csv');const csv=fs.readFileSync(await download.path(),'utf8');assert.match(csv,/Updated engineer/);assert.match(csv,/'=SAFE CSV fixture/);
 await page.locator('.rt-header-tools input').fill('CVE-2026-99999');await page.locator('.rt-header-tools button').click();await page.waitForFunction(()=>document.getElementById('detailDialog').open);assert.match(await page.locator('#dialogContent').innerText(),/not present in the available advisory index/);await page.locator('#closeDialog').click();
 page.once('dialog',dialog=>dialog.accept());await page.getByRole('button',{name:'Remove CVE-2026-99999',exact:true}).click();await page.waitForFunction(()=>document.getElementById('remediationTotal').textContent==='6');
 fixture.setEmpty();await page.reload();await page.waitForFunction(()=>document.getElementById('remediationTotal').textContent==='0');await page.screenshot({path:directory+'/remediation-empty.png',fullPage:true});
 fixture.setFailed(true);await page.reload();await page.waitForFunction(()=>document.getElementById('remediationMessage').textContent.includes('Unable to load'));assert.equal(await page.locator('#remediationSave').isDisabled(),true);await page.screenshot({path:directory+'/remediation-error.png',fullPage:true});
 fixture.setAuthenticated(false);await page.reload();await page.waitForFunction(()=>document.getElementById('remediationRecordsScope').textContent.includes('Browser-only'));assert.equal(await page.locator('#remediationTotal').innerText(),'—');assert.doesNotMatch(await page.locator('#remediationRows').innerText(),/Review engineer/);
 await page.locator('#remediationCve').focus();await page.keyboard.press('Tab');assert.equal(await page.locator('#remediationStatus').evaluate(n=>n===document.activeElement),true);
 assert.deepEqual(errors,[]);fs.writeFileSync(directory+'/measurements.json',JSON.stringify(measurements,null,2));console.log('PASS: 8 responsive widths, sidebar/routes, accurate stats, required owner create/edit, legacy rows, save/edit/delete, assignment, CSV, advisory search, keyboard, empty/error/signed-out states, read-only load.');
}finally{await browser.close();}
