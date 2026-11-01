// Fully intercepted synthetic fixtures: no production requests, writes, or emails.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {securityFixture} from './customer_security_fixture.mjs';
const {chromium}=await import(process.env.CVEHARBOR_PLAYWRIGHT_MODULE||'playwright');
const fixture=securityFixture(),directory=process.env.CVEHARBOR_REVIEW_DIR||'work/task2-browser';
fs.mkdirSync(directory,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||undefined,args:['--no-sandbox']});
try{
 const context=await browser.newContext({viewport:{width:1440,height:1080},reducedMotion:'reduce',timezoneId:'America/Toronto',serviceWorkers:'block'});
 await context.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.hostname==='api.cveharbor.com'){
   const headers={'Access-Control-Allow-Origin':'http://127.0.0.1:8080','Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS'};
   if(req.method()==='OPTIONS')return route.fulfill({status:204,headers});
   const result=await fixture.request(req.url(),{method:req.method(),body:req.postData()});
   return route.fulfill({status:result.status,headers,contentType:'application/json',body:JSON.stringify(await result.json())});
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
 await page.goto('http://127.0.0.1:8080/customer-reports/?customer=c1');
 await page.waitForSelector('.customer-vulnerability-table');
 await page.selectOption('#customerDashEnvironment','e1');
 assert.equal(await page.locator('#customerReportBody input,#customerReportBody select').count(),0);
 assert.equal(await page.locator('.cvie-source').count(),3);
 assert.equal(await page.locator('#customerReportIntelligence .cvie-panel').count(),1);
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE?.products.length===1&&!window.CVEHARBOR_CVIE.loading);
 await page.locator('#customerReportIntelligence .cvie-scan-details > summary').click();
 await page.locator('#customerReportIntelligence .cvie-coverage-details > summary').click();
 assert.match(await page.locator('#customerReportIntelligence').innerText(),/php \/ php/);
 assert.match(await page.locator('#customerReportIntelligence').innerText(),/original disclosure checks pending/);
 await page.evaluate(()=>window.CVEHARBOR_CVIE.refresh());
 assert.ok(await page.locator('#customerReportIntelligence .cvie-coverage-details').evaluate(el=>el.open),'upstream coverage expansion survives refresh in relocated report widget');
 await page.getByLabel('CVIE vulnerability history').selectOption('12');
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE.months===12&&!window.CVEHARBOR_CVIE.loading);
 await page.getByLabel('CVIE vulnerability history').selectOption('3');
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE.months===3&&!window.CVEHARBOR_CVIE.loading);
 assert.doesNotMatch(await page.locator('[data-section="Vulnerabilities Requiring Verification"] > summary').innerText(),/9999/,'global source backlog is never a customer verification count');
 assert.match(await page.locator('#customerReportAssessment').innerText(),/Insufficient Data/);
 assert.equal(await page.locator('.command-sidebar').count(),1);
 assert.equal(await page.locator('.command-nav-link.is-current').getAttribute('href'),'/customer-reports/');
 for(const width of [1440,1024,768,390]){
  await page.setViewportSize({width,height:1080});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'no page overflow at '+width);
  await page.screenshot({path:directory+'/reports-'+width+'.png',fullPage:true});
  for(const id of ['customerReportPrint','customerReportEmail','customerReportCsv'])assert.ok(await page.locator('#'+id).isVisible());
 }
 await page.setViewportSize({width:1440,height:1080});
 for(const section of await page.locator('details.customer-report-section').all()){
  await section.locator(':scope > summary').click();assert.equal(await section.getAttribute('open'),'');await section.locator(':scope > summary').click();
 }
 const dashboard=await context.newPage();dashboard.on('pageerror',e=>errors.push(e.message));
 await dashboard.goto('http://127.0.0.1:8080/customer-dashboard/?customer=c1');
 await dashboard.waitForSelector('#customerDashboardCves .customer-vulnerability-table',{state:'attached'});
 await dashboard.selectOption('#customerDashEnvironment','e1');
 await dashboard.locator('#customerFindingsSection > summary').click();
 await dashboard.locator('#customerDashboardCves .customer-finding-status-select').first().selectOption('Fixed/Patched');
 await dashboard.locator('#customerDashboardCves .customer-status-save').first().click();
 await dashboard.waitForFunction(()=>document.getElementById('customerFindingsAttention').textContent.includes('0 critical'));
 await dashboard.screenshot({path:directory+'/dashboard-remediation.png',fullPage:true});
 await page.getByRole('button',{name:'All (2)',exact:true}).click();
 const downloadPromise=page.waitForEvent('download');await page.locator('#customerReportCsv').click();
 const download=await downloadPromise;await download.saveAs(directory+'/findings.csv');
 const csv=fs.readFileSync(directory+'/findings.csv','utf8');assert.match(csv,/Fixed\/Patched/);assert.doesNotMatch(csv,/OTHER01|STAGE01|Other Customer/);
 assert.match(await page.locator('.customer-vulnerability-table').innerText(),/Fixed\/Patched/);
 await page.pdf({path:directory+'/customer-report.pdf',printBackground:true,preferCSSPageSize:true});
 // Exercise existing attachment delivery with a generated fixture PDF, intercepted locally.
 await page.locator('#customerReportEmail').click();
 await page.getByLabel('Recipient email address').fill('fixture-recipient@example.test');
 await page.getByLabel('Attach saved report PDF').setInputFiles(directory+'/customer-report.pdf');
 await page.locator('.customer-email-confirm input').check();
 fixture.setEmailFails(true);
 await page.getByRole('button',{name:'Send Report',exact:true}).click();
 await page.waitForFunction(()=>document.querySelector('.customer-email-dialog [role=status]')?.textContent.includes('Fixture email rejected'));
 assert.equal(await page.locator('.customer-email-success-dialog').count(),0,'rejected delivery must not show success');
 fixture.setEmailFails(false);
 await page.getByRole('button',{name:'Send Report',exact:true}).click();
 await page.waitForSelector('.customer-email-success-dialog');
 assert.equal(fixture.writes.find(x=>x.path==='customer-report-email').environment_id,'e1');
 await page.getByRole('button',{name:'Close',exact:true}).click();
 assert.equal(fixture.seen.filter(x=>x.method!=='GET'&&!['cvie/sync','customer-report-email'].includes(x.path)&&!x.path.startsWith('finding-statuses/')).length,0);
 assert.deepEqual(errors,[]);
 fs.writeFileSync(directory+'/verification.json',JSON.stringify({ok:true,fixtures:'Synthetic data; all API and email requests intercepted locally',widths:[390,768,1024,1440],checks:['read-only reports','CVIE widget preserved','icon sidebar preserved','independent accordions','dashboard status save','live status export refresh','CSV isolation','PDF generated','email attachment flow','no page errors']},null,2));
 console.log('PASS Chromium customer reports/dashboard: responsive layouts, sidebar, controls, status saves, CSV, PDF and mocked email flow.');
}finally{await browser.close()}
