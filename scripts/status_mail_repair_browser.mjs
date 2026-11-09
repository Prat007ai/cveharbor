// Real Worker + SQLite for shared records; synthetic inventory/advisories; intercepted email.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {renderStatusUpdate} from '../account-backend/src/status-update-mail.js';
import worker from '../account-backend/src/index.js';import {unifiedFixture,assetOne,assetTwo} from '../account-backend/tests/helpers/unified-db.mjs';import {fixtureCve} from '../account-backend/tests/helpers/assignment-db.mjs';import {securityFixture} from './customer_security_fixture.mjs';
const {chromium}=await import(process.env.CVEHARBOR_PLAYWRIGHT_MODULE||'playwright-core');
const f=await unifiedFixture(),customer=securityFixture(),originalFetch=globalThis.fetch;globalThis.fetch=f.fetcher;const directory='work/mail-repair-review';fs.mkdirSync(directory,{recursive:true});
for(const file of ['0029_finding_assignment_links.sql','0030_status_update_notifications.sql'])f.DB.sql.exec(fs.readFileSync('account-backend/migrations/'+file,'utf8'));
const request=async(path,method='GET',data)=>{const pending=[];const r=await worker.fetch(f.request(path,method,data),f.env,{waitUntil:p=>pending.push(p)});await Promise.all(pending);assert.equal(r.status,200);return r.json();};
const endpoint='/finding-remediations/'+assetOne+'/'+fixtureCve;
await request(endpoint,'POST',{});
const original=await request('/remediation-records/'+fixtureCve);await request('/remediations/'+fixtureCve,'PUT',{...original,status:'Open',status_change_reason:'Initial assignment awaiting review.',expected_updated:original.updated});
await request('/remediations/'+fixtureCve+'/assign','POST',{email:'alex@example.net',assigned_severity:'critical',fyi_recipients:['manager@example.net']});
f.DB.sql.prepare('UPDATE remediation_assignment_requests SET acknowledged_at=? WHERE cve_id=?').run(Math.floor(Date.now()/1000),fixtureCve);
const assetRecord=await request(endpoint);await request('/finding-statuses/'+assetOne+'/'+fixtureCve,'PUT',{status:'Needs Review',status_change_reason:'Earlier status update before linking the assignment.',expected_updated:assetRecord.record.updated});const assetDetails=await request('/remediation-records/'+assetRecord.record.id);await request('/remediation-records/'+assetRecord.record.id+'/comments','POST',{comment:'Earlier supporting evidence must be retained.',expected_updated:assetDetails.updated});
const mailCount=f.emails.length;const statusMails=()=>f.emails.filter(x=>x.subject.includes(' status changed: '));
f.DB.sql.exec("UPDATE inventory_assets SET technology='PHP',version='8.4.1' WHERE user_id='a'");
customer.inventory.customers=f.DB.sql.prepare("SELECT * FROM inventory_customers WHERE user_id='a'").all();customer.inventory.environments=f.DB.sql.prepare("SELECT * FROM inventory_environments WHERE user_id='a'").all();customer.inventory.assets=f.DB.sql.prepare("SELECT * FROM inventory_assets WHERE user_id='a'").all();customer.advisories.splice(1);customer.advisories[0].id=fixtureCve;
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||'/usr/bin/google-chrome',args:['--no-sandbox']});
try{
 const context=await browser.newContext({viewport:{width:1600,height:1100},reducedMotion:'reduce',timezoneId:'America/Toronto',serviceWorkers:'block'}),seen=[],errors=[];
 await context.route('**/*',async route=>{const req=route.request(),url=new URL(req.url());
  if(url.hostname==='api.cveharbor.com'){
   const headers={'Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS'};
   if(req.method()==='OPTIONS')return route.fulfill({status:204,headers});seen.push({path:url.pathname,method:req.method()});
   if(/^\/v1\/(?:remediation|finding)/.test(url.pathname)){
    const pending=[];const r=await worker.fetch(f.request(url.pathname.slice(3)+url.search,req.method(),req.postData()?JSON.parse(req.postData()):undefined),f.env,{waitUntil:p=>pending.push(p)});await Promise.all(pending);return route.fulfill({status:r.status,body:await r.text(),headers});
   }
   const result=await customer.request(req.url(),{method:req.method(),body:req.postData()}),body=await result.json();return route.fulfill({status:result.status,body:JSON.stringify(body),headers});
  }
  if(url.hostname!=='cveharbor.com')return route.abort();
  if(['/data.js','/catalog.js'].includes(url.pathname))return route.fulfill({contentType:'application/javascript',body:'window.'+(url.pathname==='/data.js'?'CVEHARBOR_DATA':'CVEHARBOR_CATALOG')+'='+JSON.stringify({advisories:customer.advisories})+';'});
  const file=path.resolve('public','.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));if(!file.startsWith(path.resolve('public')+path.sep)||!fs.existsSync(file))return route.fulfill({status:404,body:''});return route.fulfill({contentType:{'.html':'text/html','.js':'application/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml'}[path.extname(file)]||'application/octet-stream',body:fs.readFileSync(file)});
 });
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));await page.goto('https://cveharbor.com/customer-dashboard/');await page.waitForSelector('#customerDashStatus[data-ready=true]');await page.locator('#customerDashFilter').selectOption('c-'+assetOne);await page.locator('#customerDashEnvironment').selectOption('e-'+assetOne);
 // Both filters fetch fixture data asynchronously and redraw the disclosure on completion.
 await page.waitForLoadState('networkidle');
 const table=page.locator('.customer-vulnerability-table');await table.locator('tbody tr').first().waitFor({state:'attached'});await table.evaluate(n=>{let p=n.parentElement;while(p){if(p.tagName==='DETAILS')p.open=true;p=p.parentElement;}});
 assert.deepEqual(await table.locator('thead th').allTextContents(),['CVE','Published â‡…','Severity â‡…','Software / Asset â‡…','Vulnerability summary','Vulnerability Fix Status â‡…','DevOps Ticket #']);
 assert.equal(seen.some(x=>/^\/v1\/(?:finding|remediation)/.test(x.path)&&x.method!=='GET'),false,'Viewing customer findings performs no writes');
 const row=table.locator('tbody tr').first();assert.match(await row.innerText(),/Existing record â€” connect it to this customer asset/);assert.match(await row.innerText(),/Acknowledged Â· alex@example.net/);
 await row.getByRole('combobox').selectOption('Fix in Progress');await row.getByRole('button',{name:'Save status',exact:true}).click();const dialog=page.locator('.shared-record');await dialog.getByRole('heading',{name:'Link existing assignment'}).waitFor();
 // The heading precedes the assignments fetch; the link form marks completed rendering.
 await dialog.getByRole('button',{name:'Link existing assignment',exact:true}).waitFor();
 assert.match(await dialog.innerText(),/Customer North.*Production.*Web Server 01/);assert.match(await dialog.innerText(),/alex@example.net Â· Acknowledged/);
 assert.equal(await dialog.getByLabel('Status after linking').inputValue(),'Investigating');
 await dialog.screenshot({path:directory+'/link-preview.png'});
 assert.match(await dialog.innerText(),/Status update recipients:.*manager@example.net.*sender@example.test/s);await dialog.getByLabel('Reason for this change').fill('Review resumed after confirming the customer asset.');await dialog.getByLabel('I confirm this existing assignment belongs').check();await dialog.getByRole('button',{name:'Link existing assignment',exact:true}).click();await dialog.getByRole('heading',{name:fixtureCve,exact:true}).waitFor();
 assert.match(await dialog.innerText(),/alex@example.net Â· Acknowledged/);assert.match(await dialog.innerText(),/Linked the existing assignment/);assert.match(await dialog.innerText(),/Earlier supporting evidence must be retained/);assert.equal(f.emails.length,mailCount+3);assert.deepEqual(statusMails().map(x=>x.to[0]).sort(),['alex@example.net','manager@example.net','sender@example.test']);
 await dialog.getByRole('button',{name:'Close',exact:true}).click();await page.waitForFunction(()=>document.querySelector('.finding-assignment-summary')?.textContent.includes('Assigned reviewer(s)'));
 assert.doesNotMatch(await row.innerText(),/Existing record â€” connect/);assert.match(await row.innerText(),/Acknowledged Â· alex@example.net/);assert.match(await row.innerText(),/Receipt acknowledged/);
 await row.screenshot({path:directory+'/finding-acknowledged.png'});
 // Keep resolved rows visible while changing status directly in the finding table.
 await page.getByRole('button',{name:/^All \(\d+\)$/}).click();
 page.on('dialog',d=>{errors.push('Unexpected browser popup: '+d.message());void d.dismiss();});
 await row.getByRole('combobox').selectOption('Fixed/Patched');await row.getByRole('button',{name:'Save status',exact:true}).click();
 const statusDialog=page.getByRole('dialog',{name:'Update vulnerability status'});await statusDialog.waitFor();assert.match(await statusDialog.innerText(),/CVEHarbor/);assert.match(await statusDialog.innerText(),/manager@example.net/);assert.match(await statusDialog.innerText(),/alex@example.net/);assert.equal(await statusDialog.getByLabel('Reason for this change').evaluate(n=>n===document.activeElement),true);
 await statusDialog.getByRole('button',{name:'Cancel',exact:true}).click();await statusDialog.waitFor({state:'detached'});await page.waitForFunction(()=>document.querySelector('.customer-finding-status-select')?.value==='Fix in Progress');assert.equal(statusMails().length,3);assert.equal(await row.getByRole('combobox').inputValue(),'Fix in Progress');
 await row.getByRole('combobox').selectOption('Fixed/Patched');await row.getByRole('button',{name:'Save status',exact:true}).click();await statusDialog.waitFor();
 await statusDialog.getByLabel('Reason for this change').fill('   ');await statusDialog.getByRole('button',{name:'Save status',exact:true}).click();await statusDialog.getByRole('alert').filter({hasText:'Enter a reason'}).waitFor();assert.equal(statusMails().length,3);
 await statusDialog.getByLabel('Reason for this change').fill('Patch installed and validated for this customer asset.');
 for(const width of [390,1600]){await page.setViewportSize({width,height:1100});assert.ok(await statusDialog.evaluate(n=>n.scrollWidth<=n.clientWidth+1));await statusDialog.screenshot({path:directory+'/status-dialog-'+width+'.png'});}
 await statusDialog.getByRole('button',{name:'Save status',exact:true}).click();await statusDialog.waitFor({state:'detached'});

 await page.getByRole('button',{name:/^All \(\d+\)$/}).click();await page.waitForFunction(()=>[...document.querySelectorAll('.customer-finding-status-select')].some(n=>n.value==='Fixed/Patched'));
 assert.equal(statusMails().length,6);assert.deepEqual(statusMails().slice(3).map(x=>x.to[0]).sort(),['alex@example.net','manager@example.net','sender@example.test']);
 assert.match(statusMails().at(-1).text_body,/Patch installed and validated/);
 await row.getByRole('button',{name:'Save status',exact:true}).click();await page.waitForFunction(()=>document.querySelector('.customer-finding-status-select')?.disabled===false);assert.equal(statusMails().length,6);
 await row.getByRole('button',{name:'Assign / View remediation'}).click();await dialog.getByRole('heading',{name:fixtureCve,exact:true}).waitFor();assert.match(await dialog.innerText(),/Status update emails/);assert.match(await dialog.innerText(),/Accepted by email provider/);
 for(const width of [390,320,2560]){await page.setViewportSize({width,height:1000});assert.ok(await dialog.evaluate(n=>n.scrollWidth<=n.clientWidth+1),'linked modal fits '+width);}
 await dialog.getByRole('button',{name:'Close',exact:true}).click();await page.setViewportSize({width:1600,height:1100});await page.goto('https://cveharbor.com/remediation/');await page.locator('#remediationRows tr').filter({hasText:fixtureCve}).first().waitFor();
 assert.equal(await page.locator('#remediationRows tr').count(),1);assert.match(await page.locator('#remediationRows').innerText(),/Customer North/);assert.match(await page.locator('#remediationRows').innerText(),/Acknowledged/);
 await page.locator('#remediationRows').getByRole('button',{name:'View record',exact:true}).click();await dialog.getByRole('heading',{name:fixtureCve}).waitFor();await page.evaluate(()=>window.dispatchEvent(new CustomEvent('cveharbor:account-state',{detail:{authenticated:false}})));assert.equal(await dialog.evaluate(n=>n.open),false);assert.equal(await dialog.innerText(),'');
 assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediation_finding_links WHERE asset_id=?').get(assetTwo).n,0);assert.deepEqual(errors,[]);
 const emailPage=await context.newPage();for(const width of [620,390]){await emailPage.setViewportSize({width,height:1200});await emailPage.setContent(statusMails().find(x=>x.to[0]==='manager@example.net').html_body);assert.ok(await emailPage.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await emailPage.screenshot({path:directory+'/status-email-'+width+'.png',fullPage:true});}
 console.log('PASS: status change during linking and inline dashboard change notify all participants exactly once; unchanged save sends nothing; email preview fits desktop/mobile; unlinked receipt clearly labelled; explicit customer/asset confirmation; same acknowledgement in finding and one canonical queue row; shared status; responsive modal; sign-out clearing.');
}finally{globalThis.fetch=originalFetch;f.DB.sql.close();await browser.close();}
