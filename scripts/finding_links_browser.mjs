// Real Worker + SQLite for shared records; synthetic inventory/advisories; intercepted email.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import worker from '../account-backend/src/index.js';import {unifiedFixture,assetOne,assetTwo} from '../account-backend/tests/helpers/unified-db.mjs';import {fixtureCve} from '../account-backend/tests/helpers/assignment-db.mjs';import {securityFixture} from './customer_security_fixture.mjs';
const {chromium}=await import(process.env.CVEHARBOR_PLAYWRIGHT_MODULE||'playwright-core');
const f=await unifiedFixture(),customer=securityFixture(),originalFetch=globalThis.fetch;globalThis.fetch=f.fetcher;const directory='work/finding-link-review';fs.mkdirSync(directory,{recursive:true});
f.DB.sql.exec(fs.readFileSync('account-backend/migrations/0029_finding_assignment_links.sql','utf8'));
const request=async(path,method='GET',data)=>{const pending=[];const r=await worker.fetch(f.request(path,method,data),f.env,{waitUntil:p=>pending.push(p)});await Promise.all(pending);assert.equal(r.status,200);return r.json();};
const endpoint='/finding-remediations/'+assetOne+'/'+fixtureCve;
await request(endpoint,'POST',{});
await request('/remediations/'+fixtureCve+'/assign','POST',{email:'alex@example.net',assigned_severity:'critical',fyi_recipients:['manager@example.net']});
f.DB.sql.prepare('UPDATE remediation_assignment_requests SET acknowledged_at=? WHERE cve_id=?').run(Math.floor(Date.now()/1000),fixtureCve);
const mailCount=f.emails.length;
// Hold the real handler response to exercise the loading boundary deterministically.
// The dialog heading is rendered before this request finishes.
let pauseAssignments=false,releaseAssignments,observeAssignments;
const assignmentResponseGate=new Promise(resolve=>{releaseAssignments=resolve;});
const assignmentResponseObserved=new Promise(resolve=>{observeAssignments=resolve;});
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
    const r=await worker.fetch(f.request(url.pathname.slice(3)+url.search,req.method(),req.postData()?JSON.parse(req.postData()):undefined),f.env,{waitUntil:()=>{}}),body=await r.text();
    if(pauseAssignments&&req.method()==='GET'&&url.pathname==='/v1/remediations/'+fixtureCve+'/assignments'){
     pauseAssignments=false;observeAssignments({status:r.status,body:JSON.parse(body)});await assignmentResponseGate;
    }
    return route.fulfill({status:r.status,body,headers});
   }
   const result=await customer.request(req.url(),{method:req.method(),body:req.postData()}),body=await result.json();return route.fulfill({status:result.status,body:JSON.stringify(body),headers});
  }
  if(url.hostname!=='cveharbor.com')return route.abort();
  if(['/data.js','/catalog.js'].includes(url.pathname))return route.fulfill({contentType:'application/javascript',body:'window.'+(url.pathname==='/data.js'?'CVEHARBOR_DATA':'CVEHARBOR_CATALOG')+'='+JSON.stringify({advisories:customer.advisories})+';'});
  const file=path.resolve('public','.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));if(!file.startsWith(path.resolve('public')+path.sep)||!fs.existsSync(file))return route.fulfill({status:404,body:''});return route.fulfill({contentType:{'.html':'text/html','.js':'application/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml'}[path.extname(file)]||'application/octet-stream',body:fs.readFileSync(file)});
 });
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));await page.goto('https://cveharbor.com/customer-dashboard/');await page.waitForSelector('#customerDashStatus[data-ready=true]');await page.locator('#customerDashFilter').selectOption('c-'+assetOne);await page.locator('#customerDashEnvironment').selectOption('e-'+assetOne);
 const table=page.locator('.customer-vulnerability-table');await table.locator('tbody tr').first().waitFor({state:'attached'});await table.evaluate(n=>{let p=n.parentElement;while(p){if(p.tagName==='DETAILS')p.open=true;p=p.parentElement;}});
 assert.deepEqual(await table.locator('thead th').allTextContents(),['CVE','Published ⇅','Severity ⇅','Software / Asset ⇅','Vulnerability summary','Vulnerability Fix Status ⇅','DevOps Ticket #']);
 assert.equal(seen.some(x=>/^\/v1\/(?:finding|remediation)/.test(x.path)&&x.method!=='GET'),false,'Viewing customer findings performs no writes');
 const row=table.locator('tbody tr').first();assert.match(await row.innerText(),/Existing record — connect it to this customer asset/);assert.match(await row.innerText(),/Acknowledged · alex@example.net/);
 pauseAssignments=true;await row.getByRole('button',{name:'Link existing assignment',exact:true}).click();const dialog=page.locator('.shared-record');await dialog.getByRole('heading',{name:'Link existing assignment'}).waitFor();
 let responseTimeout;const captured=await Promise.race([assignmentResponseObserved,new Promise((_,reject)=>{responseTimeout=setTimeout(()=>reject(Error('Assignments response was not observed')),10000);})]).finally(()=>clearTimeout(responseTimeout));
 assert.equal(captured.status,200);assert.ok(captured.body.assignments.some(a=>a.recipient_email==='alex@example.net'&&a.status==='Acknowledged'),'Real API response retains Alex acknowledgement');
 assert.doesNotMatch(await dialog.innerText(),/alex@example.net · Acknowledged/,'Heading alone is not assignment readiness');
 assert.equal(await dialog.getByRole('button',{name:'Link existing assignment',exact:true}).count(),0,'Cannot submit before assignments load');
 releaseAssignments();
 // Wait for the form rendered after the assignment summary; retain strict content assertions.
 await dialog.getByRole('button',{name:'Link existing assignment',exact:true}).waitFor();
 assert.match(await dialog.innerText(),/Customer North.*Production.*Web Server 01/);assert.match(await dialog.innerText(),/alex@example.net · Acknowledged/);
 assert.equal(await dialog.getByLabel('Status after linking').inputValue(),'Investigating');
 await dialog.screenshot({path:directory+'/link-preview.png'});
 await dialog.getByLabel('I confirm this existing assignment belongs').check();await dialog.getByRole('button',{name:'Link existing assignment',exact:true}).click();await dialog.getByRole('heading',{name:fixtureCve,exact:true}).waitFor();
 assert.match(await dialog.innerText(),/alex@example.net · Acknowledged/);assert.match(await dialog.innerText(),/Linked the existing assignment/);assert.equal(f.emails.length,mailCount);
 await dialog.getByRole('button',{name:'Close',exact:true}).click();await page.waitForFunction(()=>document.querySelector('.finding-assignment-summary')?.textContent.includes('Assigned reviewer(s)'));
 assert.doesNotMatch(await row.innerText(),/Existing record — connect/);assert.match(await row.innerText(),/Acknowledged · alex@example.net/);assert.match(await row.innerText(),/Receipt acknowledged/);
 await row.screenshot({path:directory+'/finding-acknowledged.png'});
 await row.getByRole('button',{name:'Assign / View remediation'}).click();await dialog.getByRole('heading',{name:fixtureCve,exact:true}).waitFor();
 await dialog.getByLabel('Vulnerability Fix Status').selectOption('Remediated');await dialog.getByLabel('Reason for status change').fill('Patch installed and validated for this customer asset.');await dialog.getByRole('button',{name:'Save status and details'}).click();await page.waitForFunction(()=>document.querySelector('.shared-record select')?.value==='Remediated'&&document.querySelector('.shared-record .shared-fields textarea[name="status_change_reason"]')?.value==='');
 await dialog.getByRole('button',{name:'Close',exact:true}).click();await page.getByRole('button',{name:/^All \(\d+\)$/}).click();await page.waitForFunction(()=>[...document.querySelectorAll('.customer-finding-status-select')].some(n=>n.value==='Fixed/Patched'));
 await row.getByRole('button',{name:'Assign / View remediation'}).click();await dialog.getByRole('heading',{name:fixtureCve,exact:true}).waitFor();
 for(const width of [390,320,2560]){await page.setViewportSize({width,height:1000});assert.ok(await dialog.evaluate(n=>n.scrollWidth<=n.clientWidth+1),'linked modal fits '+width);}
 await dialog.getByRole('button',{name:'Close',exact:true}).click();await page.setViewportSize({width:1600,height:1100});await page.goto('https://cveharbor.com/remediation/');await page.locator('#remediationRows tr').filter({hasText:fixtureCve}).first().waitFor();
 assert.equal(await page.locator('#remediationRows tr').count(),1);assert.match(await page.locator('#remediationRows').innerText(),/Customer North/);assert.match(await page.locator('#remediationRows').innerText(),/Acknowledged/);
 await page.locator('#remediationRows').getByRole('button',{name:'View record',exact:true}).click();await dialog.getByRole('heading',{name:fixtureCve}).waitFor();await page.evaluate(()=>window.dispatchEvent(new CustomEvent('cveharbor:account-state',{detail:{authenticated:false}})));assert.equal(await dialog.evaluate(n=>n.open),false);assert.equal(await dialog.innerText(),'');
 assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediation_finding_links WHERE asset_id=?').get(assetTwo).n,0);assert.deepEqual(errors,[]);
 console.log('PASS: controlled delayed real API response proves heading precedes acknowledgement; completed dialog retains Alex receipt; unlinked receipt clearly labelled; explicit customer/asset confirmation; same acknowledgement in finding and one canonical queue row; shared status; responsive modal; sign-out clearing.');
}finally{releaseAssignments();globalThis.fetch=originalFetch;f.DB.sql.close();await browser.close();}
