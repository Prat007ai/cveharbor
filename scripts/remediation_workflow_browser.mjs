// Real Worker + SQLite; all network and mail are intercepted with synthetic data.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import worker from '../account-backend/src/index.js';import {assignmentFixture,fixtureCve} from '../account-backend/tests/helpers/assignment-db.mjs';
const {chromium}=await import(process.env.CVEHARBOR_PLAYWRIGHT_MODULE||'playwright-core');
const f=await assignmentFixture(),originalFetch=globalThis.fetch;globalThis.fetch=f.fetcher;
f.DB.sql.exec(fs.readFileSync('account-backend/migrations/0026_remediation_workflow.sql','utf8'));
Object.assign(f.env,{REMEDIATION_WORKFLOW_ENABLED:'true',ASSIGNMENT_FYI_ENABLED:'true',ASSIGNMENT_CONFIRM_ORIGIN:'https://confirm.cveharbor.com'});
const siteRoot=path.resolve(process.env.CVEHARBOR_CATALOGUE_PUBLIC||'public');
const manualAssignment=fs.readFileSync(path.join(siteRoot,'remediation/index.html'),'utf8').includes('id="assignManualToggle"');
if(manualAssignment)f.DB.sql.exec(fs.readFileSync('deployment/proposals/customer-remediation/manual-scope.sql','utf8'));
const background=[],directory='work/workflow-review';fs.mkdirSync(directory,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||'/usr/bin/google-chrome',args:['--no-sandbox']});
try{
 const context=await browser.newContext({reducedMotion:'reduce',timezoneId:'America/Toronto',serviceWorkers:'block',acceptDownloads:true}),seen=[];
 await context.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());seen.push({path:url.pathname,method:req.method()});
  if(['api.cveharbor.com','confirm.cveharbor.com'].includes(url.hostname)){
   if(req.method()==='OPTIONS'&&url.hostname==='api.cveharbor.com')return route.fulfill({status:204,headers:{'Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE'}});
   const publicRoute=url.hostname==='confirm.cveharbor.com'||url.pathname.startsWith('/v1/acknowledge/');
   const request=publicRoute?new Request(req.url(),{method:req.method(),headers:await req.allHeaders(),...(req.postData()?{body:req.postData()}:{} )}):f.request(url.pathname.slice(3)+url.search,req.method(),req.postData()?JSON.parse(req.postData()):undefined);
   const response=await worker.fetch(request,f.env,{waitUntil:task=>background.push(task)});return route.fulfill({status:response.status,body:await response.text(),headers:Object.fromEntries(response.headers)});
  }
  if(url.hostname!=='cveharbor.com')return route.abort();
  const file=path.resolve(siteRoot,'.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));if(!file.startsWith(siteRoot+path.sep)||!fs.existsSync(file))return route.fulfill({status:404,body:''});
  const contentType={'.html':'text/html','.js':'application/javascript','.json':'application/json','.css':'text/css','.svg':'image/svg+xml'}[path.extname(file)]||'application/octet-stream';return route.fulfill({contentType,body:fs.readFileSync(file)});
 });
 const tracker=await context.newPage(),errors=[];tracker.on('pageerror',e=>errors.push(e.message));await tracker.setViewportSize({width:1600,height:1100});await tracker.goto('https://cveharbor.com/remediation/');await tracker.waitForFunction(()=>document.getElementById('remediationTotal').textContent==='1');
 assert.match(await tracker.locator('#remediationRows td').first().innerText(),/time not recorded/);
 await tracker.setViewportSize({width:2560,height:1100});await tracker.locator('.rt-records').screenshot({path:directory+'/records-wide-not-sent.png'});await tracker.setViewportSize({width:1366,height:1000});await tracker.locator('.rt-records').screenshot({path:directory+'/records-laptop-not-sent.png'});await tracker.setViewportSize({width:1600,height:1100});
 const requestButton=tracker.getByRole('button',{name:'Request acknowledgement for '+fixtureCve,exact:true});assert.equal(await requestButton.count(),1);assert.equal(await requestButton.innerText(),'Request acknowledgement');assert.ok(await requestButton.evaluate(n=>n.getBoundingClientRect().height<=34),'compact request button');await requestButton.focus();await tracker.keyboard.press('Enter');assert.equal(await tracker.locator('#remediationAssignDialog').evaluate(n=>n.open),true);assert.equal(await tracker.locator('#remediationAssignCve').inputValue(),fixtureCve);assert.equal(await tracker.locator('#remediationAssignEmail').evaluate(n=>n===document.activeElement),true);assert.equal(f.emails.length,0);assert.ok(seen.every(x=>x.method==='GET'));await tracker.locator('#closeRemediationAssign').click();assert.equal(f.emails.length,0);
 if(manualAssignment){
  await requestButton.click();
  await tracker.locator('#assignManualToggle').click();
  await tracker.locator('#assignManualCustomer').fill('Example customer');
  await tracker.locator('#assignManualEnvironment').fill('Remote office');
  for(const tab of ['#previewFyiTab','#previewReviewerTab']){
   await tracker.locator(tab).click();
   assert.equal(await tracker.locator('#previewCustomer').innerText(),'Example customer');
   assert.equal(await tracker.locator('#previewEnvironment').innerText(),'Remote office');
  }
  for(const width of [1440,390]){
   await tracker.setViewportSize({width,height:900});
   const layout=await tracker.locator('#remediationSeverityLabel').evaluate(label=>{
    const select=label.querySelector('select').getBoundingClientRect(),help=label.querySelector('small').getBoundingClientRect(),box=label.getBoundingClientRect();
    return {stacked:select.top>box.top && help.top>=select.bottom,aligned:Math.abs(select.left-box.left)<=1 && select.right<=box.right+1};
   });
   assert.ok(layout.stacked&&layout.aligned,'Severity field and help must stack at width '+width);
  }
  await tracker.locator('#assignManualToggle').click();
  assert.equal(await tracker.locator('#assignManualCustomer').isEnabled(),false);
  await tracker.locator('#closeRemediationAssign').click();
  await tracker.setViewportSize({width:1600,height:1100});
 }
 assert.doesNotMatch(await tracker.locator('#remediationTracker').innerText(),/Cloudflare|\bD1\b|Worker/);
 await tracker.getByRole('button',{name:'Edit '+fixtureCve,exact:true}).click();await tracker.locator('#remediationStatus').selectOption('Remediated');assert.equal(await tracker.locator('#remediationReason').isVisible(),true);
 const puts=seen.filter(x=>x.method==='PUT').length;await tracker.locator('#remediationSave').click();assert.equal(seen.filter(x=>x.method==='PUT').length,puts);
 await tracker.locator('#remediationReason').fill('Patch deployed and validation completed.');await tracker.screenshot({path:directory+'/status-change-form.png',fullPage:true});await tracker.locator('#remediationSave').click();await tracker.waitForFunction(()=>document.getElementById('remediationMessage').textContent.includes('saved to your private workspace'));
 assert.match(await tracker.locator('#remediationRows').innerText(),/Investigating → Remediated/);assert.match(await tracker.locator('#remediationRows').innerText(),/Patch deployed/);assert.match(await tracker.locator('#remediationRows td').first().innerText(),/\d:\d{2}:\d{2}.*[A-Z]{2,4}/);
 await tracker.getByRole('button',{name:'View status history',exact:true}).click();await tracker.waitForFunction(()=>document.querySelector('#remediationStatusHistoryRows article'));assert.match(await tracker.locator('#remediationStatusHistoryRows').innerText(),/sender@example.test/);await tracker.screenshot({path:directory+'/status-history.png',fullPage:true});await tracker.locator('#remediationStatusHistoryClose').click();
 await requestButton.click();await tracker.getByLabel('Assigned reviewer email').fill('reviewer@example.net');await tracker.locator('#remediationAssignSeverity').selectOption('low');await tracker.locator('#remediationAssignFyi').fill('team@example.net');await tracker.locator('#remediationAssignConfirm').check();await tracker.screenshot({path:directory+'/assigned-severity-form.png',fullPage:true});assert.match(await tracker.locator('#previewSeverity').innerText(),/low/i);await tracker.locator('#remediationAssignConfirm').check();await tracker.locator('#remediationSendAssignment').click();await tracker.waitForFunction(()=>document.getElementById('remediationSuccessDialog').open);await Promise.all(background);await tracker.locator('#remediationSuccessClose').click();assert.equal(await tracker.locator('.rt-ack-request').count(),0);
 assert.match(await tracker.locator('#remediationRows td').filter({hasText:'Assigned · requester assessment'}).innerText(),/Low.*Assigned/s);
 const primary=f.emails.find(x=>x.to[0]==='reviewer@example.net'),url=primary.text_body.match(/https:\/\/confirm\.cveharbor\.com\/acknowledge\/[a-f0-9]{64}/)[0];
 const guest=await context.newPage();await guest.setViewportSize({width:620,height:1000});await guest.goto(url);assert.match(await guest.locator('body').innerText(),/Assigned severity/);assert.match(await guest.locator('body').innerText(),/Published severity/);await guest.screenshot({path:directory+'/confirmation-domain-page.png',fullPage:true});
 await Promise.all([guest.waitForNavigation({waitUntil:'domcontentloaded'}),guest.getByRole('button',{name:'I acknowledge receipt'}).click()]);assert.equal(await guest.locator('h1').innerText(),'Assignment acknowledged');await Promise.all(background);
 await tracker.locator('#remediationRefresh').click();await tracker.waitForFunction(()=>document.getElementById('remediationRows').textContent.includes('Acknowledged'));assert.equal(await tracker.locator('#remediationRows .remediation-row-assign').count(),0);assert.equal(f.DB.sql.prepare('SELECT status FROM remediations').get().status,'Remediated');assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediation_status_changes').get().n,1);
 for(const width of [1600,3200,390]){await tracker.locator('.rt-table-scroll').evaluate(n=>n.scrollLeft=0);await tracker.setViewportSize({width,height:1100});await tracker.evaluate(()=>new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))));assert.ok(await tracker.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));if(width>820)assert.ok(await tracker.locator('#remediationTracker').evaluate(n=>n.getBoundingClientRect().width>=innerWidth-document.querySelector('.command-sidebar').getBoundingClientRect().width-100),'tracker uses wide screen space');await tracker.screenshot({path:directory+'/tracker-'+width+'.png',fullPage:true});}
 await tracker.setViewportSize({width:1600,height:1100});const downloadEvent=tracker.waitForEvent('download');await tracker.locator('#remediationExport').click();const download=await downloadEvent,csv=fs.readFileSync(await download.path(),'utf8');assert.match(csv,/Assigned Severity/);assert.match(csv,/Patch deployed/);
 const preview=await context.newPage();await preview.setViewportSize({width:720,height:1100});await preview.setContent(primary.html_body);await preview.screenshot({path:directory+'/assigned-severity-email.png',fullPage:true});
 await tracker.getByRole('button',{name:'View status history',exact:true}).click();await tracker.evaluate(()=>window.dispatchEvent(new CustomEvent('cveharbor:account-state',{detail:{authenticated:false}})));assert.equal(await tracker.locator('#remediationStatusHistoryRows').innerText(),'');assert.equal(await tracker.locator('#remediationStatusHistoryDialog').evaluate(n=>n.open),false);assert.doesNotMatch(await tracker.locator('#remediationRows').innerText(),/sender@example.test|Patch deployed/);assert.deepEqual(errors,[]);
 console.log('PASS: reason required, private audit history, timestamps, severity, confirmation hostname, acknowledgement hides Assign, CSV, account clearing and responsive layouts. No production data or email used.');
}finally{globalThis.fetch=originalFetch;f.DB.sql.close();await browser.close();}
