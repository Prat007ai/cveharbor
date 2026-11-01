// Actual backend handlers with an isolated account and synthetic source-check
// states. Verifies the shared coverage UI, not production customer findings.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {DB} from '../account-backend/tests/helpers/d1.mjs';
import {subscribeProducts,cvieRoute,runCvieStep} from '../account-backend/src/cvie.js';
import {coveragePlan,coverageMetadata} from '../account-backend/src/product-coverage.js';
const {chromium}=await import(process.env.CVIE_PLAYWRIGHT_MODULE||'playwright');
const env={DB:new DB(),CVIE_SHARED_SCANS_ENABLED:process.env.CVIE_SHARED_BROWSER==='true'?'true':'false'},prefs={defaults:null,products:[{name:'PHP'},{name:'Linux',cpe:'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*'},{name:'Sample Stack',vendor:'Example'}]};
await env.DB.prepare('INSERT INTO user_technology_catalogue VALUES(?,?,0)').bind('a',JSON.stringify(prefs)).run();
await subscribeProducts(env,'a',prefs.products);
for(const p of (await env.DB.prepare('SELECT * FROM cvie_products').all()).results){
 if(p.cpe)await env.DB.prepare("UPDATE cvie_products SET status='ready',cursor_json=?,last_success_at=?,recent_complete_at=?,history_complete_at=? WHERE id=?").bind(JSON.stringify(coverageMetadata(coveragePlan(p))),Date.now(),Date.now(),Date.now(),p.id).run();
 else await env.DB.prepare("UPDATE cvie_products SET status='needs_identity',candidates_json=? WHERE id=?").bind(JSON.stringify([{cpe:'cpe:2.3:a:example:sample_stack:*:*:*:*:*:*:*:*',label:'Example / Sample Stack'}]),p.id).run();
}
if(env.CVIE_SHARED_SCANS_ENABLED==='true')await env.DB.prepare("UPDATE cvie_shared_scopes SET status='ready',last_success_at=?,recent_complete_at=?,history_complete_at=?,next_attempt_at=?").bind(Date.now(),Date.now(),Date.now(),Date.now()+21600000).run();
const directory=process.env.CVIE_SCREENSHOTS||'/workspace/cvie-coverage-review';fs.mkdirSync(directory,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:process.env.CVIE_CHROMIUM_PATH||undefined,args:['--no-sandbox']});
const reads={state:0,progress:0,advisories:0};
try{
 const context=await browser.newContext({viewport:{width:1920,height:1080},reducedMotion:'reduce',serviceWorkers:'block'});
 await context.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url());
  if(['127.0.0.1','localhost'].includes(url.hostname))return route.continue();
  if(url.hostname!=='api.cveharbor.com')return route.abort();
  const headers={'Access-Control-Allow-Origin':'http://127.0.0.1:8080','Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS'};
  const send=(body,status=200)=>route.fulfill({status,headers,contentType:'application/json',body:JSON.stringify(body)});
  if(request.method()==='OPTIONS')return send({},204);
  if(url.pathname==='/v1/me')return send({authenticated:true,email:'reviewer@example.test'});
  if(url.pathname==='/v1/technology-catalogue')return send(prefs);
  if(url.pathname.startsWith('/v1/cvie')){
   if(url.pathname==='/v1/cvie')reads.state++;
   if(url.pathname==='/v1/cvie/progress')reads.progress++;
   if(url.pathname==='/v1/cvie/advisories')reads.advisories++;
   const data=request.postData()?JSON.parse(request.postData()):{};
   const response=await cvieRoute(new Request(request.url(),{method:request.method()}),env,{id:'a'},null,data);
   return send(await response.json(),response.status);
  }
  return send({ready:true,customers:[],environments:[],assets:[],statuses:[],tickets:[],findings:[],stack:[],history:[],features:{}});
 });
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:8080/vulnerabilities/',{waitUntil:'domcontentloaded'});
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE?.products.length===3&&!window.CVEHARBOR_CVIE.loading);
 assert.equal(await page.locator('#cvieExplorer .cvie-source').count(),3,'all three source engines have visible status cards');
 await page.locator('#cvieExplorer .cvie-scan-details').evaluate(el=>el.open=true);
 const linux=page.locator('#cvieExplorer .cvie-product-status').filter({has:page.locator('strong',{hasText:/^Linux$/})});
 await linux.waitFor({state:'visible'});
 assert.match(await linux.innerText(),/Coverage limited/);assert.match(await linux.innerText(),/linux \/ linux kernel/);
 await linux.locator('.cvie-coverage-details summary').click();
 assert.match(await linux.innerText(),/Only the selected product is checked/);
 await page.evaluate(()=>window.CVEHARBOR_CVIE.refresh());
 assert.equal(await linux.locator('.cvie-coverage-details').evaluate(el=>el.open),true,'coverage explanation remains expanded while status refreshes');
 const php=page.locator('#cvieExplorer .cvie-product-status').filter({has:page.locator('strong',{hasText:/^PHP$/})});
 assert.match(await php.innerText(),/original disclosure checks pending/);assert.doesNotMatch(await php.innerText(),/No published advisories found/);
 for(const width of [1366,1920,2560,390]){
  await page.setViewportSize({width,height:width===390?844:width===2560?1440:1080});await linux.scrollIntoViewIfNeeded();
  await linux.screenshot({path:directory+'/CVIE-selected-product-coverage-'+width+'.png'});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'no overflow at '+width);
 }
 const chooser=page.getByRole('combobox',{name:'Product identity for Sample Stack'});
 await chooser.selectOption('cpe:2.3:a:example:sample_stack:*:*:*:*:*:*:*:*');
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE.products.some(p=>p.name==='Sample Stack'&&p.status==='queued'&&p.coverage.kind==='product'));
 await runCvieStep(env,()=>Response.json({startIndex:0,totalResults:0,vulnerabilities:[]}),Date.now());
 const savedJobs=async()=>JSON.stringify({private:(await env.DB.prepare('SELECT * FROM cvie_products ORDER BY id').all()).results,shared:(await env.DB.prepare('SELECT * FROM cvie_shared_scopes ORDER BY id').all()).results});
 const saved=await savedJobs();
 let navigationWrites=0;const prepare=env.DB.prepare.bind(env.DB);
 env.DB.prepare=sql=>{if(/^(INSERT|UPDATE|DELETE)/i.test(sql.trim()))navigationWrites++;return prepare(sql);};
 for(const path of ['/customer-dashboard/','/customer-reports/','/vulnerabilities/']){
  await page.goto('http://127.0.0.1:8080'+path,{waitUntil:'domcontentloaded'});
  await page.waitForFunction(()=>window.CVEHARBOR_CVIE?.products.length===3&&!window.CVEHARBOR_CVIE.loading);
  assert.equal(await page.locator('.cvie-panel:visible .cvie-source').count(),3,'source status is available on '+path);
  const progress=await page.evaluate(()=>window.CVEHARBOR_CVIE.products.find(p=>p.name==='Sample Stack').progress.windows_complete);
  assert.equal(progress,1,'saved scan position survives '+path);
  assert.equal(await savedJobs(),saved,'navigation retains the exact saved job on '+path);
 }
 assert.equal(navigationWrites,0,'dashboard, reports and explorer visits perform no scan or subscription writes');
 const beforePoll={...reads};
 await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));
 await page.waitForFunction(()=>!window.CVEHARBOR_CVIE.loading);
 assert.equal(reads.progress,beforePoll.progress+1);assert.equal(reads.state,beforePoll.state);assert.equal(reads.advisories,beforePoll.advisories,'unchanged progress never reloads result pages');
 await runCvieStep(env,()=>Response.json({startIndex:0,totalResults:0,vulnerabilities:[]}),Date.now()+7000);
 await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')));
 await page.waitForFunction(()=>!window.CVEHARBOR_CVIE.loading);
 assert.ok(reads.state>beforePoll.state,'an advanced saved scan refreshes the complete snapshot');
 assert.deepEqual(errors,[]);
 fs.writeFileSync(directory+'/verification.json',JSON.stringify({ok:true,widths:[390,1366,1920,2560],scope:'Actual backend coverage handlers with isolated account and synthetic check states; no production/customer data',checks:['broad category limited to selected member','source family displayed','coverage expansion survives polling','pending disclosure verification does not imply zero vulnerabilities','custom product selection follows shared engine','dashboard and reports navigation preserve saved progress with zero job/subscription writes','responsive layout','no browser errors']},null,2)+'\n');
 console.log('PASS Chromium shared CVIE coverage: exact/member/custom states, persistent coverage details, honest pending copy and responsive layout.');
}finally{await browser.close();}
