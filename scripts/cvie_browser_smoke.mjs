// Real Chromium UI verification; account/API responses are isolated fixtures.
// Advisory content comes from the read-only live CVIE/NVD compatibility report.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {normalizeNvd,monthsAgo} from '../account-backend/src/cvie.js';
import {knownIdentity} from '../account-backend/src/product-identity.js';
const {chromium}=await import(process.env.CVIE_PLAYWRIGHT_MODULE||'playwright');
const source=JSON.parse(fs.readFileSync('data/cvie-provider-check.json','utf8'));
assert.equal(source.ok,true,'a verified public NVD sample is required');
const product={name:'Apache Tomcat',cpe:knownIdentity('Apache Tomcat').cpe};
const all=source.advisories||(source.sample||[]).map(x=>normalizeNvd(x.cve,product)).filter(Boolean);
assert.ok(all.length,'real NVD advisories are available for the interface review');
const now=Date.now(),recent=all.filter(x=>Date.parse(x.published)>=monthsAgo(now,3));
let preferences={defaults:null,products:[]},phase='scanning',authenticated=true;
const requests=[],errors=[];
const id='11111111-1111-4111-8111-111111111111';
const inventory={customers:[{id:'c1',name:'Example Organization'}],environments:[{id:'e1',customer_id:'c1',name:'Production',kind:'Production'}],
 assets:[{id:'asset1',environment_id:'e1',name:'Application Server',asset_type:'Server',technology:product.name,version:'10.1.20'}]};
const directory=process.env.CVIE_SCREENSHOTS||'/workspace/cvie-review';fs.mkdirSync(directory,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:process.env.CVIE_CHROMIUM_PATH||undefined,args:['--no-sandbox']});
try{
 const context=await browser.newContext({viewport:{width:1920,height:1080},reducedMotion:'reduce',serviceWorkers:'block'});
 await context.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url());
  if(url.hostname==='127.0.0.1'||url.hostname==='localhost')return route.continue();
  if(url.hostname==='cdn.simpleicons.org'){
   const slug=url.pathname.slice(1).split('/')[0];
   const path=(process.env.CVIE_ICON_DIRECTORY||'/tmp/cvie-icons/svg')+'/'+slug+'.svg';
   if(/^[a-z0-9]+$/.test(slug)&&fs.existsSync(path))return route.fulfill({contentType:'image/svg+xml',body:fs.readFileSync(path)});
   return route.abort();
  }
  if(url.hostname!=='api.cveharbor.com')return route.abort();
  const headers={'Access-Control-Allow-Origin':'http://127.0.0.1:8080','Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS'};
  const send=(data,status=200)=>route.fulfill({status,headers,contentType:'application/json',body:JSON.stringify(data)});
  if(request.method()==='OPTIONS')return send({},204);
  const path=url.pathname;requests.push({path,months:url.searchParams.get('months'),method:request.method()});
  if(!authenticated)return send({error:'Sign in required'},401);
  if(path==='/v1/me')return send({authenticated:true,email:'reviewer@example.test'});
  if(path==='/v1/technology-catalogue'){
   if(request.method()==='PUT'){preferences=JSON.parse(request.postData());return send({saved:true,cvie:{ready:true,status:'queued'}});}
   return send(preferences);
  }
  if(path==='/v1/cvie/sync')return send({ready:true,status:'queued'},202);
  if(path==='/v1/cvie')return send({ready:true,products:preferences.products.map(p=>({...p,id,cpe:product.cpe,status:phase,
   icon_slug:'apachetomcat',error:'',recent_count:phase==='ready'?recent.length:0,history_count:phase==='ready'?all.length:0,
   recent_complete_at:phase==='ready'?now:null,history_complete_at:phase==='ready'?now:null,last_success_at:phase==='ready'?now:null,
   stale:false,candidates:[],progress:{windows_complete:0,windows_total:5,records_checked:0,records_in_window:null}}))});
  if(path==='/v1/cvie/advisories')return send({ready:true,months:Number(url.searchParams.get('months')),advisories:phase==='ready'?(url.searchParams.get('months')==='12'?all:recent):[],next:null});
  if(path==='/v1/inventory/status')return send({ready:true});
  if(path==='/v1/inventory')return send(inventory);
  if(path==='/v1/plugin-advisories')return send({ready:true,findings:[]});
  if(path==='/v1/finding-statuses')return send({ready:true,statuses:[]});
  if(path==='/v1/finding-tickets')return send({ready:true,append_ready:true,tickets:[]});
  if(path==='/v1/plugin-installation-status')return send({ready:true,statuses:[]});
  if(path==='/v1/plugin-sources')return send({ready:true,sources:[]});
  if(path==='/v1/customer-score-history')return send({ready:true,history:[]});
  return send({ready:true,remediations:[],stack:[],features:{},status:[]});
 });
 const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
 const base=process.env.CVIE_BASE_URL||'http://127.0.0.1:8080';
 await page.goto(base+'/vulnerabilities/',{waitUntil:'domcontentloaded'});
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE?.ready);
 await page.locator('#technologyManageButton').click();
 await page.locator('#technologyAddName').fill(product.name);
 await page.locator('#technologyAddVendor').fill('Apache');
 await page.locator('#technologyAddVersion').fill('10.1.20');
 await page.getByRole('button',{name:'Add and scan product'}).click();
 await page.waitForFunction(()=>document.getElementById('technologyCustomizeStatus').textContent.includes('CVIE is scanning'));
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE.products.length===1);
 assert.equal(preferences.products.length,1,'Add and scan saves immediately, without a second save');
 await page.locator('#technologyManageClose').click();
 await page.evaluate(()=>{const badge=document.createElement('div');badge.id='cvieReviewBadge';badge.textContent='DEVELOPMENT PREVIEW · REAL NVD ADVISORIES · SIMULATED ACCOUNT';Object.assign(badge.style,{position:'fixed',bottom:'12px',right:'12px',zIndex:'99999',background:'#16384a',color:'#baf3e8',padding:'8px 12px',borderRadius:'6px',fontSize:'11px'});document.body.append(badge);});
 await page.locator('#cvieExplorer details').evaluate(el=>{el.open=true;});
 await page.locator('#technology').scrollIntoViewIfNeeded();
 await page.screenshot({path:directory+'/CVIE-scanning-1920.png'});
 phase='ready';await page.evaluate(()=>window.CVEHARBOR_CVIE.refresh());
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE.records.length>0);
 assert.equal(await page.locator('#dateRange').inputValue(),'published3m');
 const row=page.getByRole('button',{name:/^View Apache Tomcat:/});
 assert.ok(await row.locator('img').count(),'registered product logo is automatically displayed');
 await row.click();
 assert.equal(await page.locator('#technologyFilter').inputValue(),product.name);
 await page.waitForFunction(()=>document.querySelectorAll('#advisoryTableBody tr').length>0);
 assert.ok((await page.locator('#advisoryTableBody').innerText()).includes(recent[0].id),'real CVIE records are available in the shared advisory table');
 for(const width of [1366,1920,2560]){
  await page.setViewportSize({width,height:width===2560?1440:1080});
  await page.evaluate(()=>window.scrollTo(0,0));
  await page.screenshot({path:directory+'/CVIE-platform-'+width+'.png'});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'no horizontal page overflow at '+width);
 }
 await page.setViewportSize({width:1920,height:1080});
 await page.locator('#cvieExplorer select').selectOption('12');
 await page.waitForFunction(count=>window.CVEHARBOR_CVIE.months===12&&window.CVEHARBOR_CVIE.records.length===count,all.length);
 assert.ok(requests.some(r=>r.path==='/v1/cvie/advisories'&&r.months==='12'),'12-month selection requests the longer source history');
 assert.equal(await page.locator('#dateRange').inputValue(),'published12m');
 await page.locator('#advisories').scrollIntoViewIfNeeded();
 await page.screenshot({path:directory+'/CVIE-history-12-months.png'});
 await page.setViewportSize({width:390,height:844});await page.evaluate(()=>window.scrollTo(0,0));
 await page.screenshot({path:directory+'/CVIE-mobile.png'});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'no mobile page overflow');
 // The same account-scoped records must reach the customer report through the shared matcher.
 await page.setViewportSize({width:1920,height:1080});
 await page.goto(base+'/customer-reports/?customer=c1',{waitUntil:'domcontentloaded'});
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE?.records.length>0&&document.getElementById('customerReportBody')?.textContent.includes('Apache Tomcat'));
 assert.match(await page.locator('#customerReportBody').innerText(),/CVE-\d{4}-\d+/,'CVIE findings appear in the real report renderer');
 authenticated=false;await page.evaluate(()=>window.CVEHARBOR_CVIE.refresh());
 assert.equal(await page.evaluate(()=>window.CVEHARBOR_CVIE.records.length),0,'private CVIE results clear when the account session expires');
 assert.deepEqual(errors,[],'no uncaught browser errors');
 fs.writeFileSync(directory+'/verification.json',JSON.stringify({ok:true,source:'Real NVD advisories from isolated CVIE verification',account:'Simulated; no customer data',recent_records:recent.length,history_records:all.length,widths:[390,1366,1920,2560],checks:['immediate save and scan','automatic product logo','three/twelve month retrieval','shared report findings','expired-session clearing','horizontal overflow','uncaught browser errors']},null,2));
 console.log('PASS CVIE Chromium workflow: add/scan, logo, 3/12 months, reports, expired session; screenshots at 390/1366/1920/2560.');
}finally{await browser.close();}
