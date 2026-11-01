// Actual CVIE handlers behind an isolated browser route; no customer data or login.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {DB} from '../account-backend/tests/helpers/d1.mjs';
import {subscribeProducts,cvieRoute} from '../account-backend/src/cvie.js';
import {hyperVHosts} from '../account-backend/src/hyperv.js';
const {chromium}=await import(process.env.CVIE_PLAYWRIGHT_MODULE||'playwright');
const evidence=JSON.parse(fs.readFileSync('data/cvie-hyperv-check.json','utf8'));
assert.ok(evidence.ok&&evidence.sample.length,'verified public Hyper-V samples are required');
const env={DB:new DB()},prefs={defaults:null,products:[{name:'HyperV',category:'infrastructure'}]};
await subscribeProducts(env,'a',prefs.products);
const directory=process.env.CVIE_SCREENSHOTS||'/workspace/cvie-hyperv-review';fs.mkdirSync(directory,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:process.env.CVIE_CHROMIUM_PATH||undefined,args:['--no-sandbox']});
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
  if(url.pathname==='/v1/cvie/sync')return send({ready:true},202);
  if(url.pathname.startsWith('/v1/cvie')){
   const data=request.postData()?JSON.parse(request.postData()):{};
   const response=await cvieRoute(new Request(request.url(),{method:request.method()}),env,{id:'a'},null,data);
   if(url.pathname.endsWith('/identity')&&response.ok){
    const p=await env.DB.prepare('SELECT * FROM cvie_products').first();
    for(const r of evidence.sample)await env.DB.prepare('INSERT INTO cvie_advisories VALUES(?,?,?,?,?)').bind(p.id,r.id,r.published,JSON.stringify(r),'browser-public-sample').run();
    await env.DB.prepare("UPDATE cvie_products SET status='ready',last_success_at=?,recent_complete_at=?,history_complete_at=?").bind(Date.now(),Date.now(),Date.now()).run();
   }
   return send(await response.json(),response.status);
  }
  return send({ready:true,customers:[],environments:[],assets:[],statuses:[],tickets:[],findings:[],stack:[],history:[],features:{}});
 });
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:8080/vulnerabilities/',{waitUntil:'domcontentloaded'});
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE?.products[0]?.status==='needs_identity');
 const details=page.locator('#cvieExplorer details');await details.evaluate(el=>el.open=true);
 const chooser=page.getByRole('combobox',{name:'Product identity for HyperV'});
 assert.equal(await chooser.locator('option').count(),hyperVHosts().length+1);
 const labels=await chooser.locator('option').allTextContents();assert.ok(labels.some(x=>x==='Microsoft Windows Server 2022 · Hyper-V'));
 assert.ok(!/citrix|altair|bitdefender|qnx|ibm|redhat/i.test(labels.join(' ')));
 for(const width of [1366,1920,2560,390]){
  await page.setViewportSize({width,height:width===390?844:width===2560?1440:1080});
  await page.locator('#cvieExplorer').scrollIntoViewIfNeeded();
  await page.locator('#cvieExplorer').screenshot({path:directory+'/Hyper-V-host-selection-'+width+'.png'});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'no overflow at '+width);
 }
 await page.setViewportSize({width:1920,height:1080});
 await chooser.selectOption(evidence.host.cpe);
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE?.products[0]?.status==='ready'&&window.CVEHARBOR_CVIE.records.length>0);
 assert.match(await details.innerText(),/Checking: Microsoft Windows Server 2022 · Hyper-V/);
 assert.equal(await page.getByRole('combobox',{name:'Product identity for HyperV'}).count(),0);
 await page.locator('#cvieExplorer').screenshot({path:directory+'/Hyper-V-results-1920.png'});
 assert.deepEqual(errors,[]);
 fs.writeFileSync(directory+'/verification.json',JSON.stringify({ok:true,widths:[390,1366,1920,2560],source:'Actual backend handlers with isolated account and verified public Hyper-V sample records',checks:['Microsoft host choices','unrelated vendors excluded','host selection accepted','chosen host displayed','real advisory samples visible','responsive layout','no browser errors']},null,2)+'\n');
 console.log('PASS Chromium Hyper-V: Microsoft host choices, selection and public findings; screenshots at 390/1366/1920/2560.');
}finally{await browser.close();}
