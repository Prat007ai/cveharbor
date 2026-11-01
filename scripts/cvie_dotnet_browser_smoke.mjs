// Isolated account/API fixtures; advisory content is real, verified public data.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {monthsAgo} from '../account-backend/src/cvie.js';
import {dotnetProfile} from '../account-backend/src/dotnet.js';
const {chromium}=await import(process.env.CVIE_PLAYWRIGHT_MODULE||'playwright');
const report=JSON.parse(fs.readFileSync('data/cvie-dotnet-check.json','utf8'));assert.equal(report.ok,true);
const product={id:'11111111-1111-4111-8111-111111111111',name:'.NET Core',cpe:report.profile.primary};
const profile=dotnetProfile(product),now=Date.now(),directory=process.env.CVIE_SCREENSHOTS||'/workspace/cvie-dotnet-review';fs.mkdirSync(directory,{recursive:true});
let zero=false,disclosurePending=true;
const scoped=months=>report.advisories.filter(r=>Date.parse(r.published)>=monthsAgo(now,months)||r.retained_exploited);
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
  if(url.pathname==='/v1/technology-catalogue')return send({defaults:null,products:[{name:product.name,category:'applications'}]});
  if(url.pathname==='/v1/cvie/sync')return send({ready:true},202);
  if(url.pathname==='/v1/cvie')return send({ready:true,account_id:'preview',products:[{...product,status:'ready',icon_slug:'dotnet',error:'',
   component_scope:'modern_dotnet',identity_label:profile.label,recent_count:zero?0:report.recent_count,history_count:zero?0:report.history_count,
   last_success_at:Date.parse(report.checked_at),recent_complete_at:now,history_complete_at:now,stale:false,progress:{},candidates:[]}],
   evidence:{sources:[{id:'nvd',label:'NVD product history',status:'current',last_success_at:Date.parse(report.checked_at)},
    {id:'cve_program',label:'CVE Program / original disclosures',status:disclosurePending?'catching_up':'current',pending_records:disclosurePending?report.pending_original_disclosures:0},
    {id:'cisa_kev',label:'CISA KEV',status:'current',last_success_at:Date.parse(report.checked_at)}]}});
  if(url.pathname==='/v1/cvie/advisories')return send({ready:true,account_id:'preview',advisories:zero?[]:scoped(Number(url.searchParams.get('months')||3)),next:null});
  return send({ready:true,customers:[],environments:[],assets:[],statuses:[],tickets:[],findings:[],stack:[],history:[],features:{}});
 });
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:8080/vulnerabilities/',{waitUntil:'domcontentloaded'});
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE?.records.some(r=>r.id==='CVE-2026-114148'));
 await page.locator('#cvieExplorer details').evaluate(el=>el.open=true);
 assert.match(await page.locator('#cvieExplorer').innerText(),new RegExp(report.recent_count+' advisories'));
 assert.match(await page.locator('#cvieExplorer').innerText(),/Microsoft .NET \(5\+\), ASP.NET Core/);
 for(const width of [1366,1920,2560,390]){
  await page.setViewportSize({width,height:width===390?844:width===2560?1440:1080});
  await page.locator('#cvieExplorer').scrollIntoViewIfNeeded();
  await page.locator('#cvieExplorer').screenshot({path:directory+'/NET-Core-verified-'+width+'.png'});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'no overflow at '+width);
 }
 await page.setViewportSize({width:1920,height:1080});
 await page.locator('#cvieExplorer select[aria-label="CVIE vulnerability history"]').selectOption('12');
 await page.waitForFunction(n=>window.CVEHARBOR_CVIE.months===12&&window.CVEHARBOR_CVIE.records.length===n,scoped(12).length);
 assert.match(await page.locator('#cvieExplorer').innerText(),new RegExp(report.history_count+' advisories'));
 await page.locator('#cvieExplorer').screenshot({path:directory+'/NET-Core-12-months.png'});
 zero=true;await page.evaluate(()=>window.CVEHARBOR_CVIE.refresh());
 assert.match(await page.locator('#cvieExplorer').innerText(),/No verified matches available yet · original disclosure checks pending/);
 assert.doesNotMatch(await page.locator('#cvieExplorer').innerText(),/No published advisories found/);
 disclosurePending=false;await page.evaluate(()=>window.CVEHARBOR_CVIE.refresh());
 assert.match(await page.locator('#cvieExplorer').innerText(),/checked product identity/);
 assert.deepEqual(errors,[]);
 fs.writeFileSync(directory+'/verification.json',JSON.stringify({ok:true,widths:[390,1366,1920,2560],account:'Simulated; no customer data',source:'Verified public modern .NET, Microsoft original disclosures and NVD records from the isolated live scan',recent:report.recent_count,history:report.history_count,checks:['coverage label','recent and twelve-month retrieval','awaiting-NVD disclosure visible','pending verification is distinct from zero matches','zero copy identifies checked scope','responsive layout','no browser errors']},null,2)+'\n');
 console.log('PASS Chromium .NET: verified public advisories, 3/12 months, coverage label and honest zero/pending wording at 390/1366/1920/2560.');
}finally{await browser.close();}
