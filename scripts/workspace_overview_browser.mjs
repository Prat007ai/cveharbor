// All requests are intercepted. Never reads or writes private production data.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {workspaceFixture} from './workspace_fixture.mjs';
const {chromium}=await import(process.env.CVEHARBOR_PLAYWRIGHT_MODULE||'playwright-core');
const site=path.resolve(process.env.WORKSPACE_SITE);
const output=path.resolve(process.env.WORKSPACE_SCREENSHOTS||'work/workspace-overview');
fs.mkdirSync(output,{recursive:true});
const fixture=workspaceFixture();
const feed={count:12,period_start:'2026-10-12',period_end:'2026-11-10',coverage_limited:true,
 items:Array.from({length:7},(_,i)=>({id:'CVE-2026-'+(10000+i),technology:'Fictional test technology',severity:['critical','high','medium'][i%3],published:'2026-11-09',source:{label:'Fictional test advisory',url:'https://example.test/advisory'}}))};
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||'/usr/bin/google-chrome'});
const results=[];
try{
 const context=await browser.newContext({viewport:{width:2048,height:1158},reducedMotion:'reduce',timezoneId:'America/Toronto',serviceWorkers:'block'});
 let served=site;
 await context.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  assert.equal(req.method(),'GET','The overview must make only read requests');
  if(url.origin==='https://api.cveharbor.com'){
   let r;
   if(url.pathname==='/v1/auth/totp/status')r={status:200,body:{enabled:true}};
   else if(url.pathname==='/v1/team/organizations')r={status:200,body:{organizations:[],can_create:false}};
   else r=await fixture.request(req.url(),req.method());
   return route.fulfill({status:r.status,json:r.body,headers:{'Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true'}});
  }
  if(url.origin!=='https://cveharbor.com')return route.abort();
  if(url.pathname==='/workspace-intelligence.json')return route.fulfill({json:feed});
  const file=path.resolve(served,'.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));
  assert.ok(file.startsWith(served+path.sep));
  if(!fs.existsSync(file))return route.fulfill({status:404,body:'Not in reviewed package'});
  return route.fulfill({body:fs.readFileSync(file),contentType:({'.html':'text/html','.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.jpg':'image/jpeg','.json':'application/json'})[path.extname(file)]||'application/octet-stream'});
 });
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 async function load(){await page.goto('https://cveharbor.com/workspace/');await page.waitForFunction(()=>document.getElementById('wsCustomers')?.textContent==='2');await page.waitForFunction(()=>document.getElementById('wsRefresh')?.disabled===false);}
 if(process.env.WORKSPACE_BEFORE){served=path.resolve(process.env.WORKSPACE_BEFORE);await load();await page.screenshot({path:path.join(output,'before-2048.png'),fullPage:true});await page.screenshot({path:path.join(output,'before-2048-viewport.png')});served=site;}
 await load();
 assert.equal(await page.locator('#accountPageHeading').innerText(),'Workspace Overview');
 assert.equal(await page.locator('#wsOpenRemediation').innerText(),'5');
 assert.equal(await page.locator('#wsAssets').innerText(),'9');
 assert.equal(await page.getByRole('heading',{name:'Inventory Records',exact:true}).count(),1);
 assert.match(await page.locator('#wsAssetsHint').innerText(),/Multiple entries can belong to one device/);
 assert.equal(await page.locator('#wsEnvironments').innerText(),'3');
 assert.equal(await page.getByRole('heading',{name:'Registered Environments',exact:true}).count(),1);
 assert.match(await page.locator('.ws-trend').innerText(),/Trend history not available/);
 assert.match(await page.locator('#wsProgressPanel').innerText(),/33%/);
 assert.equal(await page.locator('#wsProgressPanel progress').getAttribute('value'),'4');
 assert.match(await page.locator('#wsProgressPanel').innerText(),/Accepted Risk/);
 assert.match(await page.locator('#wsProgressPanel').innerText(),/Not Applicable/);
 assert.equal(await page.locator('#wsAdvisories').innerText(),'12');
 assert.ok(await page.evaluate(()=>document.querySelector('.ws-panels').getBoundingClientRect().top<document.querySelector('.ws-tools').getBoundingClientRect().top),'Dashboard panels precede quick-access tools');
 const links=await page.locator('.ws-navigation nav a').evaluateAll(nodes=>nodes.map(n=>({href:n.getAttribute('href'),label:n.getAttribute('aria-label')})));
 assert.equal(links.length,9);for(const l of links){assert.ok(l.label);assert.ok(fs.existsSync(path.join(site,l.href.split('#')[0],'index.html')),l.href);}
 for(const [width,height] of [[2048,1158],[1920,1080],[1536,1024],[1366,768],[1024,768],[821,900],[820,900],[768,1024],[540,900],[390,844],[320,740]]){
  await page.setViewportSize({width,height});
  const layout=await page.evaluate(()=>({width:innerWidth,page:document.documentElement.scrollWidth,rail:document.querySelector('.command-sidebar').getBoundingClientRect().width,overflow:[...document.querySelectorAll('.ws-panel,.ws-metric,.ws-navigation')].filter(n=>n.scrollWidth>n.clientWidth+1).map(n=>n.className)}));
  assert.ok(layout.page<=width+1,JSON.stringify(layout));assert.deepEqual(layout.overflow,[],JSON.stringify(layout));if(width>820)assert.ok(layout.rail<100);
  results.push(layout);
  if([2048,1366,768,390,320].includes(width))await page.screenshot({path:path.join(output,'after-'+width+'.png'),fullPage:true});
  if(width===2048)await page.screenshot({path:path.join(output,'after-2048-viewport.png')});
  if(width===390)await page.screenshot({path:path.join(output,'after-390-viewport.png')});
 }
 await page.setViewportSize({width:2048,height:1158});
 await page.locator('#wsMenuToggle').click();assert.equal(await page.locator('#wsMenuToggle').getAttribute('aria-expanded'),'false');assert.equal(await page.getByRole('link',{name:'Overview',exact:true}).isVisible(),true);
 await page.locator('#wsMenuToggle').press('Enter');assert.equal(await page.locator('#wsMenuToggle').getAttribute('aria-expanded'),'true');
 await page.locator('#wsActivityNext').click();await page.waitForFunction(()=>document.getElementById('wsActivityPage').textContent==='Page 2');
 await page.locator('#wsActivityPrevious').click();await page.waitForFunction(()=>document.getElementById('wsActivityPage').textContent==='Page 1');
 await page.locator('#ws-assets-tab').press('ArrowRight');assert.equal(await page.locator('#ws-activity-tab').getAttribute('aria-selected'),'true');
 await page.locator('#ws-tracker-tab').click();assert.match(await page.locator('#wsRemediationPanel').innerText(),/Remediated/);
 await page.locator('#ws-findings-tab').click();assert.match(await page.locator('#wsRemediationPanel').innerText(),/Fixed\/Patched/);
 await page.locator('#ws-drafts-tab').click();assert.match(await page.locator('#wsReportsPanel').innerText(),/No saved report drafts/);
 await page.locator('#wsIntelNext').click();assert.equal(await page.locator('#wsIntelPage').innerText(),'Page 2');
 // A second fictional account must replace, not combine with, the prior summary.
 fixture.summary.inventory.customers=7;fixture.summary.inventory.environments=4;fixture.summary.inventory.inventory_entries=12;fixture.summary.remediation.rows=[{status:'Open',count:1,overdue:0}];
 await page.locator('#wsRefresh').click();await page.waitForFunction(()=>document.getElementById('wsCustomers').textContent==='7');assert.equal(await page.locator('#wsOpenRemediation').innerText(),'1');assert.equal(await page.locator('#wsAssets').innerText(),'12');assert.equal(await page.locator('#wsEnvironments').innerText(),'4');assert.match(await page.locator('#wsProgressPanel').innerText(),/0%/);
 fixture.summary.inventory.available=false;await page.locator('#wsRefresh').click();await page.waitForFunction(()=>document.getElementById('wsRefreshStatus').textContent.includes('unavailable'));assert.equal(await page.locator('#wsAssets').innerText(),'—');assert.equal(await page.locator('#wsEnvironments').innerText(),'—');
 fixture.setEmpty(true);await page.locator('#wsRefresh').click();await page.waitForFunction(()=>document.getElementById('wsCustomers').textContent==='0');assert.match(await page.locator('#wsProgressPanel').innerText(),/No remediation records/);assert.equal(await page.locator('#wsAssets').innerText(),'0');assert.equal(await page.locator('#wsEnvironments').innerText(),'0');await page.screenshot({path:path.join(output,'empty.png'),fullPage:true});
 fixture.setFailed(true);await page.locator('#wsRefresh').click();await page.waitForFunction(()=>document.getElementById('wsRefreshStatus').textContent.includes('unavailable'));assert.match(await page.locator('#wsProgressPanel').innerText(),/Progress unavailable/);assert.equal(await page.locator('#wsAssets').innerText(),'—');assert.equal(await page.locator('#wsEnvironments').innerText(),'—');await page.screenshot({path:path.join(output,'error.png'),fullPage:true});
 fixture.setAuthenticated(false);await page.locator('#wsRefresh').click();await page.waitForFunction(()=>!document.body.classList.contains('workspace-authenticated'));assert.equal(await page.locator('#workspaceAccess').isVisible(),false);assert.equal(await page.locator('.ws-navigation').isVisible(),false);assert.equal(await page.locator('#wsProgressPanel').innerText(),'');assert.equal(await page.locator('#accountPageRequest').isVisible(),true);
 assert.deepEqual(errors,[]);assert.ok(fixture.seen.every(r=>r.method==='GET'));
 fs.writeFileSync(path.join(output,'measurements.json'),JSON.stringify(results,null,2));
 console.log('PASS: exact package, 11 viewports, preserved rail, secondary menu, keyboard tabs, navigation destinations, progress, pagination, fictional account replacement, empty/error/401 clearing, no writes or network access.');
}finally{await browser.close();}
