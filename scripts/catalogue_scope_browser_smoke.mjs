// Real frontend + real account/CVIE routes on in-memory SQLite, no network.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import path from 'node:path';
const {chromium}=await import(process.env.CVEHARBOR_PLAYWRIGHT_MODULE||'playwright');
import {DB} from '../account-backend/tests/helpers/d1.mjs';
import worker from '../account-backend/src/index.js';
import {versionResponse} from '../site-gate/version-scan.mjs';
const scanRequests=[];
import {identityCandidates} from '../account-backend/src/product-identity.js';
import {catalogueRevision} from '../account-backend/src/catalogue-selection.js';
const env={DB:new DB(),CVIE_SHARED_SCANS_ENABLED:'true'},token='a'.repeat(64);
env.DB.sql.prepare('INSERT INTO sessions VALUES(?,?,?,?)').run('s','a',await catalogueRevision(token),Date.now()/1000+3600);
env.DB.sql.exec("INSERT INTO user_totp VALUES('a',1); INSERT INTO inventory_assets VALUES('a','WordPress'); INSERT INTO user_stack VALUES('a','Exchange SE'); UPDATE cvie_provider_budget SET next_request_at=9999999999999;");
const data=JSON.parse(fs.readFileSync('data/demo-advisories.json','utf8'));
// Overlapping topics exercise deduplication, paging and older KEV coverage.
const sample=(i,days)=>({id:'CVE-2099-'+(40000+i),title:'Topic fixture '+i,summary:'Synthetic disclosure',
 published:new Date(Date.now()-days*86400000).toISOString(),source_type:'vendor',severity:'high',
 categories:['Windows Server OS','.NET Core'],sources:[],known_exploited:i===52});
data.advisories=[];
data.advisories.push(...Array.from({length:51},(_,i)=>sample(i,2)),sample(51,170),sample(52,410));
let signedIn=true,failSave=false,holdSave=null,delaySave=false;
let saveFault;
let sessionGate,sessionUnavailable=false,catalogueUnavailable=false;
let transientSessions=0,transientCatalogues=0,interruptedReads=0;
const pending=[],seen=[];
async function fetcher(url,options={}){
 const u=new URL(url);seen.push({path:u.pathname,scope:u.searchParams.get('scope'),method:options.method||'GET'});
 if(u.pathname==='/v1/me'){
  if(sessionGate)await sessionGate;
  if(transientSessions>0){transientSessions--;return new Response(null,{status:503})}
  if(sessionUnavailable)return Response.json({error:'Service temporarily unavailable'},{status:503});
  return Response.json({authenticated:signedIn,email:signedIn?'a@example.test':undefined},{status:signedIn?200:401});
 }
 if(transientCatalogues>0&&u.pathname==='/v1/technology-catalogue'&&options.method==='GET'){transientCatalogues--;return new Response(null,{status:503})}
 if(catalogueUnavailable&&u.pathname==='/v1/technology-catalogue'&&options.method==='GET')return new Response(null,{status:503});
 if(!u.pathname.startsWith('/v1/cvie')&&u.pathname!=='/v1/technology-catalogue')return Response.json({});
 if(interruptedReads&&u.pathname==='/v1/cvie/advisories'){interruptedReads--;return new Response(null,{status:503})}
 if(failSave&&options.method==='PUT')return Response.json({error:'Synthetic save failure'},{status:503});
 const execute=()=>worker.fetch(new Request(url,{...options,headers:{...options.headers,Origin:'https://cveharbor.com',...(signedIn?{Cookie:'cvh_session='+token}:{})}}),env,{waitUntil:p=>pending.push(p)});
 if(saveFault&&options.method==='PUT'){
  const fault=saveFault;
  saveFault=null;
  if(fault==='after')assert.equal((await execute()).status,200);
  if(fault==='concurrent'){
   const other=await fetcher(url,{method:'PUT',body:JSON.stringify({defaults:['Fortinet'],products:[]})});
   assert.equal((await other.json()).saved,true);
  }
  return Response.json({error:'Unable to process request'},{status:500});
 }
 if(delaySave&&options.method==='PUT'){delaySave=false;return new Promise(resolve=>{holdSave=async()=>resolve(await execute())})}
 return execute();
}
const assetRoot=path.resolve(process.env.CVEHARBOR_CATALOGUE_PUBLIC||'public');
const directory='work/catalogue-browser';fs.mkdirSync(directory,{recursive:true});
// A disposable regular profile allows the browser's actual page zoom to be tested.
const context=await chromium.launchPersistentContext('',{
 channel:'chromium',headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||undefined,args:['--no-sandbox'],
 viewport:{width:1440,height:1050},reducedMotion:'reduce',serviceWorkers:'block'
});
try{
 await context.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.hostname==='api.cveharbor.com'){
   const headers={'Access-Control-Allow-Origin':'http://127.0.0.1:8080','Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS'};
   if(req.method()==='OPTIONS')return route.fulfill({status:204,headers});
   const response=await fetcher(req.url(),{method:req.method(),...(req.postData()?{body:req.postData()}:{})});
   return route.fulfill({status:response.status,headers,contentType:'application/json',body:await response.text()});
  }
  if(url.hostname!=='127.0.0.1')return route.abort();
  if(url.pathname==='/v1/version-picker/catalogue'){
    const response=await versionResponse(new Request(url),{});return route.fulfill({contentType:'application/json',body:await response.text()});
  }
  if(url.pathname==='/v1/version-picker/scan'){
    scanRequests.push(Object.fromEntries(url.searchParams));
    const q=Number(url.searchParams.get('quarter')),months=Number(url.searchParams.get('months'));
    return route.fulfill({contentType:'application/json',body:JSON.stringify({rows:[{id:'CVE-2099-98011',title:'Synthetic scanned advisory',summary:'Full synthetic description',published:'2099-01-01',evidence:'Product lead',url:'https://example.org/advisory',sources:[{url:'https://example.org/advisory',label:'Vendor bulletin'}]}],next:null,nextQuarter:q+1<months/3?q+1:null})});
  }
  if(url.pathname==='/data.js')return route.fulfill({contentType:'application/javascript',body:'window.CVEHARBOR_DATA='+JSON.stringify(data)});
  const filename=path.resolve(assetRoot,'.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));
  if(!filename.startsWith(assetRoot+path.sep)||!fs.existsSync(filename))return route.fulfill({status:404,body:''});
  return route.fulfill({contentType:{'.html':'text/html','.js':'application/javascript','.mjs':'application/javascript','.css':'text/css','.svg':'image/svg+xml','.png':'image/png','.webp':'image/webp'}[path.extname(filename)]||'application/octet-stream',body:fs.readFileSync(filename)});
 });
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:8080/vulnerabilities/');
 await page.waitForSelector('.cvie-scope-summary');await page.locator('#technologyManageButton').click();
 const choices=page.locator('#technologyDefaultChoices input');
 const editor=page.locator('#technologyCustomizer');
 await editor.waitFor({state:'visible'});
 const save=editor.getByRole('button',{name:'Save my catalogue'});
 const status=editor.locator('#technologyCustomizeStatus');
 const count=editor.locator('#technologySelectedCount');
 const php=editor.locator('#technologyDefaultChoices').getByLabel('PHP',{exact:true});
 const monitorPHP=editor.getByRole('checkbox',{name:'Monitor PHP',exact:true});
 const puts=()=>seen.filter(r=>r.method==='PUT'&&r.path==='/v1/technology-catalogue').length;
 const stored=()=>JSON.parse(env.DB.sql.prepare("SELECT preferences_json FROM user_technology_catalogue WHERE user_id='a'").get().preferences_json);
 async function waitStatus(message){await page.waitForFunction(value=>document.querySelector('#technologyCustomizeStatus').textContent.includes(value),message)}
 async function reopen(){
  await page.reload();await page.waitForSelector('.cvie-scope-summary');
  await page.locator('#technologyManageButton').click();
  await editor.waitFor({state:'visible'});
 }
 const checkedNames=()=>editor.locator('#technologyDefaultChoices input:checked').evaluateAll(
  inputs=>inputs.map(input=>input.labels[0].textContent).sort()
 );
 const defaults=await checkedNames();
 assert.equal(defaults.length,38);
 assert.equal(env.DB.sql.prepare("SELECT count(*) AS n FROM user_technology_catalogue WHERE user_id='a'").get().n,0);
 const registrations=()=>env.DB.sql.prepare(
  "SELECT p.name FROM cvie_subscriptions s JOIN cvie_products p ON p.id=s.product_id WHERE s.user_id='a' AND s.origin='catalogue'"
 ).all().map(row=>row.name).sort();
 assert.deepEqual(registrations(),[]);
 const firstSaves=[];
 const observeSave=response=>{
  if(response.request().method()==='PUT'&&response.url().endsWith('/v1/technology-catalogue'))firstSaves.push(response.status());
 };
 page.on('response',observeSave);
 await save.click();
 await page.waitForFunction(()=>document.querySelector('#technologyCustomizeStatus').textContent && !document.querySelector('#technologySaveButton').disabled);
 assert.equal(await status.innerText(),'Catalogue saved. 38 technologies selected.');
 assert.match(await editor.locator('#technologyScanStatus').innerText(),/vulnerability checks/i);
 assert.deepEqual(firstSaves,[200]);assert.equal(puts(),1);
 assert.deepEqual(stored().defaults.slice().sort(),defaults);
 assert.deepEqual(registrations(),defaults);
 await reopen();assert.deepEqual(await checkedNames(),defaults);
 await save.click();await waitStatus('No changes to save.');assert.equal(puts(),1);
 page.off('response',observeSave);
 await php.uncheck();delaySave=true;await save.click();
 await waitStatus('Saving…');assert.equal(await save.isDisabled(),true);
 await holdSave();await waitStatus('Catalogue saved. 37 technologies selected.');
 await reopen();assert.equal(await php.isChecked(),false);
 await editor.locator('summary').click();
 await editor.getByLabel('Product name').fill('PHP');
 await editor.getByLabel('Installed version').fill('8.4.26');
 const beforePHP=puts();
 await save.click();await waitStatus('Add and scan product');
 assert.equal(puts(),beforePHP);assert.equal(await php.isChecked(),false);
 assert.equal(await editor.getByLabel('Product name').inputValue(),'PHP');
 assert.equal(await editor.getByLabel('Installed version').inputValue(),'8.4.26');
 assert.deepEqual(stored().products,[]);
 // An explicit add saves PHP even when a bulk edit is pending. The other edits stay in the draft.
 await editor.getByRole('button',{name:'Unselect all',exact:true}).click();
 await editor.getByRole('button',{name:'Add and scan product'}).click();
 await waitStatus('Catalogue saved. 38 technologies selected.');
 assert.equal(puts(),beforePHP+1);
 assert.equal(stored().defaults.length,37);assert.equal(await count.innerText(),'1 technology selected');
 assert.match(await status.innerText(),/Other selections are still unsaved/);

 await reopen();
 const [custom]=stored().products;assert.equal(custom.version,'8.4.26');
 assert.equal(env.DB.sql.prepare("SELECT COUNT(*) AS n FROM cvie_subscriptions s JOIN cvie_products p ON p.id=s.product_id WHERE s.origin='catalogue' AND p.name_key='php' AND s.user_id='a'").get().n,1);
 await editor.locator('summary').click();
 await editor.getByLabel('Installed version').fill('9.0');
 await save.click();await waitStatus('Clear form');assert.equal(puts(),beforePHP+1);
 await editor.getByRole('button',{name:'Clear form'}).click();
 await save.click();await waitStatus('No changes to save.');assert.equal(puts(),beforePHP+1);
 await editor.getByRole('button',{name:'Unselect all',exact:true}).click();
 assert.equal(await count.innerText(),'0 technologies selected');assert.equal(await monitorPHP.isChecked(),false);
 assert.equal(stored().products[0].enabled,undefined);
 await save.click();await waitStatus('Catalogue saved. 0 technologies selected.');
 await reopen();assert.equal(await count.innerText(),'0 technologies selected');
 const afterEmptySave=puts();
 await save.click();await waitStatus('No changes to save.');assert.equal(puts(),afterEmptySave);
 assert.deepEqual(stored().products,[{...custom,enabled:false}]);assert.equal(await monitorPHP.isChecked(),false);
 await editor.getByRole('button',{name:'Select all',exact:true}).click();
 assert.equal(await editor.locator('input:checked').count(),39);
 assert.equal(await count.innerText(),'38 technologies selected');assert.equal(stored().defaults.length,0);
 const names=(await choices.evaluateAll(inputs=>inputs.map(input=>input.labels[0].textContent)));
 const selected=names.filter(n=>n!=='PHP').slice(0,11);
 for(const name of names.filter(n=>!selected.includes(n)))await editor.getByLabel(name,{exact:true}).uncheck();
 assert.equal(await count.innerText(),'12 technologies selected');
 failSave=true;await save.click();await waitStatus('Unable to save');
 assert.equal(await count.innerText(),'12 technologies selected');assert.equal(stored().defaults.length,0);
 failSave=false;
 env.DB.sql.exec("UPDATE cvie_provider_budget SET provider='offline-fixture' WHERE provider='nvd'");
 await save.click();await waitStatus('Catalogue saved. 12 technologies selected.');
 assert.match(await editor.locator('#technologyScanStatus').innerText(),/checks are pending/);
 env.DB.sql.exec("UPDATE cvie_provider_budget SET provider='nvd' WHERE provider='offline-fixture'");
 assert.deepEqual(stored().defaults.slice().sort(),selected.slice().sort());
 for(const width of [1440,390]){
  await page.setViewportSize({width,height:width===1440?1440:844});
  assert.equal(await editor.evaluate(el=>el.scrollWidth<=el.clientWidth),true);
  assert.equal(await editor.locator('.technology-choice-group label').first().evaluate(el=>getComputedStyle(el).fontSize),'16px');
  assert.equal(await status.evaluate(el=>el.parentElement.contains(document.querySelector('#technologySaveButton'))),true);
  await editor.evaluate(el=>window.scrollTo(0,scrollY+el.getBoundingClientRect().top-100));
  await editor.screenshot({path:directory+'/catalogue-editor-'+width+'.png'});
  await editor.locator('summary').click();
  const form=editor.locator('form');
  assert.equal(await form.evaluate(el=>el.scrollWidth<=el.clientWidth+1),true);
  assert.equal(await form.locator('#technologyAddVersion').evaluate(el=>getComputedStyle(el).fontSize),'16px');
  await editor.locator('summary').click();
 }
 await page.setViewportSize({width:1440,height:950});
 const settings=await context.newPage();
 await settings.goto('chrome://settings/appearance');
 const initialZoom=await page.evaluate(()=>({ratio:devicePixelRatio,width:innerWidth}));
 await settings.evaluate(()=>chrome.settingsPrivate.setDefaultZoom(2));
 await page.waitForFunction(ratio=>devicePixelRatio===2*ratio,initialZoom.ratio);
 assert.ok(await page.evaluate(()=>innerWidth)<=initialZoom.width/2+1);
 await editor.locator('summary').click();
 for(const section of await editor.locator('fieldset, form, label, .technology-save-actions, .technology-selection-tools').all()){
  assert.ok(await section.evaluate(el=>el.scrollWidth<=el.clientWidth+1),'controls fit at 200% zoom');
 }
 await settings.evaluate(()=>chrome.settingsPrivate.setDefaultZoom(1));await settings.close();
 await reopen();assert.equal(await count.innerText(),'12 technologies selected');assert.equal(await monitorPHP.isChecked(),true);
 // Advance the saved revision from a second client while the first editor has unsaved changes.
 await php.check();
 const newer=await fetcher('https://api.cveharbor.com/v1/technology-catalogue',{method:'PUT',body:JSON.stringify({defaults:['PHP'],products:[]})});
 assert.equal((await newer.json()).saved,true);
 await save.click();await waitStatus('Another tab saved a newer catalogue');
 assert.equal(await monitorPHP.isChecked(),true);assert.equal(await php.isChecked(),true);
 assert.deepEqual(stored().defaults,['PHP']);
 await reopen();
 for(const input of await choices.all())await input.uncheck();
 await page.locator('#technologyCustomizer').getByLabel('Windows Server OS',{exact:true}).check();await page.locator('#technologyCustomizer').getByLabel('.NET Core',{exact:true}).check();
 await page.locator('#technologySaveButton').click();
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE.products.length===2&&!window.CVEHARBOR_CVIE.loading);
 assert.deepEqual((await page.locator('.technology-row-name').allTextContents()).sort(),['.NET Core','Windows Server OS']);
 // Product details are lazy: open the visible disclosure before inspecting rows.
 if(await page.locator('#technologyManageClose').isVisible())await page.locator('#technologyManageClose').click();
 const scanDetails=page.locator('#cvieExplorer .cvie-scan-details');
 if(!await scanDetails.evaluate(el=>el.open))await scanDetails.locator('summary').first().click();
 await page.waitForFunction(()=>document.querySelectorAll('#cvieExplorer .cvie-product-status').length===2);
 assert.deepEqual((await page.locator('#cvieExplorer .cvie-product-status > strong').allTextContents()).sort(),['.NET Core','Windows Server OS']);
 // A topic opens the public feed with one click even before a Windows edition is chosen.
 await page.getByRole('button',{name:'Windows Server OS',exact:true}).click();
 const topics=page.getByRole('region',{name:'My catalogue'});
 await topics.waitFor({state:'visible'});
 assert.equal(await topics.getByLabel('Technology',{exact:true}).inputValue(),'windows-server-os');
 assert.equal(await page.locator('.cvie-identity-dialog[open]').count(),0);
 // Verify both advisory entry points open the same editable assignment preview.
 for(const [scope,selector] of [['scopePublic','#publicAdvisories'],['scopeCatalogue','#catalogueAdvisories']]){
  await page.locator('#'+scope).click();
  if(scope==='scopePublic')await page.locator('#listViewBtn').click();
  const row=page.locator(selector+' tbody tr').first();
  const id=await row.locator('.table-cve button').innerText();
  await row.locator(scope==='scopePublic'?'.table-cve button':'.table-description button').click();
  await page.locator('#detailDialog').getByRole('button',{name:'Assign vulnerability by email'}).click();
  await page.locator('#remediationAssignDialog').waitFor({state:'visible'});
  assert.equal(await page.locator('#remediationAssignCve').inputValue(),id);
  for(const section of ['extraOptions','deliveryRules'])assert.ok(await page.locator('#'+section).evaluate(el=>el.open));
  await page.locator('#closeRemediationAssign').click();
 }
 const query=topics.getByRole('searchbox');
 await query.fill('Topic fixture');assert.equal(await topics.locator('tbody tr').count(),50);
 await topics.getByRole('button',{name:'Next 50'}).click();assert.equal(await topics.locator('tbody tr').count(),1);
 await topics.getByLabel('Technology',{exact:true}).selectOption('');assert.equal(await topics.locator('tbody tr').count(),50);
 await topics.getByLabel('Published',{exact:true}).selectOption('12');
 await topics.getByRole('button',{name:'Next 50'}).click();assert.equal(await topics.locator('tbody tr').count(),2);
 await topics.getByLabel('Published',{exact:true}).selectOption('older');
 assert.equal(await topics.locator('tbody tr').count(),1);assert.match(await topics.locator('tbody tr').innerText(),/CVE-2099-40052/);
 await topics.getByLabel('Published',{exact:true}).selectOption('3');await query.fill('');
 // Actual API chooser and card removal, with synthetic provider-directory records.
 if(fs.existsSync(path.join(assetRoot,'technology-version-picker.mjs'))){
  if(await page.locator('#technologyManageClose').isVisible())await page.locator('#technologyManageClose').click();
  const saved=await (await fetcher('https://api.cveharbor.com/v1/technology-catalogue')).json();
  const picker=page.locator('.version-picker[open]');
  await page.getByRole('button',{name:'Check installed version for Windows Server OS',exact:true}).click();
  await picker.getByLabel('Release',{exact:true}).waitFor();
  assert.equal(await picker.getByLabel('Release',{exact:true}).locator('option').count(),12);
  await picker.getByLabel('Release',{exact:true}).selectOption('manual');
  await picker.getByLabel('Installed version',{exact:true}).fill('wrong');
  await picker.getByText('Save and scan last 3 months').click();
  assert.match(await picker.innerText(),/20348\.2849/);assert.equal(scanRequests.length,0);
  await picker.getByLabel('Installed version',{exact:true}).fill('20348.2849');
  await picker.getByText('Save and scan last 3 months').click();
  await picker.getByText('Find more vulnerabilities · last 12 months').waitFor({state:'visible'});
  assert.deepEqual(scanRequests.map(r=>r.months),['3']);
  await picker.getByRole('button',{name:/CVE-2099-98011/}).click();
  const scanDetail=page.locator('#detailDialog[open]');
  await scanDetail.getByRole('heading',{name:'Synthetic scanned advisory'}).waitFor();
  assert.ok(await scanDetail.getByText('Full synthetic description',{exact:true}).isVisible());
  assert.equal(await scanDetail.getByRole('link',{name:'Vendor bulletin'}).getAttribute('href'),'https://example.org/advisory');
  await page.keyboard.press('Escape');
  assert.ok(await picker.isVisible());
  await picker.getByText('Find more vulnerabilities · last 12 months').click();
  await picker.getByText(/in the last 12 months/).waitFor();
  assert.deepEqual(scanRequests.map(r=>r.quarter),['0','1','2','3']);
  const changed=await (await fetcher('https://api.cveharbor.com/v1/technology-catalogue')).json();
  assert.equal(changed.products.find(p=>p.name==='Windows Server').version,'20348.2849');
  await picker.getByRole('button',{name:'Close',exact:true}).click();
  await fetcher('https://api.cveharbor.com/v1/technology-catalogue',{method:'PUT',body:JSON.stringify({...saved,revision:changed.revision})});
  await reopen();
 }else{
 const family=name=>'cpe:2.3:o:microsoft:'+name+':*:*:*:*:*:*:*:*';
 const options=identityCandidates({products:['windows_server_2025','windows_server_2022','windows_server_2019'].map(name=>({cpe:{cpeName:family(name)}}))},{name:'Windows Server OS'});
 // Start with zero stored candidates and a busy provider budget, matching the production failure.
 env.DB.sql.prepare("UPDATE cvie_products SET status='queued',candidates_json='[]',cursor_json='{}' WHERE name='Windows Server OS'").run();
 env.CVIE_SHARED_SCANS_ENABLED='true';env.NVD_API_KEY='synthetic-key';
 env.DB.sql.prepare('UPDATE cvie_provider_budget SET next_request_at=?').run(Date.now()+500);
 let directoryCalls=0;
 globalThis.fetch=async url=>{const u=new URL(url);assert.ok(u.pathname.includes('/cpes/'),'chooser must not request vulnerability history');directoryCalls++;return Response.json({startIndex:0,totalResults:3,products:options.map(p=>({cpe:{cpeName:p.cpe}}))})};
 await page.evaluate(()=>window.CVEHARBOR_CVIE.refresh());
 await page.locator('.technology-row').filter({hasText:'Windows Server OS'}).getByRole('button',{name:'Refine for my environment',exact:true}).click();
 await page.getByRole('searchbox',{name:'Search product identities'}).fill('windows server 2019');
 await page.waitForSelector('.cvie-identity-options input');
 assert.equal(directoryCalls,1);assert.match(await page.locator('.cvie-identity-options').innerText(),/2019/);
 await page.getByRole('searchbox',{name:'Search product identities'}).fill('');
 env.DB.sql.exec('UPDATE cvie_provider_budget SET next_request_at=9999999999999');
 assert.equal(await page.locator('.cvie-identity-options input').count(),3);
 await page.getByRole('searchbox',{name:'Search product identities'}).fill('2025');assert.equal(await page.locator('.cvie-identity-options input').count(),1);
 await page.locator('.cvie-identity-options input').check();
 await page.screenshot({path:directory+'/identity-dialog.png'});
 await page.getByRole('button',{name:'Use selected product',exact:true}).click();await page.waitForFunction(()=>!document.querySelector('.cvie-identity-dialog').open);
 assert.equal(env.DB.sql.prepare("SELECT cpe FROM cvie_products WHERE name='Windows Server OS'").get().cpe,family('windows_server_2025'));
 await page.waitForFunction(()=>!window.CVEHARBOR_CVIE.loading&&window.CVEHARBOR_CVIE.product('Windows Server OS')?.cpe);
 }
 const remove=page.getByRole('button',{name:'Remove Windows Server OS from my catalogue',exact:true});
 await remove.focus();assert.equal(await remove.evaluate(el=>getComputedStyle(el).opacity),'1');
 failSave=true;await remove.click();await page.waitForFunction(()=>document.getElementById('technologyActionStatus').textContent.includes('Unable to save'));assert.equal(await page.locator('.technology-row').count(),2);failSave=false;
 for(const width of [390,768,1440]){await page.setViewportSize({width,height:1050});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));await page.screenshot({path:directory+'/two-products-'+width+'.png',fullPage:true})}
 await page.locator('.technology-add-details summary').click();
 await page.locator('#technologyAddName').fill('Maria DB');await page.locator('#technologyAddVersion').fill('10.6.28');await page.getByRole('button',{name:'Add and scan product',exact:true}).click();
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE.products.length===3&&!window.CVEHARBOR_CVIE.loading);
 await page.getByRole('button',{name:'Remove Maria DB from my catalogue',exact:true}).focus();await page.getByRole('button',{name:'Remove Maria DB from my catalogue',exact:true}).click();
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE.products.length===2&&!window.CVEHARBOR_CVIE.loading);
 assert.equal(JSON.parse(env.DB.sql.prepare("SELECT preferences_json FROM user_technology_catalogue WHERE user_id='a'").get().preferences_json).products.find(p=>p.name==='Maria DB').enabled,false);
 assert.equal(env.DB.sql.prepare('SELECT count(*) n FROM inventory_assets').get().n,1);
 await page.reload();await page.waitForFunction(()=>window.CVEHARBOR_CVIE.products.length===2&&!window.CVEHARBOR_CVIE.loading);
 assert.equal(await page.locator('.technology-row').count(),2);
 await page.getByRole('button',{name:'Remove Windows Server OS from my catalogue',exact:true}).focus();await page.getByRole('button',{name:'Remove Windows Server OS from my catalogue',exact:true}).click();await page.locator('#technologyManageButton').click();
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE.products.length===1&&!window.CVEHARBOR_CVIE.loading);
 await page.locator('#technologyCustomizer').getByLabel('WordPress / Plugins',{exact:true}).check();await page.locator('#technologySaveButton').click();await page.waitForFunction(()=>window.CVEHARBOR_CVIE.products.length===2&&!window.CVEHARBOR_CVIE.loading);
 failSave=true;await page.locator('#technologyCustomizer').getByLabel('.NET Core',{exact:true}).uncheck();await page.locator('#technologySaveButton').click();await page.waitForFunction(()=>document.getElementById('technologyCustomizeStatus').textContent.includes('Unable to save'));assert.equal(await page.locator('.technology-row').count(),2);failSave=false;
 for(const input of await choices.all())await input.uncheck();await page.locator('#technologySaveButton').click();await page.waitForFunction(()=>!window.CVEHARBOR_CVIE.products.length&&!window.CVEHARBOR_CVIE.loading);
 assert.equal(await page.locator('.technology-row').count(),0);assert.match(await page.locator('#technologyEmpty').innerText(),/No technologies selected/);
 const mixedProducts=[{name:'Maria DB',version:'10.6.28-24',enabled:false},{name:'PHP',version:'8.4.26',enabled:true}];
 const seed=await fetcher('https://api.cveharbor.com/v1/technology-catalogue',{method:'PUT',body:JSON.stringify({defaults:['Linux'],products:mixedProducts})});
 assert.equal((await seed.json()).saved,true);
 await reopen();
 await editor.getByRole('button',{name:'Select all',exact:true}).click();
 for(const fault of ['before','after']){
  if(fault==='after')await php.uncheck();
  const expected=await checkedNames();
  const writesBefore=puts();
  saveFault=fault;
  await save.click();
  await page.waitForFunction(()=>!document.querySelector('#technologySaveButton').disabled);
  assert.match(await status.innerText(),/Catalogue saved/);
  assert.equal(puts()-writesBefore,fault==='before'?2:1);
  await reopen();
  assert.deepEqual(await checkedNames(),expected);
  assert.deepEqual(stored().products,mixedProducts.map(p=>({...p,enabled:true})));
 }
 await php.check();
 const beforeConflict=puts();
 saveFault='concurrent';
 await save.click();await waitStatus('Another tab saved a newer catalogue');
 assert.equal(puts()-beforeConflict,2,'only the test edit and the concurrent edit sent a PUT');
 assert.deepEqual(stored().defaults,['Fortinet']);
 assert.equal(await php.isChecked(),true);
 const manage=page.locator('#technologyManageButton'),dialog=page.locator('#technologySignInDialog');
 const actionStatus=page.locator('#technologyActionStatus');
 interruptedReads=1;
 await page.evaluate(()=>window.CVEHARBOR_CVIE.refresh());
 assert.equal(interruptedReads,0);
 assert.equal(await page.evaluate(()=>window.CVEHARBOR_CVIE.historyLoaded),true);
 assert.doesNotMatch(await page.locator('#cvieExplorer .cvie-status').innerText(),/interrupted|failed to fetch/i);
 const beforeNavigation=seen.filter(r=>r.path.startsWith('/v1/cvie')).length;
 await page.goto('http://127.0.0.1:8080/threats/');
 assert.equal(seen.filter(r=>r.path.startsWith('/v1/cvie')).length,beforeNavigation,'public navigation must not start private scans');
 let releaseSession;
 sessionGate=new Promise(resolve=>{releaseSession=resolve});
 await page.goBack({waitUntil:'domcontentloaded'});
 await manage.click();
 assert.equal(await dialog.isVisible(),false,'checking the session must not prompt for login');
 assert.equal(await page.locator('#headerAccountActions').getByText('Log In',{exact:true}).count(),0);
 assert.equal(await editor.isVisible(),false,'wait for the stored revision');
 releaseSession();sessionGate=null;
 await editor.waitFor({state:'visible'});
 assert.deepEqual(await checkedNames(),['Fortinet']);
 await page.locator('#headerAccountActions').getByText('My Workspace',{exact:true}).waitFor();
 await page.locator('#technologyManageClose').click();
 for(const failure of ['session','catalogue']){
  sessionUnavailable=failure==='session';catalogueUnavailable=failure==='catalogue';
  await manage.click();await actionStatus.getByText(/Reconnecting automatically/).waitFor();
  assert.equal(await editor.isVisible(),false);assert.equal(await dialog.isVisible(),false);
  sessionUnavailable=false;catalogueUnavailable=false;
  await editor.waitFor({state:'visible'});
  assert.deepEqual(await checkedNames(),['Fortinet']);
  await page.locator('#technologyManageClose').click();
 }
 transientSessions=1;transientCatalogues=1;
 await manage.click();await editor.waitFor({state:'visible'});
 assert.deepEqual(await checkedNames(),['Fortinet']);
 await page.goto('http://127.0.0.1:8080/threats/');
 sessionUnavailable=true;
 await page.goto('http://127.0.0.1:8080/account/');
 await page.locator('#accountSecurityStatus').getByText(/Reconnecting automatically/).waitFor();
 sessionUnavailable=false;
 await page.locator('#accountSecurityDashboard').waitFor({state:'visible'});
 assert.equal(await page.locator('#accountSecurityEmail').innerText(),'a@example.test');
 sessionUnavailable=true;
 await page.goto('http://127.0.0.1:8080/workspace/');
 const guestForm=page.locator('#accountPageSignedOut'),loginTitle=page.locator('#accountFormTitle');
 assert.equal(await guestForm.isVisible(),false);assert.equal(await loginTitle.isVisible(),false);
 await page.locator('#accountSessionRetry').waitFor({state:'visible'});
 assert.equal(await guestForm.isVisible(),false);assert.equal(await loginTitle.isVisible(),false);
 sessionUnavailable=false;transientSessions=1;
 // Wait for the workspace to reconnect on its own after the sustained outage clears.
 await page.waitForFunction(()=>document.body.classList.contains('workspace-authenticated'));
 assert.equal(await guestForm.isVisible(),false);assert.equal(await loginTitle.isVisible(),false);
 signedIn=false;await page.reload();
 await guestForm.waitFor({state:'visible'});assert.equal(await loginTitle.isVisible(),true);
 const fixtureEmail='a@example.test';
 let authenticatorPosts=0;
 await page.route('**/v1/auth/request',route=>route.fulfill({json:{challenge_id:'fixture',salt:'fixture'}}));
 await page.route('**/v1/auth/verify',route=>route.fulfill({json:{mfa_required:true,mfa_challenge:'fixture-mfa'}}));
 await page.route('**/v1/auth/totp/verify',async route=>{
  authenticatorPosts++;signedIn=true;await route.abort('connectionreset');
 });
 await page.locator('#accountPageEmail').fill(fixtureEmail);
 await page.locator('#accountPageSend').click();
 await page.locator('#accountPageCode').fill('123456');
 await page.locator('#accountPageConfirm').click();
 await page.locator('#accountPageTotpCode').waitFor({state:'visible'});
 assert.equal(await loginTitle.innerText(),'Verify your authenticator');
 assert.equal(await page.locator('#accountPageRetryMessage').isVisible(),false);
 await page.locator('#accountPageTotpCode').fill('234567');
 await page.locator('#accountPageTotpVerify button[type=submit]').click();
 await page.waitForFunction(()=>document.body.classList.contains('workspace-authenticated'));
 assert.equal(authenticatorPosts,1);
 assert.equal(await page.locator('#accountPageIdentity').textContent(),'Signed in as '+fixtureEmail);
 signedIn=false;
 await page.goto('http://127.0.0.1:8080/vulnerabilities/');
 await manage.click();await dialog.waitFor({state:'visible'});
 assert.equal(await editor.isVisible(),false);
 assert.deepEqual(errors,[]);console.log('PASS Chromium catalogue selection, persisted refresh, removal, adding, failure, empty scope and responsive layout');
}finally{await context.close();env.DB.sql.close()}
