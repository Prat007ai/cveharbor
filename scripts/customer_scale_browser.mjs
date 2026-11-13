// Capacity fixture only: no real accounts, network traffic, or paid AI.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createRequire} from 'node:module';
import {securityFixture} from './customer_security_fixture.mjs';
const require=createRequire(new URL('../staging/package.json',import.meta.url));
const {chromium}=require('playwright-core');
const root=path.resolve(process.env.INVENTORY_TEST_SITE||'public');
const strict=process.env.SCALE_BASELINE!=='true';
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
try{
 for(const width of [1440,390])for(const section of (process.env.SCALE_ROUTES||'customer-dashboard,customer-reports,environments').split(',')){
  const fixture=securityFixture();
  fixture.inventory.customers=Array.from({length:50},(_,i)=>({id:'c'+i,name:'Fictional customer '+String(i).padStart(2,'0')}));
  fixture.inventory.environments=Array.from({length:100},(_,i)=>({id:'e'+i,customer_id:'c'+Math.floor(i/2),name:'Environment '+i,kind:'Production'}));
  fixture.inventory.assets=Array.from({length:10000},(_,i)=>({id:'a'+i,environment_id:'e'+Math.floor(i/100),name:'HOST-'+Math.floor(i/5),asset_type:'Server',technology:i%5===0?'PHP':'Fictional product '+(i%40),version:'8.4.1',notes:'Synthetic scale test'}));
  fixture.advisories.push(...Array.from({length:4998},(_,i)=>({id:'CVE-2026-'+(100000+i),categories:[i<40?'PHP':'Unrelated product'],affected:i<40?'PHP before 8.4.2':'Unrelated product before 2.0',severity:'high',summary:'Fictional advisory',sources:[{url:'https://example.test/'+i,label:'Fixture'}]})));
  const page=await browser.newPage({viewport:{width,height:1000}}),errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.addInitScript(()=>{
   window.scaleTasks=[];new PerformanceObserver(list=>window.scaleTasks.push(...list.getEntries().map(x=>({start:x.startTime,duration:x.duration})))).observe({type:'longtask',buffered:true});
  });
  await page.route('**/*',async route=>{
   const request=route.request(),url=new URL(request.url());
   if(url.hostname==='api.cveharbor.com'){
    assert.ok(request.method()==='GET'||url.pathname==='/v1/cvie/sync','No external writes');
    await new Promise(resolve=>setTimeout(resolve,100));
    const result=await fixture.request(url.href,{method:request.method(),body:request.postData()});
    return route.fulfill({status:result.status,headers:{'Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true'},json:await result.json()});
   }
   if(url.hostname!=='cveharbor.com')return route.abort();
   if(url.pathname==='/data.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_DATA='+JSON.stringify({advisories:fixture.advisories})});
   if(url.pathname==='/catalog.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_CATALOG={advisories:[]}'});
   const file=path.resolve(root,'.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));assert.ok(file.startsWith(root+path.sep));
   try{const bytes=await fs.readFile(file).catch(()=>fs.readFile(path.join(root,'public',path.relative(root,file))));return route.fulfill({body:bytes,contentType:({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.mjs':'text/javascript'})[path.extname(file)]||'application/octet-stream'});}catch{return route.fulfill({status:404,body:''});}
  });
  const start=Date.now();await page.goto('https://cveharbor.com/'+section+'/');
  const selector=section==='environments'?'#inventoryMatchCustomer':'#customerDashFilter';
  await page.waitForFunction(selector=>document.querySelector(selector)?.options.length===51,selector,{timeout:120000});
  if(section!=='environments')await page.waitForSelector('#customerDashStatus[data-ready="true"]',{timeout:120000});
  else await page.waitForFunction(()=>!document.querySelector('#inventoryMatchCount').textContent.includes('Checking'),null,{timeout:120000});
  await page.waitForFunction(()=>document.querySelector('#customerDashStatus')?.dataset.assessing!=='true');
  const readyMs=Date.now()-start;
  const before=await page.evaluate(()=>({nodes:document.querySelectorAll('*').length,maxTaskMs:Math.max(0,...window.scaleTasks.map(x=>x.duration))}));
  const selectionStart=Date.now();await page.selectOption(selector,'c49');
  if(section==='environments')await page.waitForFunction(()=>!document.querySelector('#inventoryMatchCount').textContent.includes('Checking'));
  else await page.waitForFunction(()=>document.querySelector('#customerDashStatus').dataset.assessing!=='true');
  const selectionMs=Date.now()-selectionStart;
  const reads=fixture.seen.filter(x=>x.path==='inventory').length;
  await page.evaluate(()=>{for(let i=0;i<5;i++)window.dispatchEvent(new Event('focus'));});
  await page.waitForTimeout(800);
  const extraFocusReads=fixture.seen.filter(x=>x.path==='inventory').length-reads;
  const after=await page.evaluate(()=>({maxTaskMs:Math.max(0,...window.scaleTasks.map(x=>x.duration)),finalNodes:document.querySelectorAll('*').length}));
  const result={section,width,customers:50,environments:100,hosts:2000,softwareEntries:10000,advisories:5000,readyMs,selectionMs,...before,...after,extraFocusReads,errors};
  console.log(JSON.stringify(result));
  assert.deepEqual(errors,[]);
  if(strict){assert.ok(before.nodes<16000,JSON.stringify(result));assert.ok(selectionMs<1200,JSON.stringify(result));assert.equal(extraFocusReads,0);assert.ok(after.maxTaskMs<300,JSON.stringify(result));}
  if(section!=='environments'){
   const settled=()=>page.waitForFunction(()=>document.querySelector('#customerDashStatus').dataset.assessing==='false');
   if(section==='customer-dashboard')await page.locator('#customerFindingsSection > summary').click();
   const table=page.locator('.customer-vulnerability-table').first();
   assert.equal(await table.locator('tbody tr').count(),50,'Only the visible finding page is mounted');
   assert.match(await page.locator('.customer-finding-pages').first().textContent(),/of 1680 filtered findings/,'All matches remain counted');
   assert.match(await table.textContent(),/HOST-19[6-9]\d/);assert.doesNotMatch(await table.textContent(),/HOST-0\b/);
   const first=await table.locator('tbody tr').first().textContent();
   await page.getByRole('button',{name:'Next findings',exact:true}).click();await settled();
   assert.notEqual(await table.locator('tbody tr').first().textContent(),first);
   assert.match(await page.locator('.customer-finding-pages').first().textContent(),/Showing 51–100 of 1680/);
   // Changing selection while work is yielded must never finish in the old scope.
   await page.evaluate(()=>{const select=document.querySelector('#customerDashFilter');for(const id of ['c1','c49','c0']){select.value=id;select.dispatchEvent(new Event('change'));}});await settled();
   assert.equal(await page.locator('#customerDashFilter').inputValue(),'c0');assert.doesNotMatch(await table.textContent(),/HOST-19[6-9]\d/);
   if(section==='customer-reports'){
    await page.evaluate(()=>{URL.createObjectURL=blob=>{blob.text().then(value=>window.scaleCsv=value);return 'blob:fixture';};URL.revokeObjectURL=()=>{};HTMLAnchorElement.prototype.click=()=>{};});
    await page.locator('#customerReportCsv').click();await page.waitForFunction(()=>window.scaleCsv);const csv=await page.evaluate(()=>window.scaleCsv);
    assert.equal(csv.trim().split('\r\n').length,1681,'CSV includes every available filtered finding, across all UI pages');
    assert.match(csv,/Fictional customer 00/);assert.doesNotMatch(csv,/Fictional customer 49/);
   }
   // An explicit save notice must bypass the refresh window, even during a focus check.
   fixture.inventory.assets.push({id:'new-entry',environment_id:'e0',name:'NEW-SAVED-HOST',asset_type:'Server',technology:'PHP',version:'8.4.1'});
   const beforeChange=fixture.seen.filter(x=>x.path==='inventory').length;
   await page.evaluate(()=>{window.dispatchEvent(new Event('focus'));const channel=new BroadcastChannel('cveharbor-inventory-changed');channel.postMessage({changed:true});setTimeout(()=>channel.close(),100);});
   await page.waitForFunction(()=>document.querySelector('.customer-finding-pages')?.textContent.includes('of 1722 filtered findings'),null,{timeout:20000});await settled();
   assert.ok(fixture.seen.filter(x=>x.path==='inventory').length>beforeChange,'Explicit saves refresh inventory');
   fixture.setAuthenticated(false);await page.evaluate(()=>window.dispatchEvent(new Event('focus')));
   await page.waitForFunction(()=>document.querySelector('#customerDashAccess').hidden);
   assert.equal(await page.locator('.customer-vulnerability-table').count(),0,'Expired authorization removes private results');
  }
  if(section==='environments'){
   await page.locator('[aria-controls="inventory-customer-c49"]').click();
   const customer=page.locator('#inventory-customer-c49');assert.equal(await customer.locator('.inventory-asset-group').count(),20,'Only ten hosts per environment are mounted');
   await customer.getByRole('button',{name:'Next assets in Environment 98',exact:true}).click();
   assert.match(await customer.textContent(),/HOST-1979/);assert.doesNotMatch(await customer.textContent(),/HOST-1960\b/);
   assert.equal(await customer.locator('.inventory-asset-group').count(),20);
   assert.equal(await page.locator('#inventoryAssetCount').textContent(),'10000','Pagination does not reduce saved inventory count');
  }
  assert.deepEqual(errors,[]);await page.close();
 }
}finally{await browser.close();}
