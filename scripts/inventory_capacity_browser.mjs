// Browser integration with actual paginated route and SQLite. All external
// traffic is intercepted; synthetic data only, no credentials or inference.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createRequire} from 'node:module';
import {capacityFixture,fixtureId} from '../account-backend/tests/helpers/capacity-db.mjs';
import {inventoryRoute} from '../account-backend/src/inventory.js';
import {securityFixture} from './customer_security_fixture.mjs';
const require=createRequire(new URL('../staging/package.json',import.meta.url));
const {chromium}=require('playwright-core'),root=path.resolve(process.env.INVENTORY_TEST_SITE||'.');
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
try{
 for(const width of [1440,390]){
  const env=capacityFixture({assets:10000}),fixture=securityFixture(),page=await browser.newPage({viewport:{width,height:1000}}),errors=[];let pages=0;
  env.sql.exec("UPDATE inventory_assets SET technology='PHP',version='8.4.1'");
  page.on('pageerror',error=>errors.push(error.message));
  await page.route('**/*',async route=>{
   const request=route.request(),url=new URL(request.url());
   if(url.hostname==='api.cveharbor.com'){
    await new Promise(resolve=>setTimeout(resolve,50));
    let result;
    if(url.pathname==='/v1/inventory/page'||url.pathname==='/v1/inventory/status'){
     if(url.pathname.endsWith('/page'))pages++;
     try{result=await inventoryRoute(new Request(url),env,{id:'owner-0'},url.pathname);}catch(error){result=new Response(JSON.stringify({error:error.message}),{status:error.status||500});}
    }else result=await fixture.request(url.href,{method:request.method(),body:request.postData()});
    return route.fulfill({status:result.status,headers:{'Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true'},json:await result.json()});
   }
   if(url.hostname!=='cveharbor.com')return route.abort();
   if(url.pathname==='/data.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_DATA='+JSON.stringify({advisories:fixture.advisories})});
   if(url.pathname==='/catalog.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_CATALOG={advisories:[]}'});
   const file=path.resolve(root,'.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));assert.ok(file.startsWith(root+path.sep));
   try{return route.fulfill({body:await fs.readFile(file),contentType:({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json'})[path.extname(file)]||'application/octet-stream'});}catch{return route.fulfill({status:404,body:''});}
  });
  try{
   const start=Date.now();await page.goto('https://cveharbor.com/customer-reports/?customer='+fixtureId(50));
   await page.waitForSelector('#customerDashStatus[data-ready="true"]',{timeout:120000});
   assert.match(await page.locator('.customer-finding-pages').first().textContent(),/of 400 filtered findings/);
   assert.equal(await page.locator('.customer-vulnerability-table tbody tr').count(),50);
   const ready=Date.now()-start,at=Date.now();await page.selectOption('#customerDashFilter',fixtureId(1));
   await page.waitForFunction(()=>document.querySelector('#customerDashStatus').dataset.assessing==='false');
   assert.match(await page.locator('.customer-finding-pages').first().textContent(),/of 400 filtered findings/);
   const selection=Date.now()-at;assert.ok(selection<1200);
   await page.getByRole('button',{name:'Next findings',exact:true}).click();
   await page.waitForFunction(()=>document.querySelector('.customer-finding-pages')?.textContent.includes('Showing 51–100'));
   await page.evaluate(ids=>{const select=document.querySelector('#customerDashFilter');for(const id of ids){select.value=id;select.dispatchEvent(new Event('change'));}},[fixtureId(50),fixtureId(2),fixtureId(1)]);
   await page.waitForFunction(()=>document.querySelector('#customerDashStatus').dataset.assessing==='false'&&document.querySelector('.customer-finding-pages'));
   assert.equal(await page.locator('#customerDashFilter').inputValue(),fixtureId(1));
   await page.evaluate(()=>{URL.createObjectURL=blob=>{blob.text().then(text=>window.capacityCsv=text);return 'blob:fixture';};URL.revokeObjectURL=()=>{};HTMLAnchorElement.prototype.click=()=>{};});
   await page.locator('#customerReportCsv').click();await page.waitForFunction(()=>window.capacityCsv);
   const csv=await page.evaluate(()=>window.capacityCsv);assert.equal(csv.trim().split('\r\n').length,401);assert.match(csv,/Customer 0/);assert.doesNotMatch(csv,/Customer 49/);
   fixture.setAuthenticated(false);await page.evaluate(()=>window.dispatchEvent(new Event('focus')));await page.waitForFunction(()=>document.querySelector('#customerDashAccess').hidden);assert.equal(await page.locator('.customer-vulnerability-table').count(),0);
   assert.deepEqual(errors,[]);console.log(JSON.stringify({width,customers:50,environments:100,software_entries:10000,page_requests:pages,ready_ms:ready,selection_ms:selection,errors}));
  }finally{await page.close();env.close();}
 }
}finally{await browser.close();}
