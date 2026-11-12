import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
const require=createRequire(new URL('../staging/package.json',import.meta.url)),{chromium}=require('playwright-core');
const root=path.resolve(process.env.INVENTORY_TEST_SITE||'.'),screens=path.resolve(process.env.INVENTORY_SCREENSHOTS||'verification/screens');await fs.mkdir(screens,{recursive:true});
const html=await fs.readFile(path.join(root,'index.html'),'utf8');
const section=html.match(/<section id="inventoryWorkspace"[\s\S]*?<\/section>/)?.[0];assert.ok(section,'Actual inventory markup required');
const network={version:1,collected_at:'2026-01-01T00:00:00Z',adapters:[{id:'lan',name:'Fictional LAN',status:'Up',addresses:[{ip:'192.0.2.10',prefix:24,state:'Preferred'}]}],suggested:{adapter_id:'lan',ip:'192.0.2.10'}};
const rows=Array.from({length:300},(_,i)=>['DEMO-WEB01','Server','Fictional Software '+i,'1.0','Server role: Web; '+'F'.repeat(450),i===0?JSON.stringify(network):''].map(v=>'"'+v.replaceAll('"','""')+'"').join(','));
const csv='Asset Name,Asset Type,Technology,Version,Notes,Server Network\r\n'+rows.join('\r\n');assert.ok(Buffer.byteLength(csv)>131072);
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
try{for(const width of [1440,768,390]){
 const context=await browser.newContext({viewport:{width,height:950}}),page=await context.newPage(),errors=[],writes=[],snapshots=[];let fail=width===1440;
 const data={customers:[{id:'demo',name:'Northstar Demo'},{id:'other',name:'Another Fictional Customer'}],environments:[{id:'prod',customer_id:'demo',name:'Production',kind:'Production'},{id:'qa',customer_id:'demo',name:'QA',kind:'QA'},{id:'other-env',customer_id:'other',name:'Other environment',kind:'QA'}],assets:[]};
 page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.hostname==='api.cveharbor.com'){
   assert.ok(!url.pathname.includes('/ai/'),'No AI requests permitted');let result,status=200;
   if(url.pathname==='/v1/inventory/status')result={ready:true};
   else if(url.pathname==='/v1/inventory'&&req.method()==='GET')result=data;
   else if(url.pathname==='/v1/plugin-sources')result={ready:true,sources:[]};
   else if(url.pathname==='/v1/inventory/assets'&&req.method()==='POST'){
    const item=req.postDataJSON();assert.equal(item.environment_id,'qa');
    if(fail&&writes.length===30){fail=false;status=503;result={error:'Fictional interruption'};}
    else{assert.ok(!data.assets.some(a=>a.technology===item.technology),'Duplicate write after retry');writes.push(item);const asset={...item,id:'a'+writes.length};data.assets.push(asset);result={id:asset.id};status=201;}
   }else if(url.pathname==='/v1/inventory/server-network'&&req.method()==='POST'){const item=req.postDataJSON();assert.equal(item.environment_id,'qa');snapshots.push(item);result={saved:true};}
   else{result={error:'Unexpected fictional route'};status=404;}
   return route.fulfill({status,contentType:'application/json',body:JSON.stringify(result),headers:{'Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true'}});
  }
  if(url.hostname!=='cveharbor.com')return route.abort();
  if(url.pathname==='/inventory-test/')return route.fulfill({contentType:'text/html',body:'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/styles.css"><link rel="stylesheet" href="/inventory-import.css"></head><body>'+section+'<script src="/asset-import.js"></script><script src="/inventory.js"></script><script>window.dispatchEvent(new CustomEvent("cveharbor:account-state",{detail:{authenticated:true}}))</script></body></html>'});
  const full=path.resolve(root,'.'+url.pathname);assert.ok(full.startsWith(root+path.sep));try{return route.fulfill({body:await fs.readFile(full),contentType:({'.js':'text/javascript','.css':'text/css'})[path.extname(full)]||'application/octet-stream'});}catch{return route.fulfill({status:404,body:''});}
 });
 await page.goto('https://cveharbor.com/inventory-test/');await page.locator('.inventory-customer-toggle').first().waitFor();
 assert.equal(await page.locator('.inventory-customer-body:visible').count(),0);
 const first=page.locator('.inventory-customer').first(),toggle=first.locator('.inventory-customer-toggle');
 await toggle.focus();await page.keyboard.press('Enter');assert.equal(await toggle.getAttribute('aria-expanded'),'true');
 const boxes=await first.evaluate(card=>{const box=s=>{const r=card.querySelector(s).getBoundingClientRect();return {right:r.right,top:r.top,width:r.width};};return {ce:box('.inventory-customer-actions button:first-child'),cr:box('.inventory-customer-actions button:last-child'),ee:box('.inventory-record-actions button:first-child'),er:box('.inventory-record-actions button:last-child')};});
 assert.ok(Math.abs(boxes.ce.top-boxes.cr.top)<1&&Math.abs(boxes.ee.top-boxes.er.top)<1,'Paired action buttons align');assert.ok(Math.abs(boxes.cr.right-boxes.er.right)<2,'Customer/environment right edges align');
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),true,'Customer layout overflow '+width);
 await page.locator('#inventoryRecords').screenshot({path:path.join(screens,'customers-'+width+'.png')});
 await first.getByRole('button',{name:'Edit customer',exact:true}).click();await page.locator('#inventoryEnvironmentSelect').selectOption('qa');
 const panel=page.locator('.inventory-bulk-import');await panel.locator('input[type=file]').setInputFiles({name:'fictional-server.csv',mimeType:'text/csv',buffer:Buffer.from(csv)});
 await panel.getByText('300 distinct entries; 0 duplicate rows removed.').waitFor();assert.equal(await panel.locator('td').count(),500);
 await panel.getByRole('button',{name:'Next rows'}).click();await panel.getByText('Rows 101–200 of 300').waitFor();
 await panel.locator('input[type=checkbox]').check();await panel.getByRole('button',{name:'Import reviewed inventory',exact:true}).click();
 if(width===1440){await panel.getByText(/Fictional interruption/).waitFor();assert.equal(writes.length,30);await panel.locator('input[type=checkbox]').check();await panel.getByRole('button',{name:'Retry remaining inventory'}).click();}
 await panel.getByRole('link',{name:'Assess in Customer Security Dashboard'}).waitFor({timeout:60000});
 assert.equal(writes.length,300);assert.equal(snapshots.length,1);assert.equal(snapshots[0].snapshot.adapters[0].addresses[0].ip,'192.0.2.10');
 assert.equal(new URL(page.url()).pathname,'/inventory-test/');assert.equal(await page.locator('#inventoryCustomerSelect').inputValue(),'demo');assert.equal(await page.locator('#inventoryEnvironmentSelect').inputValue(),'qa');
 assert.equal(await first.locator('.inventory-customer-toggle').getAttribute('aria-expanded'),'true');assert.equal(await page.locator('.inventory-customer').nth(1).locator('.inventory-customer-toggle').getAttribute('aria-expanded'),'false');
 const link=new URL(await panel.getByRole('link',{name:'Assess in Customer Security Dashboard'}).getAttribute('href'),'https://cveharbor.com');assert.equal(link.searchParams.get('environment'),'qa');assert.equal(link.searchParams.get('customer'),'demo');
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),true,'Import layout overflow '+width);
 await panel.screenshot({path:path.join(screens,'complete-'+width+'.png')});assert.deepEqual(errors,[]);await context.close();
}console.log('PASS: single 300-row CSV above 128 KB, paged review, interruption/retry without duplicate writes, network snapshot, retained customer/QA, accessible collapsed customers and aligned actions at 1440/768/390; no AI.');}finally{await browser.close();}
