import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
const require=createRequire(new URL('../staging/package.json',import.meta.url)),{chromium}=require('playwright-core');
const root=path.resolve(process.env.INVENTORY_TEST_SITE||'.'),screens=path.resolve(process.env.INVENTORY_SCREENSHOTS||'../evidence/inventory-screens');await fs.mkdir(screens,{recursive:true});
const csv='Asset Name,Asset Type,Technology,Version,Notes\nDEMO-WEB01,Server,.NET Runtime,8.0.1,Fictional\nDEMO-WEB01,Server,.NET Runtime,8.0.2,Fictional';
const advisory={id:'CVE-2099-12345',title:'Fictional runtime advisory',affected:'.NET Runtime before 8.0.3',severity:'high',sources:[{url:'https://example.test/advisory'}]};
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
try{for(const width of [1440,768,390]){
 const context=await browser.newContext({viewport:{width,height:950}}),page=await context.newPage(),errors=[],calls=[];let assets=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.hostname==='api.cveharbor.com'){
   calls.push(url.pathname);assert.ok(!url.pathname.includes('/ai/')||(url.pathname==='/v1/ai/capabilities'&&req.method()==='GET'),'AI inference or administration must not be called');
   let data,status=200;
   if(url.pathname==='/v1/team/organizations/north/customers')data={name:'Northstar Demo',role:'Editor',customers:[{id:'demo',name:'Fictional Customer'}]};
   else if(url.pathname==='/v1/team/organizations/north/customers/demo')data={customer:{name:'Fictional Customer',role:'Editor'},environments:[{id:'prod',name:'Fictional Production',kind:'Production'}],assets,findings:[],remediations:[],activity:[]};
   else if(url.pathname==='/v1/team/organizations/north/assets/demo'&&req.method()==='POST'){const row=req.postDataJSON();assert.equal(row.environment_id,'prod');assets.push({...row,id:'asset-'+assets.length,environment:'Fictional Production'});data={id:assets.at(-1).id};status=201;}
   else if(url.pathname==='/v1/me')data={authenticated:true,email:'demo@example.test'};
   else if(url.pathname==='/v1/ai/capabilities')data={platform_role:null,organizations:[]};
   else{data={error:'Fictional route not supported'};status=404;}
   return route.fulfill({status,contentType:'application/json',body:JSON.stringify(data),headers:{'Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true'}});
  }
  if(url.hostname!=='cveharbor.com')return route.abort();
  if(url.pathname==='/import-test/')return route.fulfill({contentType:'text/html',body:'<!doctype html><html><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/styles.css"><link rel="stylesheet" href="/team-access.css"><link rel="stylesheet" href="/inventory-import.css"><body class="account-page"><main class="shell"><p id="teamStatus" role="status"></p><section id="teamAccess"><div id="teamPanel"></div></section></main><script type="module">import {organizationDashboard} from "/team-workspace.js";await organizationDashboard("north","demo");</script></body></html>'});
  if(url.pathname==='/data.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_DATA='+JSON.stringify({advisories:[advisory]})});
  if(url.pathname==='/catalog.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_CATALOG={advisories:[]}'});
  let name=url.pathname;if(name.endsWith('/'))name+='index.html';const full=path.resolve(root,'.'+name);assert.ok(full.startsWith(root+path.sep));
  try{return await route.fulfill({body:await fs.readFile(full),contentType:({'.html':'text/html','.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.png':'image/png'})[path.extname(full)]||'application/octet-stream'});}catch{return route.fulfill({status:404,body:''});}
 });
 await page.goto('https://cveharbor.com/import-test/');
 try{await page.getByRole('button',{name:'Import server inventory',exact:true}).click({timeout:5000});}catch(e){console.log({errors,body:await page.locator('body').innerText(),calls});throw e;}
 try{await page.getByLabel('Environment',{exact:true}).selectOption('prod',{timeout:5000});}catch(e){console.log({errors,body:await page.locator('body').innerText(),calls});throw e;}
 await page.locator('input[type=file]').setInputFiles({name:'fictional.csv',mimeType:'text/csv',buffer:Buffer.from(csv)});
 await page.getByText('2 distinct entries; 0 duplicate rows removed.').waitFor();
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),true,'Import overflow '+width);
 await page.screenshot({path:path.join(screens,'import-'+width+'.png'),fullPage:true});
 await page.locator('input[type=checkbox]').check();await page.getByRole('button',{name:'Import reviewed inventory',exact:true}).click();
 await page.getByText(/2 entries imported; 0 existing entries skipped/).waitFor();assert.equal(new URL(page.url()).pathname,'/import-test/');assert.equal(await page.getByLabel('Environment',{exact:true}).inputValue(),'prod');
 await page.getByRole('link',{name:'Assess in Customer Security Dashboard'}).click();
 await page.waitForURL('**/customer-dashboard/**');await page.getByText('Vulnerability findings',{exact:true}).waitFor();
 assert.equal(assets.length,2);assert.match(await page.locator('.organization-security').innerText(),/CVE-2099-12345/);
 assert.equal(await page.locator('.organization-security > section > div:not(.server-security) tbody tr').count(),4);
 assert.ok(!calls.some(x=>x.startsWith('/v1/cvie')||x.startsWith('/v1/inventory')),'No private personal inventory in organization flow');
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),true,'Dashboard overflow '+width);
 await page.screenshot({path:path.join(screens,'findings-'+width+'.png'),fullPage:true});
 assert.deepEqual(errors,[]);await context.close();
}console.log('PASS: real browser CSV review, saved import, retained environment, explicit dashboard assessment and responsive layouts at 1440, 768 and 390px; fictional data, no AI.');}finally{await browser.close();}
