import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fixture,user,question,provider} from '../account-backend/tests/helpers/ai-db.mjs';
import {assist} from '../account-backend/src/ai-allowance.js';
import {aiRoute} from '../account-backend/src/ai-routes.js';
const require=createRequire(new URL('../staging/package.json',import.meta.url)),{chromium}=require('playwright-core');
const root=path.resolve(process.env.AI_TEST_SITE||'.'),screens=path.resolve(process.env.AI_TEST_SCREENSHOTS||'../evidence/organization-ai-screens');
await fs.mkdir(screens,{recursive:true});
const f=fixture();Date.now=()=>Date.parse('2026-11-11T18:00:00Z');
await assist(f.env,user('owner'),'north',question(),provider().fetcher);
await assist(f.env,user('staff'),'north',question('fictional-held-0001','customer-b'),provider({failInference:true}).fetcher);
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
try{
 for(const size of [{width:1440,height:1000},{width:768,height:1024},{width:390,height:844}]){
  const context=await browser.newContext({viewport:size}),page=await context.newPage(),errors=[];let actor='admin';
  page.on('pageerror',e=>errors.push(e.message));
  await page.route('https://api.cveharbor.com/**',async route=>{
   const incoming=route.request(),url=new URL(incoming.url());
   let payload,status=200;
   if(url.pathname==='/v1/team/organizations')payload={organizations:[{id:'north',name:'Northstar Demo',role:'Owner'}]};
   else if(url.pathname==='/v1/team/organizations/north/customers')payload={customers:[{id:'customer-a',name:'Fictional Customer A'},{id:'customer-b',name:'Fictional Customer B'}]};
   else try{
    const req=new Request(url,{method:incoming.method(),...(incoming.postData()?{body:incoming.postData()}:{})});
    const response=await aiRoute(req,f.env,user(actor),url.pathname,{response:(data,code=200)=>Response.json(data,{status:code}),body:r=>r.json(),limit:async()=>true});
    payload=await response.json();status=response.status;
   }catch(e){payload={error:e.message};status=e.status||500;}
   await route.fulfill({status,contentType:'application/json',headers:{'Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true'},body:JSON.stringify(payload)});
  });
  await page.route('https://cveharbor.com/**',async route=>{let file=new URL(route.request().url()).pathname;if(file.endsWith('/'))file+='index.html';const full=path.resolve(root,'.'+file);assert.ok(full.startsWith(root+path.sep));try{await route.fulfill({body:await fs.readFile(full),contentType:({'.js':'text/javascript','.css':'text/css','.html':'text/html'})[path.extname(file)]||'application/octet-stream'});}catch{await route.fulfill({status:404,body:''});}});
  await page.goto('https://cveharbor.com/admin/ai-usage/');await page.waitForSelector('#dashboard:not([hidden])');
  await page.locator('#month').fill('2026-11');await page.getByRole('button',{name:'Refresh usage',exact:true}).click();await page.waitForFunction(()=>document.querySelector('#status').textContent==='Usage refreshed.');
  assert.match(await page.locator('#table').innerText(),/Northstar Demo/);
  await page.screenshot({path:path.join(screens,'admin-'+size.width+'.png'),fullPage:true});
  await page.getByRole('tab',{name:'Staff consumption'}).click();await page.waitForFunction(()=>document.querySelector('#reportTitle').textContent==='Staff consumption');assert.match(await page.locator('#table').innerText(),/staff@example.test/);
  await page.getByRole('tab',{name:'Requests & holds'}).click();await page.waitForFunction(()=>document.querySelector('#reportTitle').textContent==='Requests & holds');assert.match(await page.locator('#table').innerText(),/held/);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),true,'Dashboard overflow '+size.width);
  actor='owner';await page.goto('https://cveharbor.com/admin/ai-usage/');await page.waitForFunction(()=>document.querySelector('#status').textContent.includes('only to CVEHarbor'));
  assert.equal(await page.locator('#dashboard').isVisible(),false);
  await page.goto('https://cveharbor.com/ai/?org=north');await page.waitForSelector('#assistance:not([hidden])');await page.waitForFunction(()=>document.querySelector('#status').textContent.startsWith('Ready.'));
  assert.equal(await page.locator('#customer option').count(),2);
  assert.match(await page.locator('#metrics').innerText(),/20.00/);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),true,'Assistance overflow '+size.width);
  await page.screenshot({path:path.join(screens,'assistance-'+size.width+'.png'),fullPage:true});
  assert.deepEqual(errors,[]);await context.close();
 }
 console.log('PASS: dashboard reports, unauthorized access, assistance and responsive layouts at 1440, 768 and 390px. Fictional data only.');
}finally{await browser.close();f.store.close();}
