import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
const require=createRequire(new URL('../staging/package.json',import.meta.url));
const {chromium}=require('playwright-core');
const root=path.resolve(process.env.INVENTORY_TEST_SITE||'.');
const screens=path.resolve(process.env.INVENTORY_SCREENSHOTS||'verification/action-screens');await fs.mkdir(screens,{recursive:true});
const html=await fs.readFile(path.join(root,'index.html'),'utf8');
const section=html.match(/<section id="inventoryWorkspace"[\s\S]*?<\/section>/)?.[0];assert.ok(section);
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
try{for(const width of [1440,768,390]){
 const context=await browser.newContext({viewport:{width,height:950}}),page=await context.newPage();
 const errors=[];let deletes=0,hold=null,fail=false;
 const data={customers:[{id:'demo',name:'Fictional Click Test'}],environments:[{id:'qa',customer_id:'demo',name:'QA',kind:'QA'}],assets:[]};
 page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.hostname==='api.cveharbor.com'){
   assert.ok(!url.pathname.includes('/ai/'));let result={},status=200;
   if(req.method()==='DELETE'){
    assert.equal(url.pathname,'/v1/inventory/customers/demo');deletes++;
    await new Promise(resolve=>{hold=resolve;});
    if(fail){status=503;result={error:'Fictional service interruption'};}else{data.customers=[];data.environments=[];result={deleted:true};}
   }else if(url.pathname==='/v1/inventory/status')result={ready:true};
   else if(url.pathname==='/v1/inventory')result=data;
   else if(url.pathname==='/v1/plugin-sources')result={ready:true,sources:[]};
   else throw Error('Unexpected API request '+req.method()+' '+url.pathname);
   return route.fulfill({status,contentType:'application/json',body:JSON.stringify(result)});
  }
  if(url.hostname!=='cveharbor.com')return route.abort();
  if(url.pathname==='/action-test/')return route.fulfill({contentType:'text/html',body:'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/styles.css"></head><body>'+section+'<script src="/inventory.js"></script><script>window.dispatchEvent(new CustomEvent("cveharbor:account-state",{detail:{authenticated:true,email:"fictional@example.test"}}))</script></body></html>'});
  const file=path.resolve(root,'.'+url.pathname);assert.ok(file.startsWith(root+path.sep));return route.fulfill({body:await fs.readFile(url.pathname==='/inventory.js'&&process.env.INVENTORY_TEST_SCRIPT?process.env.INVENTORY_TEST_SCRIPT:file),contentType:url.pathname.endsWith('.js')?'text/javascript':'text/css'});
 });
 await page.goto('https://cveharbor.com/action-test/');
 const remove=page.getByRole('button',{name:'Remove customer',exact:true});await remove.waitFor();
 // Reinitializing a routed page must not register duplicate listeners.
 if(!process.env.INVENTORY_TEST_SCRIPT)await page.addScriptTag({url:'/inventory.js'});
 const toggle=page.locator('.inventory-customer-toggle');await toggle.click();assert.equal(await toggle.getAttribute('aria-expanded'),'true');
 await toggle.click();assert.equal(await toggle.getAttribute('aria-expanded'),'false');
 await page.getByRole('button',{name:'Edit customer',exact:true}).click();assert.equal(await page.locator('#inventoryCustomerSelect').inputValue(),'demo');
 // Repeated activation must not stack dialogs or send requests before confirmation.
 await remove.evaluate(b=>{for(let i=0;i<8;i++)b.click();});
 assert.equal(await page.getByRole('alertdialog').count(),1);assert.equal(deletes,0);
 await page.getByRole('button',{name:'Cancel',exact:true}).click();assert.equal(await page.getByRole('alertdialog').count(),0);assert.equal(deletes,0);
 await remove.click();await page.keyboard.press('Escape');assert.equal(await page.getByRole('alertdialog').count(),0);
 await remove.click();fail=true;
 await page.getByRole('button',{name:'Remove',exact:true}).evaluate(b=>{for(let i=0;i<8;i++)b.click();});
 await page.waitForFunction(()=>document.querySelector('.inventory-confirm-delete')?.textContent==='Removing…');
 for(let i=0;i<50&&!hold;i++)await page.waitForTimeout(100);assert.equal(deletes,1);assert.ok(hold);
 assert.equal(await page.getByRole('button',{name:'Removing…',exact:true}).isDisabled(),true);
 await page.keyboard.press('Escape');assert.equal(await page.getByRole('alertdialog').count(),1);
 await page.keyboard.press('Tab');assert.equal(await page.getByRole('alertdialog').evaluate(el=>el===document.activeElement),true);
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),true);
 await page.screenshot({path:path.join(screens,'removing-'+width+'.png')});
 hold();await page.getByText(/Removal could not be confirmed: Fictional/).waitFor();
 fail=false;hold=null;await page.getByRole('button',{name:'Retry removal'}).click();
 for(let i=0;i<50&&!hold;i++)await page.waitForTimeout(100);assert.equal(deletes,2);assert.ok(hold);hold();
 await page.getByText('Fictional Click Test removed from your private inventory.').waitFor();
 assert.equal(await page.getByRole('alertdialog').count(),0);assert.equal(await page.locator('.inventory-customer').count(),0);
 assert.deepEqual(errors,[]);await context.close();
}console.log('PASS: one-click expand/edit/cancel; repeated clicks produce one confirmation and one pending DELETE; visible progress, inline failure/retry and success at 1440/768/390. Fictional data only; no AI.');}finally{await browser.close();}
