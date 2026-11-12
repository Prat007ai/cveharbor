import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import {securityFixture} from './customer_security_fixture.mjs';
const require=createRequire(new URL('../staging/package.json',import.meta.url)),{chromium}=require('playwright-core');
const root=path.resolve(process.env.SERVER_TEST_SITE||'.'),screens=path.resolve(process.env.SERVER_SCREENSHOTS||'../evidence/server-security-screens');await fs.mkdir(screens,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
try{for(const org of [false,true])for(const width of [1440,768,390]){
 const f=securityFixture();f.inventory.assets=f.inventory.assets.filter(a=>a.technology==='PHP');
 f.inventory.assets[0].notes='Server role: Web; Fictional';f.inventory.assets[1].name='WEB01';f.inventory.assets[1].notes='Server role: Application; Fictional';
 f.inventory.assets.push({...f.inventory.assets[0],id:'a5',version:'8.4.0'}, {id:'a6',name:'DB01',environment_id:'e1',technology:'Unmapped Fictional Database',version:'1.0',asset_type:'Database'});
 const context=await browser.newContext({viewport:{width,height:950}}),page=await context.newPage(),errors=[],calls=[];let revoked=false;
 page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.hostname==='api.cveharbor.com'){
   calls.push(url.pathname);assert.ok(!url.pathname.includes('/ai/')||(url.pathname==='/v1/ai/capabilities'&&req.method()==='GET'),'No AI inference or administration');
   if(req.method()==='OPTIONS')return route.fulfill({status:204,headers:{'Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE'}});
   let data,status=200;
   if(org&&url.pathname.startsWith('/v1/team/')){
    if(revoked){status=403;data={error:'Access removed'};}
    else if(url.pathname.endsWith('/customers'))data={name:'Northstar',role:'Viewer',customers:[f.inventory.customers[0]]};
    else data={customer:{...f.inventory.customers[0],role:'Viewer'},environments:f.inventory.environments.filter(e=>e.customer_id==='c1'),assets:f.inventory.assets.filter(a=>a.environment_id!=='e3'),findings:[],remediations:[],activity:[]};
   }else if(url.pathname==='/v1/ai/capabilities')data={platform_role:null,organizations:[]};
   else {const res=await f.request(req.url(),{method:req.method(),...(req.postData()?{body:req.postData()}: {})});status=res.status;data=await res.json();}
   return route.fulfill({status,contentType:'application/json',body:JSON.stringify(data),headers:{'Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true'}});
  }
  if(url.hostname!=='cveharbor.com')return route.abort();
  if(url.pathname==='/data.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_DATA='+JSON.stringify({advisories:f.advisories})});
  if(url.pathname==='/catalog.js')return route.fulfill({contentType:'text/javascript',body:'window.CVEHARBOR_CATALOG={advisories:[]}'});
  let name=url.pathname;if(name.endsWith('/'))name+='index.html';const full=path.resolve(root,'.'+name);assert.ok(full.startsWith(root+path.sep));
  try{return await route.fulfill({body:await fs.readFile(full),contentType:({'.html':'text/html','.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.png':'image/png'})[path.extname(full)]||'application/octet-stream'});}catch{return route.fulfill({status:404,body:''});}
 });
 await page.goto('https://cveharbor.com/customer-dashboard/?customer=c1'+(org?'&org=north':''));
 const panel=page.locator('.server-security');await panel.locator('.server-card').first().waitFor();
 assert.equal(await panel.locator('.server-card').count(),3);assert.doesNotMatch(await panel.innerText(),/OTHER01|Other Customer/);
 await panel.getByLabel('Server role',{exact:true}).selectOption('Web');assert.equal(await panel.locator('.server-card').count(),1);
 assert.match(await panel.innerText(),/8\.4\.0/);assert.match(await panel.innerText(),/8\.4\.1/);assert.match(await panel.innerText(),/CVE-2026-12345/);
 assert.equal(await panel.locator('.server-table-scroll').first().locator('tbody tr').count(),4,'both versions retain their two findings');
 if(!org){await panel.getByRole('button',{name:'View CVE-2026-12345 details for WEB01'}).first().click();assert.match(await page.locator('.customer-finding-context').innerText(),/Hostname \/ asset: WEB01/);assert.match(await page.locator('.customer-finding-context').innerText(),/Server role: Web/);await page.getByRole('button',{name:'Close vulnerability details'}).click();}
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),true,'Dashboard overflow '+width);
 await panel.screenshot({path:path.join(screens,(org?'organization':'personal')+'-'+width+'.png')});
 await panel.getByLabel('Server role',{exact:true}).selectOption('Database');assert.doesNotMatch(await panel.innerText(),/CVE-2026-12345/);assert.match(await panel.innerText(),/No matches in the loaded assessment/);
 await panel.getByLabel('Server role',{exact:true}).selectOption('');await panel.getByLabel('Find a hostname or asset').fill('WEB01');assert.equal(await panel.locator('.server-card').count(),2,'same hostname in two environments stays separate');
 if(org){assert.ok(!calls.some(p=>p.startsWith('/v1/inventory')));revoked=true;await page.getByRole('button',{name:'Refresh assessment',exact:true}).click();await page.getByText('Access removed No assessment completed.').waitFor();assert.equal(await panel.count(),0);}
 else{f.setAuthenticated(false);await page.evaluate(()=>window.dispatchEvent(new CustomEvent('cveharbor:account-state',{detail:{authenticated:false}})));assert.equal(await panel.innerText(),'');}
 assert.deepEqual(errors,[]);assert.equal(f.writes.length,0);await context.close();
}console.log('PASS: personal and organization server grouping, scope isolation, role filters, side-by-side versions, CVE context, revoked access and 1440/768/390px layouts; fictional data, no AI.');}finally{await browser.close();}
