// Real frontend + real account/CVIE routes on in-memory SQLite, no network.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import path from 'node:path';
const {chromium}=await import(process.env.CVEHARBOR_PLAYWRIGHT_MODULE||'playwright');
import {DB} from '../account-backend/tests/helpers/d1.mjs';
import worker from '../account-backend/src/index.js';
import {identityCandidates} from '../account-backend/src/product-identity.js';
import {catalogueRevision} from '../account-backend/src/catalogue-selection.js';
const env={DB:new DB(),CVIE_SHARED_SCANS_ENABLED:'true'},token='a'.repeat(64);
env.DB.sql.prepare('INSERT INTO sessions VALUES(?,?,?,?)').run('s','a',await catalogueRevision(token),Date.now()/1000+3600);
env.DB.sql.exec("INSERT INTO user_totp VALUES('a',1); INSERT INTO inventory_assets VALUES('a','WordPress'); INSERT INTO user_stack VALUES('a','Exchange SE'); UPDATE cvie_provider_budget SET next_request_at=9999999999999;");
const data=JSON.parse(fs.readFileSync('data/demo-advisories.json','utf8'));
let signedIn=true,failSave=false,holdSave=null,delaySave=false;
const pending=[],seen=[];
async function fetcher(url,options={}){
 const u=new URL(url);seen.push({path:u.pathname,scope:u.searchParams.get('scope'),method:options.method||'GET'});
 if(u.pathname==='/v1/me')return Response.json({authenticated:signedIn,email:signedIn?'a@example.test':undefined},{status:signedIn?200:401});
 if(!u.pathname.startsWith('/v1/cvie')&&u.pathname!=='/v1/technology-catalogue')return Response.json({});
 if(failSave&&options.method==='PUT')return Response.json({error:'Synthetic save failure'},{status:503});
 const execute=()=>worker.fetch(new Request(url,{...options,headers:{...options.headers,Origin:'https://cveharbor.com',...(signedIn?{Cookie:'cvh_session='+token}:{})}}),env,{waitUntil:p=>pending.push(p)});
 if(delaySave&&options.method==='PUT'){delaySave=false;return new Promise(resolve=>{holdSave=async()=>resolve(await execute())})}
 return execute();
}
const directory='work/catalogue-browser';fs.mkdirSync(directory,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||undefined,args:['--no-sandbox']});
try{
 const context=await browser.newContext({viewport:{width:1440,height:1050},reducedMotion:'reduce',serviceWorkers:'block'});
 await context.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.hostname==='api.cveharbor.com'){
   const headers={'Access-Control-Allow-Origin':'http://127.0.0.1:8080','Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS'};
   if(req.method()==='OPTIONS')return route.fulfill({status:204,headers});
   const response=await fetcher(req.url(),{method:req.method(),...(req.postData()?{body:req.postData()}:{})});
   return route.fulfill({status:response.status,headers,contentType:'application/json',body:await response.text()});
  }
  if(url.hostname!=='127.0.0.1')return route.abort();
  if(url.pathname==='/data.js')return route.fulfill({contentType:'application/javascript',body:'window.CVEHARBOR_DATA='+JSON.stringify(data)});
  const filename=path.resolve('public','.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));
  if(!filename.startsWith(path.resolve('public')+path.sep)||!fs.existsSync(filename))return route.fulfill({status:404,body:''});
  return route.fulfill({contentType:{'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml','.png':'image/png','.webp':'image/webp'}[path.extname(filename)]||'application/octet-stream',body:fs.readFileSync(filename)});
 });
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:8080/vulnerabilities/');
 await page.waitForSelector('.cvie-scope-summary');await page.locator('#technologyManageButton').click();
 const choices=page.locator('#technologyDefaultChoices input');
 for(const input of await choices.all())await input.uncheck();
 await page.locator('#technologyCustomizer').getByLabel('Windows Server OS',{exact:true}).check();await page.locator('#technologyCustomizer').getByLabel('.NET Core',{exact:true}).check();
 await page.locator('#technologySaveButton').click();
 await page.waitForFunction(()=>window.CVEHARBOR_CVIE.products.length===2&&!window.CVEHARBOR_CVIE.loading);
 assert.deepEqual((await page.locator('.technology-row-name').allTextContents()).sort(),['.NET Core','Windows Server OS']);
 assert.deepEqual((await page.locator('#cvieExplorer .cvie-product-status > strong').allTextContents()).sort(),['.NET Core','Windows Server OS']);
 // Actual API chooser and card removal, with synthetic provider-directory records.
 const family=name=>'cpe:2.3:o:microsoft:'+name+':*:*:*:*:*:*:*:*';
 const options=identityCandidates({products:['windows_server_2025','windows_server_2022','windows_server_2012_r2'].map(name=>({cpe:{cpeName:family(name)}}))},{name:'Windows Server OS'});
 env.DB.sql.prepare("UPDATE cvie_products SET status='needs_identity',candidates_json=?,cursor_json=? WHERE name='Windows Server OS'").run(JSON.stringify(options),JSON.stringify({directory_query:'Microsoft Windows Server',directory_complete:true}));
 await page.evaluate(()=>window.CVEHARBOR_CVIE.refresh());
 await page.locator('.technology-row').filter({hasText:'Windows Server OS'}).getByRole('button',{name:'Choose the exact product',exact:true}).click();
 await page.waitForSelector('.cvie-identity-options input');
 assert.equal(await page.locator('.cvie-identity-options input').count(),3);
 await page.getByRole('searchbox',{name:'Search product identities'}).fill('2025');assert.equal(await page.locator('.cvie-identity-options input').count(),1);
 await page.locator('.cvie-identity-options input').check();
 await page.screenshot({path:directory+'/identity-dialog.png'});
 await page.getByRole('button',{name:'Use selected product',exact:true}).click();await page.waitForFunction(()=>!document.querySelector('.cvie-identity-dialog').open);
 assert.equal(env.DB.sql.prepare("SELECT cpe FROM cvie_products WHERE name='Windows Server OS'").get().cpe,family('windows_server_2025'));
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
 assert.deepEqual(errors,[]);console.log('PASS Chromium catalogue selection, persisted refresh, removal, adding, failure, empty scope and responsive layout');
 await context.close();
}finally{await browser.close();env.DB.sql.close()}
