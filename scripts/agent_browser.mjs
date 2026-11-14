// End-to-end wizard with SQLite backend and fictional devices. No external traffic.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import {createRequire} from 'node:module';
import {capacityFixture,fixtureId} from '../account-backend/tests/helpers/capacity-db.mjs';
import {agentManagement,agentDeviceRoute} from '../account-backend/src/agents.js';
const require=createRequire(new URL('../staging/package.json',import.meta.url)),{chromium}=require('playwright-core');
const f=capacityFixture({customers:2,environments:2,assets:0,owners:1});f.sql.exec(await fs.readFile(new URL('../account-backend/agent-schema.sql',import.meta.url),'utf8'));
const env={DB:f.DB,WINDOWS_AGENT_ENABLED:'true',AGENT_INVENTORY_SCHEMA:'1',AGENT_INSTALLER_SHA256:'a'.repeat(64),AGENT_RATE_LIMITER:{limit:async()=>({success:true})}};
const customer=fixtureId(1),environment=fixtureId(1000),root=path.resolve('.');
const html=`<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"></head><body style="background:#071827;color:#e5eff6;font-family:Arial;max-width:1100px;margin:20px auto"><h1>Register asset and technology stack</h1><label>Environment <select id="scope"><option value="one">Production</option><option value="two">Other customer</option></select></label><div id="host"></div><script type="module">import {mountAgents} from '/agent-ui.js';window.agent=mountAgents(document.querySelector('#host'),{scope:()=>document.querySelector('#scope').value==='one'?{customer:'${customer}',environment:'${environment}'}:{customer:'${fixtureId(2)}',environment:'${fixtureId(1001)}'}});document.querySelector('#scope').onchange=()=>window.agent.refresh(true);</script></body></html>`;
const server=http.createServer(async(req,res)=>{if(req.url==='/'){res.setHeader('Content-Type','text/html');res.end(html);return;}if(!['/agent-ui.js','/agent-ui.css'].includes(req.url)){res.writeHead(404).end();return;}res.setHeader('Content-Type',req.url.endsWith('.js')?'text/javascript':'text/css');res.end(await fs.readFile(path.join(root,req.url)));});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const browser=await chromium.launch({headless:true,executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
const context=await browser.newContext(),page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
await context.route('**/*',async route=>{
 const req=route.request(),url=new URL(req.url());if(url.hostname==='127.0.0.1')return route.continue();
 if(url.hostname==='api.cveharbor.com'&&url.pathname.startsWith('/v1/agents')){
  try{const result=await agentManagement(new Request(url,{method:req.method(),headers:req.headers(),body:req.postData()||undefined}),env,{id:'owner-0'});return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(result)});}catch(e){return route.fulfill({status:e.status||500,contentType:'application/json',body:JSON.stringify({error:e.message})});}
 }
 return route.abort('blockedbyclient');
});
const upload=async(action,data,credential)=>{const r=await agentDeviceRoute(new Request('https://api.cveharbor.com/v1/agent/'+action,{method:'POST',headers:{'Content-Type':'application/json',...(credential?{authorization:'Bearer '+credential}:{})},body:JSON.stringify(data)}),env);assert.ok(r.ok,'Fictional agent '+action+' HTTP '+r.status);return r.json();};
try{
 await page.goto('http://127.0.0.1:'+server.address().port);await page.getByText('Waiting for your first Windows Agent connection.').waitFor();
 await page.getByLabel('I understand this unsigned build is for testing and demos; Windows may show an unrecognized-app warning.').check();
 await page.getByRole('button',{name:'Create enrollment code'}).click();const code=await page.locator('input[readonly]').inputValue();
 const d=await upload('enroll',{code,hostname:'FIXTURE-WEB01',agent_version:'1.0.0'});
 const snap={schema:1,sequence:1,request:1,collected_at:new Date().toISOString(),hostname:'FIXTURE-WEB01',agent_version:'1.0.0',complete:true,products:Array.from({length:65},(_,i)=>({name:'Fixture product '+String(i).padStart(2,'0'),version:'1.0',details:'Synthetic only'})),warnings:[],network:{version:1,collected_at:new Date().toISOString(),adapters:[{id:'lan',name:'Production network',status:'Up',addresses:[{ip:'192.0.2.44',prefix:24,state:'Preferred'}]}],suggested:{adapter_id:'lan',ip:'192.0.2.44'}}};
 await upload('upload',snap,d.credential);await page.evaluate(()=>window.agent.refresh(true));
 const card=page.locator('[data-agent-id]');await card.locator('summary').first().click();await page.getByRole('cell',{name:'Fixture product 00',exact:true}).waitFor();
 await page.getByRole('button',{name:'Next software'}).click();await page.getByRole('cell',{name:'Fixture product 64',exact:true}).waitFor();
 const confirm=page.getByRole('button',{name:'Confirm inventory and assess'});assert.equal(await confirm.isEnabled(),false);
 await page.getByLabel('I reviewed this server and its customer/environment assignment, and enable daily synchronization.').check();await confirm.click();
 await page.getByRole('link',{name:'View vulnerability assessment'}).waitFor();await page.getByText('192.0.2.44',{exact:true}).waitFor();
 assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_agent_assets WHERE active=1').get().n,65);
 await page.getByRole('button',{name:'Sync now'}).click();await page.getByText('Collection requested — waiting for the agent.').waitFor();
 const poll=await upload('poll',{},d.credential);assert.equal(poll.collect,true);await upload('upload',{...snap,sequence:2,request:poll.request,products:snap.products.map((p,i)=>i===0?{...p,version:'2.0'}:p)},d.credential);await page.evaluate(()=>window.agent.refresh(true));
 await page.getByRole('cell',{name:'2.0',exact:true}).waitFor();assert.equal(await card.evaluate(e=>e.open),true,'expanded card preserved through sync');
 await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'mobile has no horizontal overflow');
 await fs.mkdir('verification',{recursive:true});await page.screenshot({path:'verification/agent-wizard-mobile.png',fullPage:true});
 await page.selectOption('#scope','two');await page.getByText('Waiting for your first Windows Agent connection.').waitFor();assert.equal(await page.locator('[data-agent-id]').count(),0);assert.equal(await page.locator('input[readonly]').count(),0,'scope change clears enrollment secret');
 assert.deepEqual(errors,[]);console.log('Agent wizard: enrollment, review, paginated software, primary IP, sync, expanded state, mobile and scope isolation passed.');
}finally{await browser.close();await new Promise(resolve=>server.close(resolve));f.close();}
