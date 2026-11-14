import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {capacityFixture,fixtureId} from './helpers/capacity-db.mjs';
import {agentDeviceRoute,agentManagement} from '../src/agents.js';
import {agentAlert,dispatchAgentMail} from '../src/agent-mail.js';
import {inventoryPage} from '../src/inventory-pages.js';
import {readBody} from '../src/agent-validation.js';
import worker from '../src/index.js';
const customer=fixtureId(1),environment=fixtureId(1000);
function setup(){
 const f=capacityFixture({customers:2,environments:2,assets:0,owners:2});f.sql.exec(fs.readFileSync(new URL('../agent-schema.sql',import.meta.url),'utf8'));
 f.sql.exec("ALTER TABLE team_visible_customers ADD COLUMN role TEXT; CREATE TABLE team_members(org TEXT,user_id TEXT,email TEXT,role TEXT);");
 const env={DB:f.DB,WINDOWS_AGENT_ENABLED:'true',AGENT_INVENTORY_SCHEMA:'1',AGENT_INSTALLER_SHA256:'a'.repeat(64),AGENT_SOURCE_RATE_LIMITER:{limit:async()=>({success:true})},AGENT_RATE_LIMITER:{limit:async()=>({success:true})}};
 const management=(suffix='',data=null,user={id:'owner-0'},params={})=>agentManagement(new Request('https://api.cveharbor.com/v1/agents'+suffix+'?'+new URLSearchParams({customer_id:customer,environment_id:environment,...params}),{method:data?'POST':'GET',headers:data?{'Content-Type':'application/json'}:{},body:data?JSON.stringify(data):undefined}),env,user);
 const device=(action,data,credential)=>agentDeviceRoute(new Request('https://api.cveharbor.com/v1/agent/'+action,{method:'POST',headers:{'Content-Type':'application/json',...(credential?{Authorization:'Bearer '+credential}:{})},body:JSON.stringify(data)}),env);
 const enroll=async()=>{const {code}=await management('/enrollment',{evaluation_accepted:true});const response=await device('enroll',{code,hostname:'TEST-WEB01',agent_version:'1.0.0'});assert.equal(response.status,201);return response.json();};
 const payload=(sequence=1,products=[{name:'.NET Runtime',version:'8.0.1',details:'Test only'}],extra={})=>({schema:1,sequence,request:1,collected_at:new Date().toISOString(),hostname:'TEST-WEB01',agent_version:'1.0.0',complete:true,products,network:null,warnings:[],...extra});
 const confirm=async d=>{const review=await management('/'+d.device_id);return management('/'+d.device_id+'/confirm',{revision:review.device.revision,pending_hash:review.pending_hash,daily:true});};
 return {...f,env,management,device,enroll,payload,confirm};
}
test('enrollment is one-use and scoped; review precedes projection; daily changes retain history and manual records',async()=>{
 const f=setup();try{
  const code=await f.management('/enrollment',{evaluation_accepted:true}),first=await f.device('enroll',{code:code.code,hostname:'TEST-WEB01',agent_version:'1.0.0'}),d=await first.json();assert.equal(first.status,201);
  assert.equal((await f.device('enroll',{code:code.code,hostname:'OTHER',agent_version:'1.0.0'})).status,401);
  assert.equal((await f.device('upload',f.payload(),d.credential)).status,200);assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_assets').get().n,0);
  await f.confirm(d);assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_assets').get().n,1);
  f.sql.prepare("INSERT INTO inventory_assets(id,user_id,environment_id,name,asset_type,technology,version) VALUES('manual','owner-0',?,'Manual','Software','Manual product','1')").run(environment);
  f.sql.exec('UPDATE inventory_agents SET last_sync=last_sync-86401');
  const second=f.payload(2,[{name:'.NET Runtime',version:'8.0.2',details:'Test only'}]);
  assert.equal((await f.device('upload',second,d.credential)).status,200);assert.equal((await f.device('upload',second,d.credential)).status,200);
  const page=await inventoryPage(new Request('https://api.cveharbor.com/v1/inventory/page?'+new URLSearchParams({customer_id:customer,environment_id:environment})),f.env,{id:'owner-0'});
  assert.equal(page.items.length,2);assert.equal(page.items.find(a=>a.agent_device_id).version,'8.0.2');assert.ok(page.items.some(a=>a.id==='manual'));
  assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_agent_history').get().n,2);assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_assets').get().n,3,'old software remains for history and finding references');
  assert.equal((await f.device('upload',f.payload(1),d.credential)).status,409);
  f.sql.exec('UPDATE inventory_agents SET last_sync=last_sync-86401');
  const partial=f.payload(3,[{name:'New software',version:'1',details:''}],{complete:false,warnings:['Source unreadable']});assert.equal((await f.device('upload',partial,d.credential)).status,200);
  assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_agent_assets WHERE active=1').get().n,2);
 }finally{f.close();}
});
test('device credentials do not grant browser/customer access and payload scope cannot choose ownership',async()=>{
 const f=setup();try{const d=await f.enroll();
  const r=await worker.fetch(new Request('https://api.cveharbor.com/v1/inventory',{headers:{Authorization:'Bearer '+d.credential}}),f.env,{});assert.equal(r.status,401);
  await assert.rejects(()=>f.management('/'+d.device_id,null,{id:'owner-1'}),e=>e.status===404);
  assert.equal((await f.device('upload',f.payload(1,undefined,{customer_id:fixtureId(2)}),d.credential)).status,400);
  assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_assets').get().n,0);
  const unknown=await f.device('upload',f.payload(),'b'.repeat(64));assert.equal(unknown.status,401);assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_agent_incidents').get().n,0);
  const cookie=await agentDeviceRoute(new Request('https://api.cveharbor.com/v1/agent/poll',{method:'POST',headers:{'Content-Type':'application/json',cookie:'cvh_session=test',Authorization:'Bearer '+d.credential},body:'{}'}),f.env);assert.equal(cookie.status,403);
 }finally{f.close();}
});
test('repeated authenticated invalid uploads suspend only that device and queue deduplicated trusted recipients',async()=>{
 const f=setup();try{const d=await f.enroll(),other=await f.enroll();
  await f.management('/contacts',{emails:['security@example.test']});
  for(let i=0;i<3;i++)assert.equal((await f.device('upload',{garbage:true,recipient:'attacker@example.test'},d.credential)).status,400);
  assert.equal((await f.device('poll',{},d.credential)).status,423);assert.equal((await f.device('poll',{},other.credential)).status,200);
  assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_agent_incidents').get().n,1);
  assert.deepEqual(f.sql.prepare('SELECT recipient FROM inventory_agent_mail ORDER BY recipient').all().map(r=>r.recipient),['prat.mahen@gmail.com','security@example.test']);
  const state=await f.management('/'+d.device_id);
  await assert.rejects(()=>f.management('/'+d.device_id+'/sync',{revision:state.device.revision}),e=>e.status===409);
  await f.management('/'+d.device_id+'/resume',{revision:state.device.revision,reason:'Reinstalled the approved collector after a confirmed collection defect',credential_safe:true});
  assert.equal((await f.device('poll',{},d.credential)).status,200);
  const fresh=await f.management('/'+d.device_id);await f.management('/'+d.device_id+'/revoke',{revision:fresh.device.revision});assert.equal((await f.device('poll',{},d.credential)).status,401);
 }finally{f.close();}
});
test('large unexpected removals preserve accepted inventory and stop projection',async()=>{
 const f=setup();try{const d=await f.enroll(),products=Array.from({length:12},(_,i)=>({name:'Software '+i,version:'1',details:''}));await f.device('upload',f.payload(1,products),d.credential);await f.confirm(d);
  f.sql.exec('UPDATE inventory_agents SET last_sync=last_sync-86401');
  assert.equal((await f.device('upload',f.payload(2,products.slice(0,2)),d.credential)).status,423);
  assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_agent_assets WHERE active=1').get().n,12);
  assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_agent_history').get().n,1);
 }finally{f.close();}
});
test('stream size limits apply without Content-Length and compressed bodies are rejected',async()=>{
 const req=new Request('https://example.test',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"huge":"'+'x'.repeat(4096)+'"}'});await assert.rejects(()=>readBody(req,100),e=>e.status===413);
 await assert.rejects(()=>readBody(new Request('https://example.test',{method:'POST',headers:{'Content-Type':'application/json','Content-Encoding':'gzip'},body:'{}'})),e=>e.status===415);
});
test('email content escapes hostile device names; disabled mail has no provider effects',async()=>{
 const f=setup();try{const alert=agentAlert({id:'incident',hostname:'<script>alert(1)</script>',customer:'Example',environment:'Production',customer_id:customer,environment_id:environment,opened_at:1,reason:'Repeated invalid uploads'});assert.ok(!alert.html.includes('<script>'));assert.ok(alert.html.includes('&lt;script&gt;'));assert.match(alert.text,/not confirmation/);await dispatchAgentMail(f.env);}finally{f.close();}
});
test('team customer boundaries and Viewer role are enforced on every management call',async()=>{
 const f=setup();try{
  f.sql.prepare("INSERT INTO team_visible_customers VALUES('team','owner-1','owner-0',?,'Viewer')").run(customer);
  const options={org:'team'};assert.deepEqual((await f.management('',null,{id:'owner-1'},options)).devices,[]);
  await assert.rejects(()=>f.management('/enrollment',{evaluation_accepted:true}, {id:'owner-1'},options),e=>e.status===404);
  f.sql.exec("UPDATE team_visible_customers SET role='Editor'");assert.ok((await f.management('/enrollment',{evaluation_accepted:true}, {id:'owner-1'},options)).code);
  await assert.rejects(()=>f.management('/contacts',{emails:['wrong@example.test']},{id:'owner-1'},options),e=>e.status===403);
 }finally{f.close();}
});

test('re-enrollment replaces a revoked credential while retaining stable identity and requiring review',async()=>{
 const f=setup();try{const d=await f.enroll();await f.device('upload',f.payload(),d.credential);await f.confirm(d);
  let state=await f.management('/'+d.device_id);await f.management('/'+d.device_id+'/revoke',{revision:state.device.revision});state=await f.management('/'+d.device_id);
  const one=await f.management('/'+d.device_id+'/enrollment',{revision:state.device.revision,evaluation_accepted:true});
  const two=await f.management('/'+d.device_id+'/enrollment',{revision:state.device.revision,evaluation_accepted:true});
  const replacement=await (await f.device('enroll',{code:one.code,hostname:'TEST-WEB01',agent_version:'1.0.0'})).json();assert.equal(replacement.device_id,d.device_id);assert.notEqual(replacement.credential,d.credential);
  assert.equal((await f.device('enroll',{code:two.code,hostname:'TEST-WEB01',agent_version:'1.0.0'})).status,401);
  assert.equal((await f.device('poll',{},d.credential)).status,401);assert.equal((await (await f.device('poll',{},replacement.credential)).json()).sequence,2);
  assert.equal((await f.device('upload',f.payload(2,[{name:'.NET Runtime',version:'8.0.2',details:''}],{request:2}),replacement.credential)).status,200);
  assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_agents').get().n,1);assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_agent_history').get().n,1);
  await f.confirm(replacement);assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_agent_history').get().n,2);
 }finally{f.close();}
});

test('daily collection is due after 24 hours; explicit sync queues safely; unsolicited writes and frozen storage are rejected',async()=>{
 const f=setup();try{const d=await f.enroll();await f.device('upload',f.payload(),d.credential);await f.confirm(d);
  assert.equal((await (await f.device('poll',{},d.credential)).json()).collect,false);
  assert.equal((await f.device('upload',f.payload(2),d.credential)).status,409);
  f.sql.exec('UPDATE inventory_agents SET last_sync=last_sync-86401');assert.equal((await (await f.device('poll',{},d.credential)).json()).collect,true);
  assert.equal((await f.device('upload',f.payload(2),d.credential)).status,200);
  const state=await f.management('/'+d.device_id);await f.management('/'+d.device_id+'/sync',{revision:state.device.revision});const poll=await (await f.device('poll',{},d.credential)).json();assert.equal(poll.collect,true);assert.equal(poll.request,2);
  f.sql.exec('UPDATE operations_control SET write_hold=1,database_frozen=1');assert.equal((await f.device('upload',f.payload(3,undefined,{request:2}),d.credential)).status,503);assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_agent_history').get().n,2);
 }finally{f.close();}
});

test('authenticated request floods suspend the device and queue one incident; source throttling remains separate',async()=>{
 const f=setup();try{const d=await f.enroll();f.env.AGENT_RATE_LIMITER.limit=async()=>({success:false});assert.equal((await f.device('poll',{},d.credential)).status,423);assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_agent_incidents').get().n,1);
  f.env.AGENT_SOURCE_RATE_LIMITER.limit=async()=>({success:false});assert.equal((await f.device('poll',{},d.credential)).status,429);assert.equal(f.sql.prepare('SELECT COUNT(*) n FROM inventory_agent_incidents').get().n,1);
 }finally{f.close();}
});

test('email dispatch uses separate recipients, retries only definite rejections and never repeats an ambiguous submission',async()=>{
 const f=setup();try{const d=await f.enroll();await f.management('/contacts',{emails:['security@example.test','removed@example.test']});for(let i=0;i<3;i++)await f.device('upload',{garbage:true},d.credential);
  await f.management('/contacts',{emails:['security@example.test']});Object.assign(f.env,{AGENT_EMAIL_ENABLED:'true',EMAIL_FROM:'fixture@example.test',SMTP2GO_API_KEY:'fictional-not-a-secret'});
  const seen=[];await dispatchAgentMail(f.env,async(url,options)=>{const data=JSON.parse(options.body);assert.equal(data.to.length,1);seen.push(data.to[0]);return new Response(JSON.stringify({data:{succeeded:1,failed:0,email_id:'fixture'}}));});
  assert.deepEqual(seen.sort(),['prat.mahen@gmail.com','security@example.test']);assert.equal(f.sql.prepare("SELECT state FROM inventory_agent_mail WHERE recipient='removed@example.test'").get().state,'cancelled');
  await dispatchAgentMail(f.env,()=>{throw Error('Duplicate submission');});
  f.sql.exec("UPDATE inventory_agent_mail SET state='queued',attempts=0 WHERE recipient='security@example.test'");await dispatchAgentMail(f.env,async()=>new Response('{}',{status:429}));assert.equal(f.sql.prepare("SELECT state FROM inventory_agent_mail WHERE recipient='security@example.test'").get().state,'queued');
  f.sql.exec('UPDATE inventory_agent_mail SET not_before=0');await dispatchAgentMail(f.env,async()=>{throw Error('Fictional timeout');});assert.equal(f.sql.prepare("SELECT state FROM inventory_agent_mail WHERE recipient='security@example.test'").get().state,'unconfirmed');
  await dispatchAgentMail(f.env,()=>{throw Error('Must not blindly resend');});
 }finally{f.close();}
});
