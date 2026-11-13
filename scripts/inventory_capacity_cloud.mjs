// Disposable synthetic Cloudflare rehearsal. No production bindings or credentials.
// This executor requires its separately reviewed, protected main-only workflow.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {capacityFixture,capacitySessions,fixtureId} from '../account-backend/tests/helpers/capacity-db.mjs';
import {restBatch} from './cvie_rest_batch.mjs';
const account='9706b4d98ad72884e67fd1eb875c8a61';
const blocked=new Set(['46710e51-7ca4-4571-b89c-921b9969de0b','fac61562-fc31-426d-8032-550aba63b7f6']);
// Retained receipt from authorized run 43438175247. Further diagnosis reuses
// this one fictional database; it must never create a second resource.
const retained={uuid:'b4a226d7-35e8-469f-abfe-2a2eee0a96de',name:'cveharbor-capacity-43438175247'};
export function validateRetainedDatabase(database){
 assert.equal(database.uuid,retained.uuid);assert.equal(database.name,retained.name);assert.ok(!blocked.has(database.uuid));
 return database;
}
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const stats=values=>{const rows=[...values].sort((a,b)=>a-b),q=p=>Math.round(rows[Math.min(rows.length-1,Math.floor(rows.length*p))]||0);return {count:rows.length,p50_ms:q(.5),p95_ms:q(.95),p99_ms:q(.99),max_ms:q(1)};};
export function validateCloudRun(env){
 assert.equal(env.GITHUB_REPOSITORY,'Prat007ai/cveharbor');assert.equal(env.GITHUB_REF,'refs/heads/main');assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch');assert.equal(env.GITHUB_RUN_ATTEMPT,'1');
 assert.equal(env.GITHUB_WORKFLOW_REF,'Prat007ai/cveharbor/.github/workflows/inventory-capacity-cloud.yml@refs/heads/main');
 assert.match(env.GITHUB_RUN_ID||'',/^\d{8,20}$/);assert.match(env.GITHUB_SHA||'',/^[a-f0-9]{40}$/);assert.equal(env.CAPACITY_REVIEWED_COMMIT,env.GITHUB_SHA);
 assert.equal(env.CLOUDFLARE_ACCOUNT_ID,account);assert.ok(env.CLOUDFLARE_API_TOKEN);
 return 'cveharbor-capacity-'+env.GITHUB_RUN_ID;
}
export async function cloudRehearsal(env=process.env){
 const name=validateCloudRun(env),root=path.resolve('verification/capacity-cloud');fs.mkdirSync(root,{recursive:true});
 const receipt={commit:env.GITHUB_SHA,run:env.GITHUB_RUN_ID,account,test_resource:retained.name,preview_resource:name,original_run:'43438175247',started_at:new Date().toISOString(),status:'preflight',production_touched:false};
 const save=()=>fs.writeFileSync('capacity-cloud-result.json',JSON.stringify(receipt,null,2)+'\n');save();
 async function api(suffix,method='GET',body){
  const r=await fetch('https://api.cloudflare.com/client/v4/accounts/'+account+suffix,{method,headers:{Authorization:'Bearer '+env.CLOUDFLARE_API_TOKEN,'Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{}),redirect:'error',signal:AbortSignal.timeout(60000)});
  const data=await r.json();assert.ok(r.ok&&data.success,'Cloudflare operation failed (HTTP '+r.status+'); reconcile the recorded resource, do not retry creation');return data.result;
 }
 // Refuse to initialize or change account exposure. Existing staging is untouched.
 assert.equal((await api('/workers/subdomain')).subdomain,'cveharbor-staging');
 const database=validateRetainedDatabase(await api('/d1/database/'+retained.uuid));
 receipt.database_id=database.uuid;receipt.status='retained_database_verified';save();
 const query=async sql=>{const rows=await api('/d1/database/'+database.uuid+'/query','POST',{sql});assert.ok(rows.every(r=>r.success));return rows;};
 const fixture=capacityFixture({owners:50,customers:50,environments:100,assets:50000}),tokens=capacitySessions(fixture.sql);
 let child;
 try{
  // Inspect only the known retained fixture and renew its run-only sessions.
  // Existing application records/schema and recovery leases are retained.
  const owners=(await query('SELECT id,email FROM users ORDER BY id'))[0].results;
  assert.deepEqual(owners.map(o=>[o.id,o.email]),fixture.sql.prepare('SELECT id,email FROM users ORDER BY id').all().map(o=>[o.id,o.email]));
  assert.equal((await query('SELECT count(*) n FROM inventory_customers'))[0].results[0].n,50);
  assert.equal((await query('SELECT count(*) n FROM inventory_environments'))[0].results[0].n,100);
  assert.equal((await query('SELECT count(*) n FROM inventory_assets'))[0].results[0].n,50000);
  assert.equal((await query('SELECT count(*) n FROM pragma_foreign_key_check'))[0].results[0].n,0);
  const sessions=fixture.sql.prepare('SELECT id,user_id,token_hash,expires_at FROM sessions ORDER BY id').all();
  assert.equal((await query('SELECT count(*) n FROM sessions'))[0].results[0].n,50);
  await query(restBatch(sessions.map(s=>({sql:'UPDATE sessions SET token_hash=?,expires_at=? WHERE id=? AND user_id=?',params:[s.token_hash,s.expires_at,s.id,s.user_id]}))).sql);
  receipt.status='retained_fixture_ready';save();
  const backend=path.resolve(env.CAPACITY_BACKEND_DIR||'');assert.ok(env.CAPACITY_BACKEND_DIR&&fs.existsSync(path.join(backend,'account-backend/src/index.js')));
  const entry=path.join(root,'entry.mjs');
  // This adapter limits the temporary preview to actual application reads.
  // It never bypasses application authentication and never invokes AI or mail.
  fs.writeFileSync(entry,`import worker from ${JSON.stringify(path.join(backend,'account-backend/src/index.js').replaceAll('\\','/'))};\nexport default {async fetch(req,env,ctx){const u=new URL(req.url);if(req.method!=='GET'||!['/v1/me','/v1/inventory/page','/v1/inventory/status'].includes(u.pathname))return new Response('Unavailable',{status:404});const original=await worker.fetch(req,env,ctx),r=new Response(original.body,original);r.headers.set('X-Capacity-Application','true');return r;}};\n`);
  const config={name,account_id:account,main:entry,compatibility_date:'2026-10-28',compatibility_flags:['nodejs_compat'],workers_dev:false,preview_urls:false,routes:[],vars:{RECOVERY_CONTROL_REQUIRED:'true',AI_ENABLED:'false'},d1_databases:[{binding:'DB',database_name:retained.name,database_id:database.uuid,preview_database_id:database.uuid}]};
  const configPath=path.join(root,'wrangler.json');fs.writeFileSync(configPath,JSON.stringify(config));receipt.config_sha256=sha(fs.readFileSync(configPath));save();
  const childEnv=Object.fromEntries(['PATH','HOME','TMPDIR','HTTPS_PROXY','HTTP_PROXY','NODE_EXTRA_CA_CERTS'].filter(k=>env[k]).map(k=>[k,env[k]]));
  Object.assign(childEnv,{CI:'true',CLOUDFLARE_ACCOUNT_ID:account,CLOUDFLARE_API_TOKEN:env.CLOUDFLARE_API_TOKEN,WRANGLER_SEND_METRICS:'false',CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV:'false',XDG_CONFIG_HOME:path.join(root,'wrangler-state')});
  child=spawn('npx',['--yes','wrangler@4.156.0','dev','--remote','--config',configPath,'--ip','127.0.0.1','--port','8787','--log-level','error'],{env:childEnv,stdio:['ignore','pipe','pipe']});
  // Preview URLs/tokens and fictional sessions stay out of logs and artifacts.
  child.stdout.on('data',()=>{});child.stderr.on('data',()=>{});let spawnError=false;child.on('error',()=>{spawnError=true;});
  const base='http://127.0.0.1:8787';let ready=false;
  for(let i=0;i<90&&!ready;i++){
   assert.ok(!spawnError&&child.exitCode===null,'Remote preview failed; account exposure must not be changed to make it work');
   try{const r=await fetch(base+'/v1/me',{signal:AbortSignal.timeout(2000)});ready=r.status===401;}catch{}
   if(!ready)await new Promise(resolve=>setTimeout(resolve,1000));
  }
  assert.ok(ready,'Remote preview did not start');
  const headers=i=>({Cookie:'cvh_session='+tokens[i],Origin:'https://cveharbor.com'});
  const unauth=await fetch(base+'/v1/inventory/page');assert.equal(unauth.status,401);
  const foreign=await fetch(base+'/v1/inventory/page?customer_id='+fixtureId(2),{headers:headers(0)});assert.equal(foreign.status,404);
  const samples=[],journeys=[],errors=[];let completed=0;
  const start=performance.now(),until=start+120000;
  receipt.status='running';save();
  await Promise.all(Array.from({length:50},(_,i)=>(async()=>{
   while(performance.now()<until){const began=performance.now();let diagnostic={category:'transport_failure'};try{
    let cursor=null;const ids=new Set();do{
     const params=new URLSearchParams({resource:'assets',customer_id:fixtureId(i+1)});if(cursor)params.set('cursor',cursor);
     const at=performance.now(),r=await fetch(base+'/v1/inventory/page?'+params,{headers:headers(i),signal:AbortSignal.timeout(15000)});samples.push(performance.now()-at);
     diagnostic={category:r.status===200?'response_validation':'http_failure',http_status:r.status,application_reached:r.headers.get('X-Capacity-Application')==='true',json_response:(r.headers.get('Content-Type')||'').includes('json')};
     if(r.status!==200){const body=await r.text();const code=/\b(?:Error|error code:)\s*(1\d{3})\b/.exec(body);if(code)diagnostic.provider_code=Number(code[1]);throw Error('HTTP failure');}
     const page=await r.json();assert.ok(Array.isArray(page.items)&&page.items.length<=250);
     for(const row of page.items){assert.ok(!ids.has(row.id));ids.add(row.id);assert.equal((parseInt(row.environment_id.slice(0,8),16)-1000)%50,i);}
     assert.equal(page.complete,page.next_cursor===null);cursor=page.next_cursor;
    }while(cursor);
    assert.equal(ids.size,1000);completed++;journeys.push(performance.now()-began);
   }catch{errors.push({session:i,...diagnostic});break;}}
  })()));
  Object.assign(receipt,{environment:'Cloudflare remote Worker preview and dedicated D1; single GitHub runner, authenticated reads',concurrent_sessions:50,customers:50,environments:100,host_names:10000,software_entries:50000,duration_seconds:Math.round((performance.now()-start)/1000),request_latency:stats(samples),complete_customer_load:stats(journeys),completed_journeys:completed,errors,cvie_background_tested:false});
  receipt.status='measured';save();assert.equal(errors.length,0);assert.ok(completed>=50);assert.ok(receipt.request_latency.p95_ms<1000,'Request p95 exceeds 1 second');assert.ok(receipt.complete_customer_load.p95_ms<3000,'Complete customer read p95 exceeds 3 seconds');
  receipt.status='passed';receipt.completed_at=new Date().toISOString();save();console.log(JSON.stringify(receipt));
 }finally{
  child?.kill('SIGTERM');fixture.close();
  // Retain the named synthetic database for inspection. No existing resource
  // is deleted, reset, rebound, exposed or deployed by this executor.
 }
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))await cloudRehearsal();
