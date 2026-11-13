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
 const receipt={commit:env.GITHUB_SHA,run:env.GITHUB_RUN_ID,account,test_resource:name,started_at:new Date().toISOString(),status:'preflight',production_touched:false};
 const save=()=>fs.writeFileSync('capacity-cloud-result.json',JSON.stringify(receipt,null,2)+'\n');save();
 async function api(suffix,method='GET',body){
  const r=await fetch('https://api.cloudflare.com/client/v4/accounts/'+account+suffix,{method,headers:{Authorization:'Bearer '+env.CLOUDFLARE_API_TOKEN,'Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{}),redirect:'error',signal:AbortSignal.timeout(60000)});
  const data=await r.json();assert.ok(r.ok&&data.success,'Cloudflare operation failed (HTTP '+r.status+'); reconcile the recorded resource, do not retry creation');return data.result;
 }
 // Refuse to initialize or change account exposure. Existing staging is untouched.
 assert.equal((await api('/workers/subdomain')).subdomain,'cveharbor-staging');
 assert.equal((await api('/d1/database?name='+name)).length,0,'Do not reuse an existing database');
 const database=await api('/d1/database','POST',{name});
 assert.match(database.uuid,/^[a-f0-9-]{36}$/);assert.ok(!blocked.has(database.uuid));assert.equal(database.name,name);
 receipt.database_id=database.uuid;receipt.status='created';save();
 const query=async sql=>{const rows=await api('/d1/database/'+database.uuid+'/query','POST',{sql});assert.ok(rows.every(r=>r.success));return rows;};
 const fixture=capacityFixture({owners:50,customers:50,environments:100,assets:50000}),tokens=capacitySessions(fixture.sql);
 let child;
 try{
  // Reproduce table definitions and fictional records. Install triggers after
  // the exact fixture counters, avoiding double-counting during import.
  const objects=fixture.sql.prepare("SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'").all();
  for(const obj of objects.filter(o=>o.type==='table'))await query(obj.sql);
  for(const obj of objects.filter(o=>o.type==='table')){
   assert.match(obj.name,/^[a-z_]+$/);const rows=fixture.sql.prepare('SELECT * FROM "'+obj.name+'"').all();
   for(let i=0;i<rows.length;i+=100){const part=rows.slice(i,i+100),columns=Object.keys(part[0]);
    const sql='INSERT INTO "'+obj.name+'" ('+columns.map(c=>'"'+c+'"').join(',')+') VALUES '+part.map(()=> '('+columns.map(()=>'?').join(',')+')').join(',');
    await query(restBatch([{sql,params:part.flatMap(row=>columns.map(c=>row[c]))}]).sql);
   }
  }
  for(const obj of objects.filter(o=>o.type!=='table'))await query(obj.sql);
  assert.equal((await query('SELECT count(*) n FROM inventory_assets'))[0].results[0].n,50000);
  assert.equal((await query('SELECT count(*) n FROM pragma_foreign_key_check'))[0].results[0].n,0);
  receipt.status='seeded';save();
  const backend=path.resolve(env.CAPACITY_BACKEND_DIR||'');assert.ok(env.CAPACITY_BACKEND_DIR&&fs.existsSync(path.join(backend,'account-backend/src/index.js')));
  const entry=path.join(root,'entry.mjs');
  // This adapter limits the temporary preview to actual application reads.
  // It never bypasses application authentication and never invokes AI or mail.
  fs.writeFileSync(entry,`import worker from ${JSON.stringify(path.join(backend,'account-backend/src/index.js').replaceAll('\\','/'))};\nexport default {fetch(req,env,ctx){const u=new URL(req.url);if(req.method!=='GET'||!['/v1/me','/v1/inventory/page','/v1/inventory/status'].includes(u.pathname))return new Response('Unavailable',{status:404});return worker.fetch(req,env,ctx);}};\n`);
  const config={name,account_id:account,main:entry,compatibility_date:'2026-10-28',compatibility_flags:['nodejs_compat'],workers_dev:false,preview_urls:false,routes:[],vars:{RECOVERY_CONTROL_REQUIRED:'true',AI_ENABLED:'false'},d1_databases:[{binding:'DB',database_name:name,database_id:database.uuid,preview_database_id:database.uuid}]};
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
   while(performance.now()<until){const began=performance.now();try{
    let cursor=null;const ids=new Set();do{
     const params=new URLSearchParams({resource:'assets',customer_id:fixtureId(i+1)});if(cursor)params.set('cursor',cursor);
     const at=performance.now(),r=await fetch(base+'/v1/inventory/page?'+params,{headers:headers(i),signal:AbortSignal.timeout(15000)});samples.push(performance.now()-at);
     assert.equal(r.status,200);const page=await r.json();assert.ok(Array.isArray(page.items)&&page.items.length<=250);
     for(const row of page.items){assert.ok(!ids.has(row.id));ids.add(row.id);assert.equal((parseInt(row.environment_id.slice(0,8),16)-1000)%50,i);}
     assert.equal(page.complete,page.next_cursor===null);cursor=page.next_cursor;
    }while(cursor);
    assert.equal(ids.size,1000);completed++;journeys.push(performance.now()-began);
   }catch{errors.push({session:i,category:'request_or_completeness_failure'});break;}}
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
