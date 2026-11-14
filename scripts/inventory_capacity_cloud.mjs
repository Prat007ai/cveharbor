// Disposable synthetic Cloudflare rehearsal. No production bindings or credentials.
// This executor requires its separately reviewed, protected main-only workflow.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {spawn} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import {capacityFixture,capacitySessions,fixtureId} from '../account-backend/tests/helpers/capacity-db.mjs';
import {restBatch} from './cvie_rest_batch.mjs';
import {seedOutage,extraSchemas} from './nvd_capacity_fixture.mjs';
const account='9706b4d98ad72884e67fd1eb875c8a61';
const blocked=new Set(['46710e51-7ca4-4571-b89c-921b9969de0b','fac61562-fc31-426d-8032-550aba63b7f6']);
// Retained receipt from authorized run 43438175247. Further diagnosis reuses
// this one fictional database; it must never create a second resource.
const retained={uuid:'b4a226d7-35e8-469f-abfe-2a2eee0a96de',name:'cveharbor-capacity-43438175247'};
export function validateRetainedDatabase(database){
 assert.equal(database.uuid,retained.uuid);assert.equal(database.name,retained.name);assert.ok(!blocked.has(database.uuid));
 return database;
}
export async function enableRetainedReadReplication(api,database){
 validateRetainedDatabase(database);
 const before=database.read_replication?.mode;
 assert.ok(['auto','disabled'].includes(before),'Unknown retained database replication state');
 if(before!=='auto')await api('/d1/database/'+retained.uuid,'PUT',{read_replication:{mode:'auto'}});
 const after=validateRetainedDatabase(await api('/d1/database/'+retained.uuid));
 assert.equal(after.read_replication?.mode,'auto');
 return {before,after:'auto'};
}
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const stats=values=>{const rows=[...values].sort((a,b)=>a-b),q=p=>Math.round(rows[Math.min(rows.length-1,Math.floor(rows.length*p))]||0);return {count:rows.length,p50_ms:q(.5),p95_ms:q(.95),p99_ms:q(.99),max_ms:q(1)};};
export async function stopPreview(child,{platform=process.platform,kill=process.kill,sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms))}={}){
 if(!child)return;
 if(Number.isInteger(child.pid)&&child.pid>1){
  const signal=value=>{try{if(platform==='linux')kill(-child.pid,value);else child.kill(value);}catch(error){if(error.code!=='ESRCH')throw error;}};
  signal('SIGTERM');await sleep(1000);signal('SIGKILL');
 }
 child.stdout?.destroy();child.stderr?.destroy();child.unref();
}
export function previewDiagnostics(output){
 const text=String(output).replace(/\u001b\[[0-9;]*m/g,'');
 const categories=[
  ['authentication',/authentication error|unauthorized|invalid.*token|token.*expired/i],
  ['permission',/permission denied|not authorized|forbidden/i],
  ['dependency',/ETARGET|ENOTFOUND|EAI_AGAIN|npm error|cannot find module/i],
  ['build',/build failed|could not resolve|syntaxerror|referenceerror|typeerror/i],
  ['startup_resource',/startup.*(?:CPU|memory)|CPU.*limit|memory.*limit/i],
  ['preview_configuration',/workers\.dev.*(?:disabled|register)|preview.*(?:disabled|not enabled)/i],
  ['provider_api',/request to.*Cloudflare API.*failed/i],
  ['transport',/fetch failed|ECONNRESET|ETIMEDOUT|service unavailable/i],
  ['port',/EADDRINUSE|address already in use/i]
 ].filter(([,pattern])=>pattern.test(text)).map(([name])=>name);
 const codes=[...new Set([...text.matchAll(/\[code:\s*(\d{4,6})\]/g)].map(match=>Number(match[1])))].slice(0,10);
 return {categories:categories.length?categories:['unknown'],provider_codes:codes};
}
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
 // Only this already-authorized fictional database gets managed read replicas.
 // No production/staging database, access setting or credential is changed.
 receipt.read_replication=await enableRetainedReadReplication(api,database);save();
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
  receipt.leases_before=(await query('SELECT count(*) n FROM operations_leases'))[0].results[0].n;
  receipt.status='retained_fixture_ready';save();
  const backend=path.resolve(env.CAPACITY_BACKEND_DIR||'');assert.ok(env.CAPACITY_BACKEND_DIR&&fs.existsSync(path.join(backend,'account-backend/src/index.js')));
  const cvie=await import(pathToFileURL(path.join(backend,'account-backend/src/cvie.js')));
  const seed=await seedOutage(fixture,cvie),controlKey=randomBytes(32).toString('hex');
  // Add only fictional evidence and compatible read tables to the retained test DB.
  // No inventory, account, recovery record, hold or lease is reset.
  for(const file of extraSchemas)await query(fs.readFileSync(path.join('account-backend',file),'utf8'));
  await query('CREATE TABLE IF NOT EXISTS user_technology_catalogue(user_id TEXT PRIMARY KEY,preferences_json TEXT,updated_at INTEGER)');
  for(const table of ['cvie_products','cvie_subscriptions','cvie_shared_scopes','cvie_product_scopes','cvie_shared_advisories']){
   const rows=fixture.sql.prepare('SELECT * FROM '+table).all();
   for(let offset=0;offset<rows.length;offset+=20){await query(restBatch(rows.slice(offset,offset+20).map(row=>({sql:'INSERT OR IGNORE INTO '+table+'('+Object.keys(row).join(',')+') VALUES('+Object.keys(row).map(()=>'?').join(',')+')',params:Object.values(row)}))).sql);}
  }
  const scope=fixture.sql.prepare('SELECT id FROM cvie_shared_scopes').get().id;
  await query(restBatch([{sql:"UPDATE cvie_shared_scopes SET status='queued',next_attempt_at=0,lease_until=0 WHERE id=?",params:[scope]},{sql:"UPDATE cvie_provider_budget SET next_request_at=0 WHERE provider='nvd'",params:[]}]).sql);
  receipt.outage_fixture={shared_scopes:1,subscribers:50,saved_advisories:200,epoch:seed.epoch};save();
  const entry=path.join(root,'entry.mjs');
  // This adapter limits the temporary preview to actual application reads.
  // It never bypasses application authentication and never invokes AI or mail.
  fs.writeFileSync(entry,`import worker from ${JSON.stringify(path.join(backend,'account-backend/src/index.js').replaceAll('\\','/'))};\nimport {runCvieStep} from ${JSON.stringify(path.join(backend,'account-backend/src/cvie.js').replaceAll('\\','/'))};\nimport {outageAdapter} from ${JSON.stringify(path.resolve('scripts/nvd_capacity_fixture.mjs').replaceAll('\\','/'))};\nimport {observeDatabase} from ${JSON.stringify(path.resolve('scripts/capacity_db_observer.mjs').replaceAll('\\','/'))};\nimport {publicSourceCacheKey} from ${JSON.stringify(path.join(backend,'account-backend/src/public-source-status-cache.js').replaceAll('\\','/'))};\nconst adapter=outageAdapter(worker,runCvieStep,${seed.epoch},${JSON.stringify(controlKey)});\nexport default {async fetch(req,env,ctx){const publicCacheIdentity=publicSourceCacheKey(env),observed=observeDatabase(env.DB),original=await adapter.fetch(req,{...env,DB:observed.binding,CVIE_PUBLIC_CACHE_KEY:publicCacheIdentity},ctx),r=new Response(original.body,original);r.headers.set('X-Capacity-Application','true');r.headers.set('X-Capacity-Database',JSON.stringify(observed.state));return r;}};\n`);
  const config={name,account_id:account,main:entry,compatibility_date:'2026-10-28',compatibility_flags:['nodejs_compat'],workers_dev:false,preview_urls:false,routes:[],vars:{RECOVERY_CONTROL_REQUIRED:'true',CVIE_SHARED_SCANS_ENABLED:'true',AGENT_INVENTORY_SCHEMA:'1',AI_ENABLED:'false'},d1_databases:[{binding:'DB',database_name:retained.name,database_id:database.uuid,preview_database_id:database.uuid}]};
  const configPath=path.join(root,'wrangler.json');fs.writeFileSync(configPath,JSON.stringify(config));receipt.config_sha256=sha(fs.readFileSync(configPath));save();
  const childEnv=Object.fromEntries(['PATH','HOME','TMPDIR','HTTPS_PROXY','HTTP_PROXY','NODE_EXTRA_CA_CERTS'].filter(k=>env[k]).map(k=>[k,env[k]]));
  Object.assign(childEnv,{CI:'true',CLOUDFLARE_ACCOUNT_ID:account,CLOUDFLARE_API_TOKEN:env.CLOUDFLARE_API_TOKEN,WRANGLER_SEND_METRICS:'false',CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV:'false',XDG_CONFIG_HOME:path.join(root,'wrangler-state')});
  // Give npx and its Wrangler descendants a dedicated Linux process group so
  // successful measurements can terminate the entire temporary preview tree.
  child=spawn('npx',['--yes','wrangler@4.156.0','dev','--remote','--config',configPath,'--ip','127.0.0.1','--port','8787','--log-level','error'],{env:childEnv,stdio:['ignore','pipe','pipe'],detached:process.platform==='linux'});
  // Keep only a bounded in-memory tail. Persist closed categories/numeric codes,
  // never raw output, preview URLs/tokens, session values or provider messages.
  let previewOutput='';const capture=chunk=>{previewOutput=(previewOutput+String(chunk)).slice(-32768);};
  child.stdout.on('data',capture);child.stderr.on('data',capture);let spawnError=false;child.on('error',()=>{spawnError=true;});
  const base='http://127.0.0.1:8787';let ready=false;
  for(let i=0;i<90&&!ready;i++){
   if(spawnError||child.exitCode!==null){receipt.status='preview_startup_failed';receipt.preview={...previewDiagnostics(previewOutput),spawn_error:spawnError,exit_code:child.exitCode};save();throw Error('Remote preview failed; inspect the closed startup categories. Account exposure must not be changed.');}
   try{const r=await fetch(base+'/v1/me',{signal:AbortSignal.timeout(2000)});ready=r.status===401;}catch{}
   if(!ready)await new Promise(resolve=>setTimeout(resolve,1000));
  }
  if(!ready){receipt.status='preview_startup_timeout';receipt.preview=previewDiagnostics(previewOutput);save();throw Error('Remote preview did not start');}
  previewOutput='';child.stdout.removeListener('data',capture);child.stderr.removeListener('data',capture);child.stdout.on('data',()=>{});child.stderr.on('data',()=>{});
  const headers=i=>({Cookie:'cvh_session='+tokens[i],Origin:'https://cveharbor.com'});
  const unauth=await fetch(base+'/v1/inventory/page');assert.equal(unauth.status,401);
  const foreign=await fetch(base+'/v1/inventory/page?customer_id='+fixtureId(2),{headers:headers(0)});assert.equal(foreign.status,404);
  const routing=await fetch(base+'/__outage/routing',{method:'POST',headers:{'X-Outage-Control':controlKey},signal:AbortSignal.timeout(15000)});assert.equal(routing.status,200);receipt.routing=await routing.json();save();assert.equal(receipt.routing.bookmark_present,true,'Cloud binding did not return a session bookmark');
  const samples=[],journeys=[],errors=[],databaseSamples=[];let completed=0;
  const start=performance.now(),until=start+120000;
  receipt.status='running';save();
  await Promise.all(Array.from({length:50},(_,i)=>(async()=>{
   while(performance.now()<until){const began=performance.now();let diagnostic={category:'transport_failure'};try{
    let cursor=null;const ids=new Set();do{
     const params=new URLSearchParams({resource:'assets',customer_id:fixtureId(i+1)});if(cursor)params.set('cursor',cursor);
     const at=performance.now(),r=await fetch(base+'/v1/inventory/page?'+params,{headers:headers(i),signal:AbortSignal.timeout(15000)});samples.push(performance.now()-at);
     diagnostic={category:r.status===200?'response_validation':'http_failure',http_status:r.status,application_reached:r.headers.get('X-Capacity-Application')==='true',json_response:(r.headers.get('Content-Type')||'').includes('json')};
     const database=JSON.parse(r.headers.get('X-Capacity-Database')||'null');if(database){databaseSamples.push(database);if(database.errors.length)diagnostic.database_errors=database.errors;}
     if(r.status!==200){const body=await r.text();const code=/\b(?:Error|error code:)\s*(1\d{3})\b/.exec(body);if(code)diagnostic.provider_code=Number(code[1]);throw Error('HTTP failure');}
     const page=await r.json();assert.ok(Array.isArray(page.items)&&page.items.length<=250);
     for(const row of page.items){assert.ok(!ids.has(row.id));ids.add(row.id);assert.equal((parseInt(row.environment_id.slice(0,8),16)-1000)%50,i);}
     assert.equal(page.complete,page.next_cursor===null);cursor=page.next_cursor;
    }while(cursor);
    assert.equal(ids.size,1000);completed++;journeys.push(performance.now()-began);
   }catch{errors.push({session:i,elapsed_ms:Math.round(performance.now()-start),...diagnostic});break;}}
  })()));
  Object.assign(receipt,{environment:'Cloudflare remote Worker preview and dedicated D1; single GitHub runner, authenticated reads',concurrent_sessions:50,customers:50,environments:100,host_names:10000,software_entries:50000,duration_seconds:Math.round((performance.now()-start)/1000),request_latency:stats(samples),complete_customer_load:stats(journeys),completed_journeys:completed,errors,cvie_background_tested:false});
  receipt.database={calls:databaseSamples.reduce((n,s)=>n+s.calls,0),rows_read:databaseSamples.reduce((n,s)=>n+s.rows_read,0),rows_written:databaseSamples.reduce((n,s)=>n+s.rows_written,0),primary_results:databaseSamples.reduce((n,s)=>n+s.primary_results,0),replica_results:databaseSamples.reduce((n,s)=>n+s.replica_results,0),request_db_elapsed:stats(databaseSamples.map(s=>s.elapsed_ms)),request_sql_time:stats(databaseSamples.map(s=>s.query_ms))};
  receipt.status='measured';save();
  const {outageRehearsal}=await import('./nvd_capacity_rehearsal.mjs');
  receipt.status='outage_rehearsal';save();
  // Separate the measured scenarios by a fixed recovery window; retain every
  // baseline failure. This is not a retry of a failed customer request.
  await new Promise(resolve=>setTimeout(resolve,15000));
  receipt.outage=await outageRehearsal({base,tokens,controlKey,site:'verification/capacity-site/after',seconds:60,onProgress:result=>{receipt.outage=result;receipt.cvie_background_tested=result.phases.length===2;save();}});
  receipt.cvie_background_tested=true;
  assert.equal((await query('SELECT count(*) n FROM cvie_shared_advisories'))[0].results[0].n,200);
  assert.equal((await query('SELECT count(*) n FROM operations_leases'))[0].results[0].n,receipt.leases_before);
  // Preserve the failed baseline, but collect outage evidence before applying
  // the unchanged overall success criteria. A diagnostic run never hides errors.
  assert.equal(errors.length,0);assert.ok(completed>=50);assert.ok(receipt.request_latency.p95_ms<1000,'Request p95 exceeds 1 second');assert.ok(receipt.complete_customer_load.p95_ms<3000,'Complete customer read p95 exceeds 3 seconds');
  receipt.status='passed';receipt.completed_at=new Date().toISOString();save();console.log(JSON.stringify(receipt));
 }finally{
  try{await stopPreview(child);receipt.preview_stopped=true;save();}finally{fixture.close();}
  // Retain the named synthetic database for inspection. No existing resource
  // is deleted, reset, rebound, exposed or deployed by this executor.
 }
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))await cloudRehearsal();
