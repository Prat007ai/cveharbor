// Separate operator-run adapter. No production executor import, target override,
// resource creation, export, restore, reset, resume, deployment or retry path.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {artifacts,account,cases,names,denied,marker,markerSQL,driftSQL,syntheticCounts} from './artifacts.mjs';
import {privateLog} from './private-log.mjs';
import {verifyStorage} from './storage-policy.mjs';
import {folder as productionFolder,target,receiptTable,originalTables,quote,verifyFiles} from '../build.mjs';
import {digest,canonical,schemaSQL} from '../../../../../scripts/production_schema_baseline.mjs';
import {integrityChecks} from '../../../../../account-backend/src/release-integrity-checks.js';
const uuid=x=>assert.match(x||'',/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
const hash=x=>assert.match(x||'',/^[a-f0-9]{64}$/);
const sql=name=>fs.readFileSync(path.join(productionFolder,name+'.sql'),'utf8');
const phases=['inventory','claim','perturb','install','reconcile'];
export function authorize(env,p,scenario,phase,now=Date.now()){
 assert.ok(cases.includes(scenario)&&phases.includes(phase));
 assert.equal(p.version,1);uuid(p.approval_id);assert.equal(digest(p),env.REHEARSAL_APPROVAL_SHA256);
 assert.match(p.source_sha||'',/^[a-f0-9]{40}$/);assert.equal(p.source_sha,env.REHEARSAL_SOURCE_SHA);
 assert.equal(p.account,account);assert.equal(env.CLOUDFLARE_ACCOUNT_ID,account);
 assert.equal(p.manifest_sha256,artifacts().sha256);assert.equal(p.production_manifest_sha256,verifyFiles().sha256);
 assert.ok(Number.isSafeInteger(p.not_before)&&Number.isSafeInteger(p.expires_at)&&p.expires_at>p.not_before&&p.expires_at-p.not_before<=14400);
 if(phase!=='reconcile')assert.ok(now/1000>=p.not_before&&now/1000<=p.expires_at,'Approval expired');
 assert.deepEqual(Object.keys(p.resources).sort(),[...cases].sort());
 const ids=[];for(const c of cases){const r=p.resources[c];uuid(r.uuid);assert.ok(!denied.includes(r.uuid));ids.push(r.uuid);assert.equal(r.name,names[c]);hash(r.creation_receipt_sha256);}
 assert.equal(new Set(ids).size,cases.length,'One fresh database per case');
 for(const key of ['private_storage_verified','no_bindings_or_delivery_credentials','external_writers_excluded','cost_and_quota_checked'])assert.equal(p[key],true);
 assert.equal(p.private_destination,target.private_destination);assert.equal(p.max_incremental_usd,5);assert.equal(p.max_total_bytes,1000000000);assert.equal(p.max_rows_written,1000000);
 verifyStorage(p.storage_evidence,target.private_destination);
 if(!['inventory','reconcile'].includes(phase)){
  assert.equal(env.REHEARSAL_ENABLED,'true');hash(p.resources[scenario].counts_sha256);hash(p.resources[scenario].isolation_sha256);hash(p.recovery_evidence_sha256);
  if(scenario!=='success'){assert.equal(p.resources[scenario].counts_sha256,digest(syntheticCounts()));assert.equal(p.resources[scenario].fixture_sql_sha256,artifacts().manifest.synthetic_sql_sha256);}
 }
 return p.resources[scenario];
}
export function client(env,p,scenario,{fetcher=fetch,log=()=>{},clock=Date.now}={}){
 const resource=p.resources[scenario],base='https://api.cloudflare.com/client/v4/accounts/'+account,db='/d1/database/'+resource.uuid;
 assert.ok(env.CLOUDFLARE_API_TOKEN);assert.equal(p.account,account);assert.equal(env.CLOUDFLARE_ACCOUNT_ID,account);
 assert.ok(!denied.includes(resource.uuid));uuid(resource.uuid);assert.equal(resource.name,names[scenario]);
 async function request(route,{query,mode}={}){
  assert.ok(query?route===db+'/query':route===db||/^\/workers\/scripts(?:\?page=\d+&per_page=100|\/[^/?]+\/(?:settings|deployments|versions\/[a-f0-9-]+))$/.test(route)||/^\/pages\/projects\?page=\d+&per_page=100$/.test(route));
  const started=clock();log({kind:'request',at:new Date(started).toISOString(),method:query?'POST':'GET',route,sql_sha256:query?digest(query.sql):null,simulation:mode||null});
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),mode==='interrupt'?1:60000);
  let response,body;try{
   response=await fetcher(base+route,{method:query?'POST':'GET',redirect:'error',signal:controller.signal,headers:{Authorization:'Bearer '+env.CLOUDFLARE_API_TOKEN,...(query?{'Content-Type':'application/json'}:{})},...(query?{body:JSON.stringify(query)}:{})});
   body=await response.json();
  }catch{log({kind:'transport-uncertain',at:new Date(clock()).toISOString(),simulation:mode||null});throw Error('Outcome uncertain; reconcile only');}
  finally{clearTimeout(timer);}
  // Only sanitized provider metadata. No SQL, row values, URLs or raw errors.
  log({kind:'response',at:new Date(clock()).toISOString(),http:response.status,cf_ray:response.headers.get('cf-ray'),success:body.success===true,simulation:mode||null,usage:query&&Array.isArray(body.result)?body.result.map(r=>({success:r.success,rows_read:r.meta?.rows_read,rows_written:r.meta?.rows_written,duration:r.meta?.duration})):null});
  if(mode==='lost')throw Error('Simulated lost reply after provider response; reconcile only');
  assert.ok(response.ok&&body.success===true,'Provider rejected request; reconcile only');
  if(query)assert.ok(Array.isArray(body.result)&&body.result.length&&body.result.every(r=>r.success===true),'Incomplete batch; reconcile only');
  return body;
 }
 async function select(text,params=[]){assert.ok(/^SELECT\b/.test(text)&&!text.includes(';'));const b=await request(db+'/query',{query:{sql:text,params}});assert.equal(b.result.length,1);assert.equal(b.result[0].meta?.rows_written,0);return b.result[0].results;}
 async function list(route){const all=[];for(let page=1;page<=100;page++){const b=await request(route+'?page='+page+'&per_page=100');assert.ok(Array.isArray(b.result));all.push(...b.result);if(b.result_info?.total_pages){if(page===b.result_info.total_pages)return all;}else if(b.result.length<100)return all;}throw Error('Incomplete isolation inventory');}
 async function isolation(){
  const metadata=(await request(db)).result;assert.equal(metadata.uuid,resource.uuid);assert.equal(metadata.name,resource.name);
  assert.ok(Number.isFinite(Date.parse(metadata.created_at)),'Creation metadata unavailable');
  assert.equal(digest({account,uuid:metadata.uuid,name:metadata.name,created_at:metadata.created_at}),resource.creation_receipt_sha256,'Creation receipt mismatch');
  assert.ok(Number.isSafeInteger(metadata.file_size)&&metadata.file_size<=p.max_total_bytes);
  const observations=[];
  for(const w of (await list('/workers/scripts')).sort((a,b)=>a.id.localeCompare(b.id))){
   const route='/workers/scripts/'+encodeURIComponent(w.id);
   const settings=(await request(route+'/settings')).result,deployments=(await request(route+'/deployments')).result;
   assert.ok(Array.isArray(settings.bindings)&&Array.isArray(deployments.deployments));
   const active=deployments.deployments[0];if(active)assert.ok(Array.isArray(active.versions)&&active.versions.length>0,'Incomplete active deployment inventory');
   const versions=[];for(const v of active?.versions||[]){uuid(v.version_id);const version=(await request(route+'/versions/'+v.version_id)).result;assert.equal(version.id,v.version_id);assert.ok(Array.isArray(version.resources?.bindings),'Incomplete active version bindings');versions.push(version);}
   assert.ok(!JSON.stringify({settings,versions}).includes(resource.uuid),'Worker binding detected');observations.push({id:w.id,settings,versions});
  }
  const projects=(await list('/pages/projects')).sort((a,b)=>a.name.localeCompare(b.name));
  for(const project of projects){assert.ok(project.deployment_configs&&['production','preview'].every(k=>project.deployment_configs[k]&&typeof project.deployment_configs[k]==='object'&&!Array.isArray(project.deployment_configs[k])),'Incomplete Pages isolation evidence');assert.ok(!JSON.stringify(project.deployment_configs).includes(resource.uuid),'Pages binding detected');}
  return {uuid:metadata.uuid,name:metadata.name,isolation_sha256:digest({workers:observations,pages:projects.map(x=>({name:x.name,deployment_configs:x.deployment_configs}))})};
 }
 return {select,isolation,write:(text,params=[],mode)=>request(db+'/query',{query:{sql:text,params},mode})};
}
export async function snapshot(c){
 const rows=await c.select(schemaSQL),schema_sha256=digest(canonical(rows)),counts={};
 for(const t of originalTables())counts[t]=Number((await c.select('SELECT COUNT(*) n FROM '+quote(t)))[0].n);
 const integrity={};for(const [k,q]of Object.entries(integrityChecks))integrity[k]=Number((await c.select(q))[0].n);
 integrity.foreign_keys=Number((await c.select('SELECT COUNT(*) n FROM pragma_foreign_key_check'))[0].n);
 assert.ok(Object.values(integrity).every(n=>n===0),'Integrity failed');
 return {schema_rows:rows,schema_sha256,counts,integrity};
}
export async function run(env,p,scenario,phase,{fetcher,clock=Date.now,journal}={}){
 const r=authorize(env,p,scenario,phase,clock());assert.ok(journal?.append&&journal?.claim,'Durable private log required');
 const log=e=>journal.append({approval_id:p.approval_id,scenario,phase,...e});
 const c=client(env,p,scenario,{fetcher,clock,log});
 const i=await c.isolation();log({kind:'isolation',...i});
 if(phase==='inventory')return i;
 if(phase!=='reconcile')assert.equal(i.isolation_sha256,r.isolation_sha256,'Isolation drift');
 const s=await snapshot(c);
 const definitions=await c.select("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name GLOB 'd1_*' AND sql IS NOT NULL ORDER BY type,name");
 const has=name=>definitions.some(x=>x.name===name&&x.type==='table');
 const receipts=has(receiptTable)?await c.select('SELECT id,payload FROM '+receiptTable+' ORDER BY id'):[];
 const attempts=has(marker)?await c.select('SELECT id,payload FROM '+marker+' ORDER BY id'):[];
 const plan=JSON.stringify({approval_sha256:digest(p),scenario,database:r.uuid,manifest_sha256:p.manifest_sha256});
 if(phase==='reconcile'){
  const control=s.schema_rows.some(x=>x.name==='operations_control')?await c.select('SELECT write_hold,database_frozen,revision FROM operations_control WHERE id=1'):[];
  const leases=s.schema_rows.some(x=>x.name==='operations_leases')?Number((await c.select('SELECT COUNT(*) n FROM operations_leases'))[0].n):null;
  const contexts=s.schema_rows.some(x=>x.name==='remediation_finding_write_context')?Number((await c.select('SELECT COUNT(*) n FROM remediation_finding_write_context'))[0].n):null;
  const report={kind:'reconciliation',schema_sha256:s.schema_sha256,counts_sha256:digest(s.counts),baseline_counts_match:digest(s.counts)===r.counts_sha256,installed_schema_match:s.schema_sha256===target.installed_schema_sha256,integrity:s.integrity,definition_sha256:digest(canonical(definitions)),receipt_ids:receipts.map(x=>x.id),receipts_sha256:digest(receipts),receipt_payloads_match:receipts.length>0&&receipts.every(x=>x.payload===receipts[0].payload),attempt_ids:attempts.map(x=>x.id),attempts_sha256:digest(attempts),control,leases,contexts,remote_atomicity_established:false};
  log(report);return report;
 }
 // Source/artifact/target checks ran before this phase. Recheck the immutable
 // approval pin, enable flag and window before each request without serializing
 // the deliberate two-request race behind repeated local artifact generation.
 const fresh=()=>{assert.equal(digest(p),env.REHEARSAL_APPROVAL_SHA256);assert.equal(env.REHEARSAL_ENABLED,'true');assert.ok(clock()/1000>=p.not_before&&clock()/1000<=p.expires_at,'Approval expired');};
 const write=async(q,params=[],mode)=>{fresh();log({kind:'write-intent',sql_sha256:digest(q),params_sha256:digest(params)});return c.write(q,params,mode);};
 // Claim locally before any write, then permanently in D1. Never remove either.
 try{
  if(phase==='claim'){
   assert.equal(s.schema_sha256,target.baseline_schema_sha256);assert.equal(digest(s.counts),r.counts_sha256);assert.equal(definitions.length,0,'Not a fresh restored/fixture baseline');
   if(scenario!=='success')assert.equal(Number((await c.select("SELECT COUNT(*) n FROM users WHERE id='pr270-fictional' AND email='pr270-fictional@example.invalid'"))[0].n),1);
   journal.claim(phase);
   await write(markerSQL);await write(`INSERT INTO ${marker}(id,payload) VALUES('plan',?)`,[plan]);
   await write(sql('bootstrap'));
   const time=Number((await c.select("SELECT CAST(strftime('%s','now') AS INTEGER) n"))[0].n);assert.ok(Number.isSafeInteger(time));
   const payload=JSON.stringify({operation:'install',not_before:Math.max(time-1,p.not_before),expires_at:Math.min(p.expires_at,time+(scenario==='expiry'?15:1800)),schema_rows:s.schema_rows,counts:s.counts,rehearsal:true,approval_id:p.approval_id,manifest_sha256:p.production_manifest_sha256,rehearsal_manifest_sha256:p.manifest_sha256,source_sha:p.source_sha,database:r.uuid,account,scenario,recovery_evidence_sha256:p.recovery_evidence_sha256});
   await write(`INSERT INTO ${receiptTable}(id,payload) VALUES('install-intent',?)`,[payload]);
   if(scenario!=='rejected')await write(sql('install-start'));
   log({kind:'claim-complete',counts_sha256:digest(s.counts)});return {status:'claimed'};
  }
  assert.equal(attempts.find(x=>x.id==='plan')?.payload,plan,'Missing/mismatched durable plan');
  assert.ok(!attempts.some(x=>x.id==='install'),'Installation already attempted; reconcile only');
  const expected=scenario==='rejected'?['install-intent']:['install-intent','install-started'];assert.deepEqual(receipts.map(x=>x.id),expected);
  if(receipts.length===2)assert.equal(receipts[0].payload,receipts[1].payload);
  const payload=JSON.parse(receipts[0].payload);assert.equal(payload.approval_id,p.approval_id);assert.equal(payload.database,r.uuid);assert.equal(payload.rehearsal_manifest_sha256,p.manifest_sha256);
  if(phase==='perturb'){
   assert.ok(['schema','count'].includes(scenario));assert.ok(!attempts.some(x=>x.id==='perturb'));assert.equal(s.schema_sha256,target.baseline_schema_sha256);assert.equal(digest(s.counts),r.counts_sha256);
   journal.claim(phase);await write(`INSERT INTO ${marker}(id,payload) VALUES('perturb',?)`,[plan]);await write(driftSQL[scenario]);return {status:'perturbed'};
  }
  assert.equal(phase,'install');
  if(['schema','count'].includes(scenario))assert.ok(attempts.some(x=>x.id==='perturb'),'Perform separately approved perturbation first');
  if(scenario==='expiry'){const time=Number((await c.select("SELECT CAST(strftime('%s','now') AS INTEGER) n"))[0].n);assert.ok(time>payload.expires_at,'Wait for DB clock expiry; no injected remote clock');}
  assert.equal((await c.isolation()).isolation_sha256,r.isolation_sha256);
  log({kind:'before-install',schema_sha256:s.schema_sha256,counts_sha256:digest(s.counts),receipts_sha256:digest(receipts)});
  journal.claim(phase);
  await write(`INSERT INTO ${marker}(id,payload) VALUES('install',?)`,[plan]);
  // Exact unchanged production batch. No rewritten clocks, table names or targets.
  if(scenario==='race'){
   const outcomes=await Promise.allSettled([write(sql('install')),write(driftSQL.count)]);
   log({kind:'concurrent-requests-settled',outcomes:outcomes.map(x=>x.status),ordering_proven:false});
   throw Error('Concurrent outcome requires independent reconciliation');
  }
  await write(sql('install'),[],['interrupt','lost'].includes(scenario)?scenario:undefined);
  log({kind:'batch-acknowledged',verification_required:true});return {status:'acknowledged-reconcile-required'};
 }catch{
  log({kind:'stopped-reconcile-only',automatic_retry:false,automatic_reset:false});
  throw Error('STOP: reconcile read-only; never retry, reset, resume or roll back');
 }
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const [scenario,phase,approvalPath,directory]=process.argv.slice(2);assert.equal(process.argv.length,6);
  const p=JSON.parse(fs.readFileSync(approvalPath));
  const source=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
  assert.equal(execFileSync('git',['status','--porcelain','--untracked-files=no'],{encoding:'utf8'}).trim(),'','Clean reviewed checkout required');
  const env={...process.env,REHEARSAL_SOURCE_SHA:source};
  authorize(env,p,scenario,phase);const journal=privateLog(directory,p.approval_id,scenario);
  await run(env,p,scenario,phase,{journal});console.log('Operation recorded privately. Reconciliation/independent review required; no production authorization.');
 }catch{console.error('STOP: rehearsal blocked or outcome uncertain. Preserve private evidence; reconcile only.');process.exitCode=1;}
}
