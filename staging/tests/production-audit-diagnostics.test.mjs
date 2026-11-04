import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {runBaselineAudit,canonical,digest,PRODUCTION_DB,schemaSQL} from '../../scripts/production_schema_baseline.mjs';

const sensitive='PRIVATE_TOKEN_CUSTOMER_EMAIL_SQL_BODY_MUST_NOT_APPEAR';
const env={CLOUDFLARE_AUDIT_ACCOUNT_ID:'e'.repeat(32),CLOUDFLARE_AUDIT_API_TOKEN:sensitive,BASELINE_SOURCE_SHA:'a'.repeat(40),BASELINE_SOURCE_ROOT:'fixture'};
const identity='b'.repeat(64);
const objects=canonical([{type:'table',name:'fixture',tbl_name:'fixture',sql:'CREATE TABLE fixture(id TEXT)'}]);
const expected={objects,schema_sha256:digest(objects),backend_identity:identity,application_schema_files:[]};
const deployment={deployments:[{id:'active',versions:[{version_id:'version',percentage:100}]}]};
function harness(fault=()=>null){
 const calls=[];let saved;
 const transport=async(url,init)=>{
  assert.ok(String(url).startsWith('https://api.cloudflare.com/client/v4/accounts/'+'e'.repeat(32)+'/'));
  assert.equal(init.redirect,'error');
  assert.equal(init.headers.Authorization,'Bearer '+sensitive);
  if(init.method==='POST'){
   assert.ok(String(url).endsWith('/d1/database/'+PRODUCTION_DB+'/query'));
   assert.deepEqual(JSON.parse(init.body),{sql:schemaSQL});
  }else{assert.equal(init.method,'GET');assert.equal(init.body,undefined);}
  const i=calls.push({url:String(url),method:init.method})-1;
  const failure=fault(i);if(failure)return failure;
  if(init.method==='POST')return Response.json({success:true,result:[{success:true,results:[{type:'table',name:'fixture',tbl_name:'fixture',sql:'CREATE TABLE fixture(id TEXT)'}],meta:{rows_written:0}}]});
  if(String(url).endsWith('/content/v2'))return new Response('var releaseIdentity="'+identity+'";',{headers:{'Content-Type':'application/javascript','ETag':'"deployed-content"'}});
  if(String(url).endsWith('/versions/version'))return Response.json({success:true,result:{id:'version',resources:{script:{etag:'deployed-content'}}}});
  return Response.json({success:true,result:String(url).endsWith('/deployments')?deployment:{uuid:PRODUCTION_DB,name:'cveharbor-accounts'}});
 };
 return {calls,options:{transport,build:()=>expected,write:r=>{saved=r;}},saved:()=>saved};
}
function safe(report){const json=JSON.stringify(report);assert.doesNotMatch(json,new RegExp(sensitive+'|Authorization|Bearer|CREATE TABLE|https://'));}

for(const [index,operation] of ['d1.metadata','backend.deployments','frontend.deployments','d1.schema_select','backend.active_version','backend.script_content','backend.deployment_recheck'].entries()){
 test('writes a safe failure report for '+operation,async()=>{
  const h=harness(i=>i===index?Response.json({success:false,errors:[{code:10000,message:sensitive},{code:sensitive}]},{status:403}):null);
  const report=await runBaselineAudit(env,h.options);
  assert.equal(report.status,'failed');assert.deepEqual(report.error,{operation,category:'access_denied',http_status:403,cloudflare_error_codes:[10000]});
  assert.equal(report.remote_writes_requested,0);assert.equal(report.customer_records_read,false);assert.equal(report.schema_verified,false);
  assert.equal(report,h.saved());assert.equal(h.calls.length,index+1);safe(report);
 });
}
for(const [status,category] of [[401,'authentication_failed'],[404,'resource_not_found'],[429,'rate_limited'],[500,'provider_error'],[400,'http_error']]){
 test('HTTP '+status+' remains diagnostic even with a non-JSON error body',async()=>{
  const h=harness(()=>new Response(sensitive,{status}));const r=await runBaselineAudit(env,h.options);
  assert.equal(r.error.category,category);assert.equal(r.error.http_status,status);safe(r);
 });
}
for(const [kind,category] of [['json','invalid_json'],['api','api_error'],['network','network_error'],['timeout','timeout']]){
 test('sanitizes '+kind+' failure',async()=>{
  const h=harness(()=>{if(kind==='json')return new Response(sensitive);if(kind==='api')return Response.json({success:false,errors:[{code:10001,message:sensitive}]});const e=new Error(sensitive);e.name=kind==='timeout'?'TimeoutError':'TypeError';throw e;});
  const r=await runBaselineAudit(env,h.options);assert.equal(r.error.category,category);safe(r);
 });
}
test('local schema failures produce a report before any remote call',async()=>{
 const h=harness();const r=await runBaselineAudit(env,{...h.options,build:()=>{throw Object.assign(new Error(sensitive),{code:'ERR_SQLITE_ERROR'});}});
 assert.deepEqual(r.error,{operation:'source.schema_build',category:'local_schema_error'});assert.equal(h.calls.length,0);assert.equal(r,h.saved());safe(r);
});
test('invalid account configuration is not printed or sent remotely',async()=>{
 const h=harness();const r=await runBaselineAudit({...env,CLOUDFLARE_AUDIT_ACCOUNT_ID:sensitive},h.options);
 assert.deepEqual(r.error,{operation:'configuration.account_id',category:'validation_failed'});assert.equal(h.calls.length,0);safe(r);
});
test('target mismatch and nonzero write metadata still block the audit',async()=>{
 for(const mode of ['target','writes']){
  const h=harness(i=>mode==='target'&&i===0?Response.json({success:true,result:{uuid:sensitive,name:sensitive}}):mode==='writes'&&i===3?Response.json({success:true,result:[{success:true,results:[{type:'table',name:'fixture',tbl_name:'fixture',sql:'CREATE TABLE fixture(id TEXT)'}],meta:{rows_written:1}}]}):null);
  const r=await runBaselineAudit(env,h.options);assert.equal(r.status,'failed');assert.equal(r.error.operation,mode==='target'?'d1.metadata':'d1.schema_no_writes');assert.equal(r.error.category,'validation_failed');safe(r);
 }
});
test('success and source mismatch retain existing verification behavior and the SELECT-only request boundary',async()=>{
 const h=harness();const r=await runBaselineAudit(env,h.options);assert.equal(r.status,'verified');assert.equal(r.rows_written,0);assert.equal(h.calls.filter(c=>c.method==='POST').length,1);assert.equal(h.calls.length,7);safe(r);
 const bad=harness();const blocked=await runBaselineAudit(env,{...bad.options,build:()=>({...expected,backend_identity:'f'.repeat(64)})});assert.equal(blocked.status,'blocked');assert.equal(blocked.deployed_release_verified,false);assert.equal(blocked,bad.saved());
});
test('artifact write failure is sanitized and retains the original audit diagnostic',async()=>{
 const h=harness(()=>new Response(sensitive,{status:403}));const r=await runBaselineAudit(env,{...h.options,write:()=>{throw Object.assign(new Error(sensitive),{code:'EACCES'});}});
 assert.deepEqual(r.error,{operation:'report.write',category:'local_io_error'});assert.equal(r.audit_error.operation,'d1.metadata');safe(r);
});
test('CLI exits nonzero and writes the existing artifact path on early failure without exposing raw errors',()=>{
 const cwd=fs.mkdtempSync(path.join(os.tmpdir(),'audit-diagnostic-'));
 try{
  const script=fileURLToPath(new URL('../../scripts/production_schema_baseline.mjs',import.meta.url));
  const out=path.join(cwd,'stdout'),err=path.join(cwd,'stderr'),fds=[fs.openSync(out,'w'),fs.openSync(err,'w')];
  let child;try{child=spawnSync(process.execPath,[script],{cwd,stdio:['ignore',...fds],env:{PATH:process.env.PATH,BASELINE_SOURCE_ROOT:path.join(cwd,sensitive),CLOUDFLARE_AUDIT_API_TOKEN:sensitive}});}finally{fds.forEach(fd=>fs.closeSync(fd));}
  const stdout=fs.readFileSync(out,'utf8'),stderr=fs.readFileSync(err,'utf8');
  assert.equal(child.status,1);assert.doesNotMatch(stdout+stderr,new RegExp(sensitive));
  const report=JSON.parse(fs.readFileSync(path.join(cwd,'release/artifacts/production-baseline.json')));
  assert.deepEqual(report.error,{operation:'source.schema_build',category:'local_io_error'});assert.deepEqual(JSON.parse(stdout).error,report.error);safe(report);
 }finally{fs.rmSync(cwd,{recursive:true,force:true});}
});

test('content v2 is a raw response and the audit selects the deployed version by ID',async()=>{
 const h=harness();const r=await runBaselineAudit(env,h.options);assert.equal(r.status,'verified');
 assert.ok(h.calls.some(c=>c.method==='GET'&&c.url.endsWith('/workers/scripts/cveharbor-accounts/content/v2')));
 assert.ok(h.calls.some(c=>c.method==='GET'&&c.url.endsWith('/workers/scripts/cveharbor-accounts/versions/version')));
 assert.ok(h.calls.every(c=>!c.url.endsWith('/content')&&!c.url.endsWith('/versions/latest')));
 assert.equal(r.worker_version_id,'version');assert.equal(r.deployment_stable,true);
});
function multipart({entry='worker.mjs',includeEntry=true,duplicate=false,header=true}={}){
 const form=new FormData();
 form.append('helper.wasm',new Blob([new Uint8Array([0,97,115,109,255,254])],{type:'application/wasm'}),'helper.wasm');
 form.append('metadata',JSON.stringify({description:sensitive,decoy:'var releaseIdentity="'+'f'.repeat(64)+'";'}));
 form.append('unused.js',new Blob(['var releaseIdentity="'+'f'.repeat(64)+'";'],{type:'application/javascript+module'}),'unused.js');
 if(includeEntry)form.append(entry,new Blob(['var releaseIdentity="'+identity+'";'],{type:'application/javascript+module'}),entry);
 if(duplicate)form.append(entry,new Blob([sensitive]),entry);
 return new Response(form,{headers:{ETag:'"deployed-content"',...(header?{'cf-entrypoint':entry}:{})}});
}
test('multipart parsing uses only the declared entry module, not metadata or unrelated files',async()=>{
 for(const options of [{},{entry:'src/index.js',header:false}]){
  const h=harness(i=>i===5?multipart(options):null);const r=await runBaselineAudit(env,h.options);
  assert.equal(r.status,'verified');assert.equal(r.deployed_backend_identity,identity);safe(r);
 }
});
test('missing or duplicate multipart entrypoints and JSON envelopes fail safely',async()=>{
 for(const response of [()=>multipart({includeEntry:false}),()=>multipart({duplicate:true}),()=>Response.json({result:'var releaseIdentity="'+identity+'";',message:sensitive})]){
  const h=harness(i=>i===5?response():null);const r=await runBaselineAudit(env,h.options);
  assert.equal(r.status,'failed');assert.equal(r.error.operation,'backend.script_content');assert.equal(r.error.category,'invalid_content_format');safe(r);
 }
});
test('malformed multipart boundaries retain sanitized read diagnostics',async()=>{
 const h=harness(i=>i===5?new Response(sensitive,{headers:{'Content-Type':'multipart/form-data; boundary=missing','ETag':'"deployed-content"'}}):null);
 const r=await runBaselineAudit(env,h.options);assert.equal(r.status,'failed');assert.equal(r.error.operation,'backend.script_content');assert.equal(r.error.category,'response_read_failed');safe(r);
});
test('latest uploaded content cannot pass as deployed code; missing or weak ETags also fail closed',async()=>{
 for(const etag of [null,'"latest-upload-only"','W/"deployed-content"','""']){
  const h=harness(i=>i===5?new Response('var releaseIdentity="'+identity+'"; '+sensitive,{headers:{'Content-Type':'text/javascript',...(etag?{ETag:etag}:{})}}):null);
  const r=await runBaselineAudit(env,h.options);assert.equal(r.status,'failed');assert.equal(r.error.operation,'backend.content_version_match');assert.equal(r.error.category,'validation_failed');safe(r);
 }
});
test('active version identity must match and its script hash must be available',async()=>{
 for(const version of [{id:'wrong-version',resources:{script:{etag:'deployed-content'}}},{id:'version',resources:{}}]){
  const h=harness(i=>i===4?Response.json({success:true,result:version}):null);const r=await runBaselineAudit(env,h.options);
  assert.equal(r.status,'failed');assert.equal(r.error.operation,version.id==='version'?'backend.content_version_match':'backend.active_version');safe(r);
 }
});
test('deployment or traffic changes during content retrieval cannot verify the release',async()=>{
 for(const current of [
  {id:'new-deployment',versions:[{version_id:'version',percentage:100}]},
  {id:'active',versions:[{version_id:'other',percentage:100}]},
  {id:'active',versions:[{version_id:'version',percentage:50},{version_id:'other',percentage:50}]},
  {id:'active',versions:[{version_id:'version',percentage:0}]},
 ]){
  const h=harness(i=>i===6?Response.json({success:true,result:{deployments:[current]}}):null);const r=await runBaselineAudit(env,h.options);
  assert.equal(r.status,'blocked');assert.equal(r.deployment_stable,false);assert.equal(r.deployed_release_verified,false);safe(r);
 }
});

test('active version flags expose only allowlisted boolean configuration, never binding secrets',async()=>{
 const {runtimeFlags}=await import('../../scripts/production_schema_baseline.mjs');
 const r=runtimeFlags({resources:{bindings:[{name:'RECOVERY_CONTROL_REQUIRED',type:'plain_text',text:'false'},{name:'CVIE_REGISTRY_ENABLED',type:'secret_text',text:sensitive},{name:'SMTP2GO_API_KEY',type:'secret_text',text:sensitive},{name:'EMAIL_FROM',type:'plain_text',text:sensitive}]}});
 assert.equal(r.available,true);assert.equal(r.values.RECOVERY_CONTROL_REQUIRED,'false');assert.equal(r.values.CVIE_REGISTRY_ENABLED,'unverified');assert.equal(r.values.CVIE_FAST_EVIDENCE_ENABLED,null);
 assert.doesNotMatch(JSON.stringify(r),new RegExp(sensitive+'|SMTP2GO|EMAIL_FROM'));
 assert.deepEqual(runtimeFlags({}),{available:false,values:{}});
});
