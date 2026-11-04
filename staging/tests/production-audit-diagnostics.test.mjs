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
  if(init.method==='POST')return Response.json({success:true,result:[{success:true,results:objects,meta:{rows_written:0}}]});
  if(String(url).endsWith('/content'))return new Response('var releaseIdentity="'+identity+'";');
  return Response.json({success:true,result:String(url).endsWith('/deployments')?deployment:{uuid:PRODUCTION_DB,name:'cveharbor-accounts'}});
 };
 return {calls,options:{transport,build:()=>expected,write:r=>{saved=r;}},saved:()=>saved};
}
function safe(report){const json=JSON.stringify(report);assert.doesNotMatch(json,new RegExp(sensitive+'|Authorization|Bearer|CREATE TABLE|https://'));}

for(const [index,operation] of ['d1.metadata','backend.deployments','frontend.deployments','d1.schema_select','backend.script_content','backend.deployment_recheck'].entries()){
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
  const h=harness(i=>mode==='target'&&i===0?Response.json({success:true,result:{uuid:sensitive,name:sensitive}}):mode==='writes'&&i===3?Response.json({success:true,result:[{success:true,results:objects,meta:{rows_written:1}}]}):null);
  const r=await runBaselineAudit(env,h.options);assert.equal(r.status,'failed');assert.equal(r.error.operation,mode==='target'?'d1.metadata':'d1.schema_no_writes');assert.equal(r.error.category,'validation_failed');safe(r);
 }
});
test('success and source mismatch retain existing verification behavior and the SELECT-only request boundary',async()=>{
 const h=harness();const r=await runBaselineAudit(env,h.options);assert.equal(r.status,'verified');assert.equal(r.rows_written,0);assert.equal(h.calls.filter(c=>c.method==='POST').length,1);assert.equal(h.calls.length,6);safe(r);
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
