// Metadata only: no arbitrary SQL, application record reads, exports or writes.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {fileURLToPath} from 'node:url';
import {forwardMigrations} from './release_migrations.mjs';
import {backendIdentity} from './build_release_identity.mjs';
import {normalizedDDL,recoveryTablesSQL,recoveryGuardSQL} from '../account-backend/src/recovery-schema.js';
export const PRODUCTION_DB='46710e51-7ca4-4571-b89c-921b9969de0b';
export const STAGING_ACCOUNT='9706b4d98ad72884e67fd1eb875c8a61';
export const schemaSQL="SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' AND name NOT GLOB '_cf_*' AND name NOT GLOB 'd1_*' ORDER BY type,name";
export const digest=x=>createHash('sha256').update(typeof x==='string'?x:JSON.stringify(x)).digest('hex');
export const canonical=rows=>rows.map(r=>({type:r.type,name:r.name,tbl_name:r.tbl_name,sql:normalizedDDL(r.sql)})).sort((a,b)=>(a.type+'\0'+a.name).localeCompare(b.type+'\0'+b.name));
export function expectedBaseline(sourceRoot, manifestRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..')){
 const manifest=JSON.parse(fs.readFileSync(path.join(manifestRoot,'staging/migrations.v1.json')));
 const files=manifest.entries.filter(e=>e.path.startsWith('account-backend/')&&fs.existsSync(path.join(sourceRoot,e.path)));
 const db=new DatabaseSync(':memory:');
 try{
  for(const e of files){const sql=fs.readFileSync(path.join(sourceRoot,e.path),'utf8');assert.equal(digest(sql),e.sha256,'Production source differs from the reviewed historical manifest');db.exec(sql);}
  if(fs.existsSync(path.join(sourceRoot,'release/migrations')))for(const f of forwardMigrations(sourceRoot))db.exec(f.sql);
  if(files.some(e=>e.path.endsWith('0032_recovery_control.sql')))for(const {name} of db.prepare(recoveryTablesSQL).all())for(const op of ['insert','update','delete'])db.exec(recoveryGuardSQL(name,op));
  const objects=canonical(db.prepare(schemaSQL).all());
  return {backend_identity:backendIdentity(sourceRoot),schema_sha256:digest(objects),objects,application_schema_files:files.map(e=>({path:e.path,sha256:e.sha256}))};
 }finally{db.close();}
}
// Only fixed operation labels/categories and numeric HTTP/provider codes may be logged.
class AuditRequestError extends Error {
 constructor(category,status,codes=[]){super(category);this.category=category;this.http_status=status;this.cloudflare_error_codes=codes;}
}
function safeFailure(error,operation){
 const category=error instanceof AuditRequestError?error.category:
  error?.code==='ERR_ASSERTION'?'validation_failed':
  error?.code==='ERR_SQLITE_ERROR'?'local_schema_error':
  ['ENOENT','EACCES','EPERM','EROFS','ENOSPC'].includes(error?.code)?'local_io_error':
  error?.name==='SyntaxError'?'invalid_json':
  ['TimeoutError','AbortError'].includes(error?.name)?'timeout':'internal_error';
 return {operation,category,...(error instanceof AuditRequestError?{http_status:error.http_status,cloudflare_error_codes:error.cloudflare_error_codes}:{})};
}
export async function auditBaseline(env,expected,{transport=fetch,progress=()=>{}}={}){
 const account=env.CLOUDFLARE_AUDIT_ACCOUNT_ID,token=env.CLOUDFLARE_AUDIT_API_TOKEN;
 progress('configuration.account_id');assert.match(account||'',/^[a-f0-9]{32}$/);assert.notEqual(account,STAGING_ACCOUNT);
 progress('configuration.api_token');assert.ok(token,'Audit credentials unavailable');
 progress('configuration.source_sha');assert.match(env.BASELINE_SOURCE_SHA||'',/^[a-f0-9]{40}$/);
 const base=`https://api.cloudflare.com/client/v4/accounts/${account}`;
 async function request(operation,route,{sql,content=false}={}){
  progress(operation);
  let r;
  try{r=await transport(base+route,{method:sql?'POST':'GET',redirect:'error',signal:AbortSignal.timeout(20000),headers:{Authorization:'Bearer '+token,...(sql?{'Content-Type':'application/json'}:{})},...(sql?{body:JSON.stringify({sql})}:{})});}
  catch(error){throw new AuditRequestError(['TimeoutError','AbortError'].includes(error?.name)?'timeout':'network_error',null);}
  let body;
  try{body=content&&r.ok?await r.text():await r.json();}
  catch(error){
   if(r.ok)throw new AuditRequestError(['TimeoutError','AbortError'].includes(error?.name)?'timeout':content?'response_read_failed':'invalid_json',r.status);
  }
  const codes=Array.isArray(body?.errors)?body.errors.map(e=>e?.code).filter(c=>Number.isSafeInteger(c)&&c>=0&&c<=2147483647).slice(0,8):[];
  if(!r.ok)throw new AuditRequestError(r.status===401?'authentication_failed':r.status===403?'access_denied':r.status===404?'resource_not_found':r.status===429?'rate_limited':r.status>=500?'provider_error':'http_error',r.status,codes);
  if(!content&&body?.success!==true)throw new AuditRequestError('api_error',r.status,codes);
  return content?body:body.result;
 }
 const get=(operation,route)=>request(operation,route);
 const meta=await get('d1.metadata','/d1/database/'+PRODUCTION_DB);assert.equal(meta.uuid,PRODUCTION_DB);assert.equal(meta.name,'cveharbor-accounts');
 const deployments=await get('backend.deployments','/workers/scripts/cveharbor-accounts/deployments');
 const frontend=await get('frontend.deployments','/workers/scripts/cveharbor-site/deployments');
 progress('frontend.deployment_shape');
 const frontendActive=frontend?.deployments?.[0];assert.ok(frontendActive?.id&&frontendActive.versions?.length===1&&frontendActive.versions[0].percentage===100,'Unknown active frontend deployment');
 progress('backend.deployment_shape');
 const active=deployments?.deployments?.[0];assert.ok(active?.id&&active.versions?.length===1&&active.versions[0].percentage===100,'Unknown active Worker deployment');
 const results=await request('d1.schema_select','/d1/database/'+PRODUCTION_DB+'/query',{sql:schemaSQL});
 assert.ok(results?.length===1&&results[0].success,'Schema metadata read failed');
 progress('d1.schema_no_writes');assert.equal(results[0].meta?.rows_written,0,'Audit must write zero rows');
 progress('d1.schema_compare');
 const actual=canonical(results[0].results),schemaMatch=digest(actual)===expected.schema_sha256;
 // Read deployed script metadata/content only. The public readiness endpoint runs
 // integrity queries over application tables, so it is intentionally not used here.
 const script=await request('backend.script_content','/workers/scripts/cveharbor-accounts/content',{content:true});
 progress('backend.script_identity');assert.ok(script.length<20000000,'Script exceeds audit limit');
 const matches=[...script.matchAll(/(?:var|const|let)\s+releaseIdentity\s*=\s*["']([a-f0-9]{64})["']/g)];
 const identity=matches.length===1?matches[0][1]:null;
 const after=await get('backend.deployment_recheck','/workers/scripts/cveharbor-accounts/deployments');
 const stable=after?.deployments?.[0]?.id===active.id;
 const releaseMatch=stable&&identity===expected.backend_identity;
 progress('baseline.compare');
 const names=new Map(expected.objects.map(o=>[o.type+':'+o.name,o]));
 const differences=actual.filter(o=>JSON.stringify(o)!==JSON.stringify(names.get(o.type+':'+o.name))).map(o=>({type:o.type,name:o.name}));
 const missing=expected.objects.filter(o=>!actual.some(a=>a.type===o.type&&a.name===o.name)).map(o=>({type:o.type,name:o.name}));
 return {version:1,status:schemaMatch&&releaseMatch?'verified':'blocked',source_sha:env.BASELINE_SOURCE_SHA,
  production_database_id:PRODUCTION_DB,frontend_deployment_id:frontendActive.id,frontend_version_id:frontendActive.versions[0].version_id,worker_deployment_id:active.id,worker_version_id:active.versions[0].version_id,
  backend_identity:expected.backend_identity,deployed_backend_identity:identity,version_evidence:'deployed-script-releaseIdentity',deployment_stable:stable,
  deployed_release_verified:releaseMatch,schema_verified:schemaMatch,schema_sha256:digest(actual),
  application_schema_files:expected.application_schema_files,objects:actual.map(({type,name,tbl_name,sql})=>({type,name,tbl_name,definition_sha256:digest(sql)})),
  differences,missing,rows_written:0,customer_records_read:false,captured_at:new Date().toISOString()};
}
export async function runBaselineAudit(env,{transport=fetch,build=expectedBaseline,write=report=>{
 fs.mkdirSync('release/artifacts',{recursive:true});
 fs.writeFileSync('release/artifacts/production-baseline.json',JSON.stringify(report,null,2)+'\n');
}}={}){
 let operation='source.configuration',report;
 try{
  const root=env.BASELINE_SOURCE_ROOT;assert.ok(root,'Immutable production source checkout required');
  operation='source.schema_build';const expected=build(root);
  report=await auditBaseline(env,expected,{transport,progress:value=>{operation=value;}});
 }catch(error){
  report={version:1,status:'failed',schema_verified:false,deployed_release_verified:false,customer_records_read:false,
   remote_writes_requested:0,error:safeFailure(error,operation)};
 }
 try{write(report);}catch(error){
  // Still provide a safe console diagnostic if the artifact directory is unwritable.
  return {status:'failed',error:safeFailure(error,'report.write'),...(report.error?{audit_error:report.error}:{})};
 }
 return report;
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 const result=await runBaselineAudit(process.env);
 console.log(JSON.stringify({status:result.status,schema_verified:result.schema_verified,deployed_release_verified:result.deployed_release_verified,
  rows_written:result.rows_written,customer_records_read:result.customer_records_read,...(result.error?{error:result.error}:{}),...(result.audit_error?{audit_error:result.audit_error}:{})}));
 if(result.status!=='verified')process.exitCode=1;
}
