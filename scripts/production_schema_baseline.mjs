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
export async function auditBaseline(env,expected,{transport=fetch}={}){
 const account=env.CLOUDFLARE_AUDIT_ACCOUNT_ID,token=env.CLOUDFLARE_AUDIT_API_TOKEN;
 assert.match(account||'',/^[a-f0-9]{32}$/);assert.notEqual(account,STAGING_ACCOUNT);assert.ok(token,'Audit credentials unavailable');
 assert.match(env.BASELINE_SOURCE_SHA||'',/^[a-f0-9]{40}$/);
 const base=`https://api.cloudflare.com/client/v4/accounts/${account}`;
 async function get(route){const r=await transport(base+route,{method:'GET',redirect:'error',signal:AbortSignal.timeout(20000),headers:{Authorization:'Bearer '+token}});const d=await r.json();assert.ok(r.ok&&d.success,'Read-only metadata request failed');return d.result;}
 const meta=await get('/d1/database/'+PRODUCTION_DB);assert.equal(meta.uuid,PRODUCTION_DB);assert.equal(meta.name,'cveharbor-accounts');
 const deployments=await get('/workers/scripts/cveharbor-accounts/deployments');
 const frontend=await get('/workers/scripts/cveharbor-site/deployments');
 const frontendActive=frontend?.deployments?.[0];assert.ok(frontendActive?.id&&frontendActive.versions?.length===1&&frontendActive.versions[0].percentage===100,'Unknown active frontend deployment');
 const active=deployments?.deployments?.[0];assert.ok(active?.id&&active.versions?.length===1&&active.versions[0].percentage===100,'Unknown active Worker deployment');
 const response=await transport(base+'/d1/database/'+PRODUCTION_DB+'/query',{method:'POST',redirect:'error',signal:AbortSignal.timeout(20000),headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({sql:schemaSQL})});
 const body=await response.json();assert.ok(response.ok&&body.success&&body.result?.length===1&&body.result[0].success,'Schema metadata read failed');
 assert.equal(body.result[0].meta?.rows_written,0,'Audit must write zero rows');
 const actual=canonical(body.result[0].results),schemaMatch=digest(actual)===expected.schema_sha256;
 // Read deployed script metadata/content only. The public readiness endpoint runs
 // integrity queries over application tables, so it is intentionally not used here.
 const scriptResponse=await transport(base+'/workers/scripts/cveharbor-accounts/content',{method:'GET',redirect:'error',signal:AbortSignal.timeout(20000),headers:{Authorization:'Bearer '+token}});
 assert.ok(scriptResponse.ok,'Deployed script content unavailable');
 const script=await scriptResponse.text();assert.ok(script.length<20000000,'Script exceeds audit limit');
 const matches=[...script.matchAll(/(?:var|const|let)\s+releaseIdentity\s*=\s*["']([a-f0-9]{64})["']/g)];
 const identity=matches.length===1?matches[0][1]:null;
 const after=await get('/workers/scripts/cveharbor-accounts/deployments');
 const stable=after?.deployments?.[0]?.id===active.id;
 const releaseMatch=stable&&identity===expected.backend_identity;
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
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{const root=process.env.BASELINE_SOURCE_ROOT;assert.ok(root,'Immutable production source checkout required');const result=await auditBaseline(process.env,expectedBaseline(root));fs.mkdirSync('release/artifacts',{recursive:true});fs.writeFileSync('release/artifacts/production-baseline.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({status:result.status,schema_verified:result.schema_verified,deployed_release_verified:result.deployed_release_verified,rows_written:0,customer_records_read:false}));if(result.status!=='verified')process.exitCode=1;}
 catch{console.error('Production metadata audit stopped; no records, SQL bodies or credentials logged.');process.exitCode=1;}
}
