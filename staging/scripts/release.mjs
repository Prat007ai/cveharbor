// Existing resources only. No create/delete endpoints, arbitrary SQL, production fallback or automatic rollback.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {TARGET} from '../target.mjs';
import {root,writeConfigs,configs} from './configure.mjs';
import {resourceManifest} from './inventory.mjs';
import {preflight} from './preflight.mjs';
import {diagnose,inspectWorker,management} from './diagnose.mjs';
import {probeAccess} from './probe-access.mjs';
import {migrate,loadMigrationPlan,verifySchema,migrationState} from './migrate.mjs';
import {hash} from './schema.mjs';
import {d1Client} from '../../scripts/cloudflare_d1.mjs';
import {diagnoseSchema,loadDiagnosticReference} from './schema-diagnostic.mjs';
import {adoptSchema,loadAdoption} from './adopt-schema.mjs';
import {holdStatus,setHold,freezeHold} from '../../scripts/recovery_control.mjs';
export const OPERATIONS=Object.freeze(['diagnose-schema','adopt-schema','publish-synthetic','verify','migrate','update','recover-code','hold','freeze','resume']);
export function authorize(env,event,checkout){
 assert.equal(env.GITHUB_REPOSITORY,'Prat007ai/cveharbor');assert.equal(env.GITHUB_REF,'refs/heads/codex/cvie-core-phase012');
 assert.match(env.CF_STAGING_APPROVED_COMMIT||'',/^[a-f0-9]{40}$/);assert.equal(env.GITHUB_SHA,env.CF_STAGING_APPROVED_COMMIT);assert.equal(checkout,env.GITHUB_SHA);
 const action=env.CF_STAGING_PROVISION_ACTION;assert.ok(OPERATIONS.includes(action));
 assert.ok(env.GITHUB_EVENT_NAME==='workflow_dispatch'?event.inputs?.operation===action:env.GITHUB_EVENT_NAME==='push'&&Number(env.GITHUB_RUN_ATTEMPT)>1&&event.head_commit?.id===checkout&&event.head_commit?.message?.includes('[staging-release]'),'Explicit reviewed operation required');
 assert.equal(env.CF_STAGING_ACCOUNT_ID,TARGET.account);assert.equal(env.CF_STAGING_D1_DATABASE_ID,resourceManifest().permanent_database.uuid);
 if(action==='diagnose-schema')loadDiagnosticReference(env);
 if(action==='adopt-schema'){assert.ok(!env.CF_STAGING_SCHEMA_RESUME_STEP,'Adoption does not accept a resume cursor');loadAdoption(env);}
 if(action==='migrate'){assert.match(env.CF_STAGING_SCHEMA_PLAN_SHA256||'',/^[a-f0-9]{64}$/);assert.match(env.CF_STAGING_SCHEMA_RESUME_STEP||'',/^(0|[1-9]\d*)$/);loadMigrationPlan(env);}
 if(['hold','freeze','resume'].includes(action)){assert.match(env.CF_STAGING_EXPECTED_HOLD_REVISION||'',/^\d+$/);assert.ok((env.CF_STAGING_RECOVERY_REASON||'').length>=10&&(env.CF_STAGING_RECOVERY_REASON||'').length<=500);}
 return action;
}
export function acceptPreflight(report){
 assert.equal(report.account,TARGET.account);assert.equal(report.read_only_checks_passed,true);assert.equal(report.blockers.length,0);
 assert.equal(report.checks.find(c=>c.name==='service_token_matches_policy_and_client')?.status,'pass');
 const grants=report.checks.find(c=>c.name==='token_permission_grants'),scope=report.checks.find(c=>c.name==='token_staging_only_scope');
 if(grants?.status==='pass'&&scope?.status==='pass')return;
 const a=JSON.parse(fs.readFileSync(path.join(root,'../docs/cvie-evidence/staging-owner-attestation.json'),'utf8'));
 assert.ok(a.evidence_type==='manual_account_owner_verification'&&a.account_id===TARGET.account&&a.scope_confirmed==='Restricted exclusively to the CVEHarbor Staging account'&&grants?.metadata_available===false&&grants.http_status===403&&scope?.metadata_available===false,'Token scope must be verified; conflicting scope is never accepted');
}
export async function probeBackend(env,transport=fetch,{held=false}={}){
 const response=await transport(TARGET.origin+'/v1/staging-readiness',{method:'GET',redirect:'manual',signal:AbortSignal.timeout(30000),headers:{'CF-Access-Client-Id':env.CF_STAGING_ACCESS_CLIENT_ID,'CF-Access-Client-Secret':env.CF_STAGING_ACCESS_CLIENT_SECRET}});
 const result=await response.json();assert.ok(response.status===200&&result.ready&&result.schema_ready&&result.feed_version&&result.mail_capture&&result.native_schedules===false&&result.held===held&&result.release===env.CF_STAGING_APPROVED_COMMIT,'Backend runtime is not ready for the reviewed release');
 return {release:result.release,feed_version:result.feed_version,held:result.held};
}
export async function executeRelease(env,event,checkout,deps={}){
 const action=authorize(env,event,checkout); // Before creating clients or touching credentials/network.
 if(action==='diagnose-schema')return (deps.schemaDiagnostic||diagnoseSchema)(env,{transport:deps.transport||fetch,record:(_name,value)=>(deps.record||(()=>{}))(value)});
 if(action==='adopt-schema')return (deps.adoptSchema||adoptSchema)({...env,STAGING_CHANGE_APPROVED:'PR243-STAGING-ONLY'},{transport:deps.transport||fetch,record:(name,value)=>{if(deps.record)deps.record(value);else{fs.mkdirSync(path.join(root,'artifacts'),{recursive:true});fs.writeFileSync(path.join(root,'artifacts',name+'.json'),JSON.stringify(value,null,2)+'\n');}}});
 const transport=deps.transport||fetch,get=deps.get||management(env,transport),record=deps.record||(()=>{});
 const DB=deps.DB||d1Client({database:resourceManifest().permanent_database.uuid,readOnly:action==='verify',fetcher:transport,env:{CLOUDFLARE_ACCOUNT_ID:TARGET.account,CLOUDFLARE_API_TOKEN:env.CF_STAGING_API_TOKEN}});
 const report={action,source_sha:checkout,account:TARGET.account,database_id:resourceManifest().permanent_database.uuid,completed:false,steps:[]};
 const step=(name,evidence)=>{report.steps.push({name,...evidence});record(report);};
 try{
  const p=await (deps.preflight||preflight)(env,transport,{existingDatabase:true,workerState:'deployed'});acceptPreflight(p);step('access_and_inventory',{passed:true});
  const initial=await (deps.diagnose||diagnose)(env,transport,()=>{},{allowLegacy:true});assert.ok(initial.verified);step('existing_workers',{workers:initial.workers.map(w=>({name:w.name,version_id:w.version_id,deployment_id:w.deployment_id,profile:w.profile}))});
  if(action!=='verify'){
   const bookmark=await get(`/d1/database/${resourceManifest().permanent_database.uuid}/time_travel/bookmark`);
   assert.ok(typeof bookmark?.bookmark==='string'&&bookmark.bookmark.length>5);step('recovery_bookmark',{bookmark:bookmark.bookmark});
  }
  if(action==='publish-synthetic'){
   const bucket=resourceManifest().intelligence_bucket;
   assert.equal((await get('/r2/buckets/'+bucket))?.name,bucket);
   assert.equal((await get('/r2/buckets/'+bucket+'/domains/managed'))?.enabled,false);
   const domains=await get('/r2/buckets/'+bucket+'/domains/custom');assert.ok(Array.isArray(domains.domains)&&domains.domains.length===0);
   const childEnv={PATH:env.PATH,CF_STAGING_APPROVED_COMMIT:checkout,CF_STAGING_PROVISION_ACTION:action,CF_STAGING_ACCOUNT_ID:TARGET.account,CF_STAGING_R2_ACCESS_KEY_ID:env.CF_STAGING_R2_ACCESS_KEY_ID,CF_STAGING_R2_SECRET_ACCESS_KEY:env.CF_STAGING_R2_SECRET_ACCESS_KEY,GITHUB_SHA:checkout,...(env.HTTPS_PROXY?{HTTPS_PROXY:env.HTTPS_PROXY}:{}),...(env.HTTP_PROXY?{HTTP_PROXY:env.HTTP_PROXY}:{}),...(env.NODE_EXTRA_CA_CERTS?{AWS_CA_BUNDLE:env.NODE_EXTRA_CA_CERTS}:{})};
   assert.ok(childEnv.CF_STAGING_R2_ACCESS_KEY_ID&&childEnv.CF_STAGING_R2_SECRET_ACCESS_KEY);
   const result=(deps.runner||spawnSync)('python',[path.join(root,'scripts/publish-synthetic.py')],{cwd:path.dirname(root),env:childEnv,encoding:'utf8',timeout:180000});
   assert.ok(!result.error&&result.status===0,'Synthetic staging publication failed');step('synthetic_publication',{passed:true});
  }
  else if(action==='migrate')step('migration',await (deps.migrate||migrate)({...env,STAGING_CHANGE_APPROVED:'PR243-STAGING-ONLY'},{plan:loadMigrationPlan(env),transport,record:(name,value)=>{fs.mkdirSync(path.join(root,'artifacts'),{recursive:true});fs.writeFileSync(path.join(root,'artifacts',name+'.json'),JSON.stringify(value,null,2)+'\n');}}));
  else if(['hold','freeze','resume'].includes(action)){
   const options={revision:Number(env.CF_STAGING_EXPECTED_HOLD_REVISION),reason:env.CF_STAGING_RECOVERY_REASON,hold:action==='hold'};
   const result=action==='freeze'?await freezeHold(DB,options):await setHold(DB,options);step(action,result);
  }else{
   step('schema',await (deps.verifySchema||verifySchema)(DB));
   if(action==='verify'){const status=await holdStatus(DB);step('hold_status',status);const strict=await (deps.diagnose||diagnose)(env,transport,()=>{},{allowLegacy:false,requireKey:true});assert.ok(strict.verified,'Current release configuration mismatch');step('current_release',{verified:true});step('backend_runtime',await (deps.probeBackend||probeBackend)(env,transport));}
   else{
    assert.ok(['update','recover-code'].includes(action),'Worker deployment requires an explicit update or recover-code approval');
    const state=await holdStatus(DB);
    if(action==='recover-code')assert.ok(state.write_hold===1&&state.database_frozen===1&&state.active_leases===0,'Recovery requires frozen, drained hold');
    else assert.ok(state.write_hold===0&&state.database_frozen===0,'Normal update requires resumed database');
    const cfg=writeConfigs(env);assert.ok(cfg.api.vars.STAGING_ADMIN_EMAILS,'Configure staging administrators before deployment');
    const bucket=resourceManifest().intelligence_bucket;
    assert.equal((await get('/r2/buckets/'+bucket))?.name,bucket);
    assert.equal((await get('/r2/buckets/'+bucket+'/domains/managed'))?.enabled,false);
    const custom=await get('/r2/buckets/'+bucket+'/domains/custom');assert.ok(Array.isArray(custom.domains)&&custom.domains.length===0,'Private staging bucket required');
    const manifest=deps.bundle||JSON.parse(fs.readFileSync(path.join(root,'.build/manifest.json'),'utf8'));
    assert.equal(manifest.commit,checkout);assert.equal(manifest.account,TARGET.account);assert.equal(manifest.providers,'synthetic-only');
    if(!deps.bundle)assert.equal(manifest.api_sha256,hash(fs.readFileSync(path.join(root,'.build/api.mjs'))));
    const runner=deps.runner||spawnSync;
    const childEnv={PATH:env.PATH,XDG_CONFIG_HOME:path.join(root,'.build/release-config'),CI:'true',CLOUDFLARE_ACCOUNT_ID:TARGET.account,CLOUDFLARE_API_TOKEN:env.CF_STAGING_API_TOKEN,CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV:'false',WRANGLER_SEND_METRICS:'false',...(env.HTTPS_PROXY?{HTTPS_PROXY:env.HTTPS_PROXY}:{}),...(env.HTTP_PROXY?{HTTP_PROXY:env.HTTP_PROXY}:{}),...(env.NODE_EXTRA_CA_CERTS?{NODE_EXTRA_CA_CERTS:env.NODE_EXTRA_CA_CERTS}:{})};
    fs.mkdirSync(childEnv.XDG_CONFIG_HOME,{recursive:true});
    function deploy(name,dry){const r=runner('npx',['--yes','wrangler@4.156.0','deploy','--config',path.join(root,'.build',name+'.json'),...(dry?['--dry-run']:[])],{cwd:path.join(root,'.build'),env:childEnv,encoding:'utf8',maxBuffer:4*1024*1024,timeout:180000});assert.ok(!r.error&&r.status===0,'Staging package/upload failed; inspect approved runner');step(name+(dry?'_dry_run':'_upload'),{passed:true});}
    deploy('api',true);deploy('site',true);deploy('api',false);
    const api=await (deps.inspectWorker||inspectWorker)(TARGET.api,cfg.api,get,{requireKey:true});assert.ok(api.verified);step('backend_verified',{version_id:api.version_id});
    step('backend_runtime',await (deps.probeBackend||probeBackend)(env,transport,{held:action==='recover-code'}));
    // No frontend upload before schema, bindings and actual backend runtime verification.
    deploy('site',false);const site=await (deps.inspectWorker||inspectWorker)(TARGET.site,cfg.site,get);assert.ok(site.verified);step('frontend_verified',{version_id:site.version_id});
    const after=await holdStatus(DB);assert.equal(after.revision,state.revision);assert.equal(after.write_hold,state.write_hold);assert.equal(after.database_frozen,state.database_frozen);
   }
   if(action!=='recover-code'){
    const access=await (deps.probeAccess||probeAccess)(env,transport);assert.ok(access.passed,'Access/application boundary verification failed');step('access_probes',{passed:true,checks:access.checks.length});
   }
  }
  report.completed=true;record(report);return report;
 }catch{report.failure='Stopped without automatic rollback, resource replacement or hold release';record(report);throw Error(report.failure);}
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 const record=r=>{fs.mkdirSync(path.join(root,'artifacts'),{recursive:true});fs.writeFileSync(path.join(root,'artifacts',r.action==='diagnose-schema'?'schema-diagnostic.json':r.action==='adopt-schema'?'adoption.json':'release.json'),JSON.stringify(r,null,2)+'\n');};
 try{
  const sha=spawnSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).stdout.trim();
  const event=JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH,'utf8'));
  authorize(process.env,event,sha);
  assert.equal(spawnSync('git',['diff','--exit-code','HEAD','--'],{cwd:root,encoding:'utf8'}).status,0,'Tracked source changed after review');
  if(process.argv[2]==='--check')console.log('Exact source, action and staging target validated locally.');
  else {await executeRelease(process.env,event,sha,{record});console.log('Approved permanent staging operation completed.');}
 }catch{console.error('Permanent staging operation stopped. Review sanitized release evidence; no automatic recovery attempted.');process.exitCode=1;}
}
