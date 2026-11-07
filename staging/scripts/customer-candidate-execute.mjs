// Manual, exact-target adapter. No reset, initialization, resource creation or rollback.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';import {fileURLToPath} from 'node:url';
import {TARGET} from '../target.mjs';import {configs,validate,root} from './configure.mjs';import {resourceManifest} from './inventory.mjs';
import {management,inspectWorker} from './diagnose.mjs';import {preflight} from './preflight.mjs';import {acceptPreflight,probeBackend,waitBackend} from './release.mjs';import {probeAccess} from './probe-access.mjs';
import {failure,safeFailure} from './errors.mjs';
import {d1Client} from '../../scripts/cloudflare_d1.mjs';import {verifyArtifact,output,hash} from './customer-candidate-artifact.mjs';import {schemaState,counts,migrationBatch} from './customer-candidate-schema.mjs';
import {applyCandidateMigration} from './customer-candidate-migrate.mjs';
import {verifyLiveApplication} from './routine-live.mjs';
const actions=['status','migrate','deploy','resume-frontend'];
export function authorizeCandidate(env,a){
 assert.equal(env.GITHUB_REPOSITORY,'Prat007ai/cveharbor');assert.equal(env.GITHUB_REF,'refs/heads/main');assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch');assert.equal(env.GITHUB_RUN_ATTEMPT,'1','Dispatch a fresh reviewed operation; do not rerun a write job');
 assert.equal(env.CF_STAGING_CANDIDATE_ENABLED,'true');assert.equal(env.SIMPLE_STAGING_ENABLED,'false','Baseline release lane must be disabled');
 if(env.CANDIDATE_OPERATION==='routine-deploy'){
  assert.equal(env.ROUTINE_STAGING_DELIVERY_ENABLED,'true');
  assert.equal(env.GITHUB_WORKFLOW_REF,'Prat007ai/cveharbor/.github/workflows/cvie-staging.yml@refs/heads/main');
  assert.match(env.ROUTINE_PARENT||'',/^[a-f0-9]{40}$/);
  assert.equal(env.GITHUB_SHA,a.seal.commit);assert.match(a.seal.commit,/^[a-f0-9]{40}$/);
  assert.equal(env.CF_STAGING_ACCOUNT_ID,TARGET.account);assert.equal(env.CF_STAGING_D1_DATABASE_ID,resourceManifest().permanent_database.uuid);
  return 'routine-deploy'; // Only the protected job with a reverified main artifact reaches this entrypoint.
 }
 assert.ok(actions.includes(env.CANDIDATE_OPERATION));assert.match(env.GITHUB_SHA||'',/^[a-f0-9]{40}$/);assert.equal(env.GITHUB_SHA,a.seal.commit);assert.equal(env.CF_STAGING_APPROVED_COMMIT,a.seal.commit);assert.equal(env.CANDIDATE_COMMIT,a.seal.commit);
 assert.equal(env.CF_STAGING_ACCOUNT_ID,TARGET.account);assert.equal(env.CF_STAGING_D1_DATABASE_ID,resourceManifest().permanent_database.uuid);
 assert.equal(env.CANDIDATE_ARTIFACT_SHA256,a.seal_sha256);assert.equal(env.CANDIDATE_PREPARED_SHA256,a.seal_sha256);assert.equal(env.CANDIDATE_SQL_SHA256,a.seal.sql_sha256);assert.equal(env.CANDIDATE_PROFILE_SHA256,a.seal.profile_sha256);
 const binding=[env.CANDIDATE_OPERATION,a.seal.commit,a.seal.sql_sha256,a.seal.profile_sha256,a.seal_sha256].join(':');
 if(env.CANDIDATE_OPERATION!=='status'){
  const key=env.CANDIDATE_OPERATION==='migrate'?'CF_STAGING_CANDIDATE_MIGRATION_APPROVAL':'CF_STAGING_CANDIDATE_DEPLOYMENT_APPROVAL';assert.equal(env[key],binding,'Separate operation approval does not match reviewed artifacts');
  assert.equal(env.CANDIDATE_CONFIRMATION,binding);assert.equal(env.CF_STAGING_CANDIDATE_WRITE_WINDOW,a.seal.commit,'Reviewed quiet staging test window required');
 }
 if(env.CANDIDATE_OPERATION==='resume-frontend'){assert.match(env.CANDIDATE_BACKEND_VERSION||'',/^[a-f0-9-]{36}$/);assert.match(env.CANDIDATE_FRONTEND_VERSION||'',/^[a-f0-9-]{36}$/);}
 return env.CANDIDATE_OPERATION;
}
export function candidateConfigs(env){const ordinary=configs({...env,CF_STAGING_APPLICATION_PROFILE:'production-baseline',CF_STAGING_MANUAL_JOBS_ENABLED:'false'});validate(ordinary.api,ordinary.site);assert.ok(ordinary.api.vars.STAGING_ADMIN_EMAILS,'Staging administrators required');const result=structuredClone(ordinary);
 result.api.vars.STAGING_APPLICATION_PROFILE='customer-remediation-candidate';result.api.main=path.join(output,'api.mjs');result.site.assets.directory=path.join(output,'public');
 // Only these three differences are allowed; run the original validator on the inverse.
 const inverse=structuredClone(result);inverse.api.vars.STAGING_APPLICATION_PROFILE=ordinary.api.vars.STAGING_APPLICATION_PROFILE;inverse.api.main=ordinary.api.main;inverse.site.assets.directory=ordinary.site.assets.directory;validate(inverse.api,inverse.site);return result;}
export async function strictCandidateProbe(env,transport,options={}){
 // Validate the candidate marker before the shared probe can accept a stale identity.
 const checked=async(...args)=>{const response=await transport(...args);let body;try{body=await response.clone().json();}catch{throw Error('Candidate readiness response invalid');}
  for(const [check,passed] of Object.entries({candidate_profile:body?.application_profile==='customer-remediation-candidate',mfa_configured:body?.mfa_configured===true,monitor_webhook_configured:body?.monitor_webhook_configured===true}))if(!passed)throw failure('candidate.readiness','validation',{check});return response;};
 return probeBackend(env,checked,options);
}
export async function executeCandidate(env,deps={}){
 const a=(deps.artifact||verifyArtifact)();const action=authorizeCandidate(env,a); // Before clients or network.
 const routine=action==='routine-deploy';
 if(routine)env={...env,CF_STAGING_APPROVED_COMMIT:a.seal.commit}; // Source identity for config and readiness; not a manual approval pin.
 const report={version:1,started_at:new Date().toISOString(),operation:action,commit:a.seal.commit,artifact_sha256:a.seal_sha256,completed:false,steps:[],database_changed:false,backend_uploaded:false,frontend_uploaded:false};
 const record=()=>deps.record?.(structuredClone(report));let stage='preflight';
 const step=(name,data={})=>{stage=name;report.steps.push({name,...data});record();};
 const transport=deps.transport||fetch,get=deps.get||management(env,transport);
 const DB=deps.DB||d1Client({database:resourceManifest().permanent_database.uuid,readOnly:true,fetcher:transport,env:{CLOUDFLARE_ACCOUNT_ID:TARGET.account,CLOUDFLARE_API_TOKEN:env.CF_STAGING_API_TOKEN}});
 try{
  const p=await (deps.preflight||preflight)(env,transport,{existingDatabase:true,workerState:'deployed'});acceptPreflight(p);step('access_and_inventory');
  const cfg=(deps.configs||candidateConfigs)(env),ordinary=configs({...env,CF_STAGING_APPLICATION_PROFILE:'production-baseline',CF_STAGING_MANUAL_JOBS_ENABLED:'false'});
  const inspect=deps.inspect||inspectWorker;
  async function current(name,config,fallback){let r=await inspect(name,config,get,{allowLegacy:true,requireKey:true});if(!r.verified&&fallback)r=await inspect(name,fallback,get,{allowLegacy:true,requireKey:true});assert.ok(r.verified,'Unknown current Worker configuration');assert.match(r.version_id||'',/^[a-f0-9-]{36}$/);return r;}
  const api=await current(TARGET.api,cfg.api,ordinary.api),site=await current(TARGET.site,cfg.site,ordinary.site);step('current_workers',{backend_version:api.version_id,frontend_version:site.version_id});
  if(routine){
   stage='previous_staging_release';
   for(const [name,config] of [[TARGET.api,cfg.api],[TARGET.site,cfg.site]]){
    const previous={...config,vars:{...config.vars,STAGING_RELEASE:env.ROUTINE_PARENT}};
    assert.ok((await inspect(name,previous,get,{requireKey:true})).verified,'Staging is not on the reviewed first parent');
   }
   cfg.site.main=path.join(output,'site.mjs');
   step('previous_staging_release',{commit:env.ROUTINE_PARENT});
  }
  const domains=await get('/workers/domains');assert.ok(domains.some(d=>d.hostname===new URL(TARGET.origin).hostname&&d.service===TARGET.site));
  const bucket=resourceManifest().intelligence_bucket;assert.equal((await get('/r2/buckets/'+bucket)).name,bucket);assert.equal((await get('/r2/buckets/'+bucket+'/domains/managed')).enabled,false);assert.deepEqual((await get('/r2/buckets/'+bucket+'/domains/custom')).domains,[]);
  stage='schema';let state=await schemaState(DB,a.profile);step('schema',{state:state.state,journal:state.journal});
  if(action==='status'){step('candidate_configuration',{backend_matches_candidate:(await inspect(TARGET.api,cfg.api,get,{requireKey:true})).verified===true,frontend_matches_candidate:(await inspect(TARGET.site,cfg.site,get)).verified===true});report.completed=true;record();return report;}
  if(action==='migrate'){
   if(state.state==='baseline'){
    const bookmark=await get('/d1/database/'+resourceManifest().permanent_database.uuid+'/time_travel/bookmark');assert.ok(typeof bookmark?.bookmark==='string'&&bookmark.bookmark.length>5);step('recovery_available',{bookmark_sha256:hash(bookmark.bookmark)});
    const before=await counts(DB,state.rows);stage='migration_batch';step('migration_attempt');
    const batch=migrationBatch(state.rows,before,a.statements,a.profile);
    report.database_changed=null;report.migration_outcome='unknown';record();
    if(deps.apply)await deps.apply(batch);else applyCandidateMigration(env,batch,a.profile,deps.migrationRunner);
    state=await schemaState(DB,a.profile);assert.equal(state.state,'candidate');
    const after=await counts(DB,state.rows);for(const [name,n] of Object.entries(before))assert.equal(after[name],n+(name==='staging_schema_history'?1:0),'Existing table count changed');
    assert.equal(after.remediation_customer_scopes,0);assert.equal(after.remediation_customer_ticket_history,0);report.database_changed=true;report.migration_outcome='verified';step('migration_verified',{existing_counts_unchanged:true,receipt_appended:true,native_receipt_verified:true});
   }else step('migration_already_verified');
   report.completed=true;record();return report;
  }
  assert.equal(state.state,'candidate','Separate migration must complete first');
  const probe=deps.probe||strictCandidateProbe,runner=deps.runner||spawnSync;
  fs.mkdirSync(output,{recursive:true});for(const [name,c] of Object.entries(cfg))fs.writeFileSync(path.join(output,name+'.json'),JSON.stringify(c,null,2)+'\n');
  function upload(name,dry){stage=name+(dry?'_dry_run':'_upload');if(!dry)report[name==='api'?'backend_uploaded':'frontend_uploaded']=null;
   step(stage+'_attempt');
   const r=runner('npx',['--yes','wrangler@4.156.0','deploy','--config',path.join(output,name+'.json'),...(routine?['--no-bundle']:[]),...(dry?['--dry-run']:[])],{cwd:output,encoding:'utf8',timeout:180000,maxBuffer:4*1024*1024,env:{PATH:env.PATH,CI:'true',CLOUDFLARE_ACCOUNT_ID:TARGET.account,CLOUDFLARE_API_TOKEN:env.CF_STAGING_API_TOKEN,CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV:'false',WRANGLER_SEND_METRICS:'false',XDG_CONFIG_HOME:path.join(output,'wrangler-state'),...Object.fromEntries(['HTTPS_PROXY','HTTP_PROXY','NODE_EXTRA_CA_CERTS'].filter(k=>env[k]).map(k=>[k,env[k]]))}});assert.ok(!r.error&&r.status===0,'Upload outcome requires read-only reconciliation');step(stage);}
  upload('api',true);upload('site',true);
  if(action==='resume-frontend'){
   assert.equal(api.version_id,env.CANDIDATE_BACKEND_VERSION);assert.equal(site.version_id,env.CANDIDATE_FRONTEND_VERSION);const exact=await inspect(TARGET.api,cfg.api,get,{requireKey:true});assert.ok(exact.verified);assert.equal(exact.version_id,env.CANDIDATE_BACKEND_VERSION);step('backend_reused',{version:exact.version_id});
  }else{
   // A previous attempt may have uploaded this commit: use explicit resume instead.
   assert.equal((await inspect(TARGET.api,cfg.api,get,{requireKey:true})).verified,false,'Backend already matches; diagnose and explicitly resume');
   assert.equal((await current(TARGET.api,cfg.api,ordinary.api)).version_id,api.version_id,'Backend changed before upload');
   upload('api',false);const exact=await inspect(TARGET.api,cfg.api,get,{requireKey:true});assert.ok(exact.verified);assert.match(exact.version_id||'',/^[a-f0-9-]{36}$/);report.backend_uploaded=true;step('backend_verified',{version:exact.version_id});
  }
  stage='backend_runtime';await waitBackend(env,transport,{probe,bootstrap:true,sleep:deps.sleep,now:deps.now,record:e=>{report.backend_runtime=e;record();}});step('backend_runtime');
  assert.equal((await current(TARGET.site,cfg.site,ordinary.site)).version_id,site.version_id,'Frontend changed before upload');
  const siteExact=await inspect(TARGET.site,cfg.site,get);
  if(action==='resume-frontend'&&siteExact.verified)step('frontend_reused',{version:siteExact.version_id});else {upload('site',false);const exact=await inspect(TARGET.site,cfg.site,get);assert.ok(exact.verified);assert.match(exact.version_id||'',/^[a-f0-9-]{36}$/);report.frontend_uploaded=true;step('frontend_verified',{version:exact.version_id});}
  assert.equal((await schemaState(DB,a.profile)).state,'candidate');stage='custom_runtime';await probe(env,transport);step('custom_runtime');
  stage='access_probes';const access=await (deps.access||probeAccess)(env,transport);
  if(!access.passed){
   report.access_failures=(access.checks||[]).filter(c=>!c.passed).map(({name,route,status})=>({name,route,status}));
   throw Error('Access checks failed'); // GET probe names, fixed routes and HTTP status only; never headers or body.
  }
  step('access_probes');
  if(routine){stage='live_health';await (deps.live||verifyLiveApplication)(env,transport,step);}
  report.completed=true;record();return report;
 }catch(error){report.failed_check=stage;const safe=safeFailure(error);if(/^[a-z_]{1,80}$/.test(safe.check||''))report.failed_validation=safe.check;report.recovery='dispatch_status_then_review';record();throw Error('Candidate stopped at '+stage+'; no automatic retry or rollback');}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const destination=path.join(root,'artifacts/customer-candidate-execution.json');const record=r=>{fs.mkdirSync(path.dirname(destination),{recursive:true});fs.writeFileSync(destination,JSON.stringify(r,null,2)+'\n');};
 try{
  const r=await executeCandidate(process.env,{record});
  if(r.operation==='routine-deploy'&&process.env.GITHUB_STEP_SUMMARY)fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY,
   'Delivered '+r.commit+' to '+TARGET.origin+'. Passed: candidate readiness, Access, health, JS/CSS and catalogue controls. Check the task PR acceptance criteria before closing.\n');
 }catch{if(!fs.existsSync(destination))record({completed:false,failed_check:'authorization_or_artifact'});const report=JSON.parse(fs.readFileSync(destination));console.error('Candidate stopped:',report.failed_check,report.failed_validation||'');process.exitCode=1;}
}
