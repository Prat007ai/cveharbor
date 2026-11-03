import test from 'node:test';import assert from 'node:assert/strict';
import {authorize,executeRelease,probeBackend} from '../scripts/release.mjs';
import {FullDB} from './helpers/full-db.mjs';import {TARGET} from '../target.mjs';
const sha='a'.repeat(40),env={PATH:process.env.PATH,GITHUB_REPOSITORY:'Prat007ai/cveharbor',GITHUB_REF:'refs/heads/codex/cvie-core-phase012',GITHUB_SHA:sha,GITHUB_EVENT_NAME:'workflow_dispatch',CF_STAGING_APPROVED_COMMIT:sha,CF_STAGING_PROVISION_ACTION:'update',CF_STAGING_ACCOUNT_ID:TARGET.account,CF_STAGING_D1_DATABASE_ID:'fac61562-fc31-426d-8032-550aba63b7f6',CF_STAGING_ADMIN_EMAILS:'admin@example.invalid',CF_STAGING_ACCESS_ISSUER:'https://synthetic.cloudflareaccess.com',CF_STAGING_ACCESS_AUD:'a'.repeat(64)};
const event={inputs:{operation:'update'}};
test('exact SHA, branch, operation and explicit dispatch/rerun required before credentials',()=>{
 assert.equal(authorize(env,event,sha),'update');
 for(const delta of [{GITHUB_REF:'refs/heads/main'},{GITHUB_SHA:'b'.repeat(40)},{GITHUB_EVENT_NAME:'pull_request'},{CF_STAGING_PROVISION_ACTION:'deploy-workers'},{CF_STAGING_D1_DATABASE_ID:TARGET.productionDatabase},{GITHUB_EVENT_NAME:'push',GITHUB_RUN_ATTEMPT:'1'}])assert.throws(()=>authorize({...env,...delta},event,sha));
 assert.equal(authorize({...env,GITHUB_EVENT_NAME:'push',GITHUB_RUN_ATTEMPT:'2'},{head_commit:{id:sha,message:'Reviewed [staging-release]'}},sha),'update');
});
function deps(db,calls){return {DB:db,bundle:{commit:sha,account:TARGET.account,providers:'synthetic-only'},preflight:async()=>({account:TARGET.account,read_only_checks_passed:true,blockers:[],checks:['service_token_matches_policy_and_client','token_permission_grants','token_staging_only_scope'].map(name=>({name,status:'pass'}))}),diagnose:async()=>({verified:true,workers:[]}),get:async route=>route.endsWith('/bookmark')?{bookmark:'synthetic-bookmark'}:route.endsWith('/managed')?{enabled:false}:route.endsWith('/custom')?{domains:[]}:{name:'cveharbor-intelligence-staging'},verifySchema:async()=>{calls.push('schema');return {};},runner:(command,args,opts)=>{assert.ok(!Object.keys(opts.env).some(k=>/PROD|SMTP/.test(k)));calls.push((args.some(a=>a.endsWith('/api.json'))?'api':'site')+(args.includes('--dry-run')?'-dry':'-upload'));return {status:0};},inspectWorker:async name=>{calls.push(name===TARGET.api?'api-readback':'site-readback');return {verified:true,version_id:'test'};},probeBackend:async()=>{calls.push('api-runtime');return {};},probeAccess:async()=>({passed:true,checks:[]})};}
test('schema and backend runtime gates precede frontend upload; every failure stops publication',async()=>{
 for(const failure of [null,'schema','api-upload','api-runtime']){const db=new FullDB(),calls=[];try{
  const d=deps(db,calls);if(failure==='schema')d.verifySchema=async()=>{throw Error('bad schema');};if(failure==='api-runtime')d.probeBackend=async()=>{throw Error('not ready');};if(failure==='api-upload'){const original=d.runner;d.runner=(...a)=>{const r=original(...a);return calls.at(-1)==='api-upload'?{status:1}:r;};}
  if(failure){await assert.rejects(executeRelease(env,event,sha,d));assert.ok(!calls.includes('site-upload'));}
  else{assert.ok((await executeRelease(env,event,sha,d)).completed);assert.deepEqual(calls,['schema','api-dry','site-dry','api-upload','api-readback','api-runtime','site-upload','site-readback']);}
 }finally{db.close();}}
});
test('runtime gate rejects old release, missing snapshot or wrong hold state',async()=>{
 const valid={ready:true,schema_ready:true,feed_version:'fixture',mail_capture:true,native_schedules:false,held:false,release:sha};
 for(const delta of [{release:'old'},{feed_version:null},{mail_capture:false},{held:true}])await assert.rejects(probeBackend(env,async()=>Response.json({...valid,...delta})));
 assert.equal((await probeBackend(env,async()=>Response.json(valid))).release,sha);
});

test('migration approval never falls through into publication or Worker deployment',async()=>{
 const approval=JSON.parse((await import('node:fs')).readFileSync(new URL('../bootstrap-approval.v1.json',import.meta.url),'utf8'));
 const calls=[],db=new FullDB();try{
  const e={...env,CF_STAGING_PROVISION_ACTION:'migrate',CF_STAGING_SCHEMA_PLAN_SHA256:approval.execution_plan_sha256,CF_STAGING_SCHEMA_RESUME_STEP:'0'};
  e.CF_STAGING_RECOVERY_EVIDENCE=JSON.stringify({operation:'migrate',account:TARGET.account,database_id:e.CF_STAGING_D1_DATABASE_ID,source_sha:sha,
   execution_plan_sha256:approval.execution_plan_sha256,start_step:0,start_schema_sha256:'4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
   captured_at:new Date().toISOString(),writers_quiesced:true,export_validated:true,restore_available:true,export_sha256:'f'.repeat(64),bookmark:'synthetic-bookmark',private_export_reference:'private-fixture'});
  const d=deps(db,calls);d.migrate=async()=>{calls.push('migrate');return {status:'complete'};};
  d.verifySchema=async()=>assert.fail('Migration must not enter the deployment path');
  d.runner=()=>assert.fail('Migration must not launch any publisher or Wrangler');
  const result=await executeRelease(e,{inputs:{operation:'migrate'}},sha,d);
  assert.equal(result.completed,true);assert.deepEqual(calls,['migrate']);
 }finally{db.close();}
});
test('synthetic publication approval never deploys Workers or executes schema updates',async()=>{
 const calls=[],db=new FullDB();try{
  const e={...env,CF_STAGING_PROVISION_ACTION:'publish-synthetic',CF_STAGING_R2_ACCESS_KEY_ID:'synthetic-id',CF_STAGING_R2_SECRET_ACCESS_KEY:'synthetic-secret'};
  const d=deps(db,calls);d.verifySchema=async()=>assert.fail('Publication must not enter the deployment path');
  d.migrate=async()=>assert.fail('Publication must not migrate');
  d.runner=(command,args)=>{assert.equal(command,'python');assert.ok(args[0].endsWith('/publish-synthetic.py'));calls.push('publish');return {status:0};};
  const result=await executeRelease(e,{inputs:{operation:'publish-synthetic'}},sha,d);
  assert.equal(result.completed,true);assert.deepEqual(calls,['publish']);
 }finally{db.close();}
});
