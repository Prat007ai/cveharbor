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
