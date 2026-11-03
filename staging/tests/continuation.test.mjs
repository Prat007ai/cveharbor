import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { root } from '../scripts/configure.mjs';
import { TARGET } from '../target.mjs';
import { migrate, loadMigrationPlan, STAGING_DATABASE_ID, hash } from '../scripts/migrate.mjs';
import { authorize, executeRelease } from '../scripts/release.mjs';
import { migrationRecoveryEvidence } from '../scripts/migration-recovery.mjs';
import { harness } from './helpers/continuation-db.mjs';
const plan=JSON.parse(fs.readFileSync(path.join(root,'.build/schema/execution-plan.json')));
const planSha=hash(fs.readFileSync(path.join(root,'.build/schema/execution-plan.json')));
const sha='a'.repeat(40);
const env={STAGING_CHANGE_APPROVED:'PR243-STAGING-ONLY',CF_STAGING_PROVISION_ACTION:'migrate',CF_STAGING_ACCOUNT_ID:TARGET.account,
 CF_STAGING_D1_DATABASE_ID:STAGING_DATABASE_ID,CF_STAGING_API_TOKEN:'synthetic-secret',CF_STAGING_ACCESS_AUD:'b'.repeat(64),
 CF_STAGING_SCHEMA_PLAN_SHA256:planSha,CF_STAGING_SCHEMA_RESUME_STEP:'37',GITHUB_SHA:sha,CF_STAGING_APPROVED_COMMIT:sha,
 GITHUB_REPOSITORY:'Prat007ai/cveharbor',GITHUB_REF:'refs/heads/codex/cvie-core-phase012',GITHUB_EVENT_NAME:'push',GITHUB_RUN_ATTEMPT:'2'};
const event={head_commit:{id:sha,message:'Reviewed continuation preparation [staging-release]'}};
const baseline=plan.files[1].statements.slice(0,-1);
const bridge=[...plan.files[0].statements,plan.files[1].statements.at(-1)];
async function initial(h,{adopted=true}={}){
 assert.equal((await h.execute({batch:baseline.map(sql=>({sql}))})).success,true);
 if(adopted)assert.equal((await h.execute({batch:bridge.map(sql=>({sql}))})).success,true);
}
function proof(overrides={}){return {operation:'migrate',account:TARGET.account,database_id:STAGING_DATABASE_ID,source_sha:sha,
 execution_plan_sha256:planSha,start_step:37,start_schema_sha256:plan.checkpoints[37].schema_sha256,captured_at:new Date().toISOString(),
 writers_quiesced:true,export_validated:true,restore_available:true,export_sha256:'f'.repeat(64),bookmark:'private-test-bookmark',private_export_reference:'private-test-export',...overrides};}
const approved=(overrides={})=>({...env,CF_STAGING_RECOVERY_EVIDENCE:JSON.stringify(proof(overrides))});
const preflight=()=>({account:TARGET.account,blockers:[],read_only_checks_passed:true,checks:[
 {name:'service_token_matches_policy_and_client',status:'pass'}, {name:'token_permission_grants',status:'unverified',metadata_available:false,http_status:403},
 {name:'token_staging_only_scope',status:'unverified',metadata_available:false}]});

test('review reconciles original 29 -> adopted 37 -> complete 740 without replay or filename sorting',()=>{
 const review=JSON.parse(fs.readFileSync(path.join(root,'.build/schema/continuation-summary.json')));
 assert.equal(review.execution_plan_sha256,planSha);assert.equal(review.phase_b_start,37);assert.equal(review.phase_b_statements,703);assert.equal(review.phase_b_batches,34);
 assert.equal(review.files[0].from_step,29);assert.equal(review.files[0].to_step,37);assert.equal(review.files[0].statements,8);
 assert.equal(authorize(env,event,sha),'migrate');assert.equal(loadMigrationPlan(env).checkpoints.length,741);
 const files=plan.files.map(f=>f.file);assert.ok(files.indexOf('account-backend/migrations/0032_recovery_control.sql')<files.indexOf('account-backend/migrations/0028_cvie_source_efficiency.sql'));
 for(const f of review.files)assert.equal(hash(fs.readFileSync(path.join(root,'.build/schema',f.execution_sql))),f.execution_sha256);
 assert.equal(review.files[0].execution_sha256,hash(fs.readFileSync(path.join(root,'sql/adopt-original-checkpoint29.sql'))));
});
test('remaining 703 real statements preserve original and adopted objects, verify all receipts and install the complete schema',async t=>{
 const seen=[];const h=harness(t,plan,env,async({body})=>{if(body.batch?.some(q=>!q.sql.trimStart().startsWith('SELECT')))seen.push(body.batch);});await initial(h);
 const originals=(await h.execute({sql:plan.schema_sql})).result[0].results;
 const r=await migrate(env,h.deps);assert.equal(r.status,'complete');assert.equal(r.approved_start_step,37);assert.equal(r.last_verified_step,740);
 assert.equal(r.batches.length,34);assert.equal(r.actual_state.counts.length,102);assert.equal(r.usage.verification.rows_written,0);assert.equal(r.invariants_unchanged,true);
 const after=(await h.execute({sql:plan.schema_sql})).result[0].results;
 for(const object of originals)assert.deepEqual(after.find(x=>x.type===object.type&&x.name===object.name),object);
 const ledger=(await h.execute({sql:'SELECT path,sha256,manifest_version FROM staging_schema_history ORDER BY rowid'})).result[0].results;
 const manifest=JSON.parse(fs.readFileSync(path.join(root,'migrations.v1.json')));assert.deepEqual(ledger,manifest.entries.map(e=>({path:e.path,sha256:e.sha256,manifest_version:1})));
 assert.equal(seen.length,34);assert.ok(!seen.flat().some(q=>q.sql.trim().startsWith('CREATE TABLE IF NOT EXISTS users(')));
 assert.ok(h.calls.filter(c=>c.method==='POST').length<2000);assert.equal(r.automatic_retries,0);assert.equal(r.worker_or_access_mutations,0);
});
test('original 29 without adoption, extra objects and new customer rows stop phase B before any writes',async t=>{
 for(const kind of ['unadopted','extra','rows']){
  let writes=0;const h=harness(t,plan,env,async({body})=>{if(body.batch?.some(q=>!q.sql.trimStart().startsWith('SELECT')))writes++;});await initial(h,{adopted:kind!=='unadopted'});
  if(kind==='extra')await h.execute({sql:'CREATE TABLE unexpected(id TEXT)'});
  if(kind==='rows')await h.execute({sql:"INSERT INTO users(id,email) VALUES('private','private@example.test')"});
  await assert.rejects(migrate(env,h.deps));assert.equal(writes,0);assert.ok(!h.final().actual_state.matching_steps.includes(37));
 }
});
test('lost committed phase-B response is reconciled once and the old cursor cannot repeat it',async t=>{
 let lost=false,writes=0;const h=harness(t,plan,env,async({body,execute})=>{
  if(!body.batch||body.batch.every(q=>q.sql.trimStart().startsWith('SELECT')))return;
  writes++;if(!lost){lost=true;await execute(body);throw Error('synthetic-secret');}
 });await initial(h);await assert.rejects(migrate(env,h.deps));assert.equal(writes,1);
 const next=plan.files[2].end;assert.ok(h.final().actual_state.matching_steps.includes(next));assert.equal(h.final().usage.complete,false);
 await assert.rejects(migrate(env,h.deps));assert.equal(writes,1);assert.equal(h.final().automatic_retries,0);
 const resumed=await migrate({...env,CF_STAGING_SCHEMA_RESUME_STEP:String(next)},h.deps);assert.equal(resumed.status,'complete');assert.equal(resumed.batches.length,33);
});
test('recovery evidence is bound to the new commit, current checkpoint/plan, private export and one-hour freshness',()=>{
 const e=approved();const out=migrationRecoveryEvidence(e,plan);assert.equal(out.start_step,37);assert.doesNotMatch(JSON.stringify(out),/private-test/);
 for(const patch of [{operation:'adopt-schema'},{source_sha:'b'.repeat(40)},{start_step:29},{start_schema_sha256:'f'.repeat(64)},
  {execution_plan_sha256:'f'.repeat(64)},{account:'production'},{database_id:TARGET.productionDatabase},{writers_quiesced:false},{export_validated:false},
  {restore_available:false},{private_export_reference:''},{export_sha256:''},{captured_at:new Date(Date.now()-3600001).toISOString()}])assert.throws(()=>migrationRecoveryEvidence(approved(patch),plan));
 assert.throws(()=>migrationRecoveryEvidence(env,plan));
});
test('expiry between batches stops further SQL and retains the fresh actual checkpoint',async t=>{
 let writes=0,checks=0;const h=harness(t,plan,env,async({body})=>{if(body.batch?.some(q=>!q.sql.trimStart().startsWith('SELECT')))writes++;});await initial(h);
 const fixed=Date.now(),e=approved({captured_at:new Date(fixed).toISOString()});
 await assert.rejects(migrate(env,{...h.deps,beforeWrite:()=>migrationRecoveryEvidence(e,plan,fixed+(checks++?3600001:0))}));
 assert.equal(writes,1);assert.ok(h.final().actual_state.matching_steps.includes(plan.files[2].end));assert.equal(h.final().automatic_retries,0);
});
test('release requires recovery evidence before network and schema-only migration cannot reach deployment',async()=>{
 let migration=false;const records=[];
 const deps={preflight:async()=>preflight(),diagnose:async()=>({verified:true,workers:[]}),get:async()=>({bookmark:'current-private-bookmark'}),
  DB:{},record:r=>records.push(structuredClone(r)),migrate:async(e,options)=>{migration=true;assert.equal(e.CF_STAGING_PROVISION_ACTION,'migrate');assert.equal(typeof options.beforeWrite,'function');options.beforeWrite();return {status:'complete'};},runner:()=>assert.fail('No upload')};
 await assert.rejects(executeRelease(env,event,sha,{transport:()=>assert.fail('No network without recovery')}));
 await executeRelease(approved(),event,sha,deps);assert.equal(migration,true);
 assert.doesNotMatch(JSON.stringify(records),/private-test|current-private-bookmark/);
});
