import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
import {DatabaseSync} from 'node:sqlite';
import {productionBaselinePlan} from '../scripts/production-baseline.mjs';
import {simpleRelease} from '../scripts/simple-release.mjs';
import {migrate,STAGING_DATABASE_ID} from '../scripts/migrate.mjs';
import {management} from '../scripts/diagnose.mjs';
import {failure,safeFailure} from '../scripts/errors.mjs';
import {TARGET} from '../target.mjs';
const baseline=JSON.parse(fs.readFileSync('release/baseline.json'));
const {plan,sha256,endStep}=productionBaselinePlan(baseline);
const env={GITHUB_REPOSITORY:'Prat007ai/cveharbor',GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_SHA:'a'.repeat(40),SIMPLE_STAGING_ENABLED:'true',SIMPLE_STAGING_OPERATION:'initialize',CF_STAGING_ACCOUNT_ID:TARGET.account,CF_STAGING_D1_DATABASE_ID:STAGING_DATABASE_ID,CF_STAGING_API_TOKEN:'private-token-canary',STAGING_CHANGE_APPROVED:'PR243-STAGING-ONLY',CF_STAGING_PROVISION_ACTION:'migrate',CF_STAGING_SCHEMA_RESUME_STEP:'37',CF_STAGING_SCHEMA_PLAN_SHA256:sha256,CF_STAGING_ACCESS_AUD:'b'.repeat(64)};
function fixture(step){const db=new DatabaseSync(':memory:');for(const f of plan.files)for(const sql of f.statements.slice(0,Math.max(0,Math.min(step,f.end)-f.start)))db.exec(sql);return db;}
function transport(db){return async(url,init)=>{
 const route=new URL(url).pathname.split(TARGET.account)[1];assert.ok(route!==undefined);assert.equal(init.redirect,'error');let result;
 if(init.method==='POST'){
  assert.equal(route,`/d1/database/${STAGING_DATABASE_ID}/query`);const {sql,batch}=JSON.parse(init.body);assert.equal(batch,undefined);assert.match(sql,/^(SELECT\b|PRAGMA (foreign_key_check|quick_check)$)/i);assert.ok(!sql.includes(';'));
  result=[{success:true,results:db.prepare(sql).all(),meta:{rows_read:1,rows_written:0,size_after:4096,duration:0}}];
 }else{assert.equal(init.method,'GET');
  if(route==='')result={id:TARGET.account};
  else if(route===`/d1/database/${STAGING_DATABASE_ID}`)result={uuid:STAGING_DATABASE_ID,name:TARGET.database,file_size:4096};
  else if(route.startsWith('/access/apps/'))result=[];
  else if(route.startsWith('/access/apps'))result=[{id:'abc-def',type:'self_hosted',domain:new URL(TARGET.origin).hostname,aud:env.CF_STAGING_ACCESS_AUD}];
  else{assert.match(route,/^\/workers\/scripts\/cveharbor-(accounts|site)-staging\/(settings|deployments|subdomain|schedules)$/);result={unchanged:true};}
 }return Response.json({success:true,result});};}
for(const step of [37,plan.files[2].end,endStep])test(`read-only diagnosis identifies actual step ${step}, receipts and integrity without assuming checkpoint 37`,async()=>{
 const db=fixture(step);const before=db.prepare('SELECT total_changes() n').get().n;
 try{const r=await migrate(env,{plan,endStep,readOnly:true,transport:transport(db),requestIntervalMs:0,inventory:async()=>({verified:true}),probe:async()=>({passed:true}),beforeWrite:()=>assert.fail('No write permitted')});
 assert.equal(r.status,'diagnosed');assert.ok(r.actual_state.matching_steps.includes(step));assert.equal(r.receipt_count,plan.files.filter(f=>f.end<=step).length);assert.ok(r.receipts.every(r=>r.file_index>=0));assert.equal(r.integrity_ok,true);assert.equal(r.foreign_keys_ok,true);assert.equal(r.batches.length,0);assert.equal(r.usage.verification.rows_written,0);assert.equal(db.prepare('SELECT total_changes() n').get().n,before);assert.doesNotMatch(JSON.stringify(r),/private-token-canary/);
 }finally{db.close();}
});
test('preflight failure preserves independently observed state and safe HTTP cause',async()=>{
 const db=fixture(37);let report;
 try{await assert.rejects(migrate(env,{plan,endStep,readOnly:true,transport:transport(db),requestIntervalMs:0,inventory:async()=>{throw failure('metadata.worker.settings','authorization',{http_status:403});},record:(name,r)=>{if(name==='migration')report=structuredClone(r);}}));
 assert.equal(report.failure.operation,'metadata.worker.settings');assert.equal(report.failure.http_status,403);assert.ok(report.actual_state.matching_steps.includes(37));assert.equal(report.batches.length,0);
 }finally{db.close();}
});
test('initialization retains sanitized migration failure and checkpoint progress',async()=>{
 let report;const DB={prepare:sql=>({all:async()=>({results:sql.includes('sqlite_master')?[{name:'staging_schema_history'}]:JSON.parse(fs.readFileSync('staging/migrations.v1.json')).entries.slice(0,2).map(e=>({...e,manifest_version:1}))})})};
 await assert.rejects(simpleRelease(env,{baseline,DB,get:async()=>({bookmark:'private-bookmark-canary'}),record:r=>{report=r;},initialize:async(_e,{record})=>{record('migration',{status:'stopped',actual_state:{matching_steps:[37]},batches:[],failure:{operation:'migration.inventory',category:'validation'}});throw failure('migration.inventory','validation');}}));
 assert.deepEqual(report.baseline.actual_state.matching_steps,[37]);assert.equal(report.failure.operation,'migration.inventory');assert.doesNotMatch(JSON.stringify(report),/private-token-canary|private-bookmark-canary/);
});
test('metadata HTTP failure emits only fixed operation, status, numeric codes',async()=>{
 const get=management(env,async()=>Response.json({success:false,errors:[{code:10000,message:'private-token-canary customer@example.net'}]},{status:403}));
 await assert.rejects(get(`/d1/database/${STAGING_DATABASE_ID}/time_travel/bookmark`),error=>{assert.deepEqual(safeFailure(error),{operation:'metadata.recovery_bookmark',category:'authorization',http_status:403,api_codes:[10000]});return true;});
});
test('CLI writes failure artifact even when authorization fails, without serializing assertion values',()=>{
 const file='release/artifacts/staging-release.json';fs.rmSync(file,{force:true});
 const r=spawnSync(process.execPath,['staging/scripts/simple-release.mjs'],{encoding:'utf8',env:{...process.env,GITHUB_REPOSITORY:'private-token-canary'}});
 assert.equal(r.status,1);const text=fs.readFileSync(file,'utf8');assert.equal(JSON.parse(text).failure.operation,'release.authorization');assert.doesNotMatch(text+r.stderr,/private-token-canary/);
});
test('existing workflow exposes diagnose and always uploads diagnostic evidence',()=>{
 const yaml=fs.readFileSync('.github/workflows/cvie-staging.yml','utf8');assert.match(yaml,/options: \[release, initialize, resume, diagnose\]/);assert.match(yaml,/if: \$\{\{ always\(\) \}\}\s+with:\s+name: staging-tested-/);
});

test('D1 diagnostics suppress secret-bearing provider text while identifying invalid query shape',async()=>{
 const {diagnosticTransport}=await import('../scripts/errors.mjs');
 const read=diagnosticTransport('release.initialization_receipts',async()=>Response.json({success:false,errors:[{code:7500,message:'SQL is required private-token-canary customer@example.net'}]},{status:400}));
 await assert.rejects(read('unused'),error=>{assert.deepEqual(safeFailure(error),{operation:'release.initialization_receipts',category:'missing_sql',http_status:400,api_codes:[7500]});return true;});
});
