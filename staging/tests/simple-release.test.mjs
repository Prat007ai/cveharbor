import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {simpleAuthorization,simpleRelease,verifyNativeHistory,recordNativeChecksums} from '../scripts/simple-release.mjs';
import {auditBaseline,canonical,digest,PRODUCTION_DB,schemaSQL} from '../../scripts/production_schema_baseline.mjs';
import {forwardMigrations,migrationConfig} from '../../scripts/release_migrations.mjs';
import {verifyReceipt} from '../../scripts/require_staging_release.mjs';
import {FullDB} from './helpers/full-db.mjs';import {TARGET} from '../target.mjs';
const sha='a'.repeat(40),identity='b'.repeat(64);
const env={GITHUB_REPOSITORY:'Prat007ai/cveharbor',GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'push',GITHUB_SHA:sha,SIMPLE_STAGING_ENABLED:'true',CF_STAGING_ACCOUNT_ID:TARGET.account,CF_STAGING_D1_DATABASE_ID:'fac61562-fc31-426d-8032-550aba63b7f6'};
const baseline={version:1,status:'verified',source_sha:'c'.repeat(40),schema_verified:true,deployed_release_verified:true,customer_records_read:false,rows_written:0,production_database_id:PRODUCTION_DB,schema_sha256:'d'.repeat(64),application_schema_files:[{path:'fixture',sha256:identity}]};
test('routine lane accepts only activated trusted main and a reviewed live baseline, without recovery secrets',()=>{
 simpleAuthorization(env,baseline);
 for(const patch of [{GITHUB_REF:'refs/heads/feature'},{GITHUB_EVENT_NAME:'pull_request'},{SIMPLE_STAGING_ENABLED:'false'},{CF_STAGING_D1_DATABASE_ID:PRODUCTION_DB}])assert.throws(()=>simpleAuthorization({...env,...patch},baseline));
 for(const patch of [{status:'awaiting-audit'},{deployed_release_verified:false},{schema_verified:false},{rows_written:1}])assert.throws(()=>simpleAuthorization(env,{...baseline,...patch}));
});
test('code-only staging retains the database, derives source, deploys once and needs no manual evidence',async()=>{
 const DB=new FullDB();try{let deployments=0;const report=await simpleRelease(env,{baseline,DB,get:async route=>{assert.ok(route.endsWith('/time_travel/bookmark'));return {bookmark:'private-fixture-bookmark'};},deploy:async(e,event,commit)=>{deployments++;assert.equal(e.GITHUB_REF,'refs/heads/main');assert.equal(e.CF_STAGING_APPROVED_COMMIT,sha);assert.equal(e.CF_STAGING_RECOVERY_EVIDENCE,undefined);assert.equal(commit,sha);assert.equal(event.inputs.operation,'update');}});
 assert.equal(report.status,'passed');assert.equal(deployments,1);assert.doesNotMatch(JSON.stringify(report),/private-fixture-bookmark/);
 }finally{DB.close();}
});
test('initialization cannot run on push and an uninitialized database cannot receive a routine deployment',async()=>{
 await assert.rejects(simpleRelease({...env,SIMPLE_STAGING_OPERATION:'initialize'},{baseline}));
 const DB=new FullDB({empty:true});try{await assert.rejects(simpleRelease(env,{baseline,DB,get:async()=>({bookmark:'fixture'}),deploy:()=>assert.fail('No deployment')}));}finally{DB.close();}
});
test('native migration names/order, target separation and destructive SQL stay guarded',()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'native-fixture-'));fs.mkdirSync(path.join(root,'release/migrations'),{recursive:true});
 try{fs.writeFileSync(path.join(root,'release/migrations/0001_fixture.sql'),'CREATE TABLE fixture(id TEXT);');assert.equal(forwardMigrations(root).length,1);
 fs.writeFileSync(path.join(root,'release/migrations/0002_destroy.sql'),'DELETE FROM users');assert.throws(()=>forwardMigrations(root));
 assert.throws(()=>migrationConfig({production:true,account:TARGET.account}));assert.throws(()=>migrationConfig({account:'f'.repeat(32)}));
 assert.equal(migrationConfig({account:TARGET.account}).d1_databases[0].database_id,env.CF_STAGING_D1_DATABASE_ID);
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
test('D1 native history must match filenames and checksums; unknown or edited history never replays',async()=>{
 const DB=new FullDB();try{const files=[{name:'0001_fixture.sql',sha256:identity}];assert.deepEqual(await verifyNativeHistory(DB,files),files);
 await DB.query('CREATE TABLE d1_migrations(id INTEGER PRIMARY KEY,name TEXT)');await DB.query("INSERT INTO d1_migrations VALUES(1,'0001_fixture.sql')");
 await assert.rejects(verifyNativeHistory(DB,files));await recordNativeChecksums(DB,files);assert.deepEqual(await verifyNativeHistory(DB,files),[]);
 await assert.rejects(verifyNativeHistory(DB,[{...files[0],sha256:'f'.repeat(64)}]));await assert.rejects(verifyNativeHistory(DB,[]));
 }finally{DB.close();}
});
test('production baseline uses only schema SELECT and Worker metadata/content, never customer rows or readiness queries',async()=>{
 const objects=canonical([{type:'table',name:'users',tbl_name:'users',sql:'CREATE TABLE users(id TEXT)'}]);
 const expected={objects,schema_sha256:digest(objects),backend_identity:identity,application_schema_files:[{path:'fixture',sha256:identity}]};
 const calls=[],auditEnv={CLOUDFLARE_AUDIT_ACCOUNT_ID:'e'.repeat(32),CLOUDFLARE_AUDIT_API_TOKEN:'secret-fixture',BASELINE_SOURCE_SHA:sha};
 const transport=async(url,init)=>{calls.push({url:String(url),method:init.method});assert.equal(init.redirect,'error');assert.ok(String(url).startsWith('https://api.cloudflare.com/client/v4/accounts/'+'e'.repeat(32)));
 if(init.method==='POST'){assert.ok(String(url).endsWith('/'+PRODUCTION_DB+'/query'));assert.deepEqual(JSON.parse(init.body),{sql:schemaSQL});return Response.json({success:true,result:[{success:true,results:objects,meta:{rows_written:0}}]});}
 assert.equal(init.method,'GET');if(String(url).endsWith('/content'))return new Response('var releaseIdentity="'+identity+'";');
 return Response.json({success:true,result:String(url).endsWith('/deployments')?{deployments:[{id:'deployment',versions:[{version_id:'version',percentage:100}]}]}:{uuid:PRODUCTION_DB,name:'cveharbor-accounts'}});};
 const report=await auditBaseline(auditEnv,expected,{transport});assert.equal(report.status,'verified');assert.equal(report.customer_records_read,false);assert.equal(report.rows_written,0);assert.doesNotMatch(JSON.stringify(report),/secret-fixture|CREATE TABLE/);assert.equal(calls.filter(c=>c.method==='POST').length,1);
 const wrong=await auditBaseline(auditEnv,{...expected,backend_identity:'f'.repeat(64)},{transport});assert.equal(wrong.status,'blocked');
 await assert.rejects(auditBaseline({...auditEnv,CLOUDFLARE_AUDIT_ACCOUNT_ID:TARGET.account},expected,{transport}));
});
test('production promotion rejects stale SHA, PR runs, skipped staging and partial initialization receipts',()=>{
 const run={head_sha:sha,head_branch:'main',event:'push',path:'.github/workflows/cvie-staging.yml',status:'completed',conclusion:'success'};
 const job={name:'automatic-staging',conclusion:'success'};const receipt={status:'passed',operation:'release',source_sha:sha,account:TARGET.account,database_id:env.CF_STAGING_D1_DATABASE_ID,production_mutations:0,backend_identity:identity};
 assert.equal(verifyReceipt(run,job,receipt,sha,identity),receipt);
 for(const patch of [{head_sha:'f'.repeat(40)},{event:'pull_request'},{head_branch:'feature'},{conclusion:'failure'}])assert.throws(()=>verifyReceipt({...run,...patch},job,receipt,sha,identity));
 assert.throws(()=>verifyReceipt(run,{...job,conclusion:'skipped'},receipt,sha,identity));assert.throws(()=>verifyReceipt(run,job,{...receipt,status:'schema_initialized'},sha,identity));
});

test('frontend waits outside mutation lock, stops on failure, and publishes only after backend matches',async()=>{
 const {waitFrontendBackend}=await import('../../scripts/verify_frontend_backend.mjs');let checks=0;
 const result=await waitFrontendBackend({attempts:3,sleep:async()=>{},verify:async()=>{if(++checks<3)throw Error('Old backend');return {ready:true};}});
 assert.equal(result.ready,true);assert.equal(checks,3);
 await assert.rejects(waitFrontendBackend({attempts:2,sleep:async()=>{},verify:async()=>{throw Error('Recovery hold');}}));
});

test('exceptional staging resume is explicit, revision checked, integrity gated and never deployment evidence',async()=>{
 const {setHold}=await import('../../scripts/recovery_control.mjs');const DB=new FullDB();
 try{
  const held=await setHold(DB,{hold:true,revision:0,reason:'Synthetic failure recovery'});
  const recoveryEnv={...env,GITHUB_EVENT_NAME:'workflow_dispatch',SIMPLE_STAGING_OPERATION:'resume',CF_STAGING_EXPECTED_HOLD_REVISION:String(held.revision),CF_STAGING_RECOVERY_REASON:'Validated synthetic recovery'};
  const deps={baseline,DB,get:async()=>({bookmark:'private'})};
  await assert.rejects(simpleRelease({...recoveryEnv,GITHUB_EVENT_NAME:'push'},deps));
  await assert.rejects(simpleRelease({...recoveryEnv,CF_STAGING_EXPECTED_HOLD_REVISION:'999'},deps));
  const result=await simpleRelease(recoveryEnv,deps);assert.equal(result.status,'resumed');assert.equal(result.workers_deployed,false);
 }finally{DB.close();}
});

test('failed native migration retains the staging hold and cannot deploy or emit promotion evidence',async()=>{
 const {holdStatus}=await import('../../scripts/recovery_control.mjs');const DB=new FullDB();
 try{
  let ran=0;
  await assert.rejects(simpleRelease(env,{baseline,DB,get:async()=>({bookmark:'private'}),checkNative:async()=>[{name:'fixture.sql'}],runner:(cmd,args,options)=>{ran++;assert.ok(args.includes('--remote'));assert.equal(options.env.CLOUDFLARE_ACCOUNT_ID,TARGET.account);throw Error('Synthetic migration failure');},deploy:()=>assert.fail('Deployment after migration failure')}));
  assert.equal(ran,1);assert.equal((await holdStatus(DB)).write_hold,1);
 }finally{DB.close();}
});
