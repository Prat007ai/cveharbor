// Enabled only after the one-time baseline review and administrator activation.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';import {fileURLToPath} from 'node:url';
import {TARGET} from '../target.mjs';import {root} from './configure.mjs';import {management} from './diagnose.mjs';
import {loadMigrationPlan,migrate} from './migrate.mjs';import {migrationState,verifySchema} from './manifest-state.mjs';
import {executeRelease} from './release.mjs';import {holdStatus,setHold,installGuards} from '../../scripts/recovery_control.mjs';
import {d1Client} from '../../scripts/cloudflare_d1.mjs';import {forwardMigrations,migrationConfig} from '../../scripts/release_migrations.mjs';
import {backendIdentity} from '../../scripts/build_release_identity.mjs';
export function simpleAuthorization(env,baseline){
 assert.equal(env.GITHUB_REPOSITORY,'Prat007ai/cveharbor');assert.equal(env.GITHUB_REF,'refs/heads/main');
 assert.ok(['push','workflow_dispatch'].includes(env.GITHUB_EVENT_NAME));assert.equal(env.SIMPLE_STAGING_ENABLED,'true');
 assert.match(env.GITHUB_SHA||'',/^[a-f0-9]{40}$/);assert.equal(env.CF_STAGING_ACCOUNT_ID,TARGET.account);
 assert.equal(env.CF_STAGING_D1_DATABASE_ID,'fac61562-fc31-426d-8032-550aba63b7f6');
 assert.equal(baseline.status,'verified');assert.equal(baseline.schema_verified,true);assert.equal(baseline.deployed_release_verified,true);
 assert.equal(baseline.customer_records_read,false);assert.equal(baseline.rows_written,0);assert.equal(baseline.production_database_id,TARGET.productionDatabase);
 assert.match(baseline.source_sha,/^[a-f0-9]{40}$/);assert.match(baseline.schema_sha256,/^[a-f0-9]{64}$/);
 assert.ok(baseline.application_schema_files.length>0,'Reviewed production baseline required');
}
export async function simpleRelease(env,{baseline=JSON.parse(fs.readFileSync(path.join(root,'../release/baseline.json'))),get,DB,runner,initialize,deploy,checkNative,sleep=ms=>new Promise(r=>setTimeout(r,ms)),clock=()=>new Date().toISOString()}={}){
 simpleAuthorization(env,baseline);
 const operation=env.SIMPLE_STAGING_OPERATION||'release';assert.ok(['release','initialize','resume'].includes(operation));
 if(operation!=='release')assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch','Initialization/recovery needs one explicit approval');
 const derived={...env,CF_STAGING_APPROVED_COMMIT:env.GITHUB_SHA};
 get??=management(derived);DB??=d1Client({database:env.CF_STAGING_D1_DATABASE_ID,readOnly:false,env:{CLOUDFLARE_ACCOUNT_ID:TARGET.account,CLOUDFLARE_API_TOKEN:env.CF_STAGING_API_TOKEN}});
 const report={version:1,status:'stopped',source_sha:env.GITHUB_SHA,operation,account:TARGET.account,database_id:env.CF_STAGING_D1_DATABASE_ID,started_at:clock(),baseline_source_sha:baseline.source_sha,production_mutations:0};
 // Recoverable Time Travel availability, not a secret containing a hand-edited deadline.
 const bookmark=await get('/d1/database/'+env.CF_STAGING_D1_DATABASE_ID+'/time_travel/bookmark');assert.ok(bookmark?.bookmark,'D1 Time Travel unavailable');
 report.recovery_timestamp=clock(); // Raw bookmark stays in memory, never public artifacts.
 if(operation==='resume'){
  assert.match(env.CF_STAGING_EXPECTED_HOLD_REVISION||'',/^\d+$/);
  await verifySchema(DB);
  assert.equal((await verifyNativeHistory(DB,forwardMigrations(path.resolve(root,'..')))).length,0,'Pending or unverified native migrations block resume');
  await setHold(DB,{hold:false,revision:Number(env.CF_STAGING_EXPECTED_HOLD_REVISION),reason:env.CF_STAGING_RECOVERY_REASON});
  report.status='resumed';report.workers_deployed=false;return report;
 }
 if(operation==='initialize'){
  const state=await migrationState(DB),plan=loadMigrationPlan({...derived,CF_STAGING_SCHEMA_PLAN_SHA256:JSON.parse(fs.readFileSync(path.join(root,'bootstrap-approval.v1.json'))).execution_plan_sha256});
  assert.equal(state.rows.length,2,'Only verified adopted checkpoint 37 may initialize');
  const productionFiles=baseline.application_schema_files;
  for(let i=0;i<productionFiles.length;i++){const e=plan.files[i+1];assert.equal(e.file,productionFiles[i].path);assert.equal(e.sha256,productionFiles[i].sha256);}
  const baselineEnd=plan.files[productionFiles.length].end;
  const init=initialize||migrate;
  const baseEnv={...derived,STAGING_CHANGE_APPROVED:'PR243-STAGING-ONLY',CF_STAGING_PROVISION_ACTION:'migrate',CF_STAGING_SCHEMA_PLAN_SHA256:JSON.parse(fs.readFileSync(path.join(root,'bootstrap-approval.v1.json'))).execution_plan_sha256,CF_STAGING_SCHEMA_RESUME_STEP:'37'};
  // Two locally reviewed phases, one approved operation. Exact prefix/data guards remain.
  assert.ok(baselineEnd>=37&&baselineEnd<=plan.checkpoints.length-1,'Baseline must be a reviewed forward prefix');
  if(baselineEnd>37)report.baseline=await init(baseEnv,{plan,endStep:baselineEnd});
  if(baselineEnd<plan.checkpoints.length-1)report.candidate=await init({...baseEnv,CF_STAGING_SCHEMA_RESUME_STEP:String(baselineEnd)},{plan});
  report.status='schema_initialized';report.access_restored=false;report.workers_deployed=false;return report;
 }
 const state=await migrationState(DB);assert.equal(state.pending.length,0,'Run the separately approved one-time initialization first');
 const migrations=forwardMigrations(path.resolve(root,'..'));
 // Verify applied native history and checksums before trusting or extending it.
 const pending=checkNative?await checkNative(DB,migrations):await verifyNativeHistory(DB,migrations);
 let ownedHold=null;
 const run=runner||((cmd,args,options)=>{const r=spawnSync(cmd,args,{...options,stdio:'pipe',timeout:180000});assert.equal(r.status,0,'Native staging migration failed; maintenance retained');});
 if(pending.length){
  const before=await holdStatus(DB);assert.equal(before.write_hold,0,'Existing operator hold must not be overridden');assert.equal(before.database_frozen,0);
  const held=await setHold(DB,{hold:true,revision:before.revision,reason:'Automatic staging schema release'});ownedHold=held.revision;
  // Wait briefly for in-flight operations; never expire their leases.
  let drain=held;for(let attempt=0;drain.active_leases>0&&attempt<12;attempt++){await sleep(5000);drain=await holdStatus(DB);assert.equal(drain.revision,ownedHold);assert.equal(drain.write_hold,1);assert.equal(drain.database_frozen,0);}
  assert.equal(drain.active_leases,0,'No migration performed; admission hold retained until active operations drain');
  const config=migrationConfig({account:TARGET.account,root:path.resolve(root,'..')});fs.mkdirSync(path.join(root,'.build'),{recursive:true});const configPath=path.join(root,'.build/native-migrations.json');fs.writeFileSync(configPath,JSON.stringify(config));
  run('npx',['--yes','wrangler@4.156.0','d1','migrations','apply',TARGET.database,'--remote','--config',configPath],{cwd:root,env:{PATH:env.PATH,CI:'true',CLOUDFLARE_ACCOUNT_ID:TARGET.account,CLOUDFLARE_API_TOKEN:env.CF_STAGING_API_TOKEN,CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV:'false',WRANGLER_SEND_METRICS:'false'}});
  await installGuards(DB);await recordNativeChecksums(DB,migrations);await verifySchema(DB);await setHold(DB,{hold:false,revision:ownedHold,reason:'Staging native migrations verified'});ownedHold=null;
 }
 // Reuse the established backend-before-frontend deployment and smoke gates.
 const internal={...derived,CF_STAGING_PROVISION_ACTION:'update'};
 await (deploy||executeRelease)(internal,{inputs:{operation:'update'}},env.GITHUB_SHA);
 report.status='passed';report.backend_identity=backendIdentity();report.native_migrations=migrations.map(({name,sha256})=>({name,sha256}));report.completed_at=clock();return report;
}
export async function verifyNativeHistory(DB,files){
 const has=await DB.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name='d1_migrations'").first();
 if(!has)return files;
 const rows=(await DB.prepare('SELECT name FROM d1_migrations ORDER BY id').all()).results;
 const receipt=await DB.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name='d1_release_checksums'").first();
 assert.ok(!rows.length||receipt,'Native checksum baseline missing');
 for(let i=0;i<rows.length;i++){assert.equal(rows[i].name,files[i]?.name,'Unknown/reordered native migration');const r=await DB.prepare('SELECT sha256 FROM d1_release_checksums WHERE name=?').bind(rows[i].name).first();assert.equal(r?.sha256,files[i].sha256,'Applied native migration changed');}
 return files.slice(rows.length);
}
export async function recordNativeChecksums(DB,files){
 await DB.query('CREATE TABLE IF NOT EXISTS d1_release_checksums(name TEXT PRIMARY KEY,sha256 TEXT NOT NULL)');
 const rows=(await DB.prepare('SELECT name FROM d1_migrations ORDER BY id').all()).results;assert.deepEqual(rows.map(r=>r.name),files.map(f=>f.name));
 for(const f of files)await DB.prepare('INSERT OR IGNORE INTO d1_release_checksums(name,sha256) VALUES(?,?)').bind(f.name,f.sha256).run();
 await verifyNativeHistory(DB,files);
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{const report=await simpleRelease(process.env);fs.mkdirSync('release/artifacts',{recursive:true});fs.writeFileSync('release/artifacts/staging-release.json',JSON.stringify(report,null,2)+'\n');console.log('Staging operation completed: '+report.status);}
 catch{console.error('Staging release stopped; no automatic reset/restore or production action. Existing maintenance is retained.');process.exitCode=1;}
}
