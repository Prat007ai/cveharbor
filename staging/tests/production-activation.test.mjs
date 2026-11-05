import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {FullDB} from './helpers/full-db.mjs';import {TARGET,LEGACY_ORIGIN} from '../target.mjs';
import {configs} from '../scripts/configure.mjs';import {productionEnvironment} from '../production-runtime.mjs';
import {createFrontend} from '../frontend.mjs';import {executeRelease} from '../scripts/release.mjs';
import {simpleRelease} from '../scripts/simple-release.mjs';
import {safeFailure} from '../scripts/errors.mjs';
const baseline=JSON.parse(fs.readFileSync('release/baseline.json'));
const sha='a'.repeat(40),env={GITHUB_REPOSITORY:'Prat007ai/cveharbor',GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_SHA:sha,SIMPLE_STAGING_ENABLED:'true',STAGING_APPLICATION_ENABLED:'true',CF_STAGING_APPLICATION_PROFILE:'production-baseline',CF_STAGING_APPROVED_COMMIT:sha,CF_STAGING_PROVISION_ACTION:'update',CF_STAGING_ACCOUNT_ID:TARGET.account,CF_STAGING_D1_DATABASE_ID:'fac61562-fc31-426d-8032-550aba63b7f6',CF_STAGING_ACCESS_ISSUER:'https://synthetic.cloudflareaccess.com',CF_STAGING_ACCESS_AUD:'a'.repeat(64),CF_STAGING_ADMIN_EMAILS:'admin@example.invalid'};
const database=()=>{const db=new FullDB({empty:true});db.sql.exec(fs.readFileSync('staging/schema.sql','utf8'));db.sql.prepare('INSERT INTO staging_schema_history(path,sha256,manifest_version) VALUES(?,?,1)').run('staging/schema.sql',JSON.parse(fs.readFileSync('staging/migrations.v1.json')).entries[0].sha256);for(const f of baseline.application_schema_files){db.sql.exec(fs.readFileSync(f.path,'utf8'));db.sql.prepare('INSERT INTO staging_schema_history(path,sha256,manifest_version) VALUES(?,?,1)').run(f.path,f.sha256);}return db;};
test('production compatibility changes only the staging recovery requirement and preserves published feature flags',()=>{
 const result=productionEnvironment({RECOVERY_CONTROL_REQUIRED:'true',CVIE_REGISTRY_ENABLED:'true',WEBSITE_MONITOR_ENABLED:'true',ALERT_DELIVERY_ENABLED:'true',SMTP2GO_API_KEY:'staging-capture-only'});
 assert.equal(result.RECOVERY_CONTROL_REQUIRED,'false');assert.equal(result.CVIE_REGISTRY_ENABLED,undefined);assert.equal(result.WEBSITE_MONITOR_ENABLED,'false');assert.equal(result.ALERT_DELIVERY_ENABLED,'true');assert.equal(baseline.runtime_flags.values.RECOVERY_CONTROL_REQUIRED,'true');
 const c=configs(env);assert.equal(c.api.vars.RECOVERY_CONTROL_REQUIRED,'false');assert.equal(c.api.vars.STAGING_APPLICATION_PROFILE,'production-baseline');assert.equal(c.api.workers_dev,false);assert.deepEqual(c.site.routes,[{pattern:'cveharborstage.com',custom_domain:true}]);assert.equal(c.site.assets.run_worker_first,true);assert.equal(c.api.d1_databases[0].database_id,env.CF_STAGING_D1_DATABASE_ID);
});
test('custom domain is Access gated; legacy host serves only authenticated readiness; application sessions cannot bypass Access',async()=>{
 let reads=0;const bindings={ASSETS:{fetch:async()=>{reads++;return new Response('private');}},STAGING_API:{fetch:async()=>{reads++;return new Response('readiness');}}};
 const blocked=createFrontend(async()=>false);for(const origin of [TARGET.origin,LEGACY_ORIGIN])for(const path of ['/','/workspace/','/v1/me','/assignment/id','/data.js','/v1/staging-readiness'])assert.equal((await blocked.fetch(new Request(origin+path,{headers:{Cookie:'cvh_session='+'a'.repeat(64),'Cf-Access-Authenticated-User-Email':'admin@example.invalid'}}),bindings)).status,403);
 assert.equal(reads,0);const allowed=createFrontend(async()=>true);
 for(const path of ['/','/workspace/','/v1/me','/assignment/id','/data.js'])assert.equal((await allowed.fetch(new Request(LEGACY_ORIGIN+path),bindings)).status,403);
 assert.equal((await allowed.fetch(new Request(LEGACY_ORIGIN+'/v1/staging-readiness'),bindings)).status,200);
 assert.equal((await allowed.fetch(new Request(TARGET.origin+'/'),bindings)).status,200);
});
function dependencies(DB,calls,fail){return {DB,bundle:{commit:sha,account:TARGET.account,providers:'synthetic-only',application_profile:'production-baseline',source_mode:'production-baseline',backend_source_sha:baseline.backend.source_sha,frontend_source_sha:baseline.frontend.source_sha,backend_identity:baseline.backend.identity,schema_sha256:baseline.schema_sha256},preflight:async()=>({account:TARGET.account,read_only_checks_passed:true,blockers:[],checks:['service_token_matches_policy_and_client','token_permission_grants','token_staging_only_scope'].map(name=>({name,status:'pass'}))}),diagnose:async()=>({verified:true,workers:[]}),get:async route=>{assert.ok(!route.includes('bookmark'));return route==='/workers/domains'?[{hostname:'cveharborstage.com',service:TARGET.site}]:route.endsWith('/managed')?{enabled:false}:route.endsWith('/custom')?{domains:[]}:{name:'cveharbor-intelligence-staging'};},runner:(_cmd,args)=>{const action=(args.some(a=>a.endsWith('/api.json'))?'api':'site')+(args.includes('--dry-run')?'-dry':'-upload');calls.push(action);return {status:action===fail?1:0};},inspectWorker:async()=>({verified:true}),probeBackend:async(_e,_t,options)=>{calls.push(options?.bootstrap?'backend-bootstrap':'backend-custom');if(fail==='backend-bootstrap'&&options?.bootstrap)throw Error('unready');return {};},probeAccess:async()=>({passed:true,checks:[]})};}
test('existing-Worker update uses exact production schema without recovery tables or database writes; backend verified first',async()=>{
 for(const fail of [null,'api-upload','backend-bootstrap']){const DB=database(),calls=[];try{
  const before=DB.sql.prepare('SELECT total_changes() n').get().n;
  const op=executeRelease(env,{inputs:{operation:'update'}},sha,dependencies(DB,calls,fail));
  if(fail){await assert.rejects(op);assert.ok(!calls.includes('site-upload'));}else{assert.equal((await op).completed,true);assert.deepEqual(calls,['api-dry','site-dry','api-upload','backend-bootstrap','site-upload','backend-custom']);}
  assert.equal(DB.sql.prepare('SELECT total_changes() n').get().n,before);assert.equal(DB.sql.prepare("SELECT name FROM sqlite_schema WHERE name='operations_control'").get(),undefined);
 }finally{DB.close();}}
});
test('production activation is blocked until administrator enables it; approved code-only release cannot migrate',async()=>{
 const DB=database();let uploads=0;try{
  const deps={baseline,DB,get:()=>assert.fail('No recovery capture required'),deploy:async()=>{uploads++;return {completed:true};},initialize:()=>assert.fail('No migration'),runner:()=>assert.fail('No migration')};
  await assert.rejects(simpleRelease({...env,STAGING_APPLICATION_ENABLED:'false'},deps));assert.equal(uploads,0);
  assert.equal((await simpleRelease(env,deps)).status,'passed');assert.equal(uploads,1);
  DB.sql.exec('CREATE TABLE unreviewed(id TEXT)');await assert.rejects(simpleRelease(env,deps));assert.equal(uploads,1);
 }finally{DB.close();}
});
test('synthetic preflight diagnostics survive the workflow wrapper without migrations or uploads',async()=>{
 const DB=database();let saved;try{
  const before=DB.sql.prepare('SELECT total_changes() n').get().n;
  const deploy=async(e,event,commit,options)=>{
   const d=dependencies(DB,[],null);
   d.preflight=async()=>({account:TARGET.account,read_only_checks_passed:false,blockers:['exact_access_application'],checks:[{name:'exact_access_application',status:'fail',http_status:200,matching_application_count:0}]});
   d.runner=d.get=d.diagnose=()=>assert.fail('No publication or mutations after validation failure');
   return executeRelease(e,event,commit,{...d,...options});
  };
  await assert.rejects(simpleRelease({...env,SIMPLE_STAGING_OPERATION:'publish-synthetic'},{baseline,DB,deploy,get:()=>assert.fail('No recovery or mutation'),record:r=>{saved=structuredClone(r);}}),error=>safeFailure(error).check==='exact_access_application');
  assert.equal(saved.failure.check,'exact_access_application');
  assert.equal(saved.deployment.preflight.checks[0].matching_application_count,0);
  assert.deepEqual(saved.deployment.steps,[]);
  assert.equal(DB.sql.prepare('SELECT total_changes() n').get().n,before);
 }finally{DB.close();}
});
