import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {expectedBaseline,auditBaseline,schemaSQL,runtimeCompatibility} from '../../scripts/production_schema_baseline.mjs';
import {backendIdentity} from '../../scripts/build_release_identity.mjs';
import {FullDB} from './helpers/full-db.mjs';
import {recoveryProtected} from '../../account-backend/src/recovery-control.js';
const profile=JSON.parse(fs.readFileSync(new URL('../../release/baseline.json',import.meta.url)));
function productionSchema(){const DB=new FullDB({empty:true});for(const f of profile.application_schema_files)DB.sql.exec(fs.readFileSync(new URL('../../'+f.path,import.meta.url),'utf8'));return DB;}
test('reconciled active version passes with the same source/schema and explicit incompatible runtime result',async()=>{
 const expected=expectedBaseline(new URL('../..',import.meta.url).pathname),DB=productionSchema();let posts=0;
 assert.equal(backendIdentity(new URL('../..',import.meta.url).pathname),profile.backend.identity);
 const transport=async(url,init)=>{
  const p=new URL(url).pathname;let result;
  if(init.method==='POST'){posts++;assert.ok(p.endsWith('/'+profile.production_database_id+'/query'));assert.deepEqual(JSON.parse(init.body),{sql:schemaSQL});result=[{success:true,results:DB.sql.prepare(schemaSQL).all(),meta:{rows_written:0}}];}
  else{
   assert.equal(init.method,'GET');
   if(p.endsWith('/content/v2'))return new Response('var releaseIdentity="'+profile.backend.identity+'";',{headers:{ETag:'"active-script"','Content-Type':'text/javascript'}});
   if(p.includes('/versions/'))result={id:profile.backend.version_id,resources:{script:{etag:'active-script'},bindings:Object.entries(profile.runtime_flags.values).filter(([,v])=>v!==null).map(([name,text])=>({name,type:'plain_text',text}))}};
   else if(p.endsWith('/deployments')){const v=p.includes('cveharbor-site')?profile.frontend:profile.backend;result={deployments:[{id:v.deployment_id,versions:[{version_id:v.version_id,percentage:100}]}]};}
   else result={uuid:profile.production_database_id,name:'cveharbor-accounts'};
  }
  return Response.json({success:true,result});
 };
 try{
  const r=await auditBaseline({CLOUDFLARE_AUDIT_ACCOUNT_ID:'e'.repeat(32),CLOUDFLARE_AUDIT_API_TOKEN:'synthetic-only',GITHUB_RUN_ID:'41909431530'},expected,{transport});
  assert.equal(r.status,'verified');assert.equal(r.backend_verified,true);assert.equal(r.frontend_verified,true);assert.equal(r.schema_verified,true);
  assert.equal(r.backend.deployment_id,r.worker_deployment_id);assert.equal(r.backend.version_id,r.worker_version_id);assert.equal(r.frontend.deployment_id,r.frontend_deployment_id);
  assert.equal(r.audit_run_id,41909431530);assert.deepEqual(r.runtime_flags,profile.runtime_flags);assert.deepEqual(r.runtime_compatibility,profile.runtime_compatibility);assert.equal(r.application_ready,false);
  assert.equal(r.customer_records_read,false);assert.equal(r.rows_written,0);assert.equal(posts,1);
  const old=await auditBaseline({CLOUDFLARE_AUDIT_ACCOUNT_ID:'e'.repeat(32),CLOUDFLARE_AUDIT_API_TOKEN:'synthetic-only'}, {...expected,profile:{...profile,backend:{...profile.backend,version_id:'aa8ce0f2-73d3-4714-b4c1-583d1f7283e1'}}},{transport});
  assert.equal(old.backend_verified,false);assert.equal(old.status,'blocked');
  assert.equal(old.backend.deployment_id,profile.backend.deployment_id,'Report actual deployment, never stale expected metadata');
 }finally{DB.close();}
});
test('required recovery control with the actual production schema returns 503 and skips scheduled work locally',async()=>{
 const DB=productionSchema();let fetches=0,schedules=0,background=0;
 const handler=recoveryProtected({fetch:()=>{fetches++;return new Response('unexpected');},scheduled:()=>{schedules++;}});
 const env={DB,RECOVERY_CONTROL_REQUIRED:profile.runtime_flags.values.RECOVERY_CONTROL_REQUIRED};
 const changes=DB.sql.prepare('SELECT total_changes() n').get().n;
 try{
  for(const url of ['https://api.cveharbor.com/v1/me','https://confirm.cveharbor.com/assignment/synthetic']){
   const r=await handler.fetch(new Request(url),env,{waitUntil:()=>background++});assert.equal(r.status,503);assert.equal(r.headers.get('Retry-After'),'60');
  }
  await handler.scheduled({cron:'5 * * * *'},env,{waitUntil:()=>background++});
  assert.equal(fetches,0);assert.equal(schedules,0);assert.equal(background,0);assert.equal(DB.sql.prepare('SELECT total_changes() n').get().n,changes);
  assert.equal(DB.sql.prepare('PRAGMA integrity_check').get().integrity_check,'ok');
 }finally{DB.close();}
});
test('unknown, optional, or installed recovery metadata never falsely certifies application readiness',()=>{
 for(const flags of [{available:false,values:{}},{available:true,values:{RECOVERY_CONTROL_REQUIRED:'false'}}])assert.equal(runtimeCompatibility(flags,[]).status,'not_fully_assessed');
 const present=['operations_control','operations_leases','operations_events'].map(name=>({type:'table',name}));
 assert.equal(runtimeCompatibility(profile.runtime_flags,present).status,'not_fully_assessed');
});
