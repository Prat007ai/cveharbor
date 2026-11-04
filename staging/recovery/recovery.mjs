// Deliberately separate from release.mjs: no migrations, deployment or Access writes.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {TARGET} from '../target.mjs';
import {diagnoseSchema,DIAGNOSTIC_DATABASE_ID,REFERENCE_SHA256} from '../scripts/schema-diagnostic.mjs';
import {hash,requireThat,certificate,encrypt,verifyReceipt} from './crypto.mjs';
import {recoveryStore,boundedBytes} from './store.mjs';
export const OPERATIONS=['recovery-inventory','recovery-snapshot','recovery-capture','recovery-verify'];
const ROOT=fileURLToPath(new URL('../../',import.meta.url)),BASE='https://api.cloudflare.com/client/v4/accounts/'+TARGET.account;
const DB='/d1/database/'+DIAGNOSTIC_DATABASE_ID,HOST=new URL(TARGET.origin).hostname;
const privateEnv=dir=>({PATH:process.env.PATH,HOME:dir,TMPDIR:dir,SQLITE_TMPDIR:dir,PYTHONDONTWRITEBYTECODE:'1'});
export function authorize(env,event,checkout){
 const op=env.CF_STAGING_PROVISION_ACTION;
 requireThat(OPERATIONS.includes(op)&&env.GITHUB_REPOSITORY==='Prat007ai/cveharbor'&&env.GITHUB_REF==='refs/heads/codex/cvie-core-phase012','operation_boundary');
 requireThat(/^[a-f0-9]{40}$/.test(checkout||'')&&checkout===env.GITHUB_SHA&&checkout===env.CF_STAGING_APPROVED_COMMIT,'source_approval');
 requireThat(env.CF_STAGING_ACCOUNT_ID===TARGET.account&&env.CF_STAGING_D1_DATABASE_ID===DIAGNOSTIC_DATABASE_ID,'target_boundary');
 requireThat(env.GITHUB_EVENT_NAME==='workflow_dispatch'?event.inputs?.operation===op:env.GITHUB_EVENT_NAME==='push'&&Number(env.GITHUB_RUN_ATTEMPT)>1&&event.head_commit?.id===checkout&&event.head_commit.message.includes('[staging-release]'),'event_boundary');return op;
}
export function maintenance(env,now=Date.now()){
 let p;try{p=JSON.parse(env.CF_STAGING_RECOVERY_ISOLATION||'');}catch{throw Error('maintenance_evidence_missing');}
 const start=Date.parse(p?.window_start),end=Date.parse(p?.window_end),observed=Date.parse(p?.observed_at);
 requireThat(p&&p.account===TARGET.account&&p.database_id===DIAGNOSTIC_DATABASE_ID&&p.source_sha===env.GITHUB_SHA&&p.snapshot_sha256===env.CF_STAGING_RECOVERY_SNAPSHOT_SHA256,'maintenance_binding');
 requireThat(Number.isFinite(start)&&Number.isFinite(end)&&end-start>0&&end-start<=1800000&&start<=now&&now<end&&now>=observed&&now-observed<=900000,'maintenance_expired');
 for(const flag of ['non_access_writers_quiesced','invocations_drained','human_session_denied','application_sessions_revoked','no_other_mutation_jobs','all_ingress_identified'])requireThat(p[flag]===true,'writer_isolation_not_attested');
 for(const field of ['drain_evidence_sha256','original_access_sha256','worker_state_sha256'])requireThat(/^[a-f0-9]{64}$/.test(p[field]||''),'maintenance_evidence_hash');
 requireThat(/^[a-f0-9-]{36}$/.test(p.access_app_id||''),'maintenance_app');return p;
}
export function secureTemp(requiredBytes=512*1024*1024){
 const stat=fs.statfsSync('/dev/shm');requireThat(Number(stat.type)===0x01021994&&Number(stat.bavail)*Number(stat.bsize)>=requiredBytes,'secure_tmpfs_capacity');
 requireThat(fs.readFileSync('/proc/swaps','utf8').trim().split('\n').length===1,'swap_must_be_disabled');
 const dir=fs.mkdtempSync('/dev/shm/cvie-recovery-');fs.chmodSync(dir,0o700);return dir;
}
export function managementRoute(route){
 return route===''||route===DB||route===DB+'/time_travel/bookmark'||route==='/workers/scripts'||route==='/workers/domains'||
 /^\/workers\/scripts\/(cveharbor-accounts-staging|cveharbor-site-staging)\/(settings|subdomain|schedules|deployments)$/.test(route)||
 route==='/access/apps?per_page=100'||/^\/access\/apps\/[a-f0-9-]{36}\/policies$/.test(route)||
 route==='/r2/buckets?per_page=1000'||/^\/r2\/buckets\/[a-z0-9-]{3,63}(?:\/domains\/(managed|custom)|\/cors)?$/.test(route);
}
export async function execute(env,{transport=fetch,temp=secureTemp,clock=Date.now,sleep=ms=>new Promise(r=>setTimeout(r,ms))}={}){
 const op=env.CF_STAGING_PROVISION_ACTION;requireThat(OPERATIONS.includes(op)&&env.CF_STAGING_API_TOKEN,'operation_credentials');
 let dir;const window=()=>{if(['recovery-capture','recovery-verify'].includes(op))return maintenance(env,clock());};
 async function api(route,body){
  window();requireThat(body?op==='recovery-capture'&&route===DB+'/export':managementRoute(route),'management_boundary');
  const r=await transport(BASE+route,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+env.CF_STAGING_API_TOKEN,'Content-Type':'application/json'},redirect:'error',signal:AbortSignal.timeout(30000),...(body?{body:JSON.stringify(body)}:{})});
  const p=await r.json();requireThat(r.ok&&p.success===true&&!p.errors?.length,'management_response');return p.result;
 }
 async function workers(){
  const all=await api('/workers/scripts');requireThat(Array.isArray(all)&&all.length===2&&[TARGET.api,TARGET.site].every(n=>all.some(w=>w.id===n)),'worker_inventory');
  const state=[];for(const name of [TARGET.api,TARGET.site]){
   const settings=await api('/workers/scripts/'+name+'/settings'),subdomain=await api('/workers/scripts/'+name+'/subdomain'),schedules=await api('/workers/scripts/'+name+'/schedules'),deployment=await api('/workers/scripts/'+name+'/deployments');
   const events=Array.isArray(schedules)?schedules:schedules?.schedules;
   requireThat(Array.isArray(events)&&events.length===0,'scheduled_writer');
   requireThat(subdomain?.enabled===(name===TARGET.site)&&subdomain.previews_enabled===false,'public_ingress');
   requireThat(Array.isArray(settings.bindings)&&settings.bindings.every(b=>['d1','service','assets','plain_text','ratelimit','secret_text','r2_bucket'].includes(b.type)),'unknown_event_binding');
   const db=settings.bindings.filter(b=>b.type==='d1');requireThat(name===TARGET.api?db.length===1&&db[0].id===DIAGNOSTIC_DATABASE_ID:db.length===0,'database_binding');
   requireThat(!settings.bindings.some(b=>b.type==='r2_bucket'&&b.bucket_name===env.CF_STAGING_RECOVERY_BUCKET),'recovery_bucket_worker_binding');
   state.push({name,settings,subdomain,schedules,deployment});
  }
  const domains=await api('/workers/domains');requireThat(Array.isArray(domains)&&domains.length===0,'custom_worker_ingress');return state;
 }
 async function access(){
  const apps=await api('/access/apps?per_page=100');requireThat(Array.isArray(apps)&&apps.length===1&&apps[0].domain===HOST&&apps[0].type==='self_hosted','access_inventory');
  const app=apps[0];requireThat(/^[a-f0-9-]{36}$/.test(app.id),'access_app_id');const policies=await api('/access/apps/'+app.id+'/policies');requireThat(Array.isArray(policies),'access_policies');return {app,policies};
 }
 async function privacy(bucket){
  requireThat(/^[a-z0-9][a-z0-9-]{2,62}$/.test(bucket)&&bucket!=='cveharbor-intelligence-staging','backup_bucket_isolation');
  const info=await api('/r2/buckets/'+bucket),managed=await api('/r2/buckets/'+bucket+'/domains/managed'),custom=await api('/r2/buckets/'+bucket+'/domains/custom');
  requireThat(info.name===bucket&&managed.enabled===false&&Array.isArray(custom.domains)&&custom.domains.length===0,'backup_bucket_public');return {info,managed,custom};
 }
 async function original(){
  let report;await diagnoseSchema({...env,CF_STAGING_PROVISION_ACTION:'diagnose-schema',CF_STAGING_SCHEMA_DIAGNOSTIC_SHA256:REFERENCE_SHA256},{transport:async(url,init)=>{window();return transport(url,init);},record:(_n,r)=>{report=structuredClone(r);}});
  requireThat(report.first_29_verified===true&&report.usage.complete&&report.usage.rows_written===0&&report.storage_delta_bytes===0,'checkpoint29_not_verified');return report;
 }
 async function bookmark(){const p=await api(DB+'/time_travel/bookmark');requireThat(typeof p.bookmark==='string'&&p.bookmark.length>=6,'bookmark_unavailable');return p;}
 async function isolated(){
  const proof=window(),state=await workers(),current=await access();
  requireThat(hash(JSON.stringify(state))===proof.worker_state_sha256,'worker_state_changed');
  requireThat(current.app.id===proof.access_app_id&&current.policies.length===1,'maintenance_policy_count');const p=current.policies[0];
  requireThat(p.decision==='block'&&JSON.stringify(p.include)==='[{"everyone":{}}]'&&!(p.exclude?.length)&&!(p.require?.length),'maintenance_not_block_all');
  for(const headers of [{},{'CF-Access-Client-Id':env.CF_STAGING_ACCESS_CLIENT_ID,'CF-Access-Client-Secret':env.CF_STAGING_ACCESS_CLIENT_SECRET}]){
   requireThat(Object.keys(headers).length===0||Object.values(headers).every(x=>typeof x==='string'&&x),'service_probe_credentials');
   const r=await transport(TARGET.origin+'/',{method:'GET',headers,redirect:'manual',signal:AbortSignal.timeout(30000)});requireThat(r.status===403,'maintenance_probe_failed');await r.body?.cancel();
  }
  return {proof,state,current};
 }
 try{
  requireThat((await api('')).id===TARGET.account,'account_identity');const db=await api(DB);requireThat(db.uuid===DIAGNOSTIC_DATABASE_ID&&db.name===TARGET.database&&Number.isSafeInteger(db.file_size)&&db.file_size<=100000000,'database_identity');
  const workerState=await workers();const currentAccess=await access();
  if(op==='recovery-inventory'){
   const result=await api('/r2/buckets?per_page=1000');requireThat(Array.isArray(result.buckets)&&!result.cursor&&result.buckets.length<1000,'bucket_inventory_incomplete');
   const buckets=[];for(const b of result.buckets.filter(x=>x.name!=='cveharbor-intelligence-staging')){let suitable=false;try{await privacy(b.name);suitable=!workerState.some(w=>w.settings.bindings.some(x=>x.type==='r2_bucket'&&x.bucket_name===b.name));}catch(error){if(error.message!=='backup_bucket_public')throw error;}buckets.push({name:b.name,private_and_unbound:suitable});}
   return {status:'inventory_complete',buckets,new_bucket_required:buckets.every(x=>!x.private_and_unbound),access_app_id:currentAccess.app.id,policies:currentAccess.policies.map(p=>({id:p.id,decision:p.decision,precedence:p.precedence,include_rule_count:p.include?.length||0})),worker_state_sha256:hash(JSON.stringify(workerState)),original_access_sha256:hash(JSON.stringify(currentAccess)),bookmark_available:!!(await bookmark()).bookmark,checkpoint29_verified:(await original()).first_29_verified};
  }
  requireThat(env.CF_STAGING_RECOVERY_KEY_CUSTODY_CONFIRMED==='true','private_key_custody_unconfirmed');
  const pem=env.CF_STAGING_RECOVERY_CERT_PEM,fingerprint=env.CF_STAGING_RECOVERY_CERT_SHA256;certificate(pem,fingerprint,clock());
  await privacy(env.CF_STAGING_RECOVERY_BUCKET);const rawStore=recoveryStore(env,transport);const store=(...args)=>{window();return rawStore(...args);};
  const key='recovery/v1/'+env.GITHUB_SHA+'/'+env.GITHUB_RUN_ID+'-'+env.GITHUB_RUN_ATTEMPT+'/',snapshotKey=env.CF_STAGING_RECOVERY_SNAPSHOT_KEY;
  dir=temp(Math.max(512*1024*1024,db.file_size*8+128*1024*1024));
  async function putPackage(content,name){
   window();const plain=path.join(dir,'package.json'),cipher=path.join(dir,'package.cms');fs.writeFileSync(plain,JSON.stringify(content),{mode:0o600,flag:'wx'});
   encrypt(plain,cipher,pem,fingerprint,dir);const bytes=fs.readFileSync(cipher);await store('PUT',key+name+'.cms',bytes);window();const downloaded=await store('GET',key+name+'.cms');requireThat(hash(downloaded)===hash(bytes),'ciphertext_readback');return hash(bytes);
  }
  if(op==='recovery-snapshot'){
   requireThat(currentAccess.policies.length===2&&currentAccess.policies.some(p=>p.decision==='allow')&&currentAccess.policies.some(p=>p.decision==='non_identity'),'original_policy_shape');
   const checksum=await putPackage({kind:'access-recovery-snapshot',account:TARGET.account,database_id:DIAGNOSTIC_DATABASE_ID,source_sha:env.GITHUB_SHA,captured_at:new Date(clock()).toISOString(),access:currentAccess,workers:workerState,original_access_sha256:hash(JSON.stringify(currentAccess)),worker_state_sha256:hash(JSON.stringify(workerState))},'snapshot');
   return {status:'snapshot_encrypted_and_stored',ciphertext_sha256:checksum,export_performed:false};
  }
  const isolatedState=await isolated();requireThat(/^recovery\/v1\/[a-f0-9]{40}\/[0-9]+-[0-9]+\/snapshot\.cms$/.test(snapshotKey||''),'snapshot_reference');
  requireThat(hash(await store('GET',snapshotKey))===env.CF_STAGING_RECOVERY_SNAPSHOT_SHA256,'snapshot_checksum');
  if(op==='recovery-verify'){
   const proof=verifyReceipt(env.CF_STAGING_RECOVERY_RESTORE_RECEIPT,env.CF_STAGING_RECOVERY_RESTORE_SIGNATURE,pem,fingerprint,{account:TARGET.account,database_id:DIAGNOSTIC_DATABASE_ID,source_sha:env.GITHUB_SHA,snapshot_sha256:env.CF_STAGING_RECOVERY_SNAPSHOT_SHA256,recipient_fingerprint:fingerprint},clock());
   requireThat(/^\d+$/.test(proof.capture_run_id)&&/^\d+$/.test(proof.capture_attempt),'capture_reference');
   const object='recovery/v1/'+env.GITHUB_SHA+'/'+proof.capture_run_id+'-'+proof.capture_attempt+'/checkpoint29.cms';
   requireThat(hash(await store('GET',object))===proof.ciphertext_sha256,'restore_package_checksum');
   requireThat(clock()-Date.parse(proof.captured_at)>=0&&clock()-Date.parse(proof.captured_at)<=3600000,'capture_expired');
   const diagnostic=await original();requireThat(hash((await bookmark()).bookmark)===proof.bookmark_sha256,'bookmark_changed');
   return {status:'private_recovery_verified',offline_decryption_and_restore_verified:true,checkpoint29_verified:diagnostic.first_29_verified,administrator_attested_writer_drain:true,adoption_authorized:false,migration_authorized:false};
  }
  requireThat(op==='recovery-capture','capture_operation');const before=await original(),mark=await bookmark();window();
  const capturedAt=new Date(clock()).toISOString();let exported;let cursor;
  for(let n=0;n<120;n++){
   const body={output_format:'polling',dump_options:{no_schema:false,no_data:false,tables:[]},...(cursor?{current_bookmark:cursor}:{})};
   const result=await api(DB+'/export',body);requireThat(result.success===true&&['active','complete'].includes(result.status),'export_failed_or_ambiguous');
   if(result.status==='complete'){exported=result;break;}
   requireThat(typeof result.at_bookmark==='string'&&result.at_bookmark.length>=6,'export_poll_cursor');cursor=result.at_bookmark;await sleep(2000);
  }
  requireThat(exported?.result?.signed_url,'export_timeout');const url=new URL(exported.result.signed_url);
  requireThat(url.protocol==='https:'&&url.hostname.endsWith('.r2.cloudflarestorage.com')&&!url.username&&!url.password&&url.port==='','export_download_boundary');
  window();const response=await transport(url,{redirect:'error',signal:AbortSignal.timeout(60000)});requireThat(response.ok,'export_download');const bytes=await boundedBytes(response,100000000);
  const source=path.join(dir,'before-adoption.sql'),report=path.join(dir,'local-restore.json');fs.writeFileSync(source,bytes,{mode:0o600,flag:'wx'});
  const local=spawnSync('python',['staging/scripts/verify-recovery-export.py','--export',source,'--checkpoint','29','--report',report],{cwd:ROOT,env:privateEnv(dir),stdio:'pipe',timeout:90000});requireThat(local.status===0&&local.signal===null&&JSON.parse(fs.readFileSync(report,'utf8')).status==='passed','local_export_restore_failed');
  window();const metadata={account:TARGET.account,database_id:DIAGNOSTIC_DATABASE_ID,source_sha:env.GITHUB_SHA,checkpoint:29,capture_run_id:env.GITHUB_RUN_ID,capture_attempt:env.GITHUB_RUN_ATTEMPT,captured_at:capturedAt,snapshot_sha256:env.CF_STAGING_RECOVERY_SNAPSHOT_SHA256,export_sha256:hash(bytes),recipient_fingerprint:fingerprint,bookmark:mark.bookmark,bookmark_sha256:hash(mark.bookmark),schema_sha256:before.actual_state.schema_sha256,writer_evidence:isolatedState.proof};
  const cipherHash=await putPackage({metadata,sql_base64:bytes.toString('base64'),local_restore:JSON.parse(fs.readFileSync(report,'utf8'))},'checkpoint29');
  const after=await original();requireThat((await bookmark()).bookmark===mark.bookmark&&after.actual_state.schema_sha256===before.actual_state.schema_sha256,'state_changed_during_export');await isolated();window();
  return {status:'encrypted_capture_stored_offline_restore_pending',ciphertext_sha256:cipherHash,checkpoint29_verified:true,offline_decryption_and_restore_verified:false,adoption_authorized:false,migration_authorized:false};
 }finally{if(dir)fs.rmSync(dir,{recursive:true,force:true});}
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{
  const git=spawnSync('git',['rev-parse','HEAD'],{cwd:ROOT,encoding:'utf8'});const sha=git.stdout.trim();const event=JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH,'utf8'));
  authorize(process.env,event,sha);requireThat(spawnSync('git',['diff','--exit-code','HEAD','--'],{cwd:ROOT,stdio:'pipe'}).status===0,'source_changed');
  if(process.argv[2]==='--check')console.log('Reviewed recovery operation authorized; no network or export performed.');
  else console.log(JSON.stringify(await execute(process.env)));
 }catch(error){const category=/^[a-z0-9_]{3,90}$/.test(error.message||'')?error.message:'recovery_failed';console.error(JSON.stringify({status:'stopped',operation:process.env.CF_STAGING_PROVISION_ACTION,category,automatic_retries:0,recovery_ready:false}));process.exitCode=1;}
}
