import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {spawn,spawnSync} from 'node:child_process';
import {createInterface} from 'node:readline';
import {X509Certificate} from 'node:crypto';
import {authorize,execute,maintenance,managementRoute,secureTemp} from '../recovery/recovery.mjs';
import {hash,certificate,verifyReceipt} from '../recovery/crypto.mjs';
import {recoveryStore} from '../recovery/store.mjs';
const account='9706b4d98ad72884e67fd1eb875c8a61',db='fac61562-fc31-426d-8032-550aba63b7f6',sha='a'.repeat(40),app='11111111-2222-4333-8444-555555555555';
const root=path.resolve('staging'),fixture=fs.mkdtempSync(path.join(os.tmpdir(),'fixture-recovery-'));
const command=args=>{const r=spawnSync('openssl',args,{encoding:'utf8'});assert.equal(r.status,0,'fixture crypto failed');return r.stdout;};
command(['req','-x509','-newkey','rsa:3072','-sha256','-nodes','-keyout',fixture+'/key.pem','-out',fixture+'/cert.pem','-days','1','-subj','/CN=fixture-only.invalid']);
const pem=fs.readFileSync(fixture+'/cert.pem','utf8'),fingerprint=new X509Certificate(pem).fingerprint256.replaceAll(':','').toLowerCase();
process.on('exit',()=>fs.rmSync(fixture,{recursive:true,force:true}));
const base={GITHUB_REPOSITORY:'Prat007ai/cveharbor',GITHUB_REF:'refs/heads/codex/cvie-core-phase012',GITHUB_SHA:sha,CF_STAGING_APPROVED_COMMIT:sha,GITHUB_EVENT_NAME:'push',GITHUB_RUN_ATTEMPT:'2',GITHUB_RUN_ID:'123',CF_STAGING_ACCOUNT_ID:account,CF_STAGING_D1_DATABASE_ID:db,CF_STAGING_API_TOKEN:'fixture-api-secret',CF_STAGING_RECOVERY_KEY_CUSTODY_CONFIRMED:'true',CF_STAGING_RECOVERY_BUCKET:'cveharbor-recovery-staging',CF_STAGING_RECOVERY_R2_ACCESS_KEY_ID:'fixture-r2-id',CF_STAGING_RECOVERY_R2_SECRET_ACCESS_KEY:'fixture-r2-secret',CF_STAGING_RECOVERY_CERT_PEM:pem,CF_STAGING_RECOVERY_CERT_SHA256:fingerprint,CF_STAGING_ACCESS_CLIENT_ID:'fixture-service',CF_STAGING_ACCESS_CLIENT_SECRET:'fixture-service-secret'};
async function harness(t){
 const child=spawn('python',['-u','staging/tests/sqlite-diagnostic.py'],{stdio:['pipe','pipe','pipe']});t.after(()=>{child.stdin.end();child.kill();});
 const wait=[];createInterface({input:child.stdout}).on('line',line=>wait.shift()(JSON.parse(line)));
 const sql=body=>new Promise(resolve=>{wait.push(resolve);child.stdin.write(JSON.stringify(body)+'\n');});
 const source=fs.readFileSync('account-backend/schema.sql','utf8');assert.equal((await sql({setup:source})).success,true);
 let blocked=false,corrupt=false,exportURL='https://fixture.r2.cloudflarestorage.com/export?private=sensitive',exports=0;const objects=new Map(),calls=[];
 const states=['cveharbor-accounts-staging','cveharbor-site-staging'].map((name,i)=>({name,settings:{bindings:i?[{type:'service',service:'cveharbor-accounts-staging'},{type:'assets'}]:[{type:'d1',id:db}]},subdomain:{enabled:!!i,previews_enabled:false},schedules:[],deployment:{version:'fixture'}}));
 const policies=()=>blocked?[{id:'33333333-2222-4333-8444-555555555555',decision:'block',include:[{everyone:{}}],exclude:[],require:[]}]:[{id:'44444444-2222-4333-8444-555555555555',decision:'allow',include:[{email:{email:'private@example.invalid'}}]},{id:'55555555-2222-4333-8444-555555555555',decision:'non_identity',include:[{service_token:{token_id:'private'}}]}];
 const transport=async(url,init={})=>{
  url=String(url);calls.push({url,method:init.method||'GET'});
  if(url.includes('.r2.cloudflarestorage.com/cveharbor-recovery-staging/')){
   assert.doesNotMatch(JSON.stringify(init.headers),/fixture-api-secret/);const key=url.split('/cveharbor-recovery-staging/')[1];
   if(init.method==='PUT'){assert.equal(init.headers['if-none-match'],'*');assert.equal(objects.has(key),false);objects.set(key,Buffer.from(init.body));return new Response('',{headers:{etag:'"fixture"'}});}
   let bytes=objects.get(key);assert.ok(bytes);if(corrupt&&key.endsWith('checkpoint29.cms')){bytes=Buffer.from(bytes);bytes[0]^=1;}return new Response(bytes);
  }
  if(url.startsWith('https://fixture.r2.cloudflarestorage.com/export')){assert.equal(init.headers,undefined);return new Response(source);}
  if(url.startsWith('https://cveharbor-site-staging.'))return new Response('denied',{status:403});
  const prefix='https://api.cloudflare.com/client/v4/accounts/'+account;assert.ok(url.startsWith(prefix));const route=url.slice(prefix.length);
  let result;
  if(route==='' )result={id:account};
  else if(route==='/d1/database/'+db)result={uuid:db,name:'cveharbor-accounts-staging',file_size:233472};
  else if(route.endsWith('/query')){const r=await sql(JSON.parse(init.body));return Response.json(r,{status:r.success?200:400});}
  else if(route.endsWith('/time_travel/bookmark'))result={bookmark:'fixture-bookmark'};
  else if(route.endsWith('/export')){exports++;const request=JSON.parse(init.body);assert.deepEqual(request.dump_options,{no_schema:false,no_data:false,tables:[]});if(exports===1)result={success:true,status:'active',at_bookmark:'poll-cursor'};else{assert.equal(request.current_bookmark,'poll-cursor');result={success:true,status:'complete',result:{signed_url:exportURL}};}}
  else if(route==='/workers/scripts')result=states.map(w=>({id:w.name}));
  else if(route==='/workers/domains')result=[];
  else if(route.startsWith('/workers/scripts/')){const [, , ,name,kind]=route.split('/');const w=states.find(s=>s.name===name);result=w[kind==='deployments'?'deployment':kind];}
  else if(route==='/access/apps?per_page=100')result=[{id:app,domain:'cveharbor-site-staging.cveharbor-staging.workers.dev',type:'self_hosted'}];
  else if(route.endsWith('/policies'))result=policies();
  else if(route==='/r2/buckets?per_page=1000')result={buckets:[{name:'cveharbor-recovery-staging'},{name:'cveharbor-intelligence-staging'}]};
  else if(route.endsWith('/domains/managed'))result={enabled:false};
  else if(route.endsWith('/domains/custom'))result={domains:[]};
  else if(route==='/r2/buckets/cveharbor-recovery-staging')result={name:'cveharbor-recovery-staging'};
  else assert.fail('Unexpected route '+route);
  return Response.json({success:true,result});
 };
 const deps={transport,temp:()=>fs.mkdtempSync(fixture+'/plain-'),sleep:async()=>{}};
 const isolation=snapshot=>JSON.stringify({account,database_id:db,source_sha:sha,snapshot_sha256:snapshot,window_start:new Date(Date.now()-1000).toISOString(),window_end:new Date(Date.now()+1500000).toISOString(),observed_at:new Date().toISOString(),non_access_writers_quiesced:true,invocations_drained:true,human_session_denied:true,application_sessions_revoked:true,no_other_mutation_jobs:true,all_ingress_identified:true,drain_evidence_sha256:'d'.repeat(64),original_access_sha256:'b'.repeat(64),worker_state_sha256:hash(JSON.stringify(states)),access_app_id:app});
 return {deps,objects,calls,block:()=>{blocked=true;},corrupt:()=>{corrupt=true;},url:x=>{exportURL=x;},exports:()=>exports,isolation};
}
async function prepared(t){const h=await harness(t),snapshot=await execute({...base,CF_STAGING_PROVISION_ACTION:'recovery-snapshot'},h.deps);h.block();const env={...base,GITHUB_RUN_ID:'124',CF_STAGING_PROVISION_ACTION:'recovery-capture',CF_STAGING_RECOVERY_SNAPSHOT_KEY:'recovery/v1/'+sha+'/123-2/snapshot.cms',CF_STAGING_RECOVERY_SNAPSHOT_SHA256:snapshot.ciphertext_sha256,CF_STAGING_RECOVERY_ISOLATION:h.isolation(snapshot.ciphertext_sha256)};return {h,env};}
test('exact source/action/account approval, public certificate and management/object boundaries',()=>{
 const env={...base,CF_STAGING_PROVISION_ACTION:'recovery-inventory'},event={head_commit:{id:sha,message:'review [staging-release]'}};assert.equal(authorize(env,event,sha),'recovery-inventory');
 for(const patch of [{GITHUB_RUN_ATTEMPT:'1'},{CF_STAGING_D1_DATABASE_ID:'46710e51-7ca4-4571-b89c-921b9969de0b'},{CF_STAGING_APPROVED_COMMIT:'b'.repeat(40)},{CF_STAGING_PROVISION_ACTION:'migrate'}])assert.throws(()=>authorize({...env,...patch},event,sha));
 assert.throws(()=>secureTemp(Number.MAX_SAFE_INTEGER));
 assert.throws(()=>certificate(pem,'0'.repeat(64)));assert.ok(certificate(pem,fingerprint));assert.throws(()=>certificate(pem+fs.readFileSync(fixture+'/key.pem','utf8'),fingerprint));
 for(const route of ['/d1/database/production','/workers/scripts/foo','/access/apps/'+app+'/revoke_tokens','/r2/buckets/foo/delete'])assert.equal(managementRoute(route),false);
 assert.throws(()=>recoveryStore({...base,CF_STAGING_RECOVERY_BUCKET:'cveharbor-intelligence-staging'}));
});
test('inventory performs metadata GETs and closed diagnostic reads, never starts export or writes objects',async t=>{
 const h=await harness(t),report=await execute({...base,CF_STAGING_PROVISION_ACTION:'recovery-inventory'},h.deps);
 assert.equal(report.checkpoint29_verified,true);assert.equal(report.new_bucket_required,false);assert.equal(h.exports(),0);assert.equal(h.objects.size,0);
 assert.doesNotMatch(JSON.stringify(report),/private@example|private-service|fixture-api-secret|fixture-bookmark/);
});
test('maintenance evidence rejects stale/missing/wrong target and does not infer writer quiescence from empty tables',async t=>{
 const {h,env}=await prepared(t);assert.ok(maintenance(env));
 for(const p of [{invocations_drained:false},{source_sha:'b'.repeat(40)},{observed_at:'2000-01-01T00:00:00Z'},{window_end:new Date(Date.now()+3600000).toISOString()}])assert.throws(()=>maintenance({...env,CF_STAGING_RECOVERY_ISOLATION:JSON.stringify({...JSON.parse(env.CF_STAGING_RECOVERY_ISOLATION),...p})}));
 await assert.rejects(execute({...env,CF_STAGING_RECOVERY_ISOLATION:''},h.deps));assert.equal(h.exports(),0);
});
test('real encrypted object is downloaded, decrypted and restored offline; signed receipt gates live verification',async t=>{
 const {h,env}=await prepared(t);const capture=await execute(env,h.deps);assert.equal(capture.offline_decryption_and_restore_verified,false);assert.equal(h.exports(),2);
 const key='recovery/v1/'+sha+'/124-2/checkpoint29.cms',bytes=h.objects.get(key);assert.ok(bytes);assert.equal(bytes.includes(Buffer.from('CREATE TABLE')),false);
 const downloaded=fixture+'/downloaded.cms';fs.writeFileSync(downloaded,bytes);const receipt=fixture+'/receipt.json',signature=fixture+'/signature.txt';
 const restore=spawnSync('python',['staging/recovery/offline-restore.py','--package',downloaded,'--cert',fixture+'/cert.pem','--key',fixture+'/key.pem','--work',fixture,'--receipt',receipt,'--signature',signature,'--encrypted-storage-confirmed'],{encoding:'utf8'});
 assert.equal(restore.status,0,restore.stderr);const body=fs.readFileSync(receipt,'utf8'),sig=fs.readFileSync(signature,'utf8');
 assert.ok(verifyReceipt(body,sig,pem,fingerprint,{source_sha:sha}));assert.throws(()=>verifyReceipt(body,sig,pem,fingerprint,{source_sha:'b'.repeat(40)}));assert.throws(()=>verifyReceipt(body.replace('passed','failed'),sig,pem,fingerprint,{}));assert.throws(()=>verifyReceipt(body,sig,pem,fingerprint,{},Date.now()+7200000));
 const verified=await execute({...env,CF_STAGING_PROVISION_ACTION:'recovery-verify',CF_STAGING_RECOVERY_RESTORE_RECEIPT:body,CF_STAGING_RECOVERY_RESTORE_SIGNATURE:sig},h.deps);
 assert.equal(verified.offline_decryption_and_restore_verified,true);assert.equal(verified.checkpoint29_verified,true);assert.equal(verified.migration_authorized,false);
 assert.ok(!fs.readdirSync(fixture).some(x=>x.startsWith('plain-')));
});
test('corrupt object readback stops capture without replaying the export or claiming readiness',async t=>{
 const {h,env}=await prepared(t);h.corrupt();await assert.rejects(execute(env,h.deps),/ciphertext_readback/);assert.equal(h.exports(),2);
});
test('untrusted signed download host is rejected and credentials never follow redirects',async t=>{
 const {h,env}=await prepared(t);h.url('https://attacker.invalid/steal');await assert.rejects(execute(env,h.deps),/export_download_boundary/);assert.equal(h.exports(),2);assert.ok(h.calls.every(c=>!c.url.includes('attacker.invalid')));
});
test('private key, SQL, signed URL and provider details never enter CLI failure logs',()=>{
 const result=spawnSync('node',['staging/recovery/recovery.mjs'],{encoding:'utf8',env:{PATH:process.env.PATH,CF_STAGING_API_TOKEN:'SECRET-SENTINEL',CF_STAGING_PROVISION_ACTION:'recovery-inventory'}});
 assert.notEqual(result.status,0);assert.doesNotMatch(result.stdout+result.stderr,/SECRET-SENTINEL|BEGIN.*PRIVATE|signed_url|CREATE TABLE/);
});

test('offline verifier rejects damaged ciphertext without a receipt and supports passphrase-encrypted offline keys',async t=>{
 const {h,env}=await prepared(t);await execute(env,h.deps);const bytes=h.objects.get('recovery/v1/'+sha+'/124-2/checkpoint29.cms');
 const damaged=Buffer.from(bytes);damaged[damaged.length-1]^=1;const input=fixture+'/damaged.cms';fs.writeFileSync(input,damaged);
 const args=['staging/recovery/offline-restore.py','--package',input,'--cert',fixture+'/cert.pem','--key',fixture+'/key.pem','--work',fixture,'--receipt',fixture+'/no-receipt.json','--signature',fixture+'/no-signature.txt','--encrypted-storage-confirmed'];
 const bad=spawnSync('python',args,{encoding:'utf8'});assert.notEqual(bad.status,0);assert.equal(fs.existsSync(fixture+'/no-receipt.json'),false);assert.doesNotMatch(bad.stderr,/fixture-bookmark|CREATE TABLE/);
 command(['pkey','-in',fixture+'/key.pem','-aes256','-passout','pass:fixture-only','-out',fixture+'/encrypted-key.pem']);
 fs.writeFileSync(fixture+'/encrypted-key-package.cms',bytes);
 const program="import importlib.util;from pathlib import Path;s=importlib.util.spec_from_file_location('offline','staging/recovery/offline-restore.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);p=Path(__import__('sys').argv[1]);m.restore(p/'encrypted-key-package.cms',p/'cert.pem',p/'encrypted-key.pem',p,p/'encrypted-key-receipt.json',p/'encrypted-key-signature.txt','fixture-only')";
 const good=spawnSync('python',['-c',program,fixture],{encoding:'utf8'});assert.equal(good.status,0,good.stderr);assert.ok(fs.existsSync(fixture+'/encrypted-key-receipt.json'));
});

test('maintenance expiry while polling stops immediately without a new export or backup claim',async t=>{
 const {h,env}=await prepared(t);let now=Date.now();h.deps.clock=()=>now;h.deps.sleep=async()=>{now+=1800001;};
 await assert.rejects(execute(env,h.deps),/maintenance_expired/);assert.equal(h.exports(),1);assert.ok([...h.objects.keys()].every(k=>k.endsWith('snapshot.cms')));
});
test('missing offline receipt and unconfirmed key custody cannot authorize recovery readiness or start export',async t=>{
 const {h,env}=await prepared(t);
 await assert.rejects(execute({...env,CF_STAGING_PROVISION_ACTION:'recovery-verify'},h.deps));
 await assert.rejects(execute({...env,CF_STAGING_RECOVERY_KEY_CUSTODY_CONFIRMED:'false'},h.deps),/private_key_custody_unconfirmed/);
 assert.equal(h.exports(),0);assert.throws(()=>certificate(pem,fingerprint,Date.now()+172800000));
});
