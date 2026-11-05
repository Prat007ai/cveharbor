import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {probeBackend} from '../scripts/release.mjs';
import {runtimeDiagnostic} from '../scripts/runtime-diagnostic.mjs';
import {safeFailure} from '../scripts/errors.mjs';
import {TARGET,LEGACY_ORIGIN} from '../target.mjs';
import {createStagingAPI} from '../api-wrapper.mjs';
import {createFrontend} from '../frontend.mjs';
import {FullDB,bucketFixture} from './helpers/full-db.mjs';
const sha='a'.repeat(40),env={CF_STAGING_ACCOUNT_ID:TARGET.account,CF_STAGING_D1_DATABASE_ID:'fac61562-fc31-426d-8032-550aba63b7f6',CF_STAGING_APPROVED_COMMIT:sha,CF_STAGING_ACCESS_ISSUER:'https://synthetic.cloudflareaccess.com',CF_STAGING_ACCESS_AUD:'b'.repeat(64),CF_STAGING_ACCESS_CLIENT_ID:'private-client',CF_STAGING_ACCESS_CLIENT_SECRET:'private-secret'};
const valid={ready:true,schema_ready:true,feed_version:'c'.repeat(64),mail_capture:true,mfa_configured:true,monitor_webhook_configured:true,native_schedules:false,held:false,release:sha};
test('probe reports every failed runtime check through legacy binding without response text',async()=>{
 for(const [check,patch] of Object.entries({schema_ready:{schema_ready:false},intelligence_ready:{feed_version:null},mail_capture:{mail_capture:false},mfa_configured:{mfa_configured:false},monitor_webhook_configured:{monitor_webhook_configured:false},schedules_disabled:{native_schedules:true},hold_matches:{held:true},release_matches:{release:'private-response'},ready:{ready:false}})){
  let saved;
  const transport=async(url,init)=>{assert.equal(url,LEGACY_ORIGIN+'/v1/staging-readiness');assert.equal(init.method,'GET');assert.equal(init.redirect,'manual');assert.equal(init.headers['CF-Access-Client-Secret'],'private-secret');return Response.json({...valid,...patch,private:'private-body'},{status:503});};
  await assert.rejects(probeBackend(env,transport,{bootstrap:true,record:r=>{saved=structuredClone(r);}}),e=>{const f=safeFailure(e);assert.equal(f.check,check);assert.equal(f.http_status,503);assert.equal(f.checks[check],false);assert.doesNotMatch(JSON.stringify(f),/private-/);return true;});
  assert.equal(saved.route,'legacy');assert.doesNotMatch(JSON.stringify(saved),/private-/);
 }
});
test('network, HTML denial and malformed JSON stay sanitized; old backend configuration flags remain unknown',async()=>{
 for(const [transport,check] of [[async()=>{throw Error('private-secret');},'readiness_request'],[async()=>new Response('private-body',{status:403}),'http_success'],[async()=>new Response('private-body',{status:503}),'response_json']])await assert.rejects(probeBackend(env,transport),e=>{assert.equal(safeFailure(e).check,check);assert.doesNotMatch(JSON.stringify(safeFailure(e)),/private-/);return true;});
 const {mfa_configured,monitor_webhook_configured,...old}=valid;
 const result=await probeBackend(env,async()=>Response.json(old));
 assert.equal(result.checks.mfa_configured,null);assert.equal(result.checks.monitor_webhook_configured,null);
});
test('read-only diagnosis records both active versions and compares installed backend release, not diagnostic SHA',async()=>{
 const backend='163baa37-8fe6-4821-9102-8d8e997d94dc',frontend='0'.repeat(36),installed='d'.repeat(40),calls=[];
 const report=await runtimeDiagnostic(env,{get:async route=>{calls.push(route);return {bindings:[{type:'plain_text',name:'STAGING_RELEASE',text:installed},{type:'secret_text',name:'STAGING_TOTP_ENCRYPTION_KEY',text:'private-secret'}]};},inspect:async(name,_config,_get,options)=>{assert.equal(options.allowLegacy,true);return {name,verified:true,version_id:name===TARGET.api?backend:frontend};},transport:async(url,init)=>{assert.equal(url,LEGACY_ORIGIN+'/v1/staging-readiness');assert.equal(init.method,'GET');return Response.json({...valid,release:installed});}});
 assert.equal(report.workers[0].version_id,backend);assert.equal(report.workers[1].version_id,frontend);
 assert.equal(report.backend_release_matches_requested,false);assert.equal(report.runtime.checks.release_matches,true);assert.equal(report.ready,true);
 assert.equal(report.mutation_requests,0);assert.doesNotMatch(JSON.stringify(report),/private-/);
 assert.deepEqual(calls,[`/workers/scripts/${TARGET.api}/settings`]);
 const workflow=fs.readFileSync('.github/workflows/cvie-staging.yml','utf8');assert.match(workflow,/publish-synthetic, readiness\]/);
});
test('wrapper distinguishes MFA and webhook configuration without sending mail or writing rows',async()=>{
 const DB=new FullDB(),api=createStagingAPI({fetch:()=>assert.fail('Readiness must not call the application')});
 try{
  const before=DB.sql.prepare('SELECT total_changes() n').get().n;
  const base={DB,STAGING_MODE:'true',STAGING_RELEASE:sha,STAGING_EMAIL_CAPTURE_ENABLED:'true',STAGING_TOTP_ENCRYPTION_KEY:'private-key-that-is-at-least-thirty-two-characters',STAGING_MONITOR_WEBHOOK_TOKEN:'private-webhook',INTELLIGENCE_BUCKET:await bucketFixture()};
  for(const patch of [{},{STAGING_TOTP_ENCRYPTION_KEY:'short'},{STAGING_MONITOR_WEBHOOK_TOKEN:''},{INTELLIGENCE_BUCKET:null},{STAGING_EMAIL_CAPTURE_ENABLED:'false'}]){
   const response=await api.fetch(new Request(LEGACY_ORIGIN+'/v1/staging-readiness'),{...base,...patch},{}),r=await response.json();
   assert.equal(r.schema_ready,true);assert.equal(r.ready,Object.keys(patch).length===0);
   assert.equal(r.mfa_configured,!Object.hasOwn(patch,'STAGING_TOTP_ENCRYPTION_KEY'));assert.equal(r.monitor_webhook_configured,!Object.hasOwn(patch,'STAGING_MONITOR_WEBHOOK_TOKEN'));
   assert.equal(r.mail_capture,patch.STAGING_EMAIL_CAPTURE_ENABLED!=='false');
   if(Object.hasOwn(patch,'INTELLIGENCE_BUCKET'))assert.equal(r.feed_version,null);
   assert.doesNotMatch(JSON.stringify(r),/private-|short/);
  }
  assert.equal(DB.sql.prepare('SELECT total_changes() n').get().n,before);
 }finally{DB.close();}
});
test('legacy readiness traverses the Access gate and frontend service binding with credentials stripped',async()=>{
 const DB=new FullDB(),api=createStagingAPI({fetch:()=>assert.fail('Readiness only')}),frontend=createFrontend(async()=>true);
 try{
  const backend={DB,STAGING_MODE:'true',STAGING_RELEASE:sha,STAGING_EMAIL_CAPTURE_ENABLED:'true',STAGING_TOTP_ENCRYPTION_KEY:'synthetic-key-with-at-least-thirty-two-characters',STAGING_MONITOR_WEBHOOK_TOKEN:'synthetic-token',INTELLIGENCE_BUCKET:await bucketFixture()};
  let forwarded=0;
  const transport=async(url,init)=>frontend.fetch(new Request(url,init),{STAGING_API:{fetch:async req=>{
   forwarded++;assert.equal(req.url,LEGACY_ORIGIN+'/v1/staging-readiness');
   for(const name of ['CF-Access-Client-Id','CF-Access-Client-Secret','Cf-Access-Jwt-Assertion'])assert.equal(req.headers.get(name),null);
   return api.fetch(req,backend,{});
  }}});
  const result=await probeBackend(env,transport,{bootstrap:true});assert.equal(result.checks.ready,true);assert.equal(forwarded,1);
  const denied=createFrontend(async()=>false);
  await assert.rejects(probeBackend(env,async(url,init)=>denied.fetch(new Request(url,init),{}),{bootstrap:true}),e=>safeFailure(e).http_status===403);
  assert.equal(forwarded,1);
 }finally{DB.close();}
});
