import test from 'node:test';import assert from 'node:assert/strict';
import {diagnose,inspectWorker,management} from '../scripts/diagnose.mjs';
import {configs} from '../scripts/configure.mjs';
import {TARGET} from '../target.mjs';
const env={CF_STAGING_ACCOUNT_ID:TARGET.account,CF_STAGING_D1_DATABASE_ID:'fac61562-fc31-426d-8032-550aba63b7f6',CF_STAGING_API_TOKEN:'synthetic-secret',CF_STAGING_ACCESS_ISSUER:'https://synthetic.cloudflareaccess.com',CF_STAGING_ACCESS_AUD:'a'.repeat(64)};
const api=configs(env).api;
function fixture(change=x=>x){const bindings=[...Object.entries(api.vars).map(([name,text])=>({type:'plain_text',name,text})),{type:'d1',name:'DB',id:env.CF_STAGING_D1_DATABASE_ID},{type:'ratelimit',name:'ASSIGNMENT_ACK_RATE_LIMITER',namespace_id:'24302',simple:{limit:60,period:60}},{type:'r2_bucket',name:'INTELLIGENCE_BUCKET',bucket_name:'cveharbor-intelligence-staging'},...['STAGING_TOTP_ENCRYPTION_KEY','STAGING_MONITOR_WEBHOOK_TOKEN'].map(name=>({type:'secret_text',name}))];change(bindings);
 return async route=>route.endsWith('/settings')?{bindings}:route.endsWith('/subdomain')?{enabled:false,previews_enabled:false}:route.endsWith('/schedules')?[]:route.endsWith('/deployments')?{deployments:[{id:'d',versions:[{version_id:'v',percentage:100}]}]}:assert.fail(route);}
test('permanent API metadata requires exact D1, private R2, variables and staging-only secrets',async()=>{
 assert.equal((await inspectWorker(TARGET.api,api,fixture(),{requireKey:true})).verified,true);
 for(const change of [b=>b.push({type:'secret_text',name:'SMTP2GO_API_KEY'}),b=>b.find(x=>x.type==='d1').id=TARGET.productionDatabase,b=>b.find(x=>x.type==='r2_bucket').bucket_name='production',b=>b.pop(),b=>b.push({type:'plain_text',name:'UNKNOWN',text:'true'})])assert.equal((await inspectWorker(TARGET.api,api,fixture(change),{requireKey:true})).verified,false);
});
test('metadata is GET only and rejects wrong targets or unknown worker inventory without mutation',async()=>{
 assert.throws(()=>management({...env,CF_STAGING_ACCOUNT_ID:'production'},()=>assert.fail('No network')));
 const calls=[];const transport=async(url,init)=>{assert.equal(init.method,'GET');calls.push(url);let result=url.endsWith(TARGET.account)?{id:TARGET.account}:url.includes('?per_page')?[{name:TARGET.database,uuid:env.CF_STAGING_D1_DATABASE_ID}]:url.includes('/d1/database/')?{name:TARGET.database,uuid:env.CF_STAGING_D1_DATABASE_ID}:[];return Response.json({success:true,result});};
 await assert.rejects(diagnose(env,transport),/Unapproved Worker/);assert.ok(calls.every(u=>u.includes(TARGET.account)));
 await assert.rejects(management(env,async()=>Response.json({success:false,errors:[{message:'secret-value'}]},{status:403}))('/workers/scripts'),e=>!e.message.includes('secret-value'));
});
test('subsequent update accepts a safe previous permanent release only during preflight',async()=>{
 const previous=fixture(b=>b.find(x=>x.name==='STAGING_RELEASE').text='b'.repeat(40));
 assert.equal((await inspectWorker(TARGET.api,api,previous,{allowLegacy:true})).verified,true);
 assert.equal((await inspectWorker(TARGET.api,api,previous)).verified,false);
});
