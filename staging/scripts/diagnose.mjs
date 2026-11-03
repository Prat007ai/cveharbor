// GET-only inspection accepts the recorded initial profile only during transition.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {resourceManifest,checkDatabases} from './inventory.mjs';
import {TARGET} from '../target.mjs';
import {root,configs,adminEmails} from './configure.mjs';
import {readAssetGate} from './asset-gate.mjs';
export function management(env,transport=fetch){
 if(env.CF_STAGING_ACCOUNT_ID!==TARGET.account||!env.CF_STAGING_API_TOKEN)throw Error('Dedicated staging credentials required');
 return async route=>{
  if(!route.startsWith('/')&&route!==''||route.includes('..')||route.includes('://'))throw Error('Invalid staging route');
  const r=await transport(`https://api.cloudflare.com/client/v4/accounts/${TARGET.account}${route}`,{method:'GET',redirect:'error',signal:AbortSignal.timeout(30000),headers:{Authorization:'Bearer '+env.CF_STAGING_API_TOKEN}});
  let body;try{body=await r.json();}catch{throw Error('Invalid management response');}
  if(!r.ok||!body?.success)throw Error('Staging metadata unavailable ('+r.status+')');return body.result;
 };
}
const legacy=JSON.parse(fs.readFileSync(new URL('../legacy-profile.v1.json',import.meta.url),'utf8'));
export async function inspectWorker(name,config,get,{allowLegacy=false,requireKey=false}={}){
 const settings=await get(`/workers/scripts/${name}/settings`),bindings=settings.bindings||[];
 const plain=bindings.filter(b=>b.type==='plain_text'),match=vars=>plain.length===Object.keys(vars).length&&plain.every(b=>vars[b.name]===b.text);
 const isAPI=name===TARGET.api;
 const initialVars=isAPI?legacy.api_vars:{ACCESS_ISSUER:config.vars.ACCESS_ISSUER,ACCESS_AUD:config.vars.ACCESS_AUD};
 const initial=allowLegacy&&match(initialVars),desired=match(config.vars);
 // A future reviewed update must accept the previous permanent release's safe
 // variable values, while post-upload readback must match this release exactly.
 const current=Object.fromEntries(plain.map(b=>[b.name,b.text]));let previous=false;
 if(allowLegacy){try{
  const permitted=new Set(['STAGING_RELEASE','STAGING_ADMIN_EMAILS',...(isAPI?['STAGING_MANUAL_JOBS_ENABLED']:[])]);
  previous=plain.length===Object.keys(config.vars).length&&plain.every(b=>Object.hasOwn(config.vars,b.name)&&(permitted.has(b.name)||config.vars[b.name]===b.text))&&/^[a-f0-9]{40}$/.test(current.STAGING_RELEASE)&&adminEmails(current.STAGING_ADMIN_EMAILS)===current.STAGING_ADMIN_EMAILS&&(!isAPI||['true','false'].includes(current.STAGING_MANUAL_JOBS_ENABLED));
 }catch{previous=false;}}
 const allowed=isAPI?['d1','ratelimit','plain_text','r2_bucket','secret_text']:['service','assets','plain_text','r2_bucket'];
 const db=bindings.filter(b=>b.type==='d1'),limits=bindings.filter(b=>b.type==='ratelimit'),services=bindings.filter(b=>b.type==='service'),buckets=bindings.filter(b=>b.type==='r2_bucket'),secrets=bindings.filter(b=>b.type==='secret_text');
 const exposure=await get(`/workers/scripts/${name}/subdomain`),schedule=await get(`/workers/scripts/${name}/schedules`),schedules=Array.isArray(schedule)?schedule:schedule?.schedules;
 const deployments=await get(`/workers/scripts/${name}/deployments`),active=deployments?.deployments?.[0];
 const report={name,profile:desired?'permanent':previous?'previous-permanent':initial?'initial':'unknown',
  variables_match:desired||previous||initial,unexpected_binding_count:bindings.filter(b=>!allowed.includes(b.type)).length,
  secrets_safe:secrets.every(b=>['STAGING_TOTP_ENCRYPTION_KEY','STAGING_MONITOR_WEBHOOK_TOKEN'].includes(b.name))&&new Set(secrets.map(b=>b.name)).size===secrets.length&&(!requireKey||!isAPI||['STAGING_TOTP_ENCRYPTION_KEY','STAGING_MONITOR_WEBHOOK_TOKEN'].every(n=>secrets.some(b=>b.name===n))),
  bucket_matches:initial?buckets.length===0:buckets.length===1&&buckets[0].name==='INTELLIGENCE_BUCKET'&&buckets[0].bucket_name===resourceManifest().intelligence_bucket,
  exposure_matches:exposure?.enabled===!isAPI&&exposure?.previews_enabled===false,schedules_disabled:Array.isArray(schedules)&&schedules.length===0,
  deployment_present:!!active?.id&&active.versions?.length===1&&active.versions[0].percentage===100,
  deployment_id:active?.id,version_id:active?.versions?.[0]?.version_id};
 if(isAPI){report.d1_binding_matches=db.length===1&&db[0].name==='DB'&&db[0].id===resourceManifest().permanent_database.uuid;
  report.rate_limit_matches=limits.length===1&&limits[0].name==='ASSIGNMENT_ACK_RATE_LIMITER'&&String(limits[0].namespace_id)==='24302'&&limits[0].simple?.limit===60&&limits[0].simple?.period===60;
 }else{report.service_binding_matches=services.length===1&&services[0].name==='STAGING_API'&&services[0].service===TARGET.api&&(!services[0].environment||services[0].environment==='production');Object.assign(report,await readAssetGate(settings,get));}
 report.verified=report.variables_match&&report.unexpected_binding_count===0&&report.secrets_safe&&report.bucket_matches&&report.exposure_matches&&report.schedules_disabled&&report.deployment_present&&(isAPI?report.d1_binding_matches&&report.rate_limit_matches:report.service_binding_matches&&report.assets_gate_matches===true);
 return report;
}
export async function diagnose(env,transport=fetch,record=()=>{},{allowLegacy=true,requireKey=false}={}){
 const expected=configs(env),get=management(env,transport),resources=resourceManifest();
 if((await get(''))?.id!==TARGET.account)throw Error('Account mismatch');
 checkDatabases(await get('/d1/database?per_page=100'),{permanentId:env.CF_STAGING_D1_DATABASE_ID});
 const metadata=await get('/d1/database/'+resources.permanent_database.uuid);
 if(metadata?.uuid!==resources.permanent_database.uuid||metadata?.name!==TARGET.database)throw Error('Database metadata mismatch');
 const rows=await get('/workers/scripts');
 if(!Array.isArray(rows)||rows.length!==2||[TARGET.api,TARGET.site].some(name=>rows.filter(w=>w.id===name).length!==1))throw Error('Unapproved Worker inventory');
 const report={account:TARGET.account,checked_at:new Date().toISOString(),mutation_requests:0,production_requests:0,database:{name:metadata.name,id:metadata.uuid,num_tables:metadata.num_tables??null},workers:[]};
 for(const [name,config] of [[TARGET.api,expected.api],[TARGET.site,expected.site]])report.workers.push(await inspectWorker(name,config,get,{allowLegacy,requireKey}));
 report.verified=report.workers.every(w=>w.verified);record(report);return report;
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{const r=await diagnose(process.env);fs.mkdirSync(path.join(root,'artifacts'),{recursive:true});fs.writeFileSync(path.join(root,'artifacts/diagnostics.json'),JSON.stringify(r,null,2)+'\n');if(!r.verified)process.exitCode=1;}
 catch{console.error('Staging inventory check failed; no resource changes attempted.');process.exitCode=1;}
}
