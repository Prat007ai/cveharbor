import {TARGET} from './target.mjs';
import {SCENARIOS,withStagingTransport} from './transport.mjs';
import {stagingReadiness} from './production-runtime.mjs';
import {openIntelligenceSnapshot} from '../account-backend/src/intelligence-store.js';
const reply=(body,status=200)=>Response.json(body,{status,headers:{'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'}});
export const JOBS=Object.freeze({remediation:'* * * * *',cvie:'*/5 * * * *',hourly:'5 * * * *'});
export async function adminRoute(req,env,application,safe){
 const url=new URL(req.url),actor=req.headers.get('X-CVEHarbor-Staging-Admin');
 if(!actor||!String(env.STAGING_ADMIN_EMAILS||'').split(',').map(s=>s.trim().toLowerCase()).includes(actor.toLowerCase()))return reply({error:'Staging administrator required'},403);
 if(req.method!=='GET'&&(req.method!=='POST'||req.headers.get('Origin')!==TARGET.origin||req.headers.get('Content-Type')!=='application/json'))return reply({error:'Invalid administration request'},403);
 if(url.pathname==='/__staging/status'&&req.method==='GET'){
  const schema=await stagingReadiness(safe);let version=null;try{version=(await openIntelligenceSnapshot(safe)).version;}catch{}
  return reply({schema:await schema.json(),feed_version:version,release:env.STAGING_RELEASE||'unbuilt',mail_capture:env.STAGING_EMAIL_CAPTURE_ENABLED==='true',scheduled_jobs_enabled:false});
 }
 if(url.pathname==='/__staging/mail'&&req.method==='GET')return reply({messages:(await env.DB.prepare('SELECT id,created_at,subject,recipients_json,scenario FROM staging_mail ORDER BY created_at DESC,id LIMIT 100').all()).results});
 const attachment=/^\/__staging\/mail\/([a-f0-9-]{36})\/attachment\/(\d{1,2})$/.exec(url.pathname);
 if(attachment&&req.method==='GET'){
  const rows=(await env.DB.prepare('SELECT body FROM staging_mail_attachment_chunks WHERE mail_id=? AND attachment_index=? ORDER BY chunk_index').bind(attachment[1],Number(attachment[2])).all()).results;
  if(!rows.length)return reply({error:'Not found'},404);
  return reply({base64:rows.map(r=>r.body).join('')});
 }
 const id=/^\/__staging\/mail\/([a-f0-9-]{36})$/.exec(url.pathname);
 if(id&&req.method==='GET'){const row=await env.DB.prepare('SELECT id,created_at,payload_json,scenario FROM staging_mail WHERE id=?').bind(id[1]).first();return row?reply(row):reply({error:'Not found'},404);}
 if(url.pathname==='/__staging/jobs'&&req.method==='GET')return reply({runs:(await env.DB.prepare('SELECT id,job,scenario,actor,started_at,finished_at,state FROM staging_job_runs ORDER BY started_at DESC LIMIT 100').all()).results});
 if(url.pathname==='/__staging/jobs'&&req.method==='POST'){
  if(env.STAGING_MANUAL_JOBS_ENABLED!=='true')return reply({error:'Manual job testing disabled'},409);
  const raw=await req.text();if(raw.length>2048)return reply({error:'Request too large'},413);
  let data;try{data=JSON.parse(raw);}catch{return reply({error:'Invalid JSON'},400);}
  if(!Object.hasOwn(JOBS,data.job)||!SCENARIOS.includes(data.scenario)||!/^[a-f0-9-]{36}$/.test(data.id||'')||Object.keys(data).some(k=>!['id','job','scenario'].includes(k)))return reply({error:'Choose a reviewed job, scenario and unique run ID'},400);
  const held=safe.STAGING_APPLICATION_PROFILE==='production-baseline'?!(await (await stagingReadiness(safe)).json()).schema_ready:await env.DB.prepare('SELECT write_hold,database_frozen FROM operations_control WHERE id=1').first().then(h=>!h||h.write_hold||h.database_frozen);
  if(held)return reply({error:'Application writes are held'},409);
  const prior=await env.DB.prepare('SELECT job,scenario,state FROM staging_job_runs WHERE id=?').bind(data.id).first();
  if(prior)return reply({replayed:true,...prior},prior.job===data.job&&prior.scenario===data.scenario?200:409);
  try{await env.DB.prepare("INSERT INTO staging_job_runs(id,job,scenario,actor,started_at,state) VALUES(?,?,?,?,?,'running')").bind(data.id,data.job,data.scenario,actor,Date.now()).run();}catch{return reply({error:'Another job is running or writes are held'},409);}
  const stats={};const pending=[];const ctx={waitUntil:p=>pending.push(Promise.resolve(p))};let passed=true;
  try{await withStagingTransport(env,async()=>{await application.scheduled({cron:JOBS[data.job],scheduledTime:Date.now()},safe,ctx);while(pending.length){const result=await Promise.allSettled(pending.splice(0));if(result.some(r=>r.status==='rejected'))throw Error('Scheduled work failed');}},data.scenario,stats);if(stats.failed||stats.blocked)passed=false;}catch{passed=false;}
  await env.DB.prepare('UPDATE staging_job_runs SET state=?,finished_at=? WHERE id=?').bind(passed?'passed':'failed',Date.now(),data.id).run();
  return reply({id:data.id,state:passed?'passed':'failed',real_emails_sent:0,transport:stats},passed?200:503);
 }
 return reply({error:'Not found'},404);
}
