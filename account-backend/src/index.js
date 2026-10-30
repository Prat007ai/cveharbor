// CVEHarbor account API with opt-in vulnerability digest support.
import { saveOptin, loadAlertSubscription, sendUserSample, dispatchDueDigests, unsubscribe } from './delivery.js';
import { handlePublicCveLookup } from './cve-lookup.js';
import { handler as lifecycleHandler, LifecycleError, dispatchLifecycle } from './lifecycle.js';
import { inventoryRoute, InventoryError } from './inventory.js';
import { customerScoreRoute } from './customer-score.js';
import { pluginAdvisoryRoute } from './plugin-advisories.js';
import { sourceRoute } from './plugin-sources.js';
import { monitorRoute,scanDue } from './plugin-monitor.js';
import { findingStatusRoute, FindingStatusError, findingTicketRoute } from './finding-status.js';
import { RemediationError, capabilities, listRemediations, upsertRemediation, removeRemediation, importLegacy, assignRemediation } from './remediation.js';
// The sender address must be verified in SMTP2GO. Never place credentials in GitHub.
const ALLOWED_ORIGIN='https://cveharbor.com';
const enc=new TextEncoder();
function response(body,status=200,extra={}){return new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Access-Control-Allow-Origin':ALLOWED_ORIGIN,'Access-Control-Allow-Credentials':'true','Vary':'Origin',...extra}})}
async function sha(value){const digest=await crypto.subtle.digest('SHA-256',enc.encode(value));return [...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,'0')).join('')}
function token(){return Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('')}
function cookie(req){return (req.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('cvh_session='))?.slice(12)||''}
function setCookie(value,maxAge){return 'cvh_session='+value+'; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age='+maxAge}
async function me(req,env){const value=cookie(req);if(!/^[a-f0-9]{64}$/.test(value))return null;return env.DB.prepare('SELECT users.id,users.email,sessions.id AS sid FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?').bind(await sha(value),Math.floor(Date.now()/1000)).first()}
async function body(req,maxBytes=18000){const size=Number(req.headers.get('content-length')||0);if(size>maxBytes)throw Error('Request too large');const raw=await req.text();if(raw.length>maxBytes)throw Error('Request too large');return JSON.parse(raw)}
async function limit(env,key,max){const now=Math.floor(Date.now()/1000),start=now-3600;await env.DB.prepare('DELETE FROM auth_rate_limits WHERE window_start<?').bind(start).run();await env.DB.prepare('INSERT INTO auth_rate_limits(key,window_start,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN window_start<? THEN 1 ELSE count+1 END,window_start=CASE WHEN window_start<? THEN ? ELSE window_start END').bind(key,now,start,start,now).run();const row=await env.DB.prepare('SELECT count FROM auth_rate_limits WHERE key=?').bind(key).first();return row.count<=max}
async function emailCode(env,address,code){const response=await fetch('https://api.smtp2go.com/v3/email/send',{method:'POST',headers:{'Content-Type':'application/json','X-Smtp2go-Api-Key':env.SMTP2GO_API_KEY},body:JSON.stringify({sender:env.EMAIL_FROM,to:[address],subject:'CVEHarbor sign in code',text_body:'Your CVEHarbor code: '+code+'\n\nExpires in 10 minutes. If you did not request this, ignore this email.'})});if(!response.ok)throw Error('Email delivery unavailable');const payload=await response.json();if(!payload.data||payload.data.failed>0||payload.data.succeeded<1)throw Error('Email delivery unsuccessful')}
export default {async fetch(req,env,ctx){
 const url=new URL(req.url),origin=req.headers.get('origin');
 if(req.method==='OPTIONS'){if(origin!==ALLOWED_ORIGIN)return response({error:'Forbidden'},403);return new Response(null,{status:204,headers:{'Access-Control-Allow-Origin':ALLOWED_ORIGIN,'Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Vary':'Origin'}})}
 if(!url.pathname.startsWith('/v1/'))return response({error:'Not found'},404);
 const unsub=/^\/v1\/unsubscribe\/([a-f0-9]{64})$/.exec(url.pathname);
 if(unsub && (req.method==='GET'||req.method==='POST')) {
  if(!env.DB)return response({error:'Account database unavailable'},503);
  try {return await unsubscribe(req,env,unsub[1])}catch(_) {return response({error:'Unable to process unsubscribe request'},503)}
 }
 if(origin&&origin!==ALLOWED_ORIGIN)return response({error:'Forbidden origin'},403);
 if(req.method!=='GET'&&origin!==ALLOWED_ORIGIN)return response({error:'Invalid request origin'},403);
 // Published CVE lookup is public, read-only, and independent of account login or D1.
 if(url.pathname.startsWith('/v1/cve/'))return handlePublicCveLookup(req,ctx);
 if(!env.DB)return response({error:'Account service not configured'},503);
 const path=url.pathname;
 try {
  if(path==='/v1/health'&&req.method==='GET')return response({ready:!!(env.SMTP2GO_API_KEY&&env.EMAIL_FROM),accounts:'configured'});
  if(path==='/v1/auth/request'&&req.method==='POST'){
   if(!env.SMTP2GO_API_KEY||!env.EMAIL_FROM)return response({error:'Email login unavailable'},503);
   const data=await body(req),address=String(data.email||'').trim().toLowerCase();
   if(!/^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]+$/.test(address))return response({error:'Valid email required'},400);
   const ip=req.headers.get('CF-Connecting-IP')||'unknown';
   if(!await limit(env,'ip:'+await sha(ip),12)||!await limit(env,'email:'+await sha(address),5))return response({error:'Too many requests'},429);
   const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%1000000).padStart(6,'0');
   const id=crypto.randomUUID(),salt=token();
   await env.DB.prepare('INSERT INTO login_challenges(id,email,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)').bind(id,address,await sha(salt+':'+code),Math.floor(Date.now()/1000)+600,Math.floor(Date.now()/1000)).run();
   try{await emailCode(env,address,code)}catch(e){await env.DB.prepare('DELETE FROM login_challenges WHERE id=?').bind(id).run();return response({error:'Unable to deliver code'},503)}
   return response({challenge_id:id,salt,message:'Check your email for a one-time code.'});
  }
  if(path==='/v1/auth/verify'&&req.method==='POST'){
   const data=await body(req),id=String(data.challenge_id||''),salt=String(data.salt||''),code=String(data.code||'');
   if(!/^[0-9]{6}$/.test(code)||!/^[a-f0-9]{64}$/.test(salt)||id.length>80)return response({error:'Invalid or expired code'},400);
   const ip=req.headers.get('CF-Connecting-IP')||'unknown';
   if(!await limit(env,'verify:'+await sha(ip),20))return response({error:'Too many attempts'},429);
   const row=await env.DB.prepare('SELECT * FROM login_challenges WHERE id=? AND used_at IS NULL AND expires_at>?').bind(id,Math.floor(Date.now()/1000)).first();
   if(!row||await sha(salt+':'+code)!==row.token_hash)return response({error:'Invalid or expired code'},401);
   const consumed=await env.DB.prepare('UPDATE login_challenges SET used_at=? WHERE id=? AND used_at IS NULL').bind(Math.floor(Date.now()/1000),id).run();
   if(consumed.meta.changes!==1)return response({error:'Already used'},401);
   let user=await env.DB.prepare('SELECT id,email FROM users WHERE email=?').bind(row.email).first();
   if(!user){const uid=crypto.randomUUID();await env.DB.prepare('INSERT OR IGNORE INTO users(id,email) VALUES(?,?)').bind(uid,row.email).run();user=await env.DB.prepare('SELECT id,email FROM users WHERE email=?').bind(row.email).first()}
   const session=token();await env.DB.prepare('INSERT INTO sessions(id,user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)').bind(crypto.randomUUID(),user.id,await sha(session),Math.floor(Date.now()/1000)+604800,Math.floor(Date.now()/1000)).run();
   return response({email:user.email,authenticated:true},200,{'Set-Cookie':setCookie(session,604800)});
  }
  const user=await me(req,env);
  if(path==='/v1/me'&&req.method==='GET')return response(user?{authenticated:true,email:user.email}:{authenticated:false},user?200:401);
  if(!user)return response({error:'Sign in required'},401);
  if(path==='/v1/customer-report-email'&&req.method==='POST'){
    const data=await body(req,3501000);
    const address=String(data.to||'').trim();
    const customerId=String(data.customer_id||'');
    const environmentId=String(data.environment_id||'');
    const pdf=String(data.pdf_base64||'');
    if(address.length>254||!address.includes('@')||address.split('@').length!==2||!address.split('@')[1]?.includes('.')||/\s/.test(address))return response({error:'Valid recipient email address required'},400);
    if(!/^[0-9a-f-]{36}$/i.test(customerId))return response({error:'Select a customer'},400);
    if(pdf.length>3500000||pdf.length<100||!/^JVBERi0/.test(pdf)||!/^[A-Za-z0-9+/]+={0,2}$/.test(pdf))return response({error:'Attach a valid PDF report smaller than 2.5 MB'},400);
    const record=await env.DB.prepare('SELECT name FROM inventory_customers WHERE id=? AND user_id=?').bind(customerId,user.id).first();
    if(!record)return response({error:'Customer not found in your account'},404);
    if(environmentId){
      const associated=await env.DB.prepare('SELECT id FROM inventory_environments WHERE id=? AND customer_id=? AND user_id=?').bind(environmentId,customerId,user.id).first();
      if(!associated)return response({error:'Environment does not belong to the selected customer'},400);
    }
    if(!await limit(env,'report-email:'+user.id,5))return response({error:'Email limit reached. Try again later.'},429);
    const escape=x=>String(x).replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
    const subject='CVEHarbor Customer Security Review | '+record.name;
    const html='<div style="background:#f1f6f8;padding:30px 16px;font-family:Arial,sans-serif;color:#153648"><div style="max-width:620px;margin:auto;background:white;border:1px solid #d7e4e9;border-radius:12px;overflow:hidden"><div style="background:#10374a;color:white;padding:26px 30px"><strong style="font-size:24px;letter-spacing:1px;color:#8ee8d3">CVEHarbor</strong><p style="margin:8px 0 0;color:#d8eaf0">Vulnerability Intelligence</p></div><div style="padding:28px 30px"><p style="color:#2c8c85;font-weight:bold">CUSTOMER SECURITY REVIEW</p><h2 style="margin:6px 0 20px">'+escape(record.name)+'</h2><p>Please find attached the CVEHarbor customer security review report for your reference.</p><p>The report summarizes the recorded technology inventory and potential security advisories identified for review. Findings require validation against the installed software and applicable vendor guidance.</p><p>For questions about the report or its findings, please contact the person who shared it with you.</p><p style="margin-top:25px;color:#52707b;font-size:12px">Confidential customer information. Please share only with authorized recipients.</p></div><div style="background:#edf5f6;padding:14px 30px;color:#52707b;font-size:12px">CVEHarbor | Customer Security Intelligence</div></div></div>';
    const textBody='CVEHarbor | Customer Security Review\\n\\nPlease find attached the CVEHarbor customer security review report for '+record.name+'.\\n\\nThe report contains inventory based potential advisory findings that require validation against the installed software and vendor guidance.\\n\\nConfidential customer information. Share only with authorized recipients.';
    const outgoing=await fetch('https://api.smtp2go.com/v3/email/send',{
      method:'POST',headers:{'Content-Type':'application/json','X-Smtp2go-Api-Key':env.ALERT_SMTP2GO_API_KEY||env.SMTP2GO_API_KEY||''},
      body:JSON.stringify({sender:env.EMAIL_FROM,to:[address],subject,html_body:html,text_body:textBody,
        attachments:[{filename:'CVEHarbor-Customer-Security-Review.pdf',fileblob:pdf,mimetype:'application/pdf'}]})
    });
    if(!outgoing.ok)return response({error:'Unable to send report email'},503);
    const delivered=await outgoing.json();
    if(Number(delivered?.data?.failed)>0||Number(delivered?.data?.succeeded)!==1)return response({error:'Email service did not accept report'},503);
    return response({sent:true,message:'Report emailed successfully.'});
  }
  if(path==='/v1/auth/logout'&&req.method==='POST'){await env.DB.prepare('DELETE FROM sessions WHERE id=?').bind(user.sid).run();return response({authenticated:false},200,{'Set-Cookie':setCookie('',0)})}
  if(path.startsWith('/v1/lifecycle'))return await lifecycleHandler(req,env,user,path,req.method==='POST'||req.method==='PUT'?await body(req):{});
  if(path.startsWith('/v1/finding-tickets'))return await findingTicketRoute(req,env,user,path,req.method==='POST'?await body(req):{});
  if(path.startsWith('/v1/finding-statuses'))return await findingStatusRoute(req,env,user,path,req.method==='PUT'?await body(req):{});
  if(path.startsWith('/v1/plugin-installation-status'))return await sourceRoute(req,env,user,path,req.method==='PUT'?await body(req):{});
  if(path.startsWith('/v1/plugin-sources'))return await sourceRoute(req,env,user,path,req.method==='PUT'?await body(req):{});
  if(path==='/v1/customer-score-history')return await customerScoreRoute(req,env,user,path,req.method==='POST'?await body(req):{});
  if(path.startsWith('/v1/plugin-monitor'))return await monitorRoute(req,env,user,path,req.method==='POST'?await body(req):{});
  if(path==='/v1/plugin-advisories'&&req.method==='GET')return await pluginAdvisoryRoute(req,env,user);
  if(path.startsWith('/v1/inventory'))return await inventoryRoute(req,env,user,path,req.method==='POST'||req.method==='PUT'?await body(req):{});
  if(path==='/v1/stack'&&req.method==='GET'){const rows=await env.DB.prepare('SELECT technology,product_version FROM user_stack WHERE user_id=? ORDER BY technology').bind(user.id).all();return response({stack:rows.results})}
  if(path==='/v1/stack'&&req.method==='PUT'){
   const data=await body(req);if(!Array.isArray(data.stack)||data.stack.length>100)return response({error:'Invalid stack'},400);
   const rows=data.stack.map(x=>({technology:String(x.technology||'').trim().slice(0,120),product_version:String(x.product_version||'').trim().slice(0,80)}));
   if(rows.some(x=>!x.technology))return response({error:'Invalid technology'},400);
   const ops=[env.DB.prepare('DELETE FROM user_stack WHERE user_id=?').bind(user.id),...rows.map(x=>env.DB.prepare('INSERT INTO user_stack(user_id,technology,product_version) VALUES(?,?,?)').bind(user.id,x.technology,x.product_version))];
   await env.DB.batch(ops);return response({saved:rows.length});
  }
  if(path==='/v1/remediations/features'&&req.method==='GET')return await capabilities(env);
  if(path==='/v1/remediations'&&req.method==='GET')return await listRemediations(env,user);
  if(path==='/v1/remediations'&&req.method==='PUT'){
   const data=await body(req);
   return await importLegacy(env,user,data.remediations);
  }
  const remediationRoute=/^\/v1\/remediations\/(CVE-\d{4}-\d{4,})(\/assign)?$/.exec(path);
  if(remediationRoute){
   const id=remediationRoute[1];
   if(remediationRoute[2]&&req.method==='POST')return await assignRemediation(env,user,id,await body(req));
   if(!remediationRoute[2]&&req.method==='PUT')return await upsertRemediation(env,user,id,await body(req));
   if(!remediationRoute[2]&&req.method==='DELETE')return await removeRemediation(env,user,id);
  }
  if(path==='/v1/alerts'&&req.method==='GET'){
   const row=await env.DB.prepare('SELECT enabled,severity,frequency FROM alert_preferences WHERE user_id=?').bind(user.id).first();
   const subscription=await loadAlertSubscription(env,user.id);
   return response({preferences:row||{enabled:0,severity:'critical',frequency:'daily'},
    ...subscription,delivery_active:env.ALERT_DELIVERY_ENABLED==='true'});
  }
  if(path==='/v1/alerts'&&req.method==='PUT'){
   const data=await body(req);
   if(!['critical','high'].includes(data.severity)||!['daily','hourly'].includes(data.frequency)||typeof data.enabled!=='boolean')
    return response({error:'Invalid alert preferences'},400);
   const subscribed=await loadAlertSubscription(env,user.id);
   if(subscribed.migration_required)return response({error:'Alert tables have not been initialized'},503);
   await env.DB.prepare('INSERT INTO alert_preferences(user_id,enabled,severity,frequency) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET enabled=excluded.enabled,severity=excluded.severity,frequency=excluded.frequency,updated_at=CURRENT_TIMESTAMP')
    .bind(user.id,data.enabled?1:0,data.severity,data.frequency).run();
   await saveOptin(env,user.id,data.enabled);
   return response({saved:true,consented:data.enabled,delivery_active:env.ALERT_DELIVERY_ENABLED==='true',
    message:data.enabled?'Subscription saved. You will receive matching advisories once scheduled delivery is enabled.':'Email vulnerability notifications have been disabled.'});
  }
  if(path==='/v1/alerts/test'&&req.method==='POST'){
   const status=await loadAlertSubscription(env,user.id);
   if(status.migration_required)return response({error:'Alert tables have not been initialized'},503);
   return await sendUserSample(env,user);
  }
  if(path==='/v1/account'&&req.method==='DELETE'){
   await env.DB.prepare('DELETE FROM users WHERE id=?').bind(user.id).run();return response({deleted:true},200,{'Set-Cookie':setCookie('',0)});
  }
  return response({error:'Not found'},404);
 }catch(error){if(error instanceof RemediationError||error instanceof InventoryError||error instanceof FindingStatusError||error instanceof LifecycleError)return response({error:error.message},error.status);return response({error:'Unable to process request'},500)}
},
 async scheduled(_event,env,ctx) {
  if(env.ALERT_DELIVERY_ENABLED==='true')ctx.waitUntil(dispatchDueDigests(env));
  if(env.LIFECYCLE_DELIVERY_ENABLED==='true')ctx.waitUntil(dispatchLifecycle(env));
  if(env.PLUGIN_MONITOR_ENABLED==='true')ctx.waitUntil(scanDue(env));
 }
};
