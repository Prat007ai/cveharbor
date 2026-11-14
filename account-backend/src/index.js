import {agentDeviceRoute,agentManagement} from './agents.js';
import {dispatchAgentMail} from './agent-mail.js';
import {azureConnectionProbe, probePath} from './azure-connection.js';
import {aiRoute} from './ai-routes.js';
import {releaseIdentity} from './release-build.js';
import {teamRoute} from './team-access.js';
import {updateTopicHistory} from './cvie-topic-history.js';
import {firewallRoute,dispatchFirewallDigest} from './firewall-digest.js';
import {harborPng} from './firewall-artwork.js';
import {artworkPath} from './firewall-templates.js';
import {recoveryProtected} from './recovery-control.js';
import {saveCustomerRemediation,customerTicket} from './customer-remediation.js';
import {releaseReadiness} from './release-readiness.js';
import {canonicalRecord,integrityError} from './remediation-integrity.js';
import {scheduleStatusMail} from './status-update-mail.js';
import {sharedRoute} from './finding-remediation.js';
import {observeCvie} from './cvie-metrics.js';
import {reviewerRoute,reviewActivity} from './assignment-progress.js';
import {ReviewError} from './assignment-progress-common.js';
import {scheduleProgress,retryProgress} from './assignment-progress-mail.js';
import {WorkflowError,statusHistory} from './remediation-workflow.js';
import {CONFIRM_PREFIX} from './confirmation-host.js';
import {FyiError,scheduleFyi,retryFyi} from './assignment-fyi.js';
import {acknowledgementRoute,assignmentHistory,revokeAssignment,AssignmentError} from './assignment-acknowledgement.js';
import {approvedTest} from './monitor-approved-test.js';
import {workspaceRoute} from './workspace-summary.js';
import {captureWorkspaceHistory} from './workspace-history.js';
import {catalogueProducts,catalogueRevision} from './catalogue-selection.js';
// CVEHarbor account API with opt-in vulnerability digest support.
import {newSecret,totp,verifyTotp,encryptSecret,decryptSecret,newRecoveryCodes,hashRecovery} from './totp.js';
import { saveOptin, loadAlertSubscription, sendUserSample, dispatchDueDigests, unsubscribe } from './delivery.js';
import { handlePublicCveLookup } from './cve-lookup.js';
import {cvieRoute,subscribeProducts,syncAccountProducts,runCvieStep,dispatchCvie,discoverTopicArchive,CvieError} from './cvie.js';
import {dispatchEvidence} from './cvie-evidence.js';
import {productCpe,normalizeName} from './product-identity.js';
import { handler as lifecycleHandler, LifecycleError, dispatchLifecycle } from './lifecycle.js';
import {monitoringHandler,MonitorError,dispatchProductMonitoring,dispatchProductMonitorMail} from './monitoring.js';
import {smtp2goWebhook,unsubscribeMonitor} from './monitor-mail.js';
import { inventoryRoute, InventoryError } from './inventory.js';
import {route as websiteMonitorRoute,scanDue as scanWebsiteDue} from './website-monitor.js';
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
async function me(req,env){const value=cookie(req);if(!/^[a-f0-9]{64}$/.test(value))return null;return env.DB.prepare('SELECT users.id,users.email,sessions.id AS sid FROM sessions JOIN users ON users.id=sessions.user_id JOIN user_totp ON user_totp.user_id=users.id AND user_totp.enabled=1 WHERE sessions.token_hash=? AND sessions.expires_at>?').bind(await sha(value),Math.floor(Date.now()/1000)).first()}
async function body(req,maxBytes=18000){const size=Number(req.headers.get('content-length')||0);if(size>maxBytes)throw Error('Request too large');const raw=await req.text();if(raw.length>maxBytes)throw Error('Request too large');return JSON.parse(raw)}
async function limit(env,key,max){const now=Math.floor(Date.now()/1000),start=now-3600;await env.DB.prepare('DELETE FROM auth_rate_limits WHERE window_start<?').bind(start).run();await env.DB.prepare('INSERT INTO auth_rate_limits(key,window_start,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN window_start<? THEN 1 ELSE count+1 END,window_start=CASE WHEN window_start<? THEN ? ELSE window_start END').bind(key,now,start,start,now).run();const row=await env.DB.prepare('SELECT count FROM auth_rate_limits WHERE key=?').bind(key).first();return row.count<=max}
async function authWait(env,key,max){
 const now=Math.floor(Date.now()/1000);
 const row=await env.DB.prepare('SELECT window_start,count FROM auth_rate_limits WHERE key=?').bind(key).first();
 if(!row||row.window_start<=now-3600||row.count<max)return 0;
 return Math.max(1,row.window_start+3600-now);
}
function retryResponse(seconds,kind='limit'){
 const delay=Math.max(1,Math.ceil(seconds));
 return response({error:kind==='resend'?'Please wait before requesting another verification code.':'Too many verification requests. Please try again when the limit resets.',retry_after:delay},429,{'Retry-After':String(delay)});
}
async function emailCode(env,address,code){const response=await fetch('https://api.smtp2go.com/v3/email/send',{method:'POST',headers:{'Content-Type':'application/json','X-Smtp2go-Api-Key':env.SMTP2GO_API_KEY},body:JSON.stringify({sender:env.EMAIL_FROM,to:[address],subject:'CVEHarbor sign in code',text_body:'Your CVEHarbor code: '+code+'\n\nExpires in 10 minutes. If you did not request this, ignore this email.'})});if(!response.ok)throw Error('Email delivery unavailable');const payload=await response.json();if(!payload.data||payload.data.failed>0||payload.data.succeeded<1)throw Error('Email delivery unsuccessful')}
const application = {async fetch(req,env,ctx){
 const url=new URL(req.url),origin=req.headers.get('origin');
 // The confirmation hostname exposes only the guest confirmation page, never account APIs.
 if(url.hostname==='confirm.cveharbor.com'){
  if(url.pathname===artworkPath){
   if(req.method!=='GET' && req.method!=='HEAD')return new Response(null,{status:405,headers:{Allow:'GET, HEAD'}});
   const bytes=req.method==='GET'?Uint8Array.from(atob(harborPng),ch=>ch.charCodeAt(0)):null;
   return new Response(bytes,{headers:{'Content-Type':'image/png','Cache-Control':'public, max-age=31536000, immutable','X-Content-Type-Options':'nosniff'}});
  }
  if(/^\/firewall-updates\/(?:(?:confirm|unsubscribe)\/[a-f0-9]{64}|addresses\/\d{4}-\d{2}-\d{2}\.txt)$/.test(url.pathname)){
   try{return await firewallRoute(req,env,limit);}catch{return response({error:'Subscription service temporarily unavailable'},503);}
  }
  if(url.pathname.startsWith('/assignment/'))return reviewerRoute(req,env,ctx);
  if(url.pathname.startsWith(CONFIRM_PREFIX))return acknowledgementRoute(req,env,ctx);
  return new Response('Open the confirmation link in your assignment email.',{status:404,headers:{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff'}});
 }
 // Public bearer-link flow is isolated from account sessions and all private routes.
 if(url.pathname.startsWith('/v1/acknowledge/'))return acknowledgementRoute(req,env,ctx);
 if(req.method==='OPTIONS'){if(origin!==ALLOWED_ORIGIN)return response({error:'Forbidden'},403);return new Response(null,{status:204,headers:{'Access-Control-Allow-Origin':ALLOWED_ORIGIN,'Access-Control-Allow-Credentials':'true','Access-Control-Allow-Headers':'Content-Type','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Vary':'Origin'}})}
 if(!url.pathname.startsWith('/v1/'))return response({error:'Not found'},404);
 if(url.pathname==='/v1/firewall-updates'||url.pathname.startsWith('/v1/firewall-updates/')){
  try{return await firewallRoute(req,env,limit);}catch{return response({error:'Firewall updates are temporarily unavailable.'},503);}
 }
 if(url.pathname==='/v1/monitoring/webhooks/smtp2go'){
  if(!env.DB)return response({error:'Monitoring unavailable'},503);
  try{return await smtp2goWebhook(req,env);}catch{return response({error:'Event reconciliation unavailable; retry later'},503);}
 }
 const monitorUnsub=/^\/v1\/monitoring\/unsubscribe\/([a-f0-9-]{72})$/.exec(url.pathname);
 if(monitorUnsub){try{return await unsubscribeMonitor(req,env,monitorUnsub[1]);}catch{return response({error:'Unsubscribe unavailable; retry later'},503);}}
 const unsub=/^\/v1\/unsubscribe\/([a-f0-9]{64})$/.exec(url.pathname);
 if(unsub && (req.method==='GET'||req.method==='POST')) {
  if(!env.DB)return response({error:'Account database unavailable'},503);
  try {return await unsubscribe(req,env,unsub[1])}catch(_) {return response({error:'Unable to process unsubscribe request'},503)}
 }
 if(url.pathname.startsWith('/v1/agent/'))return agentDeviceRoute(req,env);
 if(origin&&origin!==ALLOWED_ORIGIN)return response({error:'Forbidden origin'},403);
 if(req.method!=='GET'&&origin!==ALLOWED_ORIGIN)return response({error:'Invalid request origin'},403);
 // Published CVE lookup is public, read-only, and independent of account login or D1.
 if(url.pathname.startsWith('/v1/cve/'))return handlePublicCveLookup(req,ctx);
 if(!env.DB)return response({error:'Account service not configured'},503);
 let path=url.pathname;
 try {
  if(path===probePath)return azureConnectionProbe(req,env,releaseIdentity);
  if(path==='/v1/health'&&req.method==='GET')return response({ready:!!(env.SMTP2GO_API_KEY&&env.EMAIL_FROM),accounts:'configured'});
  if(path==='/v1/auth/request'&&req.method==='POST'){
   if(!env.SMTP2GO_API_KEY||!env.EMAIL_FROM)return response({error:'Email login unavailable'},503);
   const data=await body(req),address=String(data.email||'').trim().toLowerCase();
   if(address.endsWith('@workspace.cveharbor.invalid'))return response({error:'Valid email required'},400);
   if(!/^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]+$/.test(address))return response({error:'Valid email required'},400);
   const ip=req.headers.get('CF-Connecting-IP')||'unknown';
   const ipKey='ip:'+await sha(ip),emailKey='email:'+await sha(address);
   // Do not consume hourly quota when the user is already blocked.
   const blocked=Math.max(await authWait(env,ipKey,12),await authWait(env,emailKey,5));
   if(blocked)return retryResponse(blocked);
   const recent=await env.DB.prepare('SELECT created_at FROM login_challenges WHERE email=? AND created_at>? ORDER BY created_at DESC LIMIT 1').bind(address,Math.floor(Date.now()/1000)-60).first();
   if(recent)return retryResponse(Math.max(1,recent.created_at+60-Math.floor(Date.now()/1000)),'resend');
   if(!await limit(env,ipKey,12)||!await limit(env,emailKey,5)){
    const wait=Math.max(await authWait(env,ipKey,12),await authWait(env,emailKey,5));
    return retryResponse(wait||60);
   }
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
   if(!env.TOTP_ENCRYPTION_KEY)return response({error:'MFA service unavailable'},503);
   const factor=await env.DB.prepare('SELECT enabled,encrypted_secret FROM user_totp WHERE user_id=?').bind(user.id).first();
   const pending=token(),now=Math.floor(Date.now()/1000);
   await env.DB.prepare('INSERT INTO totp_login_challenges(id,user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)').bind(crypto.randomUUID(),user.id,await sha(pending),now+300,now).run();
   if(factor?.enabled===1)return response({authenticated:false,mfa_required:true,mfa_challenge:pending});
   let secret;
   if(factor?.encrypted_secret){
    secret=await decryptSecret(env,factor.encrypted_secret,user.id);
   }else{
    const candidate=newSecret(),encrypted=await encryptSecret(env,candidate,user.id);
    await env.DB.prepare('INSERT OR IGNORE INTO user_totp(user_id,encrypted_secret,enabled,last_counter,created_at) VALUES(?,?,0,-1,?)').bind(user.id,encrypted,now).run();
    const saved=await env.DB.prepare('SELECT encrypted_secret,enabled FROM user_totp WHERE user_id=?').bind(user.id).first();
    if(saved?.enabled===1)return response({authenticated:false,mfa_required:true,mfa_challenge:pending});
    secret=await decryptSecret(env,saved.encrypted_secret,user.id);
   }
   return response({authenticated:false,mfa_enrollment_required:true,mfa_challenge:pending,secret,otpauth_url:'otpauth://totp/'+encodeURIComponent('CVEHarbor:'+user.email)+'?secret='+secret+'&issuer=CVEHarbor&algorithm=SHA1&digits=6&period=30'});

  }
  if(path==='/v1/auth/totp/enroll'&&req.method==='POST'){
   if(!env.TOTP_ENCRYPTION_KEY)return response({error:'MFA unavailable'},503);
   const data=await body(req),pending=String(data.mfa_challenge||''),code=String(data.code||''),now=Math.floor(Date.now()/1000);
   if(!/^[a-f0-9]{64}$/.test(pending)||!/^\d{6}$/.test(code))return response({error:'Invalid enrollment code'},400);
   const ip=req.headers.get('CF-Connecting-IP')||'unknown';
   if(!await limit(env,'enroll-ip:'+await sha(ip),20)||!await limit(env,'enroll-challenge:'+await sha(pending),8))return response({error:'Too many attempts'},429);
   const pendingHash=await sha(pending);
   const challenge=await env.DB.prepare('SELECT user_id FROM totp_login_challenges WHERE token_hash=? AND consumed_at IS NULL AND expires_at>?').bind(pendingHash,now).first();
   if(!challenge)return response({error:'Enrollment expired. Sign in again.'},401);
   const factor=await env.DB.prepare('SELECT encrypted_secret FROM user_totp WHERE user_id=? AND enabled=0').bind(challenge.user_id).first();
   if(!factor)return response({error:'Enrollment not available'},409);
   const counter=await verifyTotp(await decryptSecret(env,factor.encrypted_secret,challenge.user_id),code);
   if(counter<0)return response({error:'Incorrect authenticator code'},401);
   const recovery=newRecoveryCodes();
   const statements=[env.DB.prepare('UPDATE totp_login_challenges SET consumed_at=? WHERE token_hash=? AND consumed_at IS NULL').bind(now,pendingHash)];
   statements.push(env.DB.prepare('DELETE FROM totp_recovery_codes WHERE user_id=?').bind(challenge.user_id));
   for(const item of recovery)statements.push(env.DB.prepare('INSERT INTO totp_recovery_codes(user_id,code_hash) VALUES(?,?)').bind(challenge.user_id,await hashRecovery(item,challenge.user_id)));
   statements.push(env.DB.prepare('UPDATE user_totp SET enabled=1,enabled_at=?,last_counter=? WHERE user_id=? AND enabled=0').bind(now,counter,challenge.user_id));
   statements.push(env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(challenge.user_id));
   const result=await env.DB.batch(statements);
   if(result[0]?.meta?.changes!==1||result[result.length-2]?.meta?.changes!==1)return response({error:'Enrollment already completed'},409);
   const session=token();
   await env.DB.prepare('INSERT INTO sessions(id,user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)').bind(crypto.randomUUID(),challenge.user_id,await sha(session),now+604800,now).run();
   const account=await env.DB.prepare('SELECT email FROM users WHERE id=?').bind(challenge.user_id).first();
   return response({authenticated:true,email:account.email,recovery_codes:recovery},200,{'Set-Cookie':setCookie(session,604800)});
  }
  if(path==='/v1/auth/totp/verify'&&req.method==='POST'){
   if(!env.TOTP_ENCRYPTION_KEY)return response({error:'MFA unavailable'},503);
   const data=await body(req),pending=String(data.mfa_challenge||''),code=String(data.code||'').trim().toLowerCase(),now=Math.floor(Date.now()/1000);
   if(!/^[a-f0-9]{64}$/.test(pending)||(!/^\d{6}$/.test(code)&&!(/^[a-f0-9]{16}$/.test(code))))return response({error:'Invalid authentication code'},400);
   const ip=req.headers.get('CF-Connecting-IP')||'unknown';
   if(!await limit(env,'totp-ip:'+await sha(ip),20)||!await limit(env,'totp-challenge:'+await sha(pending),8))return response({error:'Too many attempts'},429);
   const pendingRow=await env.DB.prepare('SELECT user_id FROM totp_login_challenges WHERE token_hash=? AND consumed_at IS NULL AND expires_at>?').bind(await sha(pending),now).first();
   if(!pendingRow)return response({error:'Expired MFA challenge'},401);
   const factor=await env.DB.prepare('SELECT encrypted_secret,last_counter FROM user_totp WHERE user_id=? AND enabled=1').bind(pendingRow.user_id).first();
   if(!factor)return response({error:'MFA not configured'},401);
   let valid=false,counter=-1,recoveryHash='';
   if(/^\d{6}$/.test(code)){
    const secret=await decryptSecret(env,factor.encrypted_secret,pendingRow.user_id);
    counter=await verifyTotp(secret,code);
    valid=counter>factor.last_counter;
   }else{
    recoveryHash=await hashRecovery(code,pendingRow.user_id);
    const match=await env.DB.prepare('SELECT code_hash FROM totp_recovery_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL').bind(pendingRow.user_id,recoveryHash).first();
    valid=!!match;
   }
   if(!valid)return response({error:'Invalid or already used authentication code'},401);
   const consumed=await env.DB.prepare('UPDATE totp_login_challenges SET consumed_at=? WHERE token_hash=? AND consumed_at IS NULL AND expires_at>?').bind(now,await sha(pending),now).run();
   if(consumed.meta.changes!==1)return response({error:'Challenge already used'},401);
   if(recoveryHash){const used=await env.DB.prepare('UPDATE totp_recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL').bind(now,pendingRow.user_id,recoveryHash).run();if(used.meta.changes!==1)return response({error:'Recovery code already used'},401)}
   else{const advanced=await env.DB.prepare('UPDATE user_totp SET last_counter=? WHERE user_id=? AND last_counter<?').bind(counter,pendingRow.user_id,counter).run();if(advanced.meta.changes!==1)return response({error:'Authenticator code already used'},401)}
   const session=token();
   await env.DB.prepare('INSERT INTO sessions(id,user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)').bind(crypto.randomUUID(),pendingRow.user_id,await sha(session),now+604800,now).run();
   const account=await env.DB.prepare('SELECT email FROM users WHERE id=?').bind(pendingRow.user_id).first();
   return response({authenticated:true,email:account.email},200,{'Set-Cookie':setCookie(session,604800)});
  }
  const user=await me(req,env);
  if(path==='/v1/me'&&req.method==='GET')return response(user?{authenticated:true,email:user.email}:{authenticated:false},user?200:401);
  if(!user)return response({error:'Sign in required'},401);
  if(path==='/v1/agents'||path.startsWith('/v1/agents/'))return response(await agentManagement(req,env,user));
  if(path.startsWith('/v1/ai/'))return await aiRoute(req,env,user,path,{response,body,limit},ctx);
  if(path.startsWith('/v1/team/'))return await teamRoute(req,env,user,path,{response,body,token,sha,limit});
  const recordPath=/^\/v1\/(remediations|remediation-records)\/(CVE-\d{4}-\d{4,}(?:~[A-F0-9-]{36})?)(.*)$/.exec(path);
  if(recordPath){const canonical=await canonicalRecord(env,user.id,recordPath[2]);if(canonical!==recordPath[2]){if(req.method!=='GET')return response({error:'This record was linked to an existing assignment. Open the current shared record before making changes.',canonical_id:canonical},409);path='/v1/'+recordPath[1]+'/'+canonical+recordPath[3];}}
  if(path.startsWith('/v1/workspace/'))return await workspaceRoute(req,env,user);
  if(path==='/v1/auth/totp/status'&&req.method==='GET'){
   const row=env.TOTP_ENCRYPTION_KEY?await env.DB.prepare('SELECT enabled FROM user_totp WHERE user_id=?').bind(user.id).first():null;
   return response({available:!!env.TOTP_ENCRYPTION_KEY,enabled:row?.enabled===1});
  }
  if(path==='/v1/auth/totp/setup'&&req.method==='POST'){
   if(!env.TOTP_ENCRYPTION_KEY)return response({error:'MFA setup unavailable'},503);
   const existing=await env.DB.prepare('SELECT enabled FROM user_totp WHERE user_id=?').bind(user.id).first();
   if(existing?.enabled===1)return response({error:'MFA already enabled'},409);
   if(!await limit(env,'totp-setup:'+user.id,5))return response({error:'Too many attempts'},429);
   const secret=newSecret(),encrypted=await encryptSecret(env,secret,user.id),now=Math.floor(Date.now()/1000);
   await env.DB.prepare('INSERT INTO user_totp(user_id,encrypted_secret,enabled,last_counter,created_at) VALUES(?,?,0,-1,?) ON CONFLICT(user_id) DO UPDATE SET encrypted_secret=excluded.encrypted_secret,enabled=0,last_counter=-1,created_at=excluded.created_at').bind(user.id,encrypted,now).run();
   return response({secret,otpauth_url:'otpauth://totp/'+encodeURIComponent('CVEHarbor:'+user.email)+'?secret='+secret+'&issuer=CVEHarbor&algorithm=SHA1&digits=6&period=30'});
  }
  if(path==='/v1/auth/totp/enable'&&req.method==='POST'){
   if(!env.TOTP_ENCRYPTION_KEY)return response({error:'MFA setup unavailable'},503);
   const data=await body(req),code=String(data.code||''),now=Math.floor(Date.now()/1000);
   if(!await limit(env,'totp-enable:'+user.id,10))return response({error:'Too many attempts'},429);
   const row=await env.DB.prepare('SELECT encrypted_secret,enabled FROM user_totp WHERE user_id=?').bind(user.id).first();
   if(!row||row.enabled)return response({error:'No pending authenticator enrollment'},409);
   const secret=await decryptSecret(env,row.encrypted_secret,user.id),counter=await verifyTotp(secret,code);
   if(counter<0)return response({error:'Incorrect authenticator code'},401);
   const recovery=newRecoveryCodes();
   const statements=[env.DB.prepare('DELETE FROM totp_recovery_codes WHERE user_id=?').bind(user.id)];
   for(const item of recovery)statements.push(env.DB.prepare('INSERT INTO totp_recovery_codes(user_id,code_hash) VALUES(?,?)').bind(user.id,await hashRecovery(item,user.id)));
   statements.push(env.DB.prepare('UPDATE user_totp SET enabled=1,enabled_at=?,last_counter=? WHERE user_id=? AND enabled=0').bind(now,counter,user.id));
   // Revoke other existing sessions so an earlier email-only session cannot persist after enrollment.
   statements.push(env.DB.prepare('DELETE FROM sessions WHERE user_id=? AND id<>?').bind(user.id,user.sid));
   // D1 batch is transactional: do not enable MFA without all recovery codes.
   const applied=await env.DB.batch(statements);
   if(applied[applied.length-2]?.meta?.changes!==1)return response({error:'Enrollment already completed'},409);
   return response({enabled:true,recovery_codes:recovery,message:'Save these codes securely. Each can only be used once.'});
  }
  if(path==='/v1/auth/totp/recovery/rotate'&&req.method==='POST'){
   if(!env.TOTP_ENCRYPTION_KEY)return response({error:'MFA unavailable'},503);
   const data=await body(req),code=String(data.code||''),now=Math.floor(Date.now()/1000);
   if(!/^\d{6}$/.test(code))return response({error:'Six digit authenticator code required'},400);
   if(!await limit(env,'totp-rotate:'+user.id,8))return response({error:'Too many attempts'},429);
   const factor=await env.DB.prepare('SELECT encrypted_secret,last_counter FROM user_totp WHERE user_id=? AND enabled=1').bind(user.id).first();
   if(!factor)return response({error:'MFA not enabled'},409);
   const counter=await verifyTotp(await decryptSecret(env,factor.encrypted_secret,user.id),code);
   if(counter<=factor.last_counter)return response({error:'Invalid or previously used authenticator code'},401);
   const recovery=newRecoveryCodes();
   const statements=[env.DB.prepare('UPDATE user_totp SET last_counter=? WHERE user_id=? AND last_counter<? AND enabled=1').bind(counter,user.id,counter),env.DB.prepare('DELETE FROM totp_recovery_codes WHERE user_id=?').bind(user.id)];
   for(const item of recovery)statements.push(env.DB.prepare('INSERT INTO totp_recovery_codes(user_id,code_hash) VALUES(?,?)').bind(user.id,await hashRecovery(item,user.id)));
   const results=await env.DB.batch(statements);
   if(results[0]?.meta?.changes!==1)return response({error:'Authenticator code already used'},401);
   return response({recovery_codes:recovery,message:'Previous recovery codes have been invalidated. Store these new codes securely.'});
  }
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
  if(path.startsWith('/v1/monitoring'))return await monitoringHandler(req,env,user,path,req.method==='POST'||req.method==='PUT'?await body(req):{});
  if(path.startsWith('/v1/lifecycle'))return await lifecycleHandler(req,env,user,path,req.method==='POST'||req.method==='PUT'?await body(req):{});
  if(path.startsWith('/v1/finding-tickets'))return await findingTicketRoute(req,env,user,path,req.method==='POST'?await body(req):{});
  const customerTicketRoute=/^\/v1\/remediation-records\/(CVE-\d{4}-\d{4,}(?:~[A-F0-9-]{36})?)\/tickets$/.exec(path);
  if(customerTicketRoute&&req.method==='POST')return await customerTicket(env,user,customerTicketRoute[1],await body(req));
  if(path==='/v1/finding-assignments'||path.startsWith('/v1/finding-remediations/')||path.startsWith('/v1/remediation-records/')){const result=await sharedRoute(req,env,user,path,req.method==='POST'?await body(req):{});if(result.ok&&req.method==='POST')scheduleStatusMail(env,ctx);return result;}
  if(path.startsWith('/v1/finding-statuses')){const result=await findingStatusRoute(req,env,user,path,req.method==='PUT'?await body(req):{});if(result.ok&&req.method==='PUT')scheduleStatusMail(env,ctx);return result;}
  if(path.startsWith('/v1/plugin-installation-status'))return await sourceRoute(req,env,user,path,req.method==='PUT'?await body(req):{});
  if(path.startsWith('/v1/plugin-sources'))return await sourceRoute(req,env,user,path,req.method==='PUT'?await body(req):{});
  if(path==='/v1/customer-score-history')return await customerScoreRoute(req,env,user,path,req.method==='POST'?await body(req):{});
  if(path.startsWith('/v1/website-monitor'))return await websiteMonitorRoute(req,env,user,path,req.method==='POST'&&path==='/v1/website-monitor'?await body(req):{});
  if(path.startsWith('/v1/plugin-monitor'))return await monitorRoute(req,env,user,path,req.method==='POST'?await body(req):{});
  if(path==='/v1/plugin-advisories'&&req.method==='GET')return await pluginAdvisoryRoute(req,env,user);
  if(path.startsWith('/v1/cvie')){const data=req.method==='PUT'||req.method==='POST'?await body(req):{};return await observeCvie(env,req.method!=='GET'?'onboard':path.endsWith('/progress')?'progress':path.includes('advisories')||path.includes('/evidence')?'evidence':path.includes('/directory')?'directory':'status',measured=>cvieRoute(req,measured,user,ctx,data));}
  if(path.startsWith('/v1/inventory')){
   const result=await inventoryRoute(req,env,user,path,req.method==='POST'||req.method==='PUT'?await body(req):{});
   if(result.ok&&['POST','PUT','DELETE'].includes(req.method)&&(/\/assets(?:\/|$)/.test(path)||req.method==='DELETE')){
    const sync=observeCvie(env,'inventory',measured=>syncAccountProducts(measured,user.id,'inventory')).then(s=>{if(s.changed)ctx?.waitUntil(runCvieStep(env,fetch,Date.now(),user.id,'inventory'));}).catch(()=>console.warn('CVIE inventory synchronization will retry on the next account sync'));
    if(env.CVIE_REGISTRY_ENABLED==='true')await sync;else ctx?.waitUntil(sync);
   }
   return result;
  }
  if(path==='/v1/technology-catalogue'&&req.method==='GET'){
   const row=await env.DB.prepare('SELECT preferences_json FROM user_technology_catalogue WHERE user_id=?').bind(user.id).first();
   return response({...row?JSON.parse(row.preferences_json):{defaults:null,products:[]},revision:await catalogueRevision(row?.preferences_json??null)});
  }
  if(path==='/v1/technology-catalogue'&&req.method==='PUT'){
   const data=await body(req),defaults=data.defaults,products=data.products;
   if(!Array.isArray(defaults)||defaults.length>100||!Array.isArray(products)||products.length>50)return response({error:'Invalid catalogue size'},400);
   if(defaults.some(x=>typeof x!=='string'||!x.trim()||x.length>120)||products.some(x=>!x||typeof x.name!=='string'||!x.name.trim()||x.name.length>120||typeof x.version!=='string'||x.version.length>80))return response({error:'Invalid product details'},400);
   if(new Set(defaults.map(normalizeName)).size!==defaults.length||new Set(products.map(x=>normalizeName(x.name))).size!==products.length)return response({error:'Duplicate entries'},400);
   if(products.some(x=>x.vendor!==undefined&&(typeof x.vendor!=='string'||x.vendor.length>100)||x.cpe&&!productCpe(x.cpe)))return response({error:'Invalid vendor or product CPE'},400);
   const selected=catalogueProducts({defaults,products});
   const payload=JSON.stringify({defaults,products,selection_keys:selected.map(p=>normalizeName(p.name))});
   if(payload.length>18000)return response({error:'Catalogue is too large'},400);
   const prior=await env.DB.prepare('SELECT preferences_json FROM user_technology_catalogue WHERE user_id=?').bind(user.id).first();
   const revision=await catalogueRevision(prior?.preferences_json??null);
   if(data.revision!==undefined&&data.revision!==revision)return response({error:'Your catalogue changed in another tab. Reload the saved catalogue before editing again.'},409);
   if(prior?.preferences_json===payload)return response({saved:true,unchanged:true,revision,cvie:{status:'unchanged'}});
   const saved=prior?await env.DB.prepare('UPDATE user_technology_catalogue SET preferences_json=?,updated_at=? WHERE user_id=? AND preferences_json=?').bind(payload,Math.floor(Date.now()/1000),user.id,prior.preferences_json).run():
    await env.DB.prepare('INSERT OR IGNORE INTO user_technology_catalogue(user_id,preferences_json,updated_at) VALUES(?,?,?)').bind(user.id,payload,Math.floor(Date.now()/1000)).run();
   if(saved.meta.changes!==1)return response({error:'Your catalogue changed while saving. Reload the saved catalogue and try again.'},409);
   const nextRevision=await catalogueRevision(payload);
   try{const cvie=await observeCvie(env,'catalogue',measured=>subscribeProducts(measured,user.id,selected,'catalogue',payload));if(cvie.changed)ctx?.waitUntil(runCvieStep(env,fetch,Date.now(),user.id,'catalogue'));return response({saved:true,revision:nextRevision,cvie:{...cvie,status:cvie.ready?'updated':'setup_required'}});}
   catch{return response({saved:true,revision:nextRevision,cvie:{ready:false,status:'sync_required',message:'Catalogue saved. CVIE synchronization will retry from the intelligence panel.'}});}
  }
  if(path==='/v1/stack'&&req.method==='GET'){const rows=await env.DB.prepare('SELECT technology,product_version FROM user_stack WHERE user_id=? ORDER BY technology').bind(user.id).all();return response({stack:rows.results})}
  if(path==='/v1/stack'&&req.method==='PUT'){
   const data=await body(req);if(!Array.isArray(data.stack)||data.stack.length>100)return response({error:'Invalid stack'},400);
   const rows=data.stack.map(x=>({technology:String(x.technology||'').trim().slice(0,120),product_version:String(x.product_version||'').trim().slice(0,80)}));
   if(rows.some(x=>!x.technology))return response({error:'Invalid technology'},400);
   if(new Set(rows.map(r=>r.technology)).size!==rows.length)return response({error:'Duplicate technology'},400);
   const prior=(await env.DB.prepare('SELECT technology,product_version FROM user_stack WHERE user_id=?').bind(user.id).all()).results||[];
   const ops=prior.filter(p=>!rows.some(r=>r.technology===p.technology)).map(p=>env.DB.prepare('DELETE FROM user_stack WHERE user_id=? AND technology=?').bind(user.id,p.technology));
   for(const row of rows)if(!prior.some(p=>p.technology===row.technology&&p.product_version===row.product_version))ops.push(env.DB.prepare(`INSERT INTO user_stack(user_id,technology,product_version) VALUES(?,?,?) ON CONFLICT(user_id,technology) DO UPDATE SET product_version=excluded.product_version WHERE product_version<>excluded.product_version`).bind(user.id,row.technology,row.product_version));
   if(!ops.length)return response({saved:rows.length,unchanged:true});
   await env.DB.batch(ops);
   ctx?.waitUntil(observeCvie(env,path.startsWith('/v1/inventory')?'inventory':'stack',measured=>syncAccountProducts(measured,user.id)).then(()=>runCvieStep(env,fetch,Date.now(),user.id)).catch(()=>console.warn('CVIE watchlist synchronization will retry on the next account sync')));
   return response({saved:rows.length});
  }
  if(path==='/v1/remediations/features'&&req.method==='GET')return await capabilities(env);
  if(path==='/v1/customer-remediations'&&req.method==='POST'){const result=await saveCustomerRemediation(env,user,await body(req));if(result.ok)scheduleStatusMail(env,ctx);return result;}
  if(path==='/v1/remediations'&&req.method==='GET')return await listRemediations(env,user,url.searchParams.get('customer_id')||'all');
  if(path==='/v1/remediations'&&req.method==='PUT'){
   const data=await body(req);
   return await importLegacy(env,user,data.remediations);
  }
  const progressRoute=/^\/v1\/remediations\/(CVE-\d{4}-\d{4,}(?:~[A-F0-9-]{36})?)\/review-activity$/.exec(path);
  if(progressRoute&&req.method==='GET')return response(await reviewActivity(env,user,progressRoute[1],url));
  const progressRetry=/^\/v1\/remediations\/(CVE-\d{4}-\d{4,}(?:~[A-F0-9-]{36})?)\/review-notifications\/(\d{1,16})\/retry$/.exec(path);
  if(progressRetry&&req.method==='POST'){const result=await retryProgress(env,user,progressRetry[1],Number(progressRetry[2]));scheduleProgress(env,ctx);return response(result);}
  const statusRoute=/^\/v1\/remediations\/(CVE-\d{4}-\d{4,}(?:~[A-F0-9-]{36})?)\/status-history$/.exec(path);
  if(statusRoute&&req.method==='GET')return response(await statusHistory(env,user,statusRoute[1],url));
  const fyiRetry=/^\/v1\/remediations\/(CVE-\d{4}-\d{4,}(?:~[A-F0-9-]{36})?)\/assignments\/([a-f0-9-]{36})\/fyi\/retry$/.exec(path);
  if(fyiRetry&&req.method==='POST'){const result=await retryFyi(env,user,fyiRetry[1],fyiRetry[2]);scheduleFyi(env,ctx);return response(result);}
  const assignmentRoute=/^\/v1\/remediations\/(CVE-\d{4}-\d{4,}(?:~[A-F0-9-]{36})?)\/assignments(?:\/([a-f0-9-]{36})\/revoke)?$/.exec(path);
  if(assignmentRoute){
   if(!assignmentRoute[2]&&req.method==='GET')return await assignmentHistory(env,user,assignmentRoute[1],url);
   if(assignmentRoute[2]&&req.method==='POST')return await revokeAssignment(env,user,assignmentRoute[1],assignmentRoute[2]);
   return response({error:'Method not allowed'},405);
  }
  const remediationRoute=/^\/v1\/remediations\/(CVE-\d{4}-\d{4,}(?:~[A-F0-9-]{36})?)(\/assign)?$/.exec(path);
  if(remediationRoute){
   const id=remediationRoute[1];
   if(remediationRoute[2]&&req.method==='POST'){const result=await assignRemediation(env,user,id,await body(req));if(result.ok)scheduleFyi(env,ctx);return result;}
   if(!remediationRoute[2]&&req.method==='PUT'){const result=await upsertRemediation(env,user,id,await body(req));if(result.ok)scheduleStatusMail(env,ctx);return result;}
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
   try{await env.DB.prepare('DELETE FROM users WHERE id=?').bind(user.id).run();}
   catch(error){
    if(String(error.message).includes('Keep an active workspace Owner'))return response({error:'Assign another active Owner before deleting this account.'},409);
    if(/FOREIGN KEY constraint failed/i.test(error.message)&&await env.DB.prepare("SELECT 1 FROM sqlite_master WHERE name='team_organizations'").first()&&await env.DB.prepare('SELECT 1 FROM team_organizations WHERE data_owner=?').bind(user.id).first())return response({error:'This account owns shared customer inventory. Contact support before deleting the account.'},409);
    throw error;
   }
   return response({deleted:true},200,{'Set-Cookie':setCookie('',0)});
  }
  return response({error:'Not found'},404);
 }catch(error){error=integrityError(error);if(error instanceof ReviewError||error instanceof WorkflowError||error instanceof FyiError||error instanceof AssignmentError||error instanceof MonitorError||error instanceof CvieError||error instanceof RemediationError||error instanceof InventoryError||error instanceof FindingStatusError||error instanceof LifecycleError)return response({error:error.message},error.status);return response({error:'Unable to process request'},500)}
},
 async scheduled(_event,env,ctx) {
  if(_event.cron==='* * * * *')ctx.waitUntil(dispatchAgentMail(env));
  if(_event?.cron==='5 * * * *')ctx.waitUntil(captureWorkspaceHistory(env));
  if(_event.cron==='*/5 * * * *')ctx.waitUntil(dispatchFirewallDigest(env));
  if(_event.cron==='* * * * *'&&env.CVIE_TOPIC_HISTORY_ENABLED==='true'){
   ctx.waitUntil(updateTopicHistory(env));
   if(Math.floor((_event.scheduledTime||Date.now())/60000)%5===2)ctx.waitUntil(discoverTopicArchive(env));
  }
  if(_event.cron==='* * * * *'){scheduleStatusMail(env,ctx);scheduleProgress(env,ctx);scheduleFyi(env,ctx);ctx.waitUntil(approvedTest(env));ctx.waitUntil(observeCvie(env,'disclosure_dispatch',dispatchEvidence));if(env.PRODUCT_MONITOR_CHECKS_ENABLED==='true'&&env.PRODUCT_MONITOR_DELIVERY_ENABLED==='true')ctx.waitUntil(dispatchProductMonitorMail(env));return;}
  if(_event.cron==='*/5 * * * *'){ctx.waitUntil(observeCvie(env,'nvd_dispatch',dispatchCvie));return;}
  if(env.ALERT_DELIVERY_ENABLED==='true')ctx.waitUntil(dispatchDueDigests(env));
  if(env.LIFECYCLE_DELIVERY_ENABLED==='true')ctx.waitUntil(dispatchLifecycle(env));
  if(env.PRODUCT_MONITOR_CHECKS_ENABLED==='true')ctx.waitUntil(dispatchProductMonitoring(env));
  if(env.PLUGIN_MONITOR_ENABLED==='true')ctx.waitUntil(scanDue(env));
  if(env.WEBSITE_MONITOR_ENABLED==='true')ctx.waitUntil(scanWebsiteDue(env));
 }
};


const protectedApplication=recoveryProtected(application);
export default {
 fetch(req,env,ctx){if(req.method==='GET'&&new URL(req.url).hostname!=='confirm.cveharbor.com'&&new URL(req.url).pathname==='/v1/release-readiness')return releaseReadiness(env);return protectedApplication.fetch(req,env,ctx);},
 scheduled:protectedApplication.scheduled
};
