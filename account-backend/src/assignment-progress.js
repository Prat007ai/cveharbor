import {recordScope,scopeLabel} from './remediation-identity.js';
import {sendEmail} from './delivery.js';
import {reviewPage} from './assignment-progress-page.js';
import {REVIEW_ORIGIN,reviewNow as now,reviewHash as hash,reviewToken,reviewQuota,progressReady,activeReviewSQL,ReviewError} from './assignment-progress-common.js';
const cookieName='__Host-cvh_review';
const cookie=(value,age=1800)=>cookieName+'='+value+'; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age='+age;
const sessionToken=req=>(req.headers.get('Cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(cookieName+'='))?.slice(cookieName.length+1)||'';
const sender=env=>({EMAIL_FROM:env.EMAIL_FROM,SMTP2GO_API_KEY:env.SMTP2GO_API_KEY,ALERT_SMTP2GO_API_KEY:env.ASSIGNMENT_SMTP2GO_API_KEY||env.SMTP2GO_API_KEY});
export async function reviewSession(req,env,id){const raw=sessionToken(req);if(!/^[a-f0-9]{64}$/.test(raw))return null;const tokenHash=await hash(raw),row=await env.DB.prepare('SELECT token_hash FROM remediation_review_sessions WHERE token_hash=? AND assignment_id=? AND expires_at>?').bind(tokenHash,id,now()).first();return row?{tokenHash,proof:await hash('review-csrf:'+raw)}:null;}
export async function saveReviewerProgress(env,row,session,data){
 const status=data.status,reason=String(data.reason||'').trim(),comment=String(data.comment||'').trim();
 if(!['Open','Investigating','Remediated','Not Applicable'].includes(status)||row.status==='Accepted Risk')throw new ReviewError('This status can only be changed by the record owner.');
 if(reason.length>1000||comment.length>2000)throw new ReviewError('Keep reasons within 1,000 characters and comments within 2,000 characters.');
 if(status!==row.status&&!reason)throw new ReviewError('Enter a reason for the status change.');
 if(status===row.status&&comment.length<10)throw new ReviewError('Add a progress comment of at least 10 characters, or change the status with a reason.');
 if(data.expected_updated!==row.updated_at)throw new ReviewError('This record has changed. Reload and review its current status before saving.',409);
 const stamp=now(),savedAt=new Date(Math.max(Date.now(),Date.parse(row.updated_at)+1||0)).toISOString();
 const batch=[
 env.DB.prepare('INSERT INTO remediation_review_write_context(user_id,cve_id,assignment_id,author_email,reason,comment,created_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(user_id,cve_id) DO UPDATE SET assignment_id=excluded.assignment_id,author_email=excluded.author_email,reason=excluded.reason,comment=excluded.comment,created_at=excluded.created_at').bind(row.user_id,row.cve_id,row.id,row.recipient_email,reason,comment,stamp),
 env.DB.prepare('INSERT INTO remediation_change_context(user_id,cve_id,reason,actor_email,changed_at,expected_updated) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id,cve_id) DO UPDATE SET reason=excluded.reason,actor_email=excluded.actor_email,changed_at=excluded.changed_at,expected_updated=excluded.expected_updated').bind(row.user_id,row.cve_id,reason,row.recipient_email,savedAt,row.updated_at),
 env.DB.prepare("UPDATE remediations SET status=?,updated_at=? WHERE user_id=? AND cve_id=? AND updated_at=? AND status!='Accepted Risk' AND EXISTS(SELECT 1 FROM remediation_review_sessions s JOIN remediation_review_access p ON p.assignment_id=s.assignment_id JOIN remediation_assignment_requests a ON a.id=p.assignment_id WHERE s.token_hash=? AND s.assignment_id=? AND s.expires_at>? AND p.expires_at>? AND a.revoked_at IS NULL AND a.delivery_status='sent')").bind(status,savedAt,row.user_id,row.cve_id,row.updated_at,session.tokenHash,row.id,stamp,stamp),

 env.DB.prepare('DELETE FROM remediation_change_context WHERE user_id=? AND cve_id=?').bind(row.user_id,row.cve_id),env.DB.prepare('DELETE FROM remediation_review_write_context WHERE user_id=? AND cve_id=?').bind(row.user_id,row.cve_id)];
 const result=await env.DB.batch(batch);if(result[2].meta?.changes!==1)throw new ReviewError('This record or invitation has changed. Reload before saving.',409);
 return {saved:true};
}
export async function reviewerRoute(req,env){
 const url=new URL(req.url),match=/^\/assignment\/([a-f0-9-]{36})$/.exec(url.pathname);
 if(url.origin!==REVIEW_ORIGIN||!match)return reviewPage({unavailable:true},404);
 if(!['GET','HEAD','POST'].includes(req.method))return reviewPage({unavailable:true},405,{Allow:'GET, HEAD, POST'});
 const id=match[1];let row=null,session=null,challenge='';
 try{
  if(!env.ASSIGNMENT_ACK_RATE_LIMITER?.limit||!await progressReady(env))return reviewPage({unavailable:true,message:'Assignment updates are temporarily unavailable. Please try again later.'},503);
  if(!(await env.ASSIGNMENT_ACK_RATE_LIMITER.limit({key:'review:'+String(req.headers.get('CF-Connecting-IP')||'unknown')})).success)return reviewPage({unavailable:true,message:'Too many requests. Please try again shortly.'},429);
  row=await env.DB.prepare(activeReviewSQL).bind(id,now()).first();if(!row)return reviewPage({unavailable:true},410);
  session=await reviewSession(req,env,id);
  if(req.method==='POST'){
   const origin=req.headers.get('Origin'),site=req.headers.get('Sec-Fetch-Site'),trustedOrigin=origin===REVIEW_ORIGIN;
   if(!trustedOrigin||(site&&site!=='same-origin')||!/^application\/x-www-form-urlencoded(?:;|$)/i.test(req.headers.get('Content-Type')||'')||Number(req.headers.get('Content-Length')||0)>18000)return reviewPage({unavailable:true,message:'Request could not be verified. Open the assignment link again.'},403);
   const raw=await req.text();if(raw.length>18000)throw new ReviewError('The update is too long.');const form=new URLSearchParams(raw),action=form.get('action');
   if(action==='send_code'){
    if(env.ASSIGNMENT_EMAIL_ENABLED!=='true'||!env.EMAIL_FROM||!(env.ASSIGNMENT_SMTP2GO_API_KEY||env.SMTP2GO_API_KEY))throw new ReviewError('Email verification is temporarily unavailable.',503);
    if(!await reviewQuota(env,'review-code:'+id,3600,3)||!await reviewQuota(env,'assignment-target:'+await hash(row.recipient_email),86400,20))throw new ReviewError('Verification email limit reached. Please try again later.',429);
    challenge=crypto.randomUUID();let n;do{n=crypto.getRandomValues(new Uint32Array(1))[0];}while(n>=4294000000);const code=String(n%1000000).padStart(6,'0'),stamp=now();
    await env.DB.batch([env.DB.prepare('UPDATE remediation_review_challenges SET used_at=? WHERE assignment_id=? AND used_at IS NULL').bind(stamp,id),env.DB.prepare('INSERT INTO remediation_review_challenges(id,assignment_id,code_hash,created_at,expires_at) VALUES(?,?,?,?,?)').bind(challenge,id,await hash(challenge+':'+code),stamp,stamp+600)]);
    try{await sendEmail(sender(env),row.recipient_email,{subject:'[CVEHarbor] Your assignment verification code',text:'Your CVEHarbor assignment verification code is '+code+'.\n\nIt expires in 10 minutes and can be used once. Do not share this code. If you did not request it, ignore this email.',html:'<p>Your CVEHarbor assignment verification code:</p><p style="font-size:28px;font-weight:bold">'+code+'</p><p>Expires in 10 minutes. Do not share this code. If you did not request it, ignore this email.</p>'});}catch{await env.DB.prepare('UPDATE remediation_review_challenges SET used_at=? WHERE id=?').bind(now(),challenge).run();throw new ReviewError('Verification email could not be confirmed as sent. Please try again later.',502);}
    return reviewPage({challenge,message:'A verification code has been sent to the assigned reviewer.'});
   }
   if(action==='verify'){
    challenge=form.get('challenge')||'';const code=form.get('code')||'';if(!/^[a-f0-9-]{36}$/.test(challenge)||!/^\d{6}$/.test(code))throw new ReviewError('Enter the six-digit verification code.');
    const stamp=now(),result=await env.DB.prepare('UPDATE remediation_review_challenges SET attempts=attempts+1,used_at=CASE WHEN code_hash=? THEN ? ELSE NULL END WHERE id=? AND assignment_id=? AND used_at IS NULL AND expires_at>? AND attempts<5 RETURNING used_at').bind(await hash(challenge+':'+code),stamp,challenge,id,stamp).first();
    if(!result?.used_at)throw new ReviewError('The code is invalid, expired or has reached its attempt limit.');
    const token=reviewToken();await env.DB.prepare('INSERT INTO remediation_review_sessions(token_hash,assignment_id,created_at,expires_at) VALUES(?,?,?,?)').bind(await hash(token),id,stamp,Math.min(stamp+1800,row.expires_at)).run();
    return reviewPage({},303,{'Location':url.pathname,'Set-Cookie':cookie(token)});
   }
   if(!session||form.get('proof')!==session.proof)throw new ReviewError('Your session could not be verified. Reload and verify your email again.',403);
   if(action==='logout'){await env.DB.prepare('DELETE FROM remediation_review_sessions WHERE token_hash=?').bind(session.tokenHash).run();return reviewPage({},303,{'Location':url.pathname,'Set-Cookie':cookie('',0)});}
   if(action!=='update')throw new ReviewError('Invalid action.');
   await saveReviewerProgress(env,row,session,Object.fromEntries(form));return reviewPage({},303,{'Location':url.pathname+'?saved=1'});
  }
  if(req.method==='HEAD'){const page=reviewPage();return new Response(null,{status:200,headers:page.headers});}
  if(!session)return reviewPage();
  const before=url.searchParams.get('before');if(before!==null&&(!/^\d{1,16}$/.test(before)||!Number.isSafeInteger(Number(before))||Number(before)<1))throw new ReviewError('Invalid activity cursor.');
  const activities=await env.DB.prepare('SELECT id,previous_status,new_status,reason,comment,created_at FROM remediation_review_activity WHERE assignment_id=? AND id<? ORDER BY id DESC LIMIT 21').bind(id,before?Number(before):Number.MAX_SAFE_INTEGER).all(),activity=(activities.results||[]).slice(0,20);
  row.scope_label=scopeLabel(await recordScope(env,row.user_id,row.cve_id));
  return reviewPage({row,verified:true,proof:session.proof,activity,next:(activities.results||[]).length>20?activity.at(-1).id:null,message:url.searchParams.get('saved')==='1'?'Your progress update has been saved. The requester can see it in the tracker.':''});
 }catch(error){if(error instanceof ReviewError)return reviewPage({row,verified:!!session,proof:session?.proof||'',challenge,message:error.message},error.status);return reviewPage({unavailable:true,message:'Assignment updates are temporarily unavailable. Please try again later.'},503);}
}
export async function reviewActivity(env,user,cve,url){
 if(!await progressReady(env))return {available:false,activity:[],assignments:[],notifications:[],next:null};
 const before=url.searchParams.get('before');if(before!==null&&(!/^\d{1,16}$/.test(before)||!Number.isSafeInteger(Number(before))||Number(before)<1))throw new ReviewError('Invalid activity cursor.');
 const rows=await env.DB.prepare('SELECT id,assignment_id,author_email,previous_status,new_status,reason,comment,created_at FROM remediation_review_activity WHERE user_id=? AND cve_id=? AND id<? ORDER BY id DESC LIMIT 51').bind(user.id,cve,before?Number(before):Number.MAX_SAFE_INTEGER).all();
 const assignments=await env.DB.prepare("SELECT a.id,a.recipient_email,a.revoked_at,a.delivery_status,p.expires_at,p.last_progress_at,p.interval_seconds FROM remediation_review_access p JOIN remediation_assignment_requests a ON a.id=p.assignment_id WHERE a.user_id=? AND a.cve_id=? ORDER BY a.seq DESC LIMIT 50").bind(user.id,cve).all();
 const notifications=await env.DB.prepare("SELECT n.id,n.kind,CASE WHEN n.kind='reminder' AND n.recipient_email!=a.recipient_email THEN 'manager' ELSE 'reviewer' END AS audience,n.recipient_email,n.state,n.created_at,n.completed_at,n.attempts FROM remediation_review_notifications n JOIN remediation_assignment_requests a ON a.id=n.assignment_id WHERE a.user_id=? AND a.cve_id=? ORDER BY n.id DESC LIMIT 50").bind(user.id,cve).all();
 const activity=(rows.results||[]).slice(0,50);return {available:true,activity,next:(rows.results||[]).length>50?activity.at(-1).id:null,assignments:assignments.results||[],notifications:notifications.results||[]};
}
