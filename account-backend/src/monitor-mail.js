import {q,sha,json} from './monitor-engine.js';
import {DAY} from './monitor-sources.js';
const API='https://api.smtp2go.com/v3/email/send',SITE='https://cveharbor.com';
export const monitorDeliveryReady=env=>env.PRODUCT_MONITOR_DELIVERY_ENABLED==='true'&&Boolean((env.ALERT_SMTP2GO_API_KEY||env.SMTP2GO_API_KEY)&&env.EMAIL_FROM&&env.SMTP2GO_MONITOR_WEBHOOK_TOKEN);
const escape=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function renderMonitorMail(rows,{test=false}={}){
 const text=[test?'CVEHarbor product monitoring test':'CVEHarbor product monitoring update','',...rows.map(row=>{
  const r=typeof row.record_json==='string'?JSON.parse(row.record_json):row.record;
  return [r.product+' · '+r.branch,'Installed version: '+(row.installed_version||'Not recorded'),
   row.kind==='security'?'Verified security release: '+r.version:row.kind==='maintenance'?'Verified branch release: '+r.version:row.kind==='test'?'Test only. No customer alert.':'Lifecycle event: '+row.kind,
   r.date?'Published support milestone: '+r.date:'Release publication date: '+(r.published||'Not published'),
   (r.reliability==='community_lifecycle'?'Community lifecycle source (verify vendor terms): ':'Official source: ')+r.source_url,
   'Action: verify edition, compatibility, vendor prerequisites and your installed version before upgrading.',
   row.unsubscribe_token?'Disable monitoring email: https://api.cveharbor.com/v1/monitoring/unsubscribe/'+row.unsubscribe_token:''].filter(Boolean).join('\n');}),
  '', 'Manage preferences: '+SITE+'/lifecycle/','A provider-accepted message is not proof of delivery or inbox placement.'].join('\n\n');
 return {subject:test?'CVEHarbor monitoring test':'CVEHarbor · '+(rows.some(r=>r.kind==='security')?'Security update available':'Product monitoring update'),text,
  html:'<!doctype html><html><body style="background:#071827;color:#deedf6;font-family:Arial,sans-serif;padding:28px"><h1 style="color:#36e8d4">CVEHarbor</h1><pre style="white-space:pre-wrap;font-family:inherit">'+escape(text)+'</pre></body></html>'};
}
export async function submitSmtp2go(env,recipient,report,fetcher=fetch,headers=[]){
 const key=env.ALERT_SMTP2GO_API_KEY||env.SMTP2GO_API_KEY;
 if(!key||!env.EMAIL_FROM)throw Object.assign(Error('SMTP2GO configuration unavailable'),{permanent:true});
 let response;
 try{response=await fetcher(API,{method:'POST',headers:{'Content-Type':'application/json','X-Smtp2go-Api-Key':key},signal:AbortSignal.timeout(20000),body:JSON.stringify({sender:env.EMAIL_FROM,to:[recipient],subject:report.subject,text_body:report.text,html_body:report.html,custom_headers:headers})});}
 catch{throw Object.assign(Error('Provider acceptance unknown; reconciliation required'),{unknown:true});}
 let payload;try{payload=await response.json();}catch{throw Object.assign(Error('Provider response ambiguous; reconciliation required'),{unknown:true});}
 const data=payload?.data;
 if(response.ok&&data?.succeeded===1&&data.failed===0&&(!data.failures||Array.isArray(data.failures)&&data.failures.length===0)&&typeof data.email_id==='string'&&/^[a-zA-Z0-9_-]{1,100}$/.test(data.email_id))
  return {provider_id:data.email_id,request_id:typeof payload.request_id==='string'?payload.request_id.slice(0,100):''};
 // SMTP2GO has no documented send idempotency key. An ambiguous 2xx/5xx
 // cannot be automatically retried without risking a duplicate submission.
 if(response.status===429)throw Object.assign(Error('SMTP2GO rate limit; retry scheduled'),{retry:true});
 if(response.ok||response.status>=500)throw Object.assign(Error('Provider acceptance unknown; reconciliation required'),{unknown:true});
 throw Object.assign(Error('SMTP2GO rejected the submission'),{permanent:true});
}
async function authorized(env,message){
 const user=await q(env.DB,`SELECT u.email FROM users u JOIN lifecycle_preferences p ON p.user_id=u.id
  LEFT JOIN lifecycle_monitor_accounts a ON a.user_id=u.id WHERE u.id=? AND p.email_enabled=1 AND COALESCE(a.disabled,0)=0`,message.user_id).first();
 if(!user||user.email.toLowerCase()!==message.recipient.toLowerCase())return false;
 return !await q(env.DB,'SELECT 1 FROM lifecycle_monitor_suppressions WHERE recipient_hash=?',await sha(message.recipient.toLowerCase())).first();
}
export async function dispatchMonitorMail(env,fetcher=fetch,now=Date.now()){
 if(!monitorDeliveryReady(env))return {submitted:0,disabled:true};
 // A crashed submitting job is never blindly resent after its lease expires.
 await q(env.DB,"UPDATE lifecycle_monitor_messages SET state='submission_unknown',detail='Interrupted submission; reconcile with SMTP2GO before retrying',lease_until=0 WHERE state='submitting' AND lease_until<?",now).run();
 const due=(await q(env.DB,`SELECT n.user_id,n.recipient,MIN(n.due_at) AS due_at,
  CASE WHEN s.delivery_mode='immediate_security' AND e.kind='security' THEN n.id ELSE '' END AS immediate_id
  FROM lifecycle_monitor_notifications n JOIN lifecycle_monitor_events e ON e.id=n.event_id
  LEFT JOIN lifecycle_watch_settings s ON s.user_id=n.user_id AND s.watch_id=n.watch_id
  WHERE n.state='pending' AND n.due_at<=? AND (COALESCE(s.delivery_mode,'daily')='immediate_security' AND e.kind='security' OR NOT EXISTS(
   SELECT 1 FROM lifecycle_monitor_messages m WHERE m.user_id=n.user_id AND m.recipient=n.recipient AND m.slot=? AND m.state<>'pending'))
  GROUP BY n.user_id,n.recipient,immediate_id ORDER BY CASE WHEN immediate_id<>'' THEN 0 ELSE 1 END,due_at LIMIT 2`,now,'digest:'+new Date(now).toISOString().slice(0,10)).all()).results||[];
 for(const owner of due){
  const slot=owner.immediate_id?'security:'+owner.immediate_id:'digest:'+new Date(now).toISOString().slice(0,10),id=await sha(owner.user_id+':'+owner.recipient+':'+slot);
  await q(env.DB,'INSERT OR IGNORE INTO lifecycle_monitor_messages(id,user_id,recipient,slot,created_at) VALUES(?,?,?,?,?)',id,owner.user_id,owner.recipient,slot,now).run();
  await q(env.DB,`UPDATE lifecycle_monitor_notifications SET message_id=?,state='queued' WHERE id IN(
   SELECT n.id FROM lifecycle_monitor_notifications n JOIN lifecycle_monitor_events e ON e.id=n.event_id
   LEFT JOIN lifecycle_watch_settings s ON s.user_id=n.user_id AND s.watch_id=n.watch_id
   WHERE n.user_id=? AND n.recipient=? AND n.state='pending' AND n.due_at<=?
   AND ((?<>'' AND n.id=?) OR (?='' AND NOT(COALESCE(s.delivery_mode,'daily')='immediate_security' AND e.kind='security')))
   ORDER BY n.due_at,n.id LIMIT 20)
   AND EXISTS(SELECT 1 FROM lifecycle_monitor_messages WHERE id=? AND state='pending')`,id,owner.user_id,owner.recipient,now,owner.immediate_id,owner.immediate_id,owner.immediate_id,id).run();
 }
 const messages=(await q(env.DB,"SELECT * FROM lifecycle_monitor_messages WHERE state='pending' AND next_attempt_at<=? AND lease_until<? AND attempts<5 ORDER BY CASE WHEN slot LIKE 'security:%' THEN 0 ELSE 1 END,created_at LIMIT 2",now,now).all()).results||[];
 let submitted=0;
 for(const message of messages){
  const token=crypto.randomUUID();
  let accepted=false;
  if((await q(env.DB,"UPDATE lifecycle_monitor_messages SET state='submitting',attempts=attempts+1,attempt_token=?,lease_until=? WHERE id=? AND state='pending' AND lease_until<?",token,now+120000,message.id,now).run()).meta.changes!==1)continue;
  try{
   const rows=(await q(env.DB,`SELECT n.*,e.kind,e.record_json,s.status AS watch_status,s.consented_at,p.email_enabled,a.disabled
    FROM lifecycle_monitor_notifications n JOIN lifecycle_monitor_events e ON e.id=n.event_id
    LEFT JOIN lifecycle_watch_settings s ON s.user_id=n.user_id AND s.watch_id=n.watch_id
    LEFT JOIN lifecycle_preferences p ON p.user_id=n.user_id LEFT JOIN lifecycle_monitor_accounts a ON a.user_id=n.user_id
    WHERE n.message_id=? AND n.state='queued'`,message.id).all()).results||[];
   const allowed=rows.filter(r=>r.watch_status==='enabled'&&r.consented_at&&r.email_enabled===1&&!r.disabled);
   if(!await authorized(env,message)||!allowed.length){
    await env.DB.batch([q(env.DB,"UPDATE lifecycle_monitor_messages SET state='suppressed',detail='Consent, ownership or monitoring eligibility changed',lease_until=0 WHERE id=? AND attempt_token=?",message.id,token),q(env.DB,"UPDATE lifecycle_monitor_notifications SET state='suppressed' WHERE message_id=? AND state='queued'",message.id)]);continue;
   }
   // Notifications removed from the digest remain suppressed in history.
   const excluded=rows.filter(r=>!allowed.some(a=>a.id===r.id));
   if(excluded.length)await q(env.DB,"UPDATE lifecycle_monitor_notifications SET state='suppressed' WHERE id IN(SELECT value FROM json_each(?))",JSON.stringify(excluded.map(r=>r.id))).run();
   const report=renderMonitorMail(allowed),unsubscribe='https://api.cveharbor.com/v1/monitoring/unsubscribe/'+allowed[0].unsubscribe_token;
   const result=await submitSmtp2go(env,message.recipient,report,fetcher,[{header:'X-CVEHarbor-Notification',value:message.id},{header:'List-Unsubscribe',value:'<'+unsubscribe+'>'},{header:'List-Unsubscribe-Post',value:'List-Unsubscribe=One-Click'}]);
   accepted=true;
   await q(env.DB,`UPDATE lifecycle_monitor_messages SET state='submitted',provider_id=?,request_id=?,submitted_at=?,lease_until=0,detail='Accepted by SMTP2GO; delivery not yet confirmed' WHERE id=? AND attempt_token=? AND state IN('submitting','submission_unknown')`,result.provider_id,result.request_id,now,message.id,token).run();submitted++;
  }catch(error){
   const unknown=accepted||error.unknown,exhausted=message.attempts+1>=5,state=unknown?'submission_unknown':error.retry&&!exhausted?'pending':'failed';
   await q(env.DB,'UPDATE lifecycle_monitor_messages SET state=?,next_attempt_at=?,lease_until=0,detail=? WHERE id=? AND attempt_token=?',state,now+Math.min(DAY,60000*2**message.attempts),unknown?'Provider acceptance unknown or recording failed; reconciliation required':error.retry?'SMTP2GO rate limit':'SMTP2GO submission rejected or unavailable',message.id,token).run();
  }
 }
 return {submitted};
}
async function secureEqual(a,b){const x=await sha(a),y=await sha(b);let mismatch=0;for(let i=0;i<x.length;i++)mismatch|=x.charCodeAt(i)^y.charCodeAt(i);return mismatch===0;}
export async function smtp2goWebhook(req,env,now=Date.now()){
 if(!env.SMTP2GO_MONITOR_WEBHOOK_TOKEN||!await secureEqual(req.headers.get('Authorization')||'','Bearer '+env.SMTP2GO_MONITOR_WEBHOOK_TOKEN))return json({error:'Unauthorized'},401);
 if(req.method!=='POST')return json({error:'Method not allowed'},405);
 const text=await req.text();if(text.length>64000)return json({error:'Event too large'},413);
 let value;try{value=req.headers.get('Content-Type')?.includes('application/json')?JSON.parse(text):Object.fromEntries(new URLSearchParams(text));}catch{return json({error:'Invalid event'},400);}
 const events=Array.isArray(value)?value:[value];if(events.length>50)return json({error:'Too many events'},400);
 for(const e of events){
  const time=typeof e.time==='number'||/^\d{10}(?:\.\d+)?$/.test(String(e.time))?Number(e.time)*1000:Date.parse(String(e.time||''));
  if(typeof e.id!=='string'||e.id.length>150||typeof e.email_id!=='string'||typeof e.rcpt!=='string'||!Number.isFinite(time)||time<now-7*DAY||time>now+300000||!['processed','delivered','bounce','reject','spam','unsubscribe'].includes(e.event))return json({error:'Invalid or expired event'},400);
  const message=await q(env.DB,'SELECT * FROM lifecycle_monitor_messages WHERE provider_id=?',e.email_id).first();
  if(!message)return json({error:'Submission correlation pending; retry event'},503);
  if(message.recipient.toLowerCase()!==e.rcpt.toLowerCase()||time<message.created_at-300000)return json({error:'Recipient or timestamp mismatch'},400);
  if(await q(env.DB,'SELECT 1 FROM lifecycle_monitor_delivery_events WHERE id=?',e.id).first())continue;
  const hard=e.event==='spam'||e.event==='unsubscribe'||e.event==='reject'||e.event==='bounce'&&e.bounce==='hard';
  const state=hard?'suppressed':e.event==='delivered'?'delivered':e.event==='bounce'?'failed':message.state;
  const statements=[q(env.DB,'INSERT OR IGNORE INTO lifecycle_monitor_delivery_events(id,message_id,event,happened_at,received_at,detail) VALUES(?,?,?,?,?,?)',e.id,message.id,e.event,time,now,e.event==='bounce'?(e.bounce==='hard'?'hard bounce':'soft bounce'):e.event),
   q(env.DB,`UPDATE lifecycle_monitor_messages SET state=CASE WHEN state='suppressed' THEN state WHEN state='delivered' AND ?<>'suppressed' THEN state ELSE ? END,
    delivered_at=CASE WHEN ?='delivered' THEN COALESCE(delivered_at,?) ELSE delivered_at END,detail=?,last_event_at=MAX(last_event_at,?)
    WHERE id=? AND (last_event_at<=? OR ?='suppressed')`,state,state,e.event,time,'SMTP2GO event: '+e.event,time,message.id,time,state)];
  if(hard)statements.push(q(env.DB,'INSERT OR IGNORE INTO lifecycle_monitor_suppressions(recipient_hash,reason,created_at) VALUES(?,?,?)',await sha(e.rcpt.toLowerCase()),e.event,now));
  await env.DB.batch(statements);
 }
 return json({accepted:true});
}
export async function unsubscribeMonitor(req,env,token){
 if(!/^[a-f0-9-]{72}$/.test(token))return json({error:'Invalid link'},404);
 const n=await q(env.DB,'SELECT user_id FROM lifecycle_monitor_notifications WHERE unsubscribe_token=?',token).first();if(!n)return json({error:'Link not found'},404);
 if(req.method==='GET')return new Response('<!doctype html><html><body><h1>CVEHarbor product monitoring</h1><p>Disable product monitoring emails for this account?</p><form method="post"><button>Unsubscribe</button></form></body></html>',{headers:{'Content-Type':'text/html;charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'none'; form-action 'self'; base-uri 'none'"}});
 if(req.method!=='POST')return json({error:'Method not allowed'},405);
 await env.DB.batch([q(env.DB,'UPDATE lifecycle_preferences SET email_enabled=0,updated_at=? WHERE user_id=?',Math.floor(Date.now()/1000),n.user_id),q(env.DB,"UPDATE lifecycle_monitor_notifications SET state='suppressed' WHERE user_id=? AND state IN('pending','queued')",n.user_id)]);
 return json({unsubscribed:true});
}
