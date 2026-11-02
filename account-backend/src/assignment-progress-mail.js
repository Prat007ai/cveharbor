import {sendEmail} from './delivery.js';import {escapeHtml as e} from './assignment-template.js';
import {reviewNow as now,reviewHash as hash,reviewQuota,progressReady,reviewLink,ReviewError} from './assignment-progress-common.js';
const utc=n=>new Date(n*1000).toISOString().replace('T',' ').replace('.000Z',' UTC');
const statusLabel=s=>s==='Investigating'?'In progress':s==='Remediated'?'Completed / Remediated':s;
export function renderProgressNotice(row){
 const reminder=row.kind==='reminder',heading=reminder?'Please update your CVE assignment':'Assignment progress updated';
 const summary=reminder?'No progress update has been recorded for '+row.cve_id+' since '+utc(row.last_progress_at)+'. This assignment has a '+row.interval_seconds/3600+'-hour update interval. Please share your progress, any blockers, or the remediation outcome.':row.actor_email+' posted an update for '+row.cve_id+' at '+utc(row.created_at)+'.';
 const status='Recorded status: '+statusLabel(reminder?row.status:row.status_snapshot)+'.';
 const note=reminder?'Acknowledging receipt or opening the page does not count as a progress update. One reminder is sent per inactivity period. A progress update starts a new interval; completion or a not-applicable status stops reminders.':'Detailed comments are available securely in the tracker and are not copied into this email. This notification does not prove remediation has been independently verified.';
 const link=reminder?reviewLink(row.assignment_id):'https://cveharbor.com/remediation/';
 const html='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;background:#eef3f7;color:#17364c;font-family:Arial,Helvetica,sans-serif;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:620px;background:white"><tr><td style="padding:24px;background:#071f31;border-bottom:3px solid #22cabb;color:white;font-size:26px;font-weight:bold">CVE<span style="color:#37d2c4">Harbor</span></td></tr><tr><td style="padding:24px"><h1 style="font-size:24px">'+heading+'</h1><p style="font-size:15px;line-height:24px">'+e(summary)+'</p><p style="background:#f2f7fa;padding:16px">'+e(row.cve_id)+'<br><strong>'+e(status)+'</strong></p>'+(reminder?'<p><a href="'+e(link)+'" style="display:inline-block;background:#078c80;color:white;padding:14px 20px;text-decoration:none;border-radius:6px;font-weight:bold">View / Update Assignment</a></p><p style="font-size:12px">Verify your assigned email to make changes. No account required.</p>':'')+'<p style="font-size:13px;line-height:21px">'+e(note)+'</p><p style="font-size:12px;color:#527084">Contact the requester to change assignment or notification preferences.</p></td></tr><tr><td style="padding:20px 24px;background:#071f31;color:#bed4df;font-size:12px">CVEHarbor · Independent vulnerability intelligence</td></tr></table></td></tr></table></body></html>';
 return {subject:'[CVEHarbor] '+(reminder?'Update requested: ':'Progress update: ')+row.cve_id,html,text:['CVEHarbor',heading,'',summary,status,'',...(reminder?['View / Update Assignment: '+link,'Verify your email to make changes. No account required.','']:[]),note,'Contact the requester to change assignment or notification preferences.'].join('\n')};
}
export async function enqueueReminders(env){
 // One unique event per assignment/progress version. Acknowledgement never changes that version.
 await env.DB.prepare("INSERT OR IGNORE INTO remediation_review_notifications(event_key,assignment_id,kind,cycle_version,recipient_email,status_snapshot,created_at) SELECT 'reminder:'||a.id||':'||p.progress_version,a.id,'reminder',p.progress_version,a.recipient_email,r.status,? FROM remediation_review_access p JOIN remediation_assignment_requests a ON a.id=p.assignment_id JOIN remediations r ON r.user_id=a.user_id AND r.cve_id=a.cve_id WHERE p.interval_seconds IS NOT NULL AND p.last_progress_at+p.interval_seconds<=? AND p.expires_at>? AND a.delivery_status='sent' AND a.revoked_at IS NULL AND r.status IN ('Open','Investigating') AND NOT EXISTS(SELECT 1 FROM remediation_review_notifications n WHERE n.event_key='reminder:'||a.id||':'||p.progress_version) ORDER BY p.last_progress_at LIMIT 50").bind(now(),now(),now()).run();
}
const rowQuery="SELECT n.*,a.user_id,a.cve_id,a.revoked_at,a.delivery_status,p.expires_at,p.interval_seconds,p.last_progress_at,p.progress_version,r.status FROM remediation_review_notifications n JOIN remediation_review_access p ON p.assignment_id=n.assignment_id JOIN remediation_assignment_requests a ON a.id=p.assignment_id JOIN remediations r ON r.user_id=a.user_id AND r.cve_id=a.cve_id WHERE n.id=?";
const eligible=row=>row&&row.revoked_at===null&&row.delivery_status==='sent'&&row.expires_at>now()&&(row.kind==='progress'||(['Open','Investigating'].includes(row.status)&&row.cycle_version===row.progress_version&&row.interval_seconds&&row.last_progress_at+row.interval_seconds<=now()));
export async function dispatchProgress(env){
 if(env.ASSIGNMENT_EMAIL_ENABLED!=='true'||!env.EMAIL_FROM||!(env.ASSIGNMENT_SMTP2GO_API_KEY||env.SMTP2GO_API_KEY)||!await progressReady(env))return;
 await env.DB.prepare('DELETE FROM remediation_review_sessions WHERE expires_at<=?').bind(now()).run();
 await env.DB.prepare('DELETE FROM remediation_review_challenges WHERE expires_at<=?').bind(now()).run();
 await env.DB.prepare("UPDATE remediation_review_notifications SET state='unconfirmed',completed_at=? WHERE state='sending' AND claimed_at<?").bind(now(),now()-900).run();
 await enqueueReminders(env);
 const rows=await env.DB.prepare("SELECT id FROM remediation_review_notifications WHERE state='queued' AND not_before<=? ORDER BY id LIMIT 10").bind(now()).all();
 for(const {id} of rows.results||[]){
  const lease=crypto.randomUUID(),claim=await env.DB.prepare("UPDATE remediation_review_notifications SET state='sending',claimed_at=?,claim_token=? WHERE id=? AND state='queued'").bind(now(),lease,id).run();if(claim.meta?.changes!==1)continue;
  let row=await env.DB.prepare(rowQuery).bind(id).first();
  const cancel=()=>env.DB.prepare("UPDATE remediation_review_notifications SET state='cancelled',completed_at=? WHERE id=? AND state='sending' AND claim_token=?").bind(now(),id,lease).run();
  if(!eligible(row)){await cancel();continue;}
  // Share sender/recipient budgets with existing assignment FYI delivery.
  if(!await reviewQuota(env,'assignment-fyi-sender:'+row.user_id,3600,50)||!await reviewQuota(env,'assignment-target:'+await hash(row.recipient_email),86400,20)){
   await env.DB.prepare("UPDATE remediation_review_notifications SET state='queued',not_before=?,claimed_at=NULL WHERE id=? AND state='sending' AND claim_token=?").bind(now()+3600,id,lease).run();continue;
  }
  row=await env.DB.prepare(rowQuery).bind(id).first();if(!eligible(row)){await cancel();continue;}
  const attempt=await env.DB.prepare("UPDATE remediation_review_notifications SET attempts=attempts+1 WHERE id=? AND state='sending' AND claim_token=? AND attempts<3").bind(id,lease).run();if(attempt.meta?.changes!==1)continue;
  try{
   const provider=await sendEmail({EMAIL_FROM:env.EMAIL_FROM,SMTP2GO_API_KEY:env.SMTP2GO_API_KEY,ALERT_SMTP2GO_API_KEY:env.ASSIGNMENT_SMTP2GO_API_KEY||env.SMTP2GO_API_KEY},row.recipient_email,renderProgressNotice(row));
   await env.DB.prepare("UPDATE remediation_review_notifications SET state='sent',completed_at=?,provider_id=? WHERE id=? AND state='sending' AND claim_token=?").bind(now(),provider,id,lease).run();
  }catch{await env.DB.prepare("UPDATE remediation_review_notifications SET state='unconfirmed',completed_at=? WHERE id=? AND state='sending' AND claim_token=?").bind(now(),id,lease).run();}
 }
}
export function scheduleProgress(env,ctx){if(env.ASSIGNMENT_PROGRESS_ENABLED==='true'&&ctx?.waitUntil)ctx.waitUntil(dispatchProgress(env).catch(()=>console.warn('Assignment progress notifications deferred; no recipient details logged')));}
export async function retryProgress(env,user,cve,id){
 if(!await progressReady(env))throw new ReviewError('Progress notifications are unavailable.',503);
 const row=await env.DB.prepare(rowQuery+' AND a.user_id=? AND a.cve_id=?').bind(id,user.id,cve).first();if(!row)throw new ReviewError('Notification not found.',404);
 if(!eligible(row))throw new ReviewError('This notification is no longer applicable.');
 const r=await env.DB.prepare("UPDATE remediation_review_notifications SET state='queued',not_before=0,claimed_at=NULL WHERE id=? AND state='unconfirmed' AND attempts<3").bind(id).run();return {queued:r.meta?.changes||0};
}
