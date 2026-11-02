import {publicCve} from './remediation-identity.js';
import {sendEmail} from './delivery.js';import {escapeHtml as e} from './assignment-template.js';
import {reviewNow as now,reviewHash as hash,reviewQuota,progressReady,reviewLink,ReviewError} from './assignment-progress-common.js';
const utc=n=>new Date(n*1000).toISOString().replace('T',' ').replace('.000Z',' UTC');
const statusLabel=s=>s==='Investigating'?'In progress':s==='Remediated'?'Completed / Remediated':s;
export function renderManagerReminder(row){
 row={...row,cve_id:publicCve(row.cve_id),record_id:row.record_id||row.cve_id};
 let advisory={};try{advisory=JSON.parse(row.public_advisory_json||'{}')}catch{}
 const severity=String(row.assigned_severity||advisory.severity||'Unknown').toUpperCase();
 const urgent=['CRITICAL','HIGH'].includes(severity),hours=row.interval_seconds/3600;
 const tracker='https://cveharbor.com/remediation/'+(row.record_id.includes('~')?'?record='+encodeURIComponent(row.record_id):'');
 const subject='Manager Attention Required: Vulnerability Status Update Overdue for '+row.cve_id;
 const greeting='Hi '+row.recipient_email+',';
 const summary='The vulnerability '+row.cve_id+' is currently assigned to '+row.assigned_recipient+', and no progress update or status change has been recorded within the expected '+hours+'-hour period.';
 const followup='Given the severity of this vulnerability and its potential security impact, please check with '+row.assigned_recipient+' on the current progress and ask them to update the remediation tracker as soon as possible.';
 const priority=urgent?'Critical and High vulnerabilities require urgent attention and should be prioritized over routine operational work, in line with your organization’s incident and change-management procedures.':'Please prioritize this review according to the vulnerability’s severity and your organization’s remediation requirements.';
 const support='If blockers, competing priorities or resource constraints are delaying remediation, please review them and determine whether additional support or reassignment is needed to address the vulnerability promptly.';
 const regular='Please ensure '+row.assigned_recipient+' provides regular progress updates until the vulnerability is fully remediated or an approved mitigation is documented.';
 const access='Sign in to CVEHarbor to view records available to your account. Being listed as an FYI recipient does not grant access to private records. If this record is unavailable, contact '+row.requester_email+'.';
 const note='This notice reflects activity recorded in CVEHarbor. Work may be happening outside the tracker; please confirm with the reviewer before drawing conclusions. Acknowledging receipt does not count as a progress update.';
 const policy='You are receiving this email as an FYI recipient for this assignment. One notice is sent per inactivity period. Recorded progress resets the interval; completed and not-applicable records stop reminders.';
 const facts=[['Assigned reviewer',row.assigned_recipient],['Current status',statusLabel(row.status)],['Last update / assignment sent',utc(row.last_progress_at)],['Update expected by',utc(row.last_progress_at+row.interval_seconds)],['Receipt acknowledgement',row.acknowledged_at?'Recorded':'Not yet recorded'],['Requester',row.requester_email]];
 const section=(content,padding='0 30px 22px',background='#ffffff')=>'<tr><td class="email-pad" bgcolor="'+background+'" style="padding:'+padding+';background-color:'+background+';font-family:Arial,Helvetica,sans-serif;color:#17364c">'+content+'</td></tr>';
 const paragraph=text=>'<p style="margin:0 0 16px;font-size:14px;line-height:23px">'+e(text)+'</p>';
 const badgeColor=severity==='CRITICAL'?'#a62a3d':severity==='HIGH'?'#a64914':'#856116';
 const details='<table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#f1f6fa" style="border:1px solid #dce7ef"><tr><td colspan="2" style="padding:18px 16px;border-bottom:1px solid #dce7ef"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td style="font-size:19px;font-weight:bold;color:#102f44">'+e(row.cve_id)+'</td><td align="right"><span style="display:inline-block;padding:5px 9px;background:'+badgeColor+';color:white;font-size:10px;font-weight:bold;border-radius:4px">'+e(severity)+'</span></td></tr></table></td></tr>'+facts.map(([key,value])=>'<tr><td width="38%" style="padding:10px 16px;border-bottom:1px solid #dce7ef;font-size:11px;line-height:17px;font-weight:bold;vertical-align:top">'+e(key)+'</td><td style="padding:10px 16px;border-bottom:1px solid #dce7ef;font-size:12px;line-height:18px;word-break:break-word">'+e(value)+'</td></tr>').join('')+'</table>';
 const button='<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" bgcolor="#078c80" style="padding:16px 12px;background:#078c80;border-radius:6px"><a href="'+tracker+'" target="_blank" rel="noopener noreferrer" style="display:block;color:#ffffff;font-size:15px;font-weight:bold;line-height:20px;text-decoration:none">Open Remediation Tracker &nbsp;→</a></td></tr></table>';
 const html='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>'+e(subject)+'</title><style>@media only screen and (max-width:480px){.email-pad{padding-left:20px!important;padding-right:20px!important}.email-heading{font-size:25px!important;line-height:31px!important}.header-note{display:none!important}}</style></head><body style="margin:0;padding:0;background:#edf3f7;color:#17364c;font-family:Arial,Helvetica,sans-serif"><div style="display:none;font-size:1px;line-height:1px;max-height:0;max-width:0;overflow:hidden;opacity:0">'+e(row.cve_id)+' needs a progress update. Please review blockers, support and next steps.</div><table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#edf3f7"><tr><td align="center" style="padding:26px 12px"><!--[if mso]><table role="presentation" width="620" cellpadding="0" cellspacing="0"><tr><td><![endif]--><table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#ffffff" style="max-width:620px;width:100%;border-collapse:collapse">'+
 section('<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td><div style="font-size:28px;font-weight:bold;color:white">CVE<span style="color:#37d2c4">Harbor</span></div><div style="margin-top:5px;font-size:9px;letter-spacing:1.3px;color:#bed4df">VULNERABILITY INTELLIGENCE</div></td><td align="right" class="header-note" style="font-size:11px;line-height:18px;color:#c9dce7">REMEDIATION OVERSIGHT<br><span style="color:#f4cd7c">Manager attention required</span></td></tr></table>','24px 30px','#071f31')+
 '<tr><td height="4" bgcolor="#22cabb" style="font-size:1px;line-height:4px">&nbsp;</td></tr>'+
 section('<p style="margin:0 0 10px;font-size:10px;font-weight:bold;letter-spacing:1.4px;color:#996717">ACTION REQUESTED · UPDATE OVERDUE</p><h1 class="email-heading" style="margin:0;font-size:30px;line-height:37px;color:#102f44">Vulnerability status<br>update overdue.</h1>','28px 30px 24px')+
 section(paragraph(greeting)+paragraph(summary),'0 30px 8px')+
 section(details)+
 section(paragraph(followup)+'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#fff7e7"><tr><td style="padding:15px 16px;border-left:3px solid #d6a246;font-size:13px;line-height:21px;color:#674b1e">'+e(priority)+'</td></tr></table>')+
 section('<h2 style="margin:0 0 12px;font-size:18px;line-height:24px;color:#102f44">Remove blockers. Keep progress visible.</h2>'+paragraph(support)+paragraph(regular),'0 30px 8px')+
 section(button+'<p style="margin:12px 0 0;font-size:11px;line-height:18px;color:#526d7f">'+e(access)+'</p>')+
 section('<p style="margin:0;font-size:12px;line-height:20px;color:#526d7f">'+e(note)+'</p>','18px 30px','#f1f6fa')+
 section('<div style="font-size:19px;font-weight:bold;color:white">CVE<span style="color:#37d2c4">Harbor</span></div><p style="margin:8px 0 12px;font-size:11px;line-height:18px;color:#bed4df">Independent vulnerability intelligence. Clear ownership. Visible progress.</p><p style="margin:0;font-size:10px;line-height:17px;color:#bed4df">'+e(policy)+'</p>','22px 30px','#071f31')+
 '</table><!--[if mso]></td></tr></table></body></html>';
 const text=['CVEHarbor | Manager Attention Required',subject,'',greeting,'',summary,'','CVE: '+row.cve_id,'Severity: '+severity,...facts.map(([key,value])=>key+': '+value),'',followup,'',priority,'',support,'',regular,'','Open Remediation Tracker: '+tracker,access,'',note,'',policy].join('\n');
 return {subject,html,text};
}
export function renderProgressNotice(row){
 row={...row,cve_id:publicCve(row.cve_id),record_id:row.record_id||row.cve_id};
 if(row.kind==='reminder'&&row.assigned_recipient&&row.recipient_email!==row.assigned_recipient)return renderManagerReminder(row);
 const reminder=row.kind==='reminder',heading=reminder?'Please update your CVE assignment':'Assignment progress updated';
 const summary=reminder?'No progress update has been recorded for '+row.cve_id+' since '+utc(row.last_progress_at)+'. This assignment has a '+row.interval_seconds/3600+'-hour update interval. Please share your progress, any blockers, or the remediation outcome.':row.actor_email+' posted an update for '+row.cve_id+' at '+utc(row.created_at)+'.';
 const status='Recorded status: '+statusLabel(reminder?row.status:row.status_snapshot)+'.';
 const note=reminder?'Acknowledging receipt or opening the page does not count as a progress update. One reminder is sent per inactivity period. A progress update starts a new interval; completion or a not-applicable status stops reminders.':'Detailed comments are available securely in the tracker and are not copied into this email. This notification does not prove remediation has been independently verified.';
 const link=reminder?reviewLink(row.assignment_id):'https://cveharbor.com/remediation/';
 const html='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;background:#eef3f7;color:#17364c;font-family:Arial,Helvetica,sans-serif;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:620px;background:white"><tr><td style="padding:24px;background:#071f31;border-bottom:3px solid #22cabb;color:white;font-size:26px;font-weight:bold">CVE<span style="color:#37d2c4">Harbor</span></td></tr><tr><td style="padding:24px"><h1 style="font-size:24px">'+heading+'</h1><p style="font-size:15px;line-height:24px">'+e(summary)+'</p><p style="background:#f2f7fa;padding:16px">'+e(row.cve_id)+'<br><strong>'+e(status)+'</strong></p>'+(reminder?'<p><a href="'+e(link)+'" style="display:inline-block;background:#078c80;color:white;padding:14px 20px;text-decoration:none;border-radius:6px;font-weight:bold">View / Update Assignment</a></p><p style="font-size:12px">Verify your assigned email to make changes. No account required.</p>':'')+'<p style="font-size:13px;line-height:21px">'+e(note)+'</p><p style="font-size:12px;color:#527084">Contact the requester to change assignment or notification preferences.</p></td></tr><tr><td style="padding:20px 24px;background:#071f31;color:#bed4df;font-size:12px">CVEHarbor · Independent vulnerability intelligence</td></tr></table></td></tr></table></body></html>';
 return {subject:'[CVEHarbor] '+(reminder?'Update requested: ':'Progress update: ')+row.cve_id,html,text:['CVEHarbor',heading,'',summary,status,'',...(reminder?['View / Update Assignment: '+link,'Verify your email to make changes. No account required.','']:[]),note,'Contact the requester to change assignment or notification preferences.'].join('\n')};
}
export async function enqueueReminders(env){
 // Atomically enqueue the reviewer and each FYI once for the same new inactivity event.
 // Existing events are never expanded retroactively, including previously sent/uncertain ones.
 await env.DB.prepare(`WITH due AS MATERIALIZED (
  SELECT a.id,a.recipient_email,r.status,p.progress_version,p.last_progress_at
  FROM remediation_review_access p JOIN remediation_assignment_requests a ON a.id=p.assignment_id
  JOIN remediations r ON r.user_id=a.user_id AND r.cve_id=a.cve_id
  WHERE p.interval_seconds IS NOT NULL AND p.last_progress_at+p.interval_seconds<=? AND p.expires_at>?
  AND a.delivery_status='sent' AND a.revoked_at IS NULL AND r.status IN ('Open','Investigating')
  AND NOT EXISTS(SELECT 1 FROM remediation_review_notifications n WHERE n.event_key='reminder:'||a.id||':'||p.progress_version)
  ORDER BY p.last_progress_at,a.id LIMIT 50
 ), recipients AS (
  SELECT id,recipient_email FROM due
  UNION SELECT d.id,f.recipient_email FROM due d JOIN remediation_assignment_fyi f ON f.assignment_id=d.id
 )
 INSERT OR IGNORE INTO remediation_review_notifications(event_key,assignment_id,kind,cycle_version,recipient_email,status_snapshot,created_at)
 SELECT 'reminder:'||d.id||':'||d.progress_version,d.id,'reminder',d.progress_version,x.recipient_email,d.status,?
 FROM due d JOIN recipients x ON x.id=d.id`).bind(now(),now(),now()).run();
}
const rowQuery="SELECT n.*,a.user_id,a.cve_id,a.recipient_email AS assigned_recipient,a.requester_email,a.acknowledged_at,a.public_advisory_json,m.assigned_severity,a.revoked_at,a.delivery_status,p.expires_at,p.interval_seconds,p.last_progress_at,p.progress_version,r.status FROM remediation_review_notifications n JOIN remediation_review_access p ON p.assignment_id=n.assignment_id JOIN remediation_assignment_requests a ON a.id=p.assignment_id JOIN remediations r ON r.user_id=a.user_id AND r.cve_id=a.cve_id LEFT JOIN remediation_assignment_metadata m ON m.assignment_id=a.id WHERE n.id=?";

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
