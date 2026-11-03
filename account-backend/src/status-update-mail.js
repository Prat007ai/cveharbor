import {sendEmail} from './delivery.js';
import {escapeHtml as e} from './assignment-template.js';
import {publicCve,recordScope,scopeLabel,findingStatus} from './remediation-identity.js';
import {reviewNow as now,reviewHash as hash,reviewQuota,reviewLink} from './assignment-progress-common.js';
export async function statusMailReady(env){try{await env.DB.prepare('SELECT id FROM remediation_status_notifications LIMIT 1').first();return true;}catch{return false;}}
export function renderStatusUpdate(row){
 const cve=publicCve(row.cve_id),before=findingStatus(row.previous_status),after=findingStatus(row.new_status);
 const subject='[CVEHarbor] '+cve+' status changed: '+after;
 const link=row.reviewer_id?reviewLink(row.reviewer_id):'https://cveharbor.com/remediation/?record='+encodeURIComponent(row.cve_id);
 const access=row.reviewer_id?'Verify your assigned email to view or update this assignment.':'Sign in to view this record if it belongs to your account. This notification does not grant access to private customer records; contact the requester if access is needed.';
 const context=row.scope?scopeLabel(row.scope):'CVE remediation record';
 const when=new Date(row.changed_at).toISOString().replace('T',' ').replace(/\.\d{3}Z$/,' UTC');
 const facts=[['CVE',cve],['Customer / environment / asset',context],['Previous status',before],['New status',after],['Updated by',row.changed_by],['Updated at',when]];
 const reason=row.reason||'No reason recorded.';
 const html='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+e(subject)+'</title></head><body style="margin:0;background:#edf3f7;color:#17364c;font-family:Arial,Helvetica,sans-serif"><table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td align="center" style="padding:24px 12px"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:620px;background:white"><tr><td style="padding:24px;background:#071f31;border-bottom:4px solid #22cabb;color:white;font-size:28px;font-weight:bold">CVE<span style="color:#37d2c4">Harbor</span><div style="font-size:10px;letter-spacing:1px;margin-top:6px;color:#bed4df">VULNERABILITY INTELLIGENCE</div></td></tr><tr><td style="padding:26px"><p style="font-size:11px;letter-spacing:1px;color:#076e73;font-weight:bold">REMEDIATION STATUS UPDATE</p><h1 style="font-size:26px;line-height:34px;margin:12px 0">'+e(cve)+' has an update.</h1><p style="font-size:14px;line-height:23px">Hi '+e(row.recipient_email)+',</p><p style="font-size:15px;line-height:24px">'+e(row.changed_by)+' changed the vulnerability status from <strong>'+e(before)+'</strong> to <strong>'+e(after)+'</strong>.</p><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f1f6fa;border:1px solid #dce7ef">'+facts.map(([k,v])=>'<tr><td style="padding:10px 12px;font-size:12px;vertical-align:top;border-bottom:1px solid #dce7ef;width:34%"><strong>'+e(k)+'</strong></td><td style="padding:10px 12px;font-size:13px;line-height:20px;overflow-wrap:anywhere;word-break:break-word;border-bottom:1px solid #dce7ef">'+e(v)+'</td></tr>').join('')+'</table><h2 style="font-size:17px;margin:24px 0 10px">Reason for this change</h2><p style="font-size:14px;line-height:23px;white-space:pre-wrap;overflow-wrap:anywhere">'+e(reason)+'</p><p style="margin:24px 0 12px"><a href="'+e(link)+'" style="display:inline-block;background:#087b79;border-radius:5px;padding:14px 20px;color:white;font-size:14px;font-weight:bold;text-decoration:none">View remediation record →</a></p><p style="font-size:12px;line-height:20px;color:#526d7f">'+e(access)+'</p></td></tr><tr><td style="padding:20px 26px;background:#071f31;color:#bed4df;font-size:11px;line-height:19px">You received this update as an assigned reviewer, requester or FYI recipient. Each person receives one email per recorded status change. Receipt acknowledgement is tracked separately from remediation progress.</td></tr></table></td></tr></table></body></html>';
 return {subject,html,text:['CVEHarbor | Remediation status update','', 'Hi '+row.recipient_email+',','',...facts.map(([k,v])=>k+': '+v),'','Reason for this change:',reason,'','View remediation record: '+link,access,'','You received this update as an assigned reviewer, requester or FYI recipient. Receipt acknowledgement is separate from remediation progress.'].join('\n')};
}
const query=`SELECT n.*,s.user_id,s.cve_id,s.previous_status,s.new_status,s.reason,s.changed_by,s.changed_at FROM remediation_status_notifications n JOIN remediation_status_changes s ON s.id=n.change_id WHERE n.id=?`;
async function eligible(env,row){return row&&await env.DB.prepare('SELECT recipient_email FROM remediation_status_participants WHERE user_id=? AND cve_id=? AND recipient_email=?').bind(row.user_id,row.cve_id,row.recipient_email).first();}
export async function dispatchStatusMail(env){
 if(env.ASSIGNMENT_EMAIL_ENABLED!=='true'||env.REMEDIATION_WORKFLOW_ENABLED!=='true'||!env.EMAIL_FROM||!(env.ASSIGNMENT_SMTP2GO_API_KEY||env.SMTP2GO_API_KEY)||!await statusMailReady(env))return;
 await env.DB.prepare("UPDATE remediation_status_notifications SET state='unconfirmed',completed_at=? WHERE state='sending' AND claimed_at<?").bind(now(),now()-900).run();
 const rows=await env.DB.prepare("SELECT id FROM remediation_status_notifications WHERE state='queued' AND not_before<=? ORDER BY id LIMIT 20").bind(now()).all();
 for(const {id} of rows.results||[]){
  const lease=crypto.randomUUID(),claim=await env.DB.prepare("UPDATE remediation_status_notifications SET state='sending',claimed_at=?,claim_token=? WHERE id=? AND state='queued'").bind(now(),lease,id).run();if(claim.meta?.changes!==1)continue;
  const row=await env.DB.prepare(query).bind(id).first();
  const cancel=()=>env.DB.prepare("UPDATE remediation_status_notifications SET state='cancelled',completed_at=? WHERE id=? AND state='sending' AND claim_token=?").bind(now(),id,lease).run();
  if(!await eligible(env,row)){await cancel();continue;}
  if(!await reviewQuota(env,'assignment-fyi-sender:'+row.user_id,3600,50)||!await reviewQuota(env,'assignment-target:'+await hash(row.recipient_email),86400,20)){
   await env.DB.prepare("UPDATE remediation_status_notifications SET state='queued',not_before=?,claimed_at=NULL WHERE id=? AND state='sending' AND claim_token=?").bind(now()+3600,id,lease).run();continue;
  }
  const reviewer=await env.DB.prepare("SELECT a.id FROM remediation_assignment_requests a JOIN remediation_review_access p ON p.assignment_id=a.id WHERE a.user_id=? AND a.cve_id=? AND lower(a.recipient_email)=? AND a.delivery_status='sent' AND a.revoked_at IS NULL AND p.expires_at>? ORDER BY a.seq DESC LIMIT 1").bind(row.user_id,row.cve_id,row.recipient_email,now()).first();
  row.reviewer_id=reviewer?.id;row.scope=await recordScope(env,row.user_id,row.cve_id);
  if(!await eligible(env,row)){await cancel();continue;}
  try{
   const provider=await sendEmail({EMAIL_FROM:env.EMAIL_FROM,SMTP2GO_API_KEY:env.SMTP2GO_API_KEY,ALERT_SMTP2GO_API_KEY:env.ASSIGNMENT_SMTP2GO_API_KEY||env.SMTP2GO_API_KEY},row.recipient_email,renderStatusUpdate(row));
   await env.DB.prepare("UPDATE remediation_status_notifications SET state='sent',completed_at=?,provider_id=? WHERE id=? AND state='sending' AND claim_token=?").bind(now(),provider,id,lease).run();
  }catch{await env.DB.prepare("UPDATE remediation_status_notifications SET state='unconfirmed',completed_at=? WHERE id=? AND state='sending' AND claim_token=?").bind(now(),id,lease).run();}
 }
}
export function scheduleStatusMail(env,ctx){if(ctx?.waitUntil)ctx.waitUntil(dispatchStatusMail(env).catch(()=>console.warn('Status update email dispatch deferred')));}
export async function statusMailHistory(env,user,id){if(!await statusMailReady(env))return {available:false,notifications:[]};const rows=await env.DB.prepare('SELECT n.id,n.recipient_email,n.state,n.created_at,s.previous_status,s.new_status FROM remediation_status_notifications n JOIN remediation_status_changes s ON s.id=n.change_id WHERE s.user_id=? AND s.cve_id=? ORDER BY n.id DESC LIMIT 50').bind(user.id,id).all();return {available:true,notifications:rows.results||[]};}
