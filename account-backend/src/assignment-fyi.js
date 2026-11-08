import {publicCve,recordScope} from './remediation-identity.js';
import {workflowReady} from './remediation-workflow.js';
import {sendEmail} from './delivery.js';
import {escapeHtml,advisoryFields,trustedReference,customerEmailFields} from './assignment-template.js';
const now=()=>Math.floor(Date.now()/1000);
const hash=async value=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))),b=>b.toString(16).padStart(2,'0')).join('');
export class FyiError extends Error{constructor(message,status=400){super(message);this.status=status;}}
export function normalizeFyi(value,assignee){
 if(value===undefined)return [];
 if(!Array.isArray(value)||value.length>20)throw new FyiError('Enter up to five FYI email addresses.');
 const emails=[];
 for(const raw of value){
  if(typeof raw!=='string')throw new FyiError('Enter valid FYI email addresses.');
  const email=raw.trim().toLowerCase();
  if(email.length>254||!/^[^\s<>@,;]{1,64}@[^\s<>@,;]{1,189}\.[^\s<>@,;]+$/.test(email))throw new FyiError('Enter valid FYI email addresses.');
  if(email!==assignee&&!emails.includes(email))emails.push(email);
 }
 if(emails.length>5)throw new FyiError('You can notify up to five FYI recipients.');
 return emails;
}
export async function fyiReady(env){
 if(env.ASSIGNMENT_FYI_ENABLED!=='true')return false;
 try{await env.DB.prepare('SELECT assignment_id FROM remediation_assignment_fyi LIMIT 1').first();await env.DB.prepare('SELECT id FROM remediation_assignment_notifications LIMIT 1').first();return true;}catch{return false;}
}
const utc=value=>new Date(value*1000).toISOString().replace('T',' ').replace('.000Z',' UTC');
export function renderFyiNotice(row){
 row={...row,cve_id:publicCve(row.cve_id),record_id:row.record_id||row.cve_id};
 const e=escapeHtml;let a={};try{a=JSON.parse(row.public_advisory_json||'{}')}catch{}
 const ack=row.kind==='acknowledged';
 const heading=ack?'Assignment receipt acknowledged':'Vulnerability review assigned';
 const summary=ack?row.assignee_email+' acknowledged receipt of the assignment for '+row.cve_id+' via the emailed link at '+utc(row.created_at)+'.':row.requester_email+' assigned '+row.cve_id+' to '+row.assignee_email+' for review.';
 const status=row.remediation_status==='Investigating'?'In Progress (Investigating)':row.remediation_status;
 const notice=ack?'Acknowledgement confirms receipt only; it does not confirm that investigation or remediation has started, or verify the recipient’s identity.':'You are receiving this for awareness only. No acknowledgement or action is required from you.';
 const fields=[...customerEmailFields(row.scope),...(row.assigned_severity?[['Assigned severity (requester assessment)',row.assigned_severity.toUpperCase()]]:[]),...advisoryFields(a).map(([k,v])=>[row.assigned_severity&&k==='Severity'?'Published severity':k,v])],refs=(a.references||[]).filter(r=>trustedReference(r.url));
 const html='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CVEHarbor FYI</title></head><body style="margin:0;background:#eef3f7;color:#17364c;font-family:Arial,Helvetica,sans-serif;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px;"><!--[if mso]><table role="presentation" width="620"><tr><td><![endif]--><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:620px;background:white;"><tr><td style="padding:24px;background:#071f31;border-bottom:3px solid #22cabb;color:white;"><div style="font-size:26px;font-weight:bold;">CVE<span style="color:#37d2c4;">Harbor</span></div><p style="font-size:10px;letter-spacing:1px;">VULNERABILITY INTELLIGENCE</p><span style="font-size:12px;color:#73ead8;">FYI · '+(ack?'Receipt update':'No action required')+'</span></td></tr><tr><td style="padding:24px;"><h1 style="font-size:24px;color:#0e2e45;">'+heading+'</h1><p style="font-size:14px;line-height:23px;">'+e(summary)+'</p><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f2f7fa;border:1px solid #dce9f0;border-radius:6px;"><tr><td colspan="2" style="padding:16px;"><strong>'+e(row.cve_id)+'</strong><p style="font-size:13px;">'+e(a.title||'Advisory details not available')+'</p></td></tr>'+fields.map(([k,v])=>'<tr><td width="35%" valign="top" style="padding:8px 16px;font-size:12px;border-top:1px solid #dce9f0;">'+e(k)+'</td><td style="padding:8px 16px;font-size:12px;word-break:break-word;border-top:1px solid #dce9f0;">'+e(v)+'</td></tr>').join('')+'</table>'+(status?'<p style="font-size:13px;">Saved remediation status at '+(ack?'acknowledgement':'assignment')+': <strong>'+e(status)+'</strong></p>':'')+'<p style="background:#e6f2ff;padding:14px;font-size:13px;line-height:21px;">'+e(notice)+'</p>'+refs.slice(0,3).map(r=>'<p><a href="'+e(r.url)+'" style="color:#075c91;font-size:13px;">'+e(r.label)+'</a></p>').join('')+'<p style="font-size:12px;color:#527084;">You were included as an FYI recipient by '+e(row.requester_email)+'. Contact the requester to change future notifications.</p></td></tr><tr><td style="background:#071f31;color:#bed4df;padding:20px 24px;font-size:12px;">CVEHarbor · Independent vulnerability intelligence<br>This notification is not evidence of customer exposure.</td></tr></table><!--[if mso]></td></tr></table><![endif]--></td></tr></table></body></html>';
 const text=['CVEHarbor | FYI',heading,'',summary,...(status?['Saved remediation status at '+(ack?'acknowledgement':'assignment')+': '+status]:[]),'',row.cve_id,a.title||'Advisory details not available',...fields.map(([k,v])=>k+': '+v),'',notice,...refs.map(r=>r.label+': '+r.url),'','Included by '+row.requester_email+'. Contact the requester to change future notifications.'].join('\n');
 return {subject:'[CVEHarbor] FYI: '+row.cve_id+(ack?' assignment acknowledged':' review assigned'),html,text};
}
async function quota(env,key,seconds,max){
 const stamp=now(),cutoff=stamp-seconds;
 const result=await env.DB.prepare('INSERT INTO remediation_assignment_limits(key,window_start,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN window_start<? THEN 1 ELSE count+1 END,window_start=CASE WHEN window_start<? THEN ? ELSE window_start END WHERE window_start<? OR count<?').bind(key,stamp,cutoff,cutoff,stamp,cutoff,max).run();return result.meta?.changes===1;
}
export async function dispatchFyi(env){
 if(env.ASSIGNMENT_EMAIL_ENABLED!=='true'||!env.EMAIL_FROM||!(env.ASSIGNMENT_SMTP2GO_API_KEY||env.SMTP2GO_API_KEY)||!await fyiReady(env))return;
 // A crashed/uncertain provider call is never retried automatically: SMTP2GO has no idempotency guarantee here.
 await env.DB.prepare("UPDATE remediation_assignment_notifications SET state='unconfirmed',completed_at=? WHERE state='sending' AND claimed_at<?").bind(now(),now()-900).run();
 const rows=await env.DB.prepare("SELECT n.id FROM remediation_assignment_notifications n JOIN remediation_assignment_requests a ON a.id=n.assignment_id WHERE n.state='queued' AND n.not_before<=? AND a.delivery_status='sent' AND a.revoked_at IS NULL AND (n.kind='assigned' OR EXISTS(SELECT 1 FROM remediation_assignment_notifications initial WHERE initial.assignment_id=n.assignment_id AND initial.recipient_email=n.recipient_email AND initial.kind='assigned' AND initial.state IN ('sent','unconfirmed'))) ORDER BY n.id LIMIT 10").bind(now()).all();
 for(const item of rows.results||[]){
  const lease=crypto.randomUUID();
  const claim=await env.DB.prepare("UPDATE remediation_assignment_notifications SET state='sending',claimed_at=?,claim_token=? WHERE id=? AND state='queued' AND EXISTS(SELECT 1 FROM remediation_assignment_requests a WHERE a.id=assignment_id AND a.revoked_at IS NULL)").bind(now(),lease,item.id).run();if(claim.meta?.changes!==1)continue;
  const row=await env.DB.prepare('SELECT n.*,a.user_id,a.cve_id,a.recipient_email AS assignee_email,a.requester_email,a.public_advisory_json FROM remediation_assignment_notifications n JOIN remediation_assignment_requests a ON a.id=n.assignment_id JOIN remediations r ON r.user_id=a.user_id AND r.cve_id=a.cve_id WHERE n.id=? AND a.revoked_at IS NULL').bind(item.id).first();
  if(row){
   const fingerprint=JSON.parse(row.public_advisory_json||'{}').context_fingerprint;
   if(fingerprint){
    const scope=await recordScope(env,row.user_id,row.cve_id);
    if(scope&&await hash(JSON.stringify([scope.customer_id,scope.environment_id||'']))===fingerprint)row.scope=scope;
   }
  }
  if(row&&await workflowReady(env)){const meta=await env.DB.prepare('SELECT assigned_severity FROM remediation_assignment_metadata WHERE assignment_id=?').bind(row.assignment_id).first();row.assigned_severity=meta?.assigned_severity||'';}
  if(!row){await env.DB.prepare("UPDATE remediation_assignment_notifications SET state='cancelled',completed_at=? WHERE id=?").bind(now(),item.id).run();continue;}
  if(!await quota(env,'assignment-fyi-sender:'+row.user_id,3600,50)||!await quota(env,'assignment-target:'+await hash(row.recipient_email),86400,20)){
   await env.DB.prepare("UPDATE remediation_assignment_notifications SET state='queued',not_before=?,claimed_at=NULL WHERE id=? AND state='sending' AND claim_token=?").bind(now()+3600,item.id,lease).run();continue;
  }
  const attempt=await env.DB.prepare("UPDATE remediation_assignment_notifications SET attempts=attempts+1 WHERE id=? AND state='sending' AND claim_token=?").bind(item.id,lease).run();if(attempt.meta?.changes!==1)continue;
  try{
   const report=renderFyiNotice(row),provider=await sendEmail({EMAIL_FROM:env.EMAIL_FROM,SMTP2GO_API_KEY:env.SMTP2GO_API_KEY,ALERT_SMTP2GO_API_KEY:env.ASSIGNMENT_SMTP2GO_API_KEY||env.SMTP2GO_API_KEY},row.recipient_email,report);
   await env.DB.prepare("UPDATE remediation_assignment_notifications SET state='sent',completed_at=?,provider_id=? WHERE id=? AND state='sending' AND claim_token=?").bind(now(),provider,item.id,lease).run();
  }catch{
   await env.DB.prepare("UPDATE remediation_assignment_notifications SET state='unconfirmed',completed_at=? WHERE id=? AND state='sending' AND claim_token=?").bind(now(),item.id,lease).run();
  }
 }
}
export function scheduleFyi(env,ctx){if(env.ASSIGNMENT_FYI_ENABLED==='true'&&ctx?.waitUntil)ctx.waitUntil(dispatchFyi(env).catch(()=>{console.warn('FYI notification processing deferred; no assignment details logged');}));}
export async function addFyiHistory(env,user,rows){
 if(!rows.length||!await fyiReady(env))return rows;
 const ids=rows.map(r=>r.id),data=await env.DB.prepare('SELECT f.assignment_id,f.recipient_email,n.kind,n.state,n.completed_at,n.attempts FROM remediation_assignment_fyi f JOIN remediation_assignment_requests a ON a.id=f.assignment_id LEFT JOIN remediation_assignment_notifications n ON n.assignment_id=f.assignment_id AND n.recipient_email=f.recipient_email WHERE a.user_id=? AND f.assignment_id IN ('+ids.map(()=>'?').join(',')+') ORDER BY f.recipient_email,n.id').bind(user.id,...ids).all();
 return rows.map(row=>({...row,fyi:(data.results||[]).filter(x=>x.assignment_id===row.id).map(({assignment_id,...rest})=>rest)}));
}
export async function retryFyi(env,user,cve,id){
 if(!await fyiReady(env))throw new FyiError('FYI notifications are unavailable.',503);
 const row=await env.DB.prepare('SELECT id,revoked_at FROM remediation_assignment_requests WHERE id=? AND user_id=? AND cve_id=?').bind(id,user.id,cve).first();
 if(!row)throw new FyiError('Assignment not found',404);if(row.revoked_at!==null)throw new FyiError('This assignment link has been revoked.');
 const result=await env.DB.prepare("UPDATE remediation_assignment_notifications SET state='queued',not_before=0,claimed_at=NULL WHERE assignment_id=? AND state='unconfirmed' AND attempts<3").bind(id).run();return {queued:result.meta?.changes||0};
}
