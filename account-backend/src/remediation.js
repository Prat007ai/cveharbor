// CVEHarbor's authenticated remediation records, private D1 storage, and
// tightly controlled email assignment notifications. No Azure DevOps access
// or customer inventory is collected by this service.
import { sendEmail } from './delivery.js';

const idPattern=/^CVE-\d{4}-\d{4,}$/;
const emailPattern=/^[^\s@<>]{1,64}@[^\s@<>]{1,189}\.[^\s@<>]+$/;
const states=new Set(['Open','Investigating','Remediated','Accepted Risk','Not Applicable']);
const time=()=>Math.floor(Date.now()/1000);
const reply=(body,status=200)=>new Response(JSON.stringify(body),{
  status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',
    'X-Content-Type-Options':'nosniff','Access-Control-Allow-Origin':'https://cveharbor.com',
    'Access-Control-Allow-Credentials':'true','Vary':'Origin'}
});
export class RemediationError extends Error{
  constructor(message,status=400){super(message);this.status=status;}
}
export function normalizeId(value){
  const id=String(value||'').trim().toUpperCase();
  return idPattern.test(id)&&id.length<=28?id:null;
}
export function normalizeRecord(id,record){
  const data=record||{};
  const status=String(data.status||'Open');
  const owner=String(data.owner||'').trim().slice(0,100);
  const due=String(data.due||'').trim();
  const notes=String(data.notes||'').trim().slice(0,1200);
  if(!normalizeId(id)||!states.has(status)||due&&!/^\d{4}-\d{2}-\d{2}$/.test(due))
    throw new RemediationError('Invalid remediation record');
  return {id:normalizeId(id),status,owner,due,notes};
}
export async function isMigrated(env){
  try{
    await env.DB.prepare('SELECT user_id FROM remediation_assignments LIMIT 1').first();
    return true;
  }catch(_){return false;}
}
export function assignmentReady(env){
  return env.ASSIGNMENT_EMAIL_ENABLED==='true' && !!env.EMAIL_FROM &&
    !!(env.ASSIGNMENT_SMTP2GO_API_KEY||env.SMTP2GO_API_KEY);
}
export async function capabilities(env){
  return reply({storage:'d1',version:2,assignments_available:await isMigrated(env),
    assignment_email_enabled:assignmentReady(env)});
}
export async function listRemediations(env,user){
  const migrated=await isMigrated(env);
  const sql=migrated
    ? 'SELECT r.cve_id AS id,r.status,r.owner,r.due,r.notes,r.updated_at AS updated,a.assignee_email AS assigned_to,a.state AS assignment_status,a.last_sent_at AS notified_at FROM remediations r LEFT JOIN remediation_assignments a ON r.user_id=a.user_id AND r.cve_id=a.cve_id WHERE r.user_id=? ORDER BY r.updated_at DESC LIMIT 250'
    : 'SELECT cve_id AS id,status,owner,due,notes,updated_at AS updated FROM remediations WHERE user_id=? ORDER BY updated_at DESC LIMIT 250';
  const rows=await env.DB.prepare(sql).bind(user.id).all();
  return reply({remediations:rows.results||[],assignments_available:migrated});
}
async function capacity(env,userId,id){
  const existing=await env.DB.prepare('SELECT cve_id FROM remediations WHERE user_id=? AND cve_id=?').bind(userId,id).first();
  if(existing)return;
  const count=await env.DB.prepare('SELECT COUNT(*) AS total FROM remediations WHERE user_id=?').bind(userId).first();
  if(Number(count?.total||0)>=250)throw new RemediationError('The account has reached its 250 remediation record limit',409);
}
export async function upsertRemediation(env,user,id,data){
  const item=normalizeRecord(id,data);
  await capacity(env,user.id,item.id);
  await env.DB.prepare(
    'INSERT INTO remediations(user_id,cve_id,status,owner,due,notes,updated_at) VALUES(?,?,?,?,?,?,?) '+
    'ON CONFLICT(user_id,cve_id) DO UPDATE SET status=excluded.status,owner=excluded.owner,due=excluded.due,notes=excluded.notes,updated_at=excluded.updated_at'
  ).bind(user.id,item.id,item.status,item.owner,item.due,item.notes,new Date().toISOString()).run();
  return reply({saved:true,id:item.id,storage:'d1'});
}
export async function removeRemediation(env,user,id){
  if(!normalizeId(id))throw new RemediationError('Invalid CVE ID');
  await env.DB.prepare('DELETE FROM remediations WHERE user_id=? AND cve_id=?').bind(user.id,id).run();
  return reply({removed:true,id});
}
// Previous browser-to-cloud import must never delete other D1 records or
// accidentally erase assignment audit rows.
export async function importLegacy(env,user,records){
  if(!Array.isArray(records)||records.length>250)throw new RemediationError('Invalid import');
  const items=records.map(row=>normalizeRecord(row?.id,row));
  if(new Set(items.map(item=>item.id)).size!==items.length)
    throw new RemediationError('Duplicate CVE identifiers in import');
  const existing=await env.DB.prepare('SELECT cve_id FROM remediations WHERE user_id=?').bind(user.id).all();
  const union=new Set([...(existing.results||[]).map(x=>x.cve_id),...items.map(x=>x.id)]);
  if(union.size>250)throw new RemediationError('Import would exceed the 250 record limit',409);
  if(!items.length)return reply({saved:0,storage:'d1'});
  const now=new Date().toISOString();
  const statements=items.map(item=>env.DB.prepare(
    'INSERT INTO remediations(user_id,cve_id,status,owner,due,notes,updated_at) VALUES(?,?,?,?,?,?,?) '+
    'ON CONFLICT(user_id,cve_id) DO UPDATE SET status=excluded.status,owner=excluded.owner,due=excluded.due,notes=excluded.notes,updated_at=excluded.updated_at'
  ).bind(user.id,item.id,item.status,item.owner,item.due,item.notes,now));
  await env.DB.batch(statements);
  return reply({saved:items.length,storage:'d1',message:'Records imported without deleting existing cloud records or assignments.'});
}
function safe(value){return String(value).replace(/[&<>"']/g,ch=>({
  '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
})[ch]);}
export function renderAssignmentEmail(cve,recipient,requester,reviewerNotes=''){
  if(!normalizeId(cve)||!emailPattern.test(recipient)||!emailPattern.test(requester))
    throw new RemediationError('Invalid assignment details');
  const notes=String(reviewerNotes||'').trim();
  if(notes.length>1000)throw new RemediationError('Reviewer notes must be 1000 characters or fewer');
  // Never make unsupported severity, affected product or publication date claims.
  const official='https://www.cve.org/CVERecord?id='+encodeURIComponent(cve);
  const nvd='https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(cve);
  const harbor='https://cveharbor.com/vulnerabilities/?cve='+encodeURIComponent(cve);
  const boards='https://learn.microsoft.com/en-us/azure/devops/boards/work-items/view-add-work-items';
  const subject='[CVEHarbor] Vulnerability review request: '+cve;
  const requested='A colleague has requested your review of '+cve+'. This vulnerability may affect systems you manage, but exposure in your environment has not been confirmed. Review the original advisory and determine whether the affected product and versions are present in systems you manage.';
  const actions=[
    'Review official vulnerability details and confirm affected products, versions and prerequisites.',
    'Check systems and applications within your responsibility and confirm whether they are affected.',
    'Determine the appropriate patch, mitigation or risk treatment using vendor guidance.',
    'If work is needed, create or update a work item in your own Azure DevOps organization and tell the requester the outcome.'
  ];
  const links=[['Official CVE record',official],['NVD vulnerability details',nvd],['Review in CVEHarbor',harbor],['Azure DevOps work item guidance',boards]];
  const textBody=['CVEHARBOR | VULNERABILITY REVIEW REQUEST','','Vulnerability review request: '+cve,'','Requested by: '+requester,'',requested,'',
   'WHAT YOU NEED TO DO',...actions.map((x,i)=>(i+1)+'. '+x),'',
   ...(notes?['NOTES FROM THE REQUESTER',notes,'']:[]),'RELATED REFERENCES',...links.map(([name,url])=>name+': '+url),'',
   'CVEHarbor does not create a DevOps work item automatically. This is a review request, not proof of exposure. Keep customer secrets and internal environment details in your approved private systems.'];
  // Fixed-width presentation tables and explicit cell backgrounds support Outlook desktop.
  const td=(content,background='#ffffff',padding='22px 28px')=>'<td bgcolor="'+background+'" style="background-color:'+background+';padding:'+padding+';font-family:Arial,Helvetica,sans-serif;color:#193247;">'+content+'</td>';
  const row=(content,background,padding)=>'<tr>'+td(content,background,padding)+'</tr>';
  const linkHtml=links.map(([name,url])=>'<tr><td style="padding:6px 0;font-family:Arial,Helvetica,sans-serif;font-size:14px;"><a href="'+safe(url)+'" style="color:#087f88;text-decoration:underline;">'+safe(name)+'</a></td></tr>').join('');
  const actionHtml=actions.map((item,i)=>'<tr><td width="32" valign="top" style="padding:9px 6px 9px 0;color:#068a88;font-weight:bold;font-size:15px;">'+(i+1)+'.</td><td valign="top" style="padding:9px 0;font-size:14px;line-height:21px;color:#243e51;">'+safe(item)+'</td></tr>').join('');
  const headline='<div style="font-size:11px;letter-spacing:1.5px;font-weight:bold;color:#087f88;margin-bottom:10px;">VULNERABILITY REVIEW REQUEST</div>'+
    '<h1 style="font-family:Arial,Helvetica,sans-serif;font-size:25px;line-height:32px;margin:0 0 18px;color:#102d40;">Review requested: '+safe(cve)+'</h1>'+
    '<p style="font-size:14px;line-height:22px;margin:0 0 12px;">Hello,</p>'+
    '<p style="font-size:14px;line-height:23px;margin:0;">'+safe(requested)+'</p>';
  const details='<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#eaf5f6" style="border-collapse:collapse;background-color:#eaf5f6;"><tr><td style="padding:20px 22px;font-family:Arial,Helvetica,sans-serif;color:#18384a;">'+
    '<div style="font-size:17px;font-weight:bold;margin-bottom:12px;">CVE details</div>'+
    '<div style="font-size:14px;line-height:23px;">CVE ID: <strong>'+safe(cve)+'</strong></div>'+
    '<div style="font-size:13px;line-height:21px;margin-top:10px;color:#405d6e;">Check severity, affected versions and publication details in the official links below.</div></td></tr></table>';
  const notesHtml=notes?row('<h2 style="font-size:17px;margin:0 0 12px;color:#15394c;">Sender notes</h2>'+
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#edf6f8"><tr><td style="padding:15px;font-size:14px;line-height:22px;white-space:pre-wrap;color:#27485b;">'+safe(notes).replace(/\\n/g,'<br>')+'</td></tr></table>','#ffffff','8px 28px 16px'):'';
  const button='<table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center"><tr><td bgcolor="#078f8a" style="background-color:#078f8a;padding:14px 24px;text-align:center;">'+
    '<a href="'+safe(harbor)+'" style="font-family:Arial,Helvetica,sans-serif;color:#ffffff;text-decoration:none;font-size:15px;font-weight:bold;">Review this CVE in CVEHarbor</a></td></tr></table>';
  const html='<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>'+
    '<body style="margin:0;padding:0;background-color:#f3f7fa;font-family:Arial,Helvetica,sans-serif;color:#193247;">'+
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f3f7fa" style="border-collapse:collapse;background-color:#f3f7fa;"><tr><td align="center" style="padding:28px 12px;">'+
    '<!--[if mso]><table role="presentation" width="640" align="center" cellpadding="0" cellspacing="0" border="0"><tr><td><![endif]-->'+
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" align="center" bgcolor="#ffffff" style="border-collapse:collapse;width:100%;max-width:640px;background-color:#ffffff;border:1px solid #d6e5ea;">'+
    row('<div style="font-size:26px;font-weight:bold;line-height:32px;color:#ffffff;">CVE<span style="color:#5ae1d4;">Harbor</span></div>'+
      '<div style="font-size:10px;letter-spacing:1.8px;color:#badce2;margin-top:6px;">VULNERABILITY INTELLIGENCE</div>','#0b2538','23px 28px')+
    '<tr><td bgcolor="#21bdb2" height="3" style="height:3px;line-height:3px;font-size:0;">&nbsp;</td></tr>'+
    row(headline)+
    row(details,'#ffffff','8px 28px 18px')+
    row('<h2 style="font-size:17px;margin:0 0 12px;color:#15394c;">What you need to do</h2>'+
      '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'+actionHtml+'</table>','#ffffff','8px 28px 16px')+
    notesHtml+
    row('<h2 style="font-size:17px;margin:0 0 10px;color:#15394c;">Related links</h2>'+
      '<table role="presentation" cellpadding="0" cellspacing="0" border="0">'+linkHtml+'</table>','#ffffff','8px 28px 22px')+
    row(button,'#ffffff','0 28px 24px')+
    row('<div style="font-size:12px;line-height:19px;color:#5c7482;">Requested by '+safe(requester)+'. This email requests investigation and does not confirm exposure or automatically create an Azure DevOps work item. Keep sensitive customer details inside your approved systems.</div>','#eff5f7','20px 28px')+
    '</table><!--[if mso]></td></tr></table><![endif]-->'+
    '</td></tr></table></body></html>';
  return {subject,text:textBody.join('\\n'),html};
}

async function quota(env,key,seconds,max){
  const now=time(),cutoff=now-seconds;
  // Prune counters only after every possible 24 hour notification window.
  await env.DB.prepare('DELETE FROM remediation_assignment_limits WHERE window_start<?').bind(now-86400).run();
  const result=await env.DB.prepare(
    'INSERT INTO remediation_assignment_limits(key,window_start,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET '+
    'count=CASE WHEN window_start<? THEN 1 ELSE count+1 END,'+
    'window_start=CASE WHEN window_start<? THEN ? ELSE window_start END '+
    'WHERE window_start<? OR count<?'
  ).bind(key,now,cutoff,cutoff,now,cutoff,max).run();
  return result.meta?.changes===1;
}
export async function assignRemediation(env,user,id,raw){
  const cve=normalizeId(id);
  const recipient=String(raw?.email||'').trim().toLowerCase();
  const reviewerNotes=String(raw?.reviewer_notes||'').trim();
  if(reviewerNotes.length>1000)throw new RemediationError('Reviewer notes must be 1000 characters or fewer');
  if(!cve||recipient.length>254||!emailPattern.test(recipient))
    throw new RemediationError('Enter a valid CVE ID and recipient email');
  if(!await isMigrated(env))throw new RemediationError('Assignment database migration is required',503);
  if(!assignmentReady(env))throw new RemediationError('Assignment email delivery is not enabled',503);
  const prior=await env.DB.prepare(
    'SELECT assignee_email,state,claimed_at,last_sent_at FROM remediation_assignments WHERE user_id=? AND cve_id=?'
  ).bind(user.id,cve).first();
  const now=time();
  if(prior?.assignee_email===recipient && prior?.state==='sent' && now-Number(prior.last_sent_at||0)<86400)
    return reply({assigned:true,notified:true,duplicate:true,id:cve,assigned_to:recipient,
      message:'An assignment email was already sent to this person within the last 24 hours.'});
  if(prior?.state==='sending' && now-Number(prior.claimed_at||0)<900)
    throw new RemediationError('An assignment notification is already in progress',409);
  // Authenticated sender and per-recipient limits protect this cross-organization notification feature.
  if(!await quota(env,'assignment-sender:'+user.id,3600,10))
    throw new RemediationError('Hourly assignment limit reached',429);
  const enc=new TextEncoder();
  const digest=await crypto.subtle.digest('SHA-256',enc.encode(recipient));
  const hash=Array.from(new Uint8Array(digest),x=>x.toString(16).padStart(2,'0')).join('');
  if(!await quota(env,'assignment-target:'+hash,86400,2))
    throw new RemediationError('Recipient notification limit reached for today',429);
  await capacity(env,user.id,cve);
  await env.DB.prepare(
    "INSERT OR IGNORE INTO remediations(user_id,cve_id,status,owner,due,notes,updated_at) VALUES(?,?,'Open','','','',?)"
  ).bind(user.id,cve,new Date().toISOString()).run();
  const claim=await env.DB.prepare(
    'INSERT INTO remediation_assignments(user_id,cve_id,assignee_email,assigned_by,state,claimed_at) VALUES(?,?,?,?,?,?) '+
    'ON CONFLICT(user_id,cve_id) DO UPDATE SET assignee_email=excluded.assignee_email,assigned_by=excluded.assigned_by,'+
    'state=excluded.state,claimed_at=excluded.claimed_at '+
    "WHERE remediation_assignments.state!='sending' OR remediation_assignments.claimed_at<?"
  ).bind(user.id,cve,recipient,user.email,'sending',now,now-900).run();
  if(claim.meta?.changes!==1)throw new RemediationError('An assignment is already being sent',409);
  const report=renderAssignmentEmail(cve,recipient,user.email,reviewerNotes);
  try{
    // A separate assignment key can isolate quota and abuse monitoring.
    const senderEnv={EMAIL_FROM:env.EMAIL_FROM,SMTP2GO_API_KEY:env.SMTP2GO_API_KEY,
      ALERT_SMTP2GO_API_KEY:env.ASSIGNMENT_SMTP2GO_API_KEY||env.SMTP2GO_API_KEY};
    const providerId=await sendEmail(senderEnv,recipient,report);
    await env.DB.prepare(
      "UPDATE remediation_assignments SET state='sent',last_sent_at=?,provider_id=? WHERE user_id=? AND cve_id=? AND state='sending' AND claimed_at=?"
    ).bind(time(),providerId,user.id,cve,now).run();
    return reply({assigned:true,notified:true,id:cve,assigned_to:recipient,
      message:'Assignment email accepted by SMTP2GO. The recipient will create and track work in Azure DevOps.'});
  }catch(_){
    await env.DB.prepare(
      "UPDATE remediation_assignments SET state='failed' WHERE user_id=? AND cve_id=? AND state='sending' AND claimed_at=?"
    ).bind(user.id,cve,now).run();
    throw new RemediationError('The assignment was saved, but the email provider did not confirm delivery. Retry later.',502);
  }
}
