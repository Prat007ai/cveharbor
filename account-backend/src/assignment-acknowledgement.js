import {assignmentRecord} from './customer-remediation.js';
import {activeRecords} from './remediation-integrity.js';
import {publicCve,recordScope,scopeLabel} from './remediation-identity.js';
import {progressReady,storedReminderPolicy,reminderInterval,reviewLink} from './assignment-progress-common.js';
import {workflowReady,assignedSeverity} from './remediation-workflow.js';
import {acknowledgementLink,confirmationRequest} from './confirmation-host.js';
import {normalizeFyi,fyiReady,addFyiHistory,scheduleFyi} from './assignment-fyi.js';
import {sendEmail} from './delivery.js';
import {lookUpPublishedCve} from './cve-lookup.js';
import {publicSnapshot,renderAssignmentNotice,escapeHtml,advisoryFields,trustedReference} from './assignment-template.js';
const now=()=>Math.floor(Date.now()/1000);
export const hashToken=async value=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))),b=>b.toString(16).padStart(2,'0')).join('');
const newToken=()=>Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
export class AssignmentError extends Error{constructor(message,status=400){super(message);this.status=status;}}
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true','Vary':'Origin','X-Content-Type-Options':'nosniff'}});
export async function acknowledgementReady(env){
 try{await env.DB.prepare('SELECT id FROM remediation_assignment_requests LIMIT 1').first();return true;}catch{return false;}
}
export function acknowledgementStatus(row,time=now()){
 if(row.revoked_at!==null&&row.revoked_at!==undefined)return 'Revoked';
 if(row.delivery_status==='failed')return 'Delivery failed';
 if(row.delivery_status!=='sent')return 'Sending';
 if(row.acknowledged_at!==null&&row.acknowledged_at!==undefined)return 'Acknowledged';
 if(row.expires_at<=time)return 'Expired';
 return 'Pending';
}
export async function assignmentSummary(env,user){
 const rows=await env.DB.prepare('SELECT a.cve_id,a.delivery_status,a.acknowledged_at,a.revoked_at,a.expires_at FROM remediation_assignment_requests a WHERE a.user_id=? AND a.seq=(SELECT MAX(b.seq) FROM remediation_assignment_requests b WHERE b.user_id=a.user_id AND b.cve_id=a.cve_id AND b.recipient_email=a.recipient_email)').bind(user.id).all();
 const result=new Map();
 for(const row of rows.results||[]){const summary=result.get(row.cve_id)||{total:0,states:{}};summary.total++;const status=acknowledgementStatus(row);summary.states[status]=(summary.states[status]||0)+1;if(status==='Acknowledged')summary.latest_acknowledged_at=Math.max(summary.latest_acknowledged_at||0,row.acknowledged_at);result.set(row.cve_id,summary);}
 return result;
}
export async function assignmentHistory(env,user,cve,url){
 if(!await acknowledgementReady(env))return json({assignments:[],next:null,available:false});
 const before=url.searchParams.get('before');if(before!==null&&(!/^\d{1,16}$/.test(before)||!Number.isSafeInteger(Number(before))||Number(before)<1))throw new AssignmentError('Invalid history cursor');
 const rows=await env.DB.prepare('SELECT a.seq,a.id,a.recipient_email,a.delivery_status,a.created_at,a.sent_at,a.expires_at,a.acknowledged_at,a.revoked_at FROM remediation_assignment_requests a JOIN remediations r ON r.user_id=a.user_id AND r.cve_id=a.cve_id WHERE a.user_id=? AND a.cve_id=? AND a.seq<? ORDER BY a.seq DESC LIMIT 51').bind(user.id,cve,before?Number(before):Number.MAX_SAFE_INTEGER).all();
 const page=(rows.results||[]).slice(0,50).map(row=>({...row,status:acknowledgementStatus(row),acknowledgement_evidence:row.acknowledged_at?'Acknowledged via emailed link':null}));
 return json({available:true,assignments:await addFyiHistory(env,user,page),next:(rows.results||[]).length>50?page.at(-1).seq:null});
}
export async function revokeAssignment(env,user,cve,id){
 if(!/^[a-f0-9-]{36}$/.test(id))throw new AssignmentError('Invalid assignment');
 const result=await env.DB.prepare('UPDATE remediation_assignment_requests SET revoked_at=? WHERE id=? AND user_id=? AND cve_id=? AND revoked_at IS NULL').bind(now(),id,user.id,cve).run();
 if(result.meta?.changes!==1){const old=await env.DB.prepare('SELECT id FROM remediation_assignment_requests WHERE id=? AND user_id=? AND cve_id=?').bind(id,user.id,cve).first();if(!old)throw new AssignmentError('Assignment not found',404);}
 return json({revoked:true});
}
async function quota(env,key,seconds,max){
 const stamp=now(),cutoff=stamp-seconds;
 await env.DB.prepare('DELETE FROM remediation_assignment_limits WHERE window_start<?').bind(stamp-86400).run();
 const result=await env.DB.prepare('INSERT INTO remediation_assignment_limits(key,window_start,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN window_start<? THEN 1 ELSE count+1 END,window_start=CASE WHEN window_start<? THEN ? ELSE window_start END WHERE window_start<? OR count<?').bind(key,stamp,cutoff,cutoff,stamp,cutoff,max).run();
 return result.meta?.changes===1;
}
export async function assignWithAcknowledgement(env,user,cve,recipient,notes,raw){
 const fyi=normalizeFyi(raw.fyi_recipients,recipient),workflow=await workflowReady(env),progress=await progressReady(env);
 if(env.ASSIGNMENT_PROGRESS_ENABLED==='true'&&!progress)throw new AssignmentError('Reviewer updates are temporarily unavailable. No email was sent.',503);
 if(raw.assigned_severity!==undefined){assignedSeverity(raw.assigned_severity);if(!workflow)throw new AssignmentError('Assigned severity is temporarily unavailable. No email was sent.',503);}
 if(raw.customer_id){
  if(!await acknowledgementReady(env)||fyi.length&&!await fyiReady(env))throw new AssignmentError('Assignment delivery is unavailable.',503);
  cve=await assignmentRecord(env,user,cve,recipient,raw);
 }
 const existingMeta=workflow?await env.DB.prepare('SELECT assigned_severity FROM remediation_record_metadata WHERE user_id=? AND cve_id=?').bind(user.id,cve).first():null;
 const selectedSeverity=raw.assigned_severity===undefined?(existingMeta?.assigned_severity||''):raw.assigned_severity;
 if(fyi.length&&!await fyiReady(env))throw new AssignmentError('FYI notification setup is unavailable. No email was sent.',503);
 if(!await acknowledgementReady(env))throw new AssignmentError('Acknowledgement setup is unavailable. No email was sent.',503);
 const time=now(),prior=await env.DB.prepare('SELECT id,sent_at,expires_at,revoked_at,delivery_status FROM remediation_assignment_requests WHERE user_id=? AND cve_id=? AND recipient_email=? ORDER BY seq DESC LIMIT 1').bind(user.id,cve,recipient).first();
 if(raw.resend!==true&&prior?.delivery_status==='sent'&&prior.revoked_at===null&&prior.expires_at>time&&time-prior.sent_at<86400)return json({assigned:true,notified:true,duplicate:true,id:cve,assigned_to:recipient,message:'An assignment was already sent to this recipient. Choose Resend to issue a new link.'});
 if(!await quota(env,'assignment-sender:'+user.id,3600,10))throw new AssignmentError('Hourly assignment limit reached',429);
 if(!await quota(env,'assignment-target:'+await hashToken(recipient),86400,20))throw new AssignmentError('Recipient notification limit reached for today',429);
 const record=await env.DB.prepare('SELECT owner,due FROM remediations WHERE user_id=? AND cve_id=?').bind(user.id,cve).first();
 if(record&&!String(record.owner||'').trim())throw new AssignmentError('Please select an owner. Edit this record before assigning.');
 if(!record){const count=await env.DB.prepare('SELECT COUNT(*) AS total FROM remediations WHERE user_id=?'+await activeRecords(env)).bind(user.id).first();if(Number(count?.total||0)>=250)throw new AssignmentError('The account has reached its 250 remediation record limit',409);}
 await env.DB.prepare("INSERT OR IGNORE INTO remediations(user_id,cve_id,status,owner,due,notes,updated_at) VALUES(?,?,'Open',?,'','',?)").bind(user.id,cve,recipient,new Date().toISOString()).run();
 const claim=await env.DB.prepare("INSERT INTO remediation_assignments(user_id,cve_id,assignee_email,assigned_by,state,claimed_at) VALUES(?,?,?,?,'sending',?) ON CONFLICT(user_id,cve_id) DO UPDATE SET assignee_email=excluded.assignee_email,assigned_by=excluded.assigned_by,state=excluded.state,claimed_at=excluded.claimed_at WHERE remediation_assignments.state!='sending' OR remediation_assignments.claimed_at<?").bind(user.id,cve,recipient,user.email,time,time-900).run();
 if(claim.meta?.changes!==1)throw new AssignmentError('An assignment notification is already in progress',409);
 const id=crypto.randomUUID(),token=newToken(),hash=await hashToken(token);
 const configured=Number(env.ASSIGNMENT_ACK_TTL_SECONDS||604800),ttl=Number.isInteger(configured)?Math.min(2592000,Math.max(300,configured)):604800;
 const expires=time+ttl;
 try{
  const advisory=publicSnapshot(publicCve(cve),await lookUpPublishedCve(publicCve(cve)));
  const scope=await recordScope(env,user.id,cve);
  // Save only a fingerprint in the public snapshot. Resolve private names for the intended FYI separately.
  if(scope&&raw.share_customer_context===true)advisory.context_fingerprint=await hashToken(JSON.stringify([scope.customer_id,scope.environment_id||'']));
  await env.DB.prepare("INSERT INTO remediation_assignment_requests(id,user_id,cve_id,recipient_email,requester_email,token_hash,delivery_status,public_advisory_json,created_at,expires_at) VALUES(?,?,?,?,?,?,'sending',?,?,?)").bind(id,user.id,cve,recipient,user.email,hash,JSON.stringify(advisory),time,expires).run();
  if(fyi.length)await env.DB.batch(fyi.map(email=>env.DB.prepare('INSERT INTO remediation_assignment_fyi(assignment_id,recipient_email,created_at) VALUES(?,?,?)').bind(id,email,time)));
  if(workflow)await env.DB.prepare('INSERT INTO remediation_assignment_metadata(assignment_id,assigned_severity) VALUES(?,?)').bind(id,selectedSeverity).run();
  const interval=reminderInterval(selectedSeverity||advisory.severity);
  if(progress)await env.DB.prepare('INSERT INTO remediation_review_access(assignment_id,expires_at,interval_seconds,last_progress_at) VALUES(?,?,?,?)').bind(id,time+2592000,storedReminderPolicy(selectedSeverity||advisory.severity),time).run();
  const report=renderAssignmentNotice({advisory,scope,manageUrl:progress?reviewLink(id):'',reminderHours:interval?interval/3600:null,assignedSeverity:selectedSeverity,requester:user.email,notes:[scope?('Assigned finding: '+scopeLabel(scope)):null,notes].filter(Boolean).join('\n'),due:record?.due||'',url:acknowledgementLink(env,token),expiresAt:expires});
  const senderEnv={EMAIL_FROM:env.EMAIL_FROM,SMTP2GO_API_KEY:env.SMTP2GO_API_KEY,ALERT_SMTP2GO_API_KEY:env.ASSIGNMENT_SMTP2GO_API_KEY||env.SMTP2GO_API_KEY};
  const providerId=await sendEmail(senderEnv,recipient,report),sent=now();
  // Atomically publish the accepted email and invalidate earlier links for this recipient only.
  const metadataOps=workflow?[
   env.DB.prepare('INSERT INTO remediation_record_metadata(user_id,cve_id,assigned_severity,assessed_by,assessed_at) SELECT ?,?,?,?,? WHERE ?=(SELECT id FROM remediation_assignment_requests WHERE user_id=? AND cve_id=? AND delivery_status=\'sent\' ORDER BY seq DESC LIMIT 1) ON CONFLICT(user_id,cve_id) DO UPDATE SET assigned_severity=excluded.assigned_severity,assessed_by=excluded.assessed_by,assessed_at=excluded.assessed_at').bind(user.id,cve,selectedSeverity,user.email,new Date().toISOString(),id,user.id,cve),
   env.DB.prepare('UPDATE remediations SET updated_at=?,owner=? WHERE user_id=? AND cve_id=?').bind(new Date().toISOString(),scope?recipient:(record?.owner||recipient),user.id,cve)
  ]:[];
  await env.DB.batch([
   env.DB.prepare('UPDATE remediation_assignment_requests SET revoked_at=? WHERE user_id=? AND cve_id=? AND recipient_email=? AND seq<(SELECT seq FROM remediation_assignment_requests WHERE id=?) AND revoked_at IS NULL').bind(sent,user.id,cve,recipient,id),
   env.DB.prepare("UPDATE remediation_assignment_requests SET delivery_status='sent',sent_at=?,provider_id=?,revoked_at=CASE WHEN EXISTS(SELECT 1 FROM remediation_assignment_requests newer WHERE newer.user_id=remediation_assignment_requests.user_id AND newer.cve_id=remediation_assignment_requests.cve_id AND newer.recipient_email=remediation_assignment_requests.recipient_email AND newer.seq>remediation_assignment_requests.seq AND newer.delivery_status='sent') THEN ? ELSE revoked_at END WHERE id=? AND user_id=? AND delivery_status='sending'").bind(sent,providerId,sent,id,user.id),
   env.DB.prepare("UPDATE remediation_assignments SET state='sent',last_sent_at=?,provider_id=? WHERE user_id=? AND cve_id=? AND state='sending' AND claimed_at=?").bind(sent,providerId,user.id,cve,time),...metadataOps
  ]);
  return json({assigned:true,notified:true,id:cve,assigned_to:recipient,acknowledgement:'Pending',fyi_queued:fyi.length,message:'Email accepted by the provider. Awaiting explicit acknowledgement via the emailed link.'});
 }catch{
  await env.DB.batch([
   env.DB.prepare("UPDATE remediation_assignment_requests SET delivery_status='failed' WHERE id=? AND user_id=? AND delivery_status='sending'").bind(id,user.id),
   env.DB.prepare("UPDATE remediation_assignments SET state='failed' WHERE user_id=? AND cve_id=? AND state='sending' AND claimed_at=?").bind(user.id,cve,time)
  ]);
  throw new AssignmentError('Email delivery was not confirmed. No acknowledgement is pending for this attempt. Retry later.',502);
 }
}
const pageHeaders={'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store, max-age=0','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','X-Robots-Tag':'noindex, nofollow, noarchive','Strict-Transport-Security':'max-age=31536000','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"};
export function renderAcknowledgementPage(row,state,message='',proof=''){
 const e=escapeHtml;let advisory={};try{advisory=JSON.parse(row?.public_advisory_json||'{}')}catch{}
 const success=state==='Acknowledged',pending=state==='Pending';
 const title=success?'Assignment acknowledged':pending?'Acknowledge assignment':state==='Expired'?'This link has expired':state==='Unavailable'?'Please try again later':'This link is unavailable';
 const stamp=success&&row?.acknowledged_at?new Date(row.acknowledged_at*1000).toISOString().replace('T',' ').replace('.000Z',' UTC'):'';
 const recipient=row?.recipient_email?row.recipient_email.replace(/^(.)([^@]*)(@.)(.*)(\.[^.]+)$/,(_,a,b,c,d,f)=>a+'***'+c+'***'+f):'';
 const assigned=row?.assigned_severity||'',rating=assigned||advisory.severity;
 const severity=rating?rating.toUpperCase():'NOT RATED';
 const severityColor={critical:'#a71935',high:'#dc333b',medium:'#996408',low:'#087e87'}[rating]||'#526b7e';
 const detail=(pending||success)?'<section class="details" aria-label="Public vulnerability details"><div class="advisory-head"><span class="shield" aria-hidden="true">!</span><div><h2>'+e(publicCve(row.cve_id))+'</h2><p>'+e(advisory.title||'Advisory details not available')+'</p></div><div class="rating">'+(assigned?'<small>Assigned severity</small>':'')+'<span style="background:'+severityColor+'">'+e(severity)+'</span>'+(advisory.cvss!==null&&advisory.cvss!==undefined?'<small>Published CVSS: '+e(advisory.cvss)+'</small>':'')+'</div></div><dl>'+advisoryFields(advisory).filter(([k])=>k!=='CVSS'&&(assigned||k!=='Severity')).map(([k,v])=>[k==='Severity'?'Published severity':k,v]).map(([k,v])=>'<div><dt>'+e(k)+'</dt><dd>'+e(v)+'</dd></div>').join('')+'</dl></section>':'';
 const ref=(pending||success)?(advisory.references||[]).find(r=>trustedReference(r.url)):null;
 return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>'+title+' | CVEHarbor</title><style>html{color-scheme:light}*{box-sizing:border-box}body{margin:0;padding:28px 14px;background:#0b253a;color:#102d44;font:15px/1.6 Arial,Helvetica,sans-serif}main{max-width:560px;margin:auto;border:1px solid #416075;border-radius:9px;overflow:hidden;background:white}header,footer{background:#041f32;color:#bed3df;padding:24px 28px}header{border-bottom:3px solid #22cabb}.brand{color:#fff;font-size:28px;font-weight:700;letter-spacing:-1px}.brand span{color:#33d8cb}.tag{font-size:10px;letter-spacing:1.4px}.content{padding:26px 28px}h1{font-size:25px;line-height:1.3;margin:15px 0 9px;text-align:center}h2{font-size:18px;margin:0}p{margin:9px 0 20px}.intro{text-align:center}.symbol{width:70px;height:70px;border-radius:50%;display:grid;place-items:center;background:#def7f1;color:#075c5b;margin:auto;font-size:35px}.details{background:#f2f7fa;border:1px solid #deebf1;border-radius:7px;padding:18px;margin:24px 0}.advisory-head{display:grid;grid-template-columns:42px 1fr auto;gap:10px;align-items:start;margin-bottom:12px}.shield{width:40px;height:40px;display:grid;place-items:center;border-radius:50%;background:#fbe6e9;color:#d92d3e;font-size:25px;font-weight:bold}.rating{text-align:right}.rating span{display:inline-block;color:white;border-radius:6px;padding:3px 9px;font-size:10px;font-weight:bold}.rating small{display:block;font-size:11px;margin-top:4px;white-space:nowrap}.details p{font-size:13px;margin:4px 0 14px}dl{font-size:12px;margin:0}dl div{display:grid;grid-template-columns:38% 1fr;gap:12px;padding:9px 0;border-top:1px solid #dce9f0}dt{font-weight:bold}dd{margin:0;overflow-wrap:anywhere}button,.link{display:block;width:100%;text-align:center;border-radius:6px;font:700 15px Arial;padding:16px 12px;text-decoration:none}button{cursor:pointer;background:#078c80;color:white;border:1px solid #078c80}.link{border:1px solid #387d9a;color:#07527b;background:white;font-size:13px;margin-top:18px}.notice{background:#e6f2ff;border-radius:6px;padding:14px;font-size:13px;margin-top:12px}.meta{font-size:12px;color:#4f6d7e;overflow-wrap:anywhere}footer{font-size:11px}footer .brand{font-size:18px}a:focus-visible,button:focus-visible{outline:3px solid #0089b0;outline-offset:4px}@media(max-width:420px){body{padding:12px}.content,header,footer{padding:22px 18px}h1{font-size:23px}.details{padding:14px}.advisory-head{grid-template-columns:1fr auto}.shield{display:none}h2{font-size:16px}dl div{grid-template-columns:37% 1fr;gap:10px}}</style></head><body><main><header><div class="brand">CVE<span>Harbor</span></div><div class="tag">VULNERABILITY INTELLIGENCE</div></header><div class="content"><div class="symbol" aria-hidden="true">'+(success?'✓':pending?'✓':'!')+'</div><h1>'+title+'</h1><p class="intro">'+(success?'Thank you. Receipt of this vulnerability review request has been recorded.':pending?'Confirm you have received this vulnerability review request.':e(message||'Ask the requester to send a new assignment email.'))+'</p>'+((pending||success)&&recipient?'<p class="meta intro">Emailed to '+e(recipient)+'</p>':'')+detail+(pending?'<form method="post"><input type="hidden" name="confirm" value="receipt"><input type="hidden" name="proof" value="'+e(proof)+'"><button type="submit">I acknowledge receipt</button></form>':'')+(success?'<p class="notice" role="status">Acknowledged via emailed link<br><time>'+e(stamp)+'</time></p>':'')+((pending||success)?'<p class="notice">This confirms receipt only. It does not mean the vulnerability has been investigated or fixed.</p>':'')+(ref?'<a class="link" rel="noreferrer noopener" href="'+e(ref.url)+'">View public advisory</a>':'')+'</div><footer><div class="brand">CVE<span>Harbor</span></div>Independent vulnerability intelligence<br>No CVEHarbor account required. Link use does not verify the recipient’s identity.</footer></main></body></html>';
}
function page(row,state,status=200,message='',extra={},proof=''){return new Response(renderAcknowledgementPage(row,state,message,proof),{status,headers:{...pageHeaders,...extra}});}
export async function acknowledgementRoute(req,env,ctx){
 const url=new URL(req.url),route=confirmationRequest(url),token=route?.token;
 if(!route)return page(null,'Invalid',400);
 if(!['GET','HEAD','POST'].includes(req.method))return page(null,'Invalid',405,'Only GET and POST are supported.',{Allow:'GET, HEAD, POST'});
 try{
  // Native Cloudflare rate limiting stores no tokens and never writes to the customer database.
  if(!env.ASSIGNMENT_ACK_RATE_LIMITER)return page(null,'Unavailable',503);
  const allowed=await env.ASSIGNMENT_ACK_RATE_LIMITER.limit({key:'ack:'+await hashToken(req.headers.get('CF-Connecting-IP')||'unknown')});
  if(!allowed.success)return page(null,'Unavailable',429,'Too many attempts. Please wait a minute and try again.',{'Retry-After':'60'});
  if(!/^[a-f0-9]{64}$/.test(token))return page(null,'Invalid',404);
  if(req.method==='POST'){
   // No-referrer native forms may omit Origin/Fetch Metadata or send Origin: null.
   // A separate token-bound confirmation proof is rendered only on the guest page.
   // Cross-site forms cannot read it; the bearer token itself is never embedded in HTML.
   const origin=req.headers.get('Origin'),site=req.headers.get('Sec-Fetch-Site');
   if((origin&&origin!=='null'&&origin!==route.origin)||(site&&site!=='same-origin')||!/^application\/x-www-form-urlencoded(?:;|$)/i.test(req.headers.get('Content-Type')||'')||Number(req.headers.get('Content-Length')||0)>256)return page(null,'Invalid',403);
   const raw=await req.text(),form=new URLSearchParams(raw);
   if(raw.length>256||form.get('confirm')!=='receipt')return page(null,'Invalid',400);
   if(form.get('proof')!==await hashToken('confirm:'+token))return page(null,'Invalid',403);
  }
  const workflow=await workflowReady(env),hash=await hashToken(token),query=workflow?'SELECT a.*,m.assigned_severity FROM remediation_assignment_requests a JOIN remediations r ON r.user_id=a.user_id AND r.cve_id=a.cve_id LEFT JOIN remediation_assignment_metadata m ON m.assignment_id=a.id WHERE a.token_hash=?':'SELECT a.* FROM remediation_assignment_requests a JOIN remediations r ON r.user_id=a.user_id AND r.cve_id=a.cve_id WHERE a.token_hash=?';
  let row=await env.DB.prepare(query).bind(hash).first();
  if(!row)return page(null,'Invalid',404);
  let state=acknowledgementStatus(row);
  if(state==='Revoked'||state==='Delivery failed')return page(null,'Invalid',410);
  if(state==='Expired')return page(null,'Expired',410);
  if(state==='Sending')return page(null,'Unavailable',503,'This assignment is not ready. Please try again shortly.');
  if(req.method==='POST'&&state==='Pending'){
   // One conditional write; the audit trigger is in the same transaction. Never change remediation status.
   await env.DB.prepare("UPDATE remediation_assignment_requests SET acknowledged_at=? WHERE token_hash=? AND delivery_status='sent' AND acknowledged_at IS NULL AND revoked_at IS NULL AND expires_at>? AND EXISTS(SELECT 1 FROM remediations r WHERE r.user_id=remediation_assignment_requests.user_id AND r.cve_id=remediation_assignment_requests.cve_id)").bind(now(),hash,now()).run();
   row=await env.DB.prepare(query).bind(hash).first();state=row?acknowledgementStatus(row):'Invalid';
   if(state!=='Acknowledged')return page(null,state==='Expired'?'Expired':'Invalid',410);
  }
  if(req.method==='POST'&&state==='Acknowledged')scheduleFyi(env,ctx);
  const result=page(row,state,200,'',{},state==='Pending'?await hashToken('confirm:'+token):'');return req.method==='HEAD'?new Response(null,{headers:result.headers}):result;
 }catch{return page(null,'Unavailable',503,'The acknowledgement service is temporarily unavailable. Please retry later.');}
}
