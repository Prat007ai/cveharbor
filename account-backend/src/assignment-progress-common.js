export const REVIEW_ORIGIN='https://confirm.cveharbor.com';
export const reviewNow=()=>Math.floor(Date.now()/1000);
export const reviewToken=()=>Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
export const reviewHash=async value=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))),b=>b.toString(16).padStart(2,'0')).join('');
// Migration 0027 constrains persisted values to these two legacy policy values.
export const storedReminderPolicy=severity=>['critical','high'].includes(severity)?86400:severity==='medium'?172800:null;
export const effectiveIntervalSQL='CASE p.interval_seconds WHEN 86400 THEN 3600 WHEN 172800 THEN 14400 END';
export const reminderInterval=severity=>['critical','high'].includes(severity)?3600:severity==='medium'?14400:null;
export const reviewLink=id=>REVIEW_ORIGIN+'/assignment/'+id;
export class ReviewError extends Error{constructor(message,status=400){super(message);this.status=status;}}
export async function progressReady(env){
 if(env.ASSIGNMENT_PROGRESS_ENABLED!=='true')return false;
 try{for(const table of ['remediation_review_access','remediation_review_challenges','remediation_review_sessions','remediation_review_activity','remediation_review_notifications','remediation_review_write_context'])await env.DB.prepare('SELECT 1 FROM '+table+' LIMIT 1').first();return true;}catch{return false;}
}
export async function reviewQuota(env,key,seconds,max){
 const stamp=reviewNow(),cutoff=stamp-seconds;
 const r=await env.DB.prepare('INSERT INTO remediation_assignment_limits(key,window_start,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN window_start<? THEN 1 ELSE count+1 END,window_start=CASE WHEN window_start<? THEN ? ELSE window_start END WHERE window_start<? OR count<?').bind(key,stamp,cutoff,cutoff,stamp,cutoff,max).run();return r.meta?.changes===1;
}
export const activeReviewSQL='SELECT a.id,a.user_id,a.cve_id,a.recipient_email,a.requester_email,a.public_advisory_json,p.expires_at,'+effectiveIntervalSQL+' AS interval_seconds,p.last_progress_at,p.progress_version,r.status,r.updated_at FROM remediation_review_access p JOIN remediation_assignment_requests a ON a.id=p.assignment_id JOIN remediations r ON r.user_id=a.user_id AND r.cve_id=a.cve_id WHERE a.id=? AND a.delivery_status=\'sent\' AND a.revoked_at IS NULL AND p.expires_at>?';
