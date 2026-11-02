export class WorkflowError extends Error{constructor(message,status=400){super(message);this.status=status;}}
export const severityLevels=new Set(['','critical','high','medium','low','info']);
export function assignedSeverity(raw){if(typeof raw!=='string'||!severityLevels.has(raw))throw new WorkflowError('Select a valid assigned severity.');return raw;}
export async function workflowReady(env){
 if(env.REMEDIATION_WORKFLOW_ENABLED!=='true')return false;
 try{await env.DB.prepare('SELECT user_id FROM remediation_record_metadata LIMIT 1').first();await env.DB.prepare('SELECT id FROM remediation_status_changes LIMIT 1').first();await env.DB.prepare('SELECT user_id FROM remediation_change_context LIMIT 1').first();await env.DB.prepare('SELECT assignment_id FROM remediation_assignment_metadata LIMIT 1').first();return true;}catch{return false;}
}
export async function requireWorkflow(env){if(!await workflowReady(env))throw new WorkflowError('Record updates are temporarily unavailable. Please try again later.',503);}
export async function workflowWriteStatements(env,user,item,data,time){
 const current=await env.DB.prepare('SELECT status,updated_at FROM remediations WHERE user_id=? AND cve_id=?').bind(user.id,item.id).first();
 const reason=typeof data.status_change_reason==='string'?data.status_change_reason.trim():'';
 if(reason.length>1000)throw new WorkflowError('The status change reason must be 1,000 characters or fewer.');
 const expected=data.expected_updated===undefined?(current?.updated_at||''):String(data.expected_updated);
 if(current&&expected!==current.updated_at)throw new WorkflowError('This record was updated elsewhere. Refresh and review it before saving.',409);
 if(!current&&expected)throw new WorkflowError('This record no longer exists. Refresh before saving.',409);
 if(current&&current.status!==item.status&&!reason)throw new WorkflowError('Enter a reason for the status change.');
 const savedAt=new Date(Math.max(Date.parse(time),(Date.parse(current?.updated_at)||0)+1)).toISOString();
 return [
  env.DB.prepare('INSERT INTO remediation_change_context(user_id,cve_id,reason,actor_email,changed_at,expected_updated) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id,cve_id) DO UPDATE SET reason=excluded.reason,actor_email=excluded.actor_email,changed_at=excluded.changed_at,expected_updated=excluded.expected_updated').bind(user.id,item.id,reason,user.email,savedAt,expected),
  env.DB.prepare('INSERT INTO remediations(user_id,cve_id,status,owner,due,notes,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(user_id,cve_id) DO UPDATE SET status=excluded.status,owner=excluded.owner,due=excluded.due,notes=excluded.notes,updated_at=excluded.updated_at').bind(user.id,item.id,item.status,item.owner,item.due,item.notes,savedAt),
  env.DB.prepare('DELETE FROM remediation_change_context WHERE user_id=? AND cve_id=?').bind(user.id,item.id)
 ];
}
export async function runWorkflowWrite(env,statements){
 try{await env.DB.batch(statements);}catch(error){
  if(String(error.message).includes('Remediation record changed'))throw new WorkflowError('This record was updated elsewhere. Refresh and review it before saving.',409);
  if(String(error.message).includes('status change reason required'))throw new WorkflowError('Enter a reason for the status change.');
  throw error;
 }
}
export async function recordMetadata(env,user){
 const rows=await env.DB.prepare('SELECT m.cve_id,m.assigned_severity,m.assessed_by,m.assessed_at FROM remediation_record_metadata m WHERE m.user_id=?').bind(user.id).all();
 const changes=await env.DB.prepare('SELECT s.* FROM remediation_status_changes s WHERE s.user_id=? AND s.id=(SELECT MAX(x.id) FROM remediation_status_changes x WHERE x.user_id=s.user_id AND x.cve_id=s.cve_id)').bind(user.id).all();
 return {metadata:new Map((rows.results||[]).map(r=>[r.cve_id,r])),changes:new Map((changes.results||[]).map(r=>[r.cve_id,r]))};
}
export async function statusHistory(env,user,cve,url){
 await requireWorkflow(env);const before=url.searchParams.get('before');if(before!==null&&(!/^\d{1,16}$/.test(before)||!Number.isSafeInteger(Number(before))||Number(before)<1))throw new WorkflowError('Invalid history cursor.');
 const rows=await env.DB.prepare('SELECT id,previous_status,new_status,reason,changed_by,changed_at FROM remediation_status_changes WHERE user_id=? AND cve_id=? AND id<? ORDER BY id DESC LIMIT 51').bind(user.id,cve,before?Number(before):Number.MAX_SAFE_INTEGER).all();const entries=(rows.results||[]).slice(0,50);return {changes:entries,next:(rows.results||[]).length>50?entries.at(-1).id:null};
}
