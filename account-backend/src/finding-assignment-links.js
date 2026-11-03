import {WorkflowError,requireWorkflow,workflowWriteStatements,runWorkflowWrite} from './remediation-workflow.js';
import {recordScope,scopeSQL,linkedReady,workStatus,findingStatus} from './remediation-identity.js';
import {acknowledgementStatus} from './assignment-acknowledgement.js';
export async function attachmentReady(env){try{await env.DB.prepare('SELECT id FROM remediation_link_audit LIMIT 1').first();await env.DB.prepare('SELECT record_id FROM remediation_retired_records LIMIT 1').first();return true;}catch{return false;}}
const fields='r.cve_id AS id,r.status,r.owner,r.due,r.notes,r.updated_at AS updated';
const emptyGuard=`owner='Unassigned' AND due='' AND NOT EXISTS(SELECT 1 FROM remediation_assignments a WHERE a.user_id=remediations.user_id AND a.cve_id=remediations.cve_id) AND NOT EXISTS(SELECT 1 FROM remediation_assignment_requests a WHERE a.user_id=remediations.user_id AND a.cve_id=remediations.cve_id) AND NOT EXISTS(SELECT 1 FROM remediation_status_changes a WHERE a.user_id=remediations.user_id AND a.cve_id=remediations.cve_id) AND NOT EXISTS(SELECT 1 FROM remediation_owner_comments a WHERE a.user_id=remediations.user_id AND a.record_id=remediations.cve_id) AND NOT EXISTS(SELECT 1 FROM remediation_record_metadata a WHERE a.user_id=remediations.user_id AND a.cve_id=remediations.cve_id)`;
export async function findingAssignments(env,user){
 if(!await linkedReady(env))return {ready:false,findings:[],standalone:[]};
 const records=await env.DB.prepare('SELECT '+fields+' FROM remediations r WHERE r.user_id=?').bind(user.id).all();
 const scopes=await env.DB.prepare(scopeSQL).bind(user.id).all(),byRecord=new Map(scopes.results.map(s=>[s.record_id,s]));
 const requests=await env.DB.prepare('SELECT a.cve_id,a.recipient_email,a.acknowledged_at,a.delivery_status,a.revoked_at,a.expires_at,a.sent_at FROM remediation_assignment_requests a WHERE a.user_id=? AND a.seq=(SELECT MAX(b.seq) FROM remediation_assignment_requests b WHERE b.user_id=a.user_id AND b.cve_id=a.cve_id AND b.recipient_email=a.recipient_email)').bind(user.id).all();
 const assignments=new Map();for(const a of requests.results){const items=assignments.get(a.cve_id)||[];items.push({email:a.recipient_email,status:acknowledgementStatus(a),acknowledged_at:a.acknowledged_at,sent_at:a.sent_at});assignments.set(a.cve_id,items);}
 const findings=[],standalone=[];for(const r of records.results){const scope=byRecord.get(r.id),item={record_id:r.id,cve_id:scope?.cve_id||r.id,owner:r.owner,assignments:assignments.get(r.id)||[]};if(scope)findings.push({...item,asset_id:scope.asset_id});else if(!r.id.includes('~'))standalone.push(item);}
 return {ready:true,linking_available:await attachmentReady(env),findings,standalone};
}
export async function findingLinkPreview(env,user,assetId,cve){
 if(!await linkedReady(env))throw new WorkflowError('Shared records are unavailable.',503);
 const asset=await env.DB.prepare('SELECT a.name asset_name,a.technology,a.version,e.name environment_name,c.name customer_name FROM inventory_assets a JOIN inventory_environments e ON e.id=a.environment_id AND e.user_id=a.user_id JOIN inventory_customers c ON c.id=e.customer_id AND c.user_id=e.user_id WHERE a.id=? AND a.user_id=?').bind(assetId,user.id).first();if(!asset)throw new WorkflowError('Asset not found in your account.',404);
 const link=await env.DB.prepare(scopeSQL+' AND l.asset_id=? AND l.cve_id=?').bind(user.id,assetId,cve).first();
 const record=link?await env.DB.prepare('SELECT '+fields+' FROM remediations r WHERE r.user_id=? AND r.cve_id=?').bind(user.id,link.record_id).first():null;
 const source=await env.DB.prepare('SELECT '+fields+' FROM remediations r WHERE r.user_id=? AND r.cve_id=? AND NOT EXISTS(SELECT 1 FROM remediation_finding_links l WHERE l.user_id=r.user_id AND l.record_id=r.cve_id)').bind(user.id,cve).first();
 const finding=await env.DB.prepare('SELECT status,notes,updated_at FROM customer_finding_statuses WHERE user_id=? AND asset_id=? AND cve_id=?').bind(user.id,assetId,cve).first();
 const empty=record?!!await env.DB.prepare('SELECT cve_id FROM remediations WHERE user_id=? AND cve_id=? AND '+emptyGuard).bind(user.id,record.id).first():true;
 return {asset,asset_id:assetId,cve_id:cve,record:record?{...record,fix_status:findingStatus(record.status)}:null,manual:source?{...source,fix_status:findingStatus(source.status)}:null,finding,can_link:!!source&&empty&&await attachmentReady(env),blocked_reason:source&&!empty?'This asset record already has work or assignment history. It cannot be automatically combined with the standalone record.':''};
}
export async function attachExisting(env,user,assetId,cve,data){
 await requireWorkflow(env);if(!await attachmentReady(env))throw new WorkflowError('Linking is temporarily unavailable.',503);
 if(data.confirm!==true)throw new WorkflowError('Review and confirm the customer asset before linking.');
 const p=await findingLinkPreview(env,user,assetId,cve);
 if(p.record?.id===cve)return {id:cve,linked:true,duplicate:true};
 if(!p.manual||!p.can_link)throw new WorkflowError(p.blocked_reason||'The standalone record is no longer available to link. Refresh the finding.',409);
 if(data.expected_source!==p.manual.updated||data.expected_target!==(p.record?.updated||'')||data.expected_finding!==JSON.stringify(p.finding))throw new WorkflowError('These records changed. Refresh and review the link again.',409);
 const status=workStatus(data.status);if(!['Open','Investigating','Remediated','Not Applicable','Accepted Risk'].includes(status))throw new WorkflowError('Choose a valid finding status.');
 const reason='Linked existing standalone assignment to '+p.asset.customer_name+' / '+p.asset.environment_name+' / '+p.asset.asset_name+'. Selected finding status: '+findingStatus(status)+'.';
 const item={...p.manual,status},time=new Date().toISOString();const statements=await workflowWriteStatements(env,user,item,{expected_updated:p.manual.updated,status_change_reason:reason.slice(0,1000)},time);
 statements.push(env.DB.prepare('INSERT INTO remediation_link_audit(user_id,record_id,asset_id,cve_id,retired_record_id,previous_status,selected_status,snapshot_json,linked_by,linked_at) VALUES(?,?,?,?,?,?,?,?,?,?)').bind(user.id,cve,assetId,cve,p.record?.id||'',p.manual.status,status,JSON.stringify({retired:p.record,finding:p.finding,asset:p.asset}),user.email,time));
 // Re-check target emptiness and version inside the same transaction. A failed delete leaves
 // its unique asset link in place, causing the subsequent link insert to roll back everything.
 if(p.record){
  statements.push(env.DB.prepare('INSERT INTO remediation_retired_records(user_id,record_id,canonical_id) SELECT user_id,cve_id,? FROM remediations WHERE user_id=? AND cve_id=? AND updated_at=? AND '+emptyGuard).bind(cve,user.id,p.record.id,p.record.updated));
  statements.push(env.DB.prepare('DELETE FROM remediations WHERE user_id=? AND cve_id=? AND updated_at=? AND '+emptyGuard).bind(user.id,p.record.id,p.record.updated));
 }
 statements.push(env.DB.prepare('INSERT INTO remediation_finding_links(user_id,record_id,asset_id,cve_id) VALUES(?,?,?,?)').bind(user.id,cve,assetId,cve));
 // The projection trigger runs after the new link exists, including unchanged status values.
 statements.push(env.DB.prepare('UPDATE remediations SET status=status WHERE user_id=? AND cve_id=?').bind(user.id,cve));

 try{await runWorkflowWrite(env,statements);}catch(e){if(e instanceof WorkflowError)throw e;throw new WorkflowError('The link could not be saved because the records changed. Refresh and review again.',409);}
 return {id:cve,linked:true,scope:await recordScope(env,user.id,cve)};
}
