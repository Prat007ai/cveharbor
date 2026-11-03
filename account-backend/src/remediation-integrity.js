// Phase 1 guards are additive. Old schemas remain readable during rollout.
import {WorkflowError} from './remediation-workflow.js';
export async function integrityReady(env){try{await env.DB.prepare('SELECT user_id FROM remediation_finding_write_context LIMIT 1').first();return true;}catch{return false;}}
export async function activeRecords(env,alias='remediations'){
 if(!await integrityReady(env))return '';
 return ` AND NOT EXISTS(SELECT 1 FROM remediation_retired_records retired WHERE retired.user_id=${alias}.user_id AND retired.record_id=${alias}.cve_id)`;
}
export async function canonicalRecord(env,user,id){
 if(!await integrityReady(env))return id;
 const row=await env.DB.prepare('SELECT t.canonical_id FROM remediation_retired_records t JOIN remediations r ON r.user_id=t.user_id AND r.cve_id=t.canonical_id WHERE t.user_id=? AND t.record_id=?').bind(user,id).first();
 return row?.canonical_id||id;
}
// A transaction-local snapshot is checked by SQLite before any create/link writes.
export function findingGuard(env,user,p){
 return env.DB.prepare('INSERT INTO remediation_finding_write_context(user_id,asset_id,cve_id,expected_record,expected_manual,expected_finding,expected_asset) VALUES(?,?,?,?,?,?,?)').bind(user.id,p.asset_id,p.cve_id,p.record?.id||null,p.manual?.updated||null,JSON.stringify(p.finding),JSON.stringify(p.asset));
}
export function clearFindingGuard(env,user,p){return env.DB.prepare('DELETE FROM remediation_finding_write_context WHERE user_id=? AND asset_id=? AND cve_id=?').bind(user.id,p.asset_id,p.cve_id);}
export function integrityError(error){
 if(/Finding changed|Finding scope changed|Record integrity|retained history|retired record|linked to an existing assignment/i.test(String(error.message)))return new WorkflowError('This record or customer asset changed, or contains retained history. Refresh and review it before proceeding.',409);
 return error;
}
