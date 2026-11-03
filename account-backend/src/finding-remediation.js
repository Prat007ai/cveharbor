import {findingAssignments,findingLinkPreview,attachExisting,attachmentReady} from './finding-assignment-links.js';
import {WorkflowError,requireWorkflow,workflowWriteStatements,runWorkflowWrite} from './remediation-workflow.js';
import {linkedReady,recordKey,publicCve,recordScope,workStatus,findingStatus} from './remediation-identity.js';
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true','Vary':'Origin'}});
const assetSQL=`SELECT a.*,e.name environment_name,c.name customer_name FROM inventory_assets a JOIN inventory_environments e ON e.id=a.environment_id AND e.user_id=a.user_id JOIN inventory_customers c ON c.id=e.customer_id AND c.user_id=e.user_id WHERE a.user_id=? AND a.id=?`;
export async function linkFinding(env,user,assetId,cve){
 await requireWorkflow(env);if(!await linkedReady(env))throw new WorkflowError('Shared remediation is temporarily unavailable.',503);
 const asset=await env.DB.prepare(assetSQL).bind(user.id,assetId).first();if(!asset)throw new WorkflowError('Asset not found in your account.',404);
 const id=recordKey(cve+'~'+assetId);if(!id||publicCve(id)!==cve)throw new WorkflowError('Invalid finding.');
 const existing=await env.DB.prepare('SELECT record_id FROM remediation_finding_links WHERE user_id=? AND asset_id=? AND cve_id=?').bind(user.id,assetId,cve).first();
 if(existing)return {id:existing.record_id,scope:await recordScope(env,user.id,existing.record_id)};
 const count=await env.DB.prepare('SELECT COUNT(*) total FROM remediations WHERE user_id=?').bind(user.id).first();if(count.total>=250)throw new WorkflowError('The account has reached its 250 remediation record limit.',409);
 await env.DB.batch([
  env.DB.prepare("INSERT OR IGNORE INTO remediations(user_id,cve_id,status,owner,due,notes,updated_at) SELECT ?,?,CASE COALESCE(s.status,'Needs Review') WHEN 'Needs Review' THEN 'Open' WHEN 'Fix in Progress' THEN 'Investigating' WHEN 'Fixed/Patched' THEN 'Remediated' ELSE s.status END,'Unassigned','',COALESCE(s.notes,''),? FROM (SELECT 1) LEFT JOIN customer_finding_statuses s ON s.user_id=? AND s.asset_id=? AND s.cve_id=?").bind(user.id,id,new Date().toISOString(),user.id,assetId,cve),
  env.DB.prepare('INSERT OR IGNORE INTO remediation_finding_links(user_id,record_id,asset_id,cve_id) VALUES(?,?,?,?)').bind(user.id,id,assetId,cve)
 ]);
 return {id,scope:await recordScope(env,user.id,id)};
}
export async function updateLinkedFinding(env,user,assetId,cve,data){
 if(!await linkedReady(env))return false;
 const link=await env.DB.prepare('SELECT record_id FROM remediation_finding_links WHERE user_id=? AND asset_id=? AND cve_id=?').bind(user.id,assetId,cve).first();if(!link)return false;
 await requireWorkflow(env);if(typeof data.expected_updated!=='string')throw new WorkflowError('Refresh this finding before saving its shared status.',409);
 const row=await env.DB.prepare('SELECT cve_id AS id,status,owner,due,notes,updated_at FROM remediations WHERE user_id=? AND cve_id=?').bind(user.id,link.record_id).first();
 const item={...row,status:workStatus(data.status)};
 await runWorkflowWrite(env,await workflowWriteStatements(env,user,item,{...data,status_change_reason:data.status_change_reason,expected_updated:data.expected_updated},new Date().toISOString()));return true;
}
export async function sharedRecord(env,user,id){
 if(!await linkedReady(env))throw new WorkflowError('Shared remediation is temporarily unavailable.',503);
 const row=await env.DB.prepare('SELECT cve_id AS id,status,owner,due,notes,updated_at AS updated FROM remediations WHERE user_id=? AND cve_id=?').bind(user.id,id).first();if(!row)throw new WorkflowError('Record not found.',404);
 const scope=await recordScope(env,user.id,id);if(id.includes('~')&&!scope)throw new WorkflowError('Record not found.',404);
 const tickets=scope?await env.DB.prepare('SELECT ticket_number,created_at FROM customer_finding_ticket_history WHERE user_id=? AND asset_id=? AND cve_id=? ORDER BY created_at').bind(user.id,scope.asset_id,scope.cve_id).all():{results:[]};
 const comments=await env.DB.prepare('SELECT id,author_email,comment,created_at FROM remediation_owner_comments WHERE user_id=? AND record_id=? ORDER BY id DESC LIMIT 100').bind(user.id,id).all();
 const links=await attachmentReady(env)?await env.DB.prepare('SELECT linked_by,linked_at,snapshot_json FROM remediation_link_audit WHERE user_id=? AND record_id=? ORDER BY id DESC LIMIT 50').bind(user.id,id).all():{results:[]};
 return {...row,link_history:links.results,cve_id:publicCve(id),fix_status:findingStatus(row.status),scope,tickets:tickets.results||[],comments:comments.results||[]};
}
export async function sharedRoute(req,env,user,path,data={}){
 if(path==='/v1/finding-assignments'&&req.method==='GET')return json(await findingAssignments(env,user));
 const attach=/^\/v1\/finding-remediations\/([a-f0-9-]{36})\/(CVE-\d{4}-\d{4,})\/link-existing$/.exec(path);
 if(attach&&req.method==='POST')return json(await attachExisting(env,user,attach[1],attach[2],data));
 const link=/^\/v1\/finding-remediations\/([a-f0-9-]{36})\/(CVE-\d{4}-\d{4,})$/.exec(path);
 if(link&&req.method==='GET')return json(await findingLinkPreview(env,user,link[1],link[2]));
 if(link&&req.method==='POST')return json(await linkFinding(env,user,link[1],link[2]));
 const match=/^\/v1\/remediation-records\/(CVE-\d{4}-\d{4,}(?:~[A-F0-9-]{36})?)(\/comments)?$/.exec(path);
 if(!match)return json({error:'Not found'},404);
 const row=await sharedRecord(env,user,match[1]);
 if(!match[2]&&req.method==='GET')return json(row);
 if(match[2]&&req.method==='POST'){
  if(typeof data.expected_updated!=='string')throw new WorkflowError('Refresh the shared record before commenting.',409);
  const comment=typeof data.comment==='string'?data.comment.trim():'';if(comment.length<10||comment.length>2000)throw new WorkflowError('Enter a progress comment of 10–2,000 characters.');
  // Comment insertion and optimistic update are one atomic transaction.
  const statements=await workflowWriteStatements(env,user,row,{expected_updated:data.expected_updated},new Date().toISOString());
  statements.push(env.DB.prepare('INSERT INTO remediation_owner_comments(user_id,record_id,author_email,comment,created_at) VALUES(?,?,?,?,?)').bind(user.id,row.id,user.email,comment,Math.floor(Date.now()/1000)));
  await runWorkflowWrite(env,statements);return json({saved:true});
 }
 return json({error:'Method not allowed'},405);
}
