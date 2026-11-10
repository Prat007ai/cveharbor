import {manualScopesReady,manualSelection} from './manual-assignment-context.js';
import {WorkflowError,requireWorkflow,workflowWriteStatements,runWorkflowWrite} from './remediation-workflow.js';
import {normalizeRecord,upsertRemediation} from './remediation.js';
import {recordScope,recordKey} from './remediation-identity.js';
import {activeRecords} from './remediation-integrity.js';
import {linkFinding} from './finding-remediation.js';
import {customerContext,customerRecordsReady} from './customer-remediation-context.js';
export async function saveCustomerRemediation(env,user,data,writeGuards=[]){
 const cve=String(data.cve_id||'').trim().toUpperCase();if(!/^CVE-\d{4}-\d{4,}$/.test(cve)||cve.length>28)throw new WorkflowError('Invalid CVE ID.');
 const context=await customerContext(env,user,data);
 let id=data.existing_id?recordKey(data.existing_id):null;
 if(data.existing_id&&(!id||id!==cve))throw new WorkflowError('Only an existing unassigned record can be associated.');
 const current=await env.DB.prepare('SELECT cve_id,status,updated_at FROM remediations WHERE user_id=? AND cve_id=?').bind(user.id,id||cve).first();
 if(id&&(!current||typeof data.expected_updated!=='string'||data.expected_updated!==current.updated_at))throw new WorkflowError('Record changed. Refresh before associating.',409);
 if(id&&await recordScope(env,user.id,id))throw new WorkflowError('Existing customer relationships cannot be changed here.',409);
 if(!context){if(!id&&current)throw new WorkflowError('An unassigned record already exists. Edit it explicitly.',409);return upsertRemediation(env,user,cve,data);}
 if(id&&data.confirm_association!==true)throw new WorkflowError('Confirm that this existing record belongs to the selected customer.');
 if(context.asset){
  if(id)throw new WorkflowError('Use the existing reviewed asset-link flow to associate an unassigned record.',409);
  const initial=normalizeRecord(cve,data);
  if(await env.DB.prepare('SELECT record_id FROM remediation_finding_links WHERE user_id=? AND asset_id=? AND cve_id=?').bind(user.id,context.asset,cve).first())throw new WorkflowError('This asset already has this CVE. Open its existing record.',409);
  const finding=await env.DB.prepare('SELECT status FROM customer_finding_statuses WHERE user_id=? AND asset_id=? AND cve_id=?').bind(user.id,context.asset,cve).first();
  const before=({'Needs Review':'Open','Fix in Progress':'Investigating','Fixed/Patched':'Remediated'}[finding?.status]||finding?.status||'Open');
  if(before!==data.status&&!String(data.status_change_reason||'').trim())throw new WorkflowError('Enter a reason to change the existing asset finding status.');
  const result=await linkFinding(env,user,context.asset,cve,data,initial);
  // Asset creation deliberately reuses the established relationship and guard flow.
  return Response.json({saved:true,id:result.id,open_record:true},{headers:{'Cache-Control':'no-store'}});
 }
 if(!await customerRecordsReady(env))throw new WorkflowError('Customer-level records require the separately approved migration.',503);
 await requireWorkflow(env);
 const count=await env.DB.prepare('SELECT COUNT(*) total FROM remediations WHERE user_id=?'+await activeRecords(env)).bind(user.id).first();
 if(!id&&count.total>=250)throw new WorkflowError('The account has reached its 250 remediation record limit.',409);
 const duplicate=await env.DB.prepare('SELECT record_id FROM remediation_customer_scopes WHERE user_id=? AND customer_id=? AND ifnull(environment_id,\'\')=? AND cve_id=?').bind(user.id,context.customer,context.environment||'',cve).first();
 if(duplicate)throw new WorkflowError('A record already exists for this customer context and CVE. Open it instead.',409);
 id||=cve+'~'+crypto.randomUUID().toUpperCase();
 const item=normalizeRecord(id,data),stamp=new Date().toISOString();
 const statements=[...writeGuards,...await workflowWriteStatements(env,user,item,data,stamp)];
 statements.push(env.DB.prepare('INSERT INTO remediation_customer_scopes(user_id,record_id,cve_id,customer_id,environment_id,associated_by,associated_at) VALUES(?,?,?,?,?,?,?)').bind(user.id,id,cve,context.customer,context.environment,user.email,stamp));
 try{await runWorkflowWrite(env,statements);}catch(error){if(/UNIQUE|Customer remediation/i.test(String(error.message)))throw new WorkflowError('Customer context changed or already has this CVE. Refresh before saving.',409);throw error;}
 return Response.json({saved:true,id},{headers:{'Cache-Control':'no-store'}});
}
// Reuse the exact account/customer/environment record without changing an existing ticket.
export async function manualAssignmentRecord(env,user,cve,recipient,selection){
 if(cve.includes('~'))throw new WorkflowError('Open a new assignment to use a different customer.');
 const {customer,environment,customerKey,environmentKey}=await manualSelection(selection);
 if(!await manualScopesReady(env))throw new WorkflowError('Manual customer assignments are unavailable.',503);
 await requireWorkflow(env);
 const find=()=>env.DB.prepare('SELECT record_id FROM remediation_manual_scopes WHERE user_id=? AND customer_key=? AND environment_key=? AND cve_id=?')
  .bind(user.id,customerKey,environmentKey,cve).first();
 const prior=await find();
 if(prior)return prior.record_id;
 const count=await env.DB.prepare('SELECT COUNT(*) total FROM remediations WHERE user_id=?'+await activeRecords(env)).bind(user.id).first();
 if(count.total>=250)throw new WorkflowError('The account has reached its 250 remediation record limit.',409);
 const id=cve+'~'+crypto.randomUUID().toUpperCase(),data={owner:recipient,status:'Open'};
 const batch=await workflowWriteStatements(env,user,normalizeRecord(id,data),data,new Date().toISOString());
 batch.push(env.DB.prepare('INSERT INTO remediation_manual_scopes(user_id,record_id,cve_id,customer_key,environment_key,customer_name,environment_name) VALUES(?,?,?,?,?,?,?)')
  .bind(user.id,id,cve,customerKey,environmentKey,customer,environment));
 try { await runWorkflowWrite(env,batch); }
 catch(error){const concurrent=await find();if(concurrent)return concurrent.record_id;throw error;}
 return id;
}
export async function assignmentRecord(env,user,cve,recipient,selection){
 const context=await customerContext(env,user,selection);
 if(!context||context.asset||cve.includes('~'))throw new WorkflowError('Choose a customer and an optional environment for a new investigation.');
 if(!await customerRecordsReady(env))throw new WorkflowError('Customer assignments are unavailable until the customer schema is ready.',503);
 const find=()=>env.DB.prepare("SELECT record_id FROM remediation_customer_scopes WHERE user_id=? AND cve_id=? AND customer_id=? AND ifnull(environment_id,'')=?").bind(user.id,cve,context.customer,context.environment||'').first();
 const prior=await find();
 if(prior)return prior.record_id;
 try{
  const saved=await saveCustomerRemediation(env,user,{cve_id:cve,customer_id:context.customer,environment_id:context.environment,owner:recipient,status:'Open'});
  return (await saved.json()).id;
 }catch(error){
  if(error.status===409){const concurrent=await find();if(concurrent)return concurrent.record_id;}
  throw error;
 }
}
export async function customerTicket(env,user,id,data){
 const scope=await recordScope(env,user.id,id);
 if(!scope||scope.asset_id||scope.manual)throw new WorkflowError('Customer-level record not found.',404);
 const ticket=typeof data.ticket_number==='string'?data.ticket_number.trim():'';
 if(!ticket||ticket.length>64||/[\x00-\x1f\x7f]/.test(ticket))throw new WorkflowError('Enter a ticket reference of 1–64 characters.');
 await env.DB.prepare('INSERT OR IGNORE INTO remediation_customer_ticket_history(user_id,record_id,ticket_number,created_at) VALUES(?,?,?,?)').bind(user.id,id,ticket,new Date().toISOString()).run();
 return Response.json({saved:true},{headers:{'Cache-Control':'no-store'}});
}
