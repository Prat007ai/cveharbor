import {WorkflowError} from './remediation-workflow.js';

const source = 'remediation_manual_scopes';
export async function manualScopesReady(env) {
 try {
  await env.DB.prepare('SELECT record_id FROM remediation_manual_scopes LIMIT 1').first();
  return true;
 } catch (error) {
  if(String(error.message).includes('no such table'))return false;
  throw error;
 }
}

const selectScope = `SELECT record_id,cve_id,customer_key AS customer_id,customer_name,
 nullif(environment_key,'') AS environment_id,nullif(environment_name,'') AS environment_name,
 NULL AS asset_id,NULL AS asset_name,1 AS manual FROM ${source} WHERE user_id=?`;
export async function manualScopes(env,userId) {
 if(!await manualScopesReady(env))return [];
 return (await env.DB.prepare(selectScope).bind(userId).all()).results;
}
export async function manualScope(env,userId,recordId) {
 if(!String(recordId).includes('~')||!await manualScopesReady(env))return null;
 return env.DB.prepare(selectScope+' AND record_id=?').bind(userId,recordId).first();
}

function label(value,required) {
 if(typeof value!=='string'||/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(value))
  throw new WorkflowError('Enter a single-line customer or environment name.');
 const clean=value.normalize('NFC').trim().replace(/\s+/gu,' ');
 if((required&&!clean)||clean.length>100)throw new WorkflowError('Enter a customer name and use 100 characters or fewer per field.');
 return clean;
}
async function key(value) {
 const bytes=new TextEncoder().encode(value.toLowerCase());
 const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',bytes));
 return 'manual:'+Array.from(hash,b=>b.toString(16).padStart(2,'0')).join('');
}
export async function manualSelection(raw) {
 if(raw.customer_id||raw.environment_id||raw.asset_id||raw.share_customer_context!==true)
  throw new WorkflowError('Select one assignment context and confirm its recipients.');
 const customer=label(raw.manual_customer,true),environment=label(raw.manual_environment??'',false);
 return {customer,environment,customerKey:await key(customer),environmentKey:environment?await key(environment):''};
}
