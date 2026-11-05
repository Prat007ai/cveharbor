import {WorkflowError} from './remediation-workflow.js';
export async function customerRecordsReady(env){try{await env.DB.prepare('SELECT record_id FROM remediation_customer_scopes LIMIT 1').first();await env.DB.prepare('SELECT record_id FROM remediation_customer_ticket_history LIMIT 1').first();return true;}catch{return false;}}
export const customerScopeSQL=`SELECT s.record_id,s.cve_id,s.customer_id,c.name customer_name,s.environment_id,e.name environment_name,NULL asset_id,NULL asset_name FROM remediation_customer_scopes s JOIN inventory_customers c ON c.id=s.customer_id AND c.user_id=s.user_id LEFT JOIN inventory_environments e ON e.id=s.environment_id AND e.user_id=s.user_id AND e.customer_id=s.customer_id WHERE s.user_id=?`;
export async function customerScope(env,user,key){return await customerRecordsReady(env)?env.DB.prepare(customerScopeSQL+' AND s.record_id=?').bind(user,key).first():null;}
export async function customerScopes(env,user){return await customerRecordsReady(env)?(await env.DB.prepare(customerScopeSQL).bind(user).all()).results:[];}
export async function ownedCustomer(env,user,id){
 if(typeof id!=='string'||id.length>80||!await env.DB.prepare('SELECT id FROM inventory_customers WHERE user_id=? AND id=?').bind(user,id).first())throw new WorkflowError('Customer not found in your account.',404);
}
export async function customerContext(env,user,data){
 const customer=data.customer_id,environment=data.environment_id||null,asset=data.asset_id||null;
 if([environment,asset].some(id=>id!==null&&(typeof id!=='string'||id.length>80)))throw new WorkflowError('Invalid inventory context.');
 if(customer==='unassigned'){if(environment||asset)throw new WorkflowError('Unassigned records cannot include inventory context.');return null;}
 await ownedCustomer(env,user.id,customer);
 if(environment&&!await env.DB.prepare('SELECT id FROM inventory_environments WHERE id=? AND user_id=? AND customer_id=?').bind(environment,user.id,customer).first())throw new WorkflowError('Environment not found for this customer.',404);
 if(asset&&(!environment||!await env.DB.prepare('SELECT id FROM inventory_assets WHERE id=? AND user_id=? AND environment_id=?').bind(asset,user.id,environment).first()))throw new WorkflowError('Asset not found for this environment.',404);
 return {customer,environment,asset};
}
