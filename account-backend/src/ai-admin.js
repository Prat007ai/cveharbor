import {WorkflowError} from './remediation-workflow.js';
import {sql} from './ai-allowance.js';
import {PRICE,USD,charge,period,priceCurrent} from './ai-pricing.js';

// Account emails are verified by the existing MFA sign-in flow. This binding is
// release-controlled, never a request field or an organization role.
export function owner(env,user){
 if(typeof user.email!=='string'||!user.email)return false;
 return [env.CVEHARBOR_AI_PLATFORM_OWNER_EMAIL,env.CVEHARBOR_AI_PLATFORM_BACKUP_OWNER_EMAIL]
  .some(email=>typeof email==='string'&&!!email&&user.email.toLowerCase()===email.toLowerCase());
}
export async function administrator(env,user){return owner(env,user)||!!await sql(env.DB,'SELECT user_id FROM ai_admins WHERE user_id=?',user.id).first();}
const denied=()=>new WorkflowError('Platform administrator access required.',403);
const ownerOnly=(env,user)=>{if(!owner(env,user))throw denied();};
function audit(db,user,action,target,detail){return sql(db,'INSERT INTO ai_audit(actor,action,target,detail,authorized) VALUES(?,?,?,?,1)',user.id,action,target,detail);}
export async function adminRoute(req,env,user,path,data){
 const db=env.DB;
 if(!await administrator(env,user))throw denied();
 if(path==='/access'){
  ownerOnly(env,user);
  if(req.method==='GET')return {admins:(await sql(db,'SELECT a.user_id,u.email,a.granted_at FROM ai_admins a JOIN users u ON u.id=a.user_id ORDER BY u.email').all()).results};
  if(req.method!=='POST'||!['grant','revoke'].includes(data.action)||typeof data.email!=='string'||data.email.length>254)throw new WorkflowError('Choose an existing verified account and access action.');
  const target=await sql(db,'SELECT u.id,u.email FROM users u JOIN user_totp t ON t.user_id=u.id AND t.enabled=1 WHERE lower(u.email)=?',data.email.trim().toLowerCase()).first();
  if(!target||owner(env,target))throw new WorkflowError('Choose an existing account with authenticator access. The platform owner cannot be changed here.',409);
  await db.batch([audit(db,user,data.action+' dashboard access',target.id,'Platform AI usage dashboard only'),
   data.action==='grant'?sql(db,'INSERT INTO ai_admins(user_id,granted_by) VALUES(?,?) ON CONFLICT DO NOTHING',target.id,user.id):sql(db,'DELETE FROM ai_admins WHERE user_id=?',target.id)]);
  return {saved:true};
 }
 if(path==='/organizations'&&req.method==='POST'){
  ownerOnly(env,user);
  if(typeof data.org!=='string'||typeof data.enabled!=='boolean')throw new WorkflowError('Choose an organization and activation state.');
  if(data.enabled&&(!priceCurrent()||env.CVEHARBOR_AI_ENABLED!=='true'))throw new WorkflowError('The reviewed AI release and price card must be active first.',409);
  await db.batch([audit(db,user,data.enabled?'enable organization AI':'pause organization AI',data.org,'Shared USD 20 per UTC calendar month'),
   sql(db,'INSERT INTO ai_organizations(org,enabled) VALUES(?,?) ON CONFLICT(org) DO UPDATE SET enabled=excluded.enabled',data.org,Number(data.enabled))]);
  return {saved:true};
 }
 if(path==='/reconcile'&&req.method==='POST'){
  ownerOnly(env,user);
  if(typeof data.request_id!=='string'||typeof data.evidence!=='string'||data.evidence.trim().length<10||data.evidence.length>500)throw new WorkflowError('Supply the request identifier and a verified delivery/usage evidence reference.');
  const row=await sql(db,"SELECT * FROM ai_requests WHERE id=? AND (state='held' OR (state IN ('reserved','dispatched') AND updated_at<unixepoch()-300))",data.request_id).first();
  if(!row||row.price_id!==PRICE.id)throw new WorkflowError('This hold requires review of its original price card or is already reconciled.',409);
  let cost;try{cost=charge(data.usage,{input:row.input_rate,cached:row.cached_rate,output:row.output_rate});}catch{throw new WorkflowError('Verified usage must fit the original reservation.');}
  if(row.state==='reserved'&&cost!==0)throw new WorkflowError('An undispatched request cannot have inference charges.');
  const u=data.usage;
  await db.batch([sql(db,`INSERT INTO ai_audit(actor,action,target,detail,authorized) VALUES(?,'reconcile usage',?,?,EXISTS(SELECT 1 FROM ai_requests WHERE id=? AND state=?))`,user.id,row.id,JSON.stringify({evidence:data.evidence,usage:u,charged:cost,previous_state:row.state}),row.id,row.state),
   sql(db,"UPDATE ai_requests SET state=?,charged=?,input_tokens=?,output_tokens=?,cached_tokens=?,reasoning_tokens=?,reason='verified_reconciliation',updated_at=unixepoch() WHERE id=? AND state=?",row.state==='reserved'?'released':'settled',cost,u.input_tokens,u.output_tokens,u.cached_input_tokens||0,u.reasoning_tokens||0,row.id,row.state)]);
  return {saved:true};
 }
 if(path!=='/usage'||req.method!=='GET')throw new WorkflowError('Not found.',404);
 const url=new URL(req.url),month=url.searchParams.get('month')||period();
 const org=url.searchParams.get('org')||'',offset=Number(url.searchParams.get('offset')||0);
 if(!/^20\d{2}-(0[1-9]|1[0-2])$/.test(month)||org.length>80||!Number.isSafeInteger(offset)||offset<0||offset>100000)throw new WorkflowError('Invalid report filter.');
 // Each query rechecks dashboard permission; a revoked delegate cannot read a
 // later query just because they passed the initial request check.
 const grant='(?=1 OR EXISTS(SELECT 1 FROM ai_admins WHERE user_id=?))';
 const args=[Number(owner(env,user)),user.id];
 const result=await db.batch([
  sql(db,`SELECT count(*) organizations,COALESCE(SUM(m.spent),0) spent,COALESCE(SUM(m.reserved),0) reserved
   FROM team_organizations o LEFT JOIN ai_months m ON m.org=o.id AND m.month=? WHERE (?='' OR o.id=?) AND ${grant}`,month,org,org,...args),
  sql(db,`SELECT r.state,COUNT(*) requests,COALESCE(SUM(r.input_tokens),0) input_tokens,COALESCE(SUM(r.output_tokens),0) output_tokens,
   COALESCE(SUM(r.cached_tokens),0) cached_tokens,COALESCE(SUM(r.reasoning_tokens),0) reasoning_tokens
   FROM ai_requests r WHERE r.month=? AND (?='' OR r.org=?) AND ${grant} GROUP BY r.state`,month,org,org,...args),
  sql(db,`SELECT o.id,o.name,COALESCE(a.enabled,0) enabled,COALESCE(m.spent,0) spent,COALESCE(m.reserved,0) reserved,
   (SELECT COUNT(*) FROM ai_requests r WHERE r.org=o.id AND r.month=?) requests
   FROM team_organizations o LEFT JOIN ai_months m ON m.org=o.id AND m.month=? LEFT JOIN ai_organizations a ON a.org=o.id
   WHERE (?='' OR o.id=?) AND ${grant} ORDER BY o.name,o.id LIMIT 50 OFFSET ?`,month,month,org,org,...args,offset),
  sql(db,`SELECT r.actor,u.email,r.org,o.name organization,COUNT(*) requests,SUM(r.charged) spent,
   SUM(CASE WHEN r.state IN ('reserved','dispatched','held') THEN r.reservation ELSE 0 END) reserved,
   SUM(COALESCE(r.input_tokens,0)) input_tokens,SUM(COALESCE(r.output_tokens,0)) output_tokens
   FROM ai_requests r LEFT JOIN users u ON u.id=r.actor JOIN team_organizations o ON o.id=r.org
   WHERE r.month=? AND (?='' OR r.org=?) AND ${grant} GROUP BY r.actor,r.org ORDER BY spent DESC,r.actor,r.org LIMIT 50 OFFSET ?`,month,org,org,...args,offset),
  sql(db,`SELECT r.id,r.org,o.name organization,u.email,r.feature,r.model,r.price_id,r.state,r.charged,r.reservation,r.reason,r.input_tokens,r.output_tokens,r.cached_tokens,r.reasoning_tokens,r.created_at
   FROM ai_requests r LEFT JOIN users u ON u.id=r.actor JOIN team_organizations o ON o.id=r.org
   WHERE r.month=? AND (?='' OR r.org=?) AND ${grant} ORDER BY r.created_at DESC,r.id DESC LIMIT 50 OFFSET ?`,month,org,org,...args,offset),
  sql(db,`SELECT substr(datetime(created_at,'unixepoch'),1,10) day,SUM(charged) spent,COUNT(*) requests FROM ai_requests
   WHERE month=? AND (?='' OR org=?) AND ${grant} GROUP BY day ORDER BY day`,month,org,org,...args)
 ]);
 return {month,currency:'USD',units_per_usd:USD,allowance_per_organization_usd:20,offset,page_size:50,
  platform_owner:owner(env,user),inference_enabled:env.CVEHARBOR_AI_ENABLED==='true',price_current:priceCurrent(),
  price:PRICE,totals:result[0].results[0],states:result[1].results,organizations:result[2].results,
  users:result[3].results,requests:result[4].results,daily:result[5].results};
}
