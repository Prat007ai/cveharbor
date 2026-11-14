import {activeAssets} from './agent-validation.js';
import {activeRecords} from './remediation-integrity.js';
import {readWorkspaceHistory} from './workspace-history.js';
// Read-only workspace projection. Authentication is supplied by index.js.
// Existing account ownership remains authoritative; no scope IDs come from the caller.
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true','Vary':'Origin'}});
const ownership=`JOIN inventory_environments e ON e.id=a.environment_id AND e.user_id=a.user_id JOIN inventory_customers c ON c.id=e.customer_id AND c.user_id=e.user_id`;
async function read(env,sql,args=[]){try{return {available:true,rows:(await env.DB.prepare(sql).bind(...args).all()).results||[]}}catch{return {available:false,rows:[]}}}
export async function workspaceRoute(req,env,user){
 if(!user?.id)return json({error:'Sign in required'},401);
 if(req.method!=='GET')return json({error:'Read only'},405);
 const url=new URL(req.url),observed=env.AGENT_INVENTORY_SCHEMA==='1'?' AND '+activeAssets('a'):'';
 if(url.pathname==='/v1/workspace/trend')return json(await readWorkspaceHistory(env,user.id));
 if(url.pathname==='/v1/workspace/summary'){
  const active=await activeRecords(env);
  const [inventory,remediation,findings,monitoring,notifications,providerDelivery]=await Promise.all([
   read(env,`SELECT (SELECT COUNT(*) FROM inventory_customers WHERE user_id=?) customers,(SELECT COUNT(*) FROM inventory_environments e JOIN inventory_customers c ON c.id=e.customer_id AND c.user_id=e.user_id WHERE e.user_id=?) environments,(SELECT COUNT(*) FROM inventory_assets a ${ownership} WHERE a.user_id=?${observed}) inventory_entries`,[user.id,user.id,user.id]),
   read(env,`SELECT status,COUNT(*) count,SUM(CASE WHEN status IN ('Open','Investigating') AND due<>'' AND date(due)<date('now') THEN 1 ELSE 0 END) overdue FROM remediations WHERE user_id=?${active} GROUP BY status`,[user.id]),
   read(env,`SELECT s.status,COUNT(*) count FROM customer_finding_statuses s JOIN inventory_assets a ON a.id=s.asset_id AND a.user_id=s.user_id ${ownership} WHERE s.user_id=?${observed} GROUP BY s.status`,[user.id]),
   read(env,`SELECT COUNT(*) registered,SUM(CASE WHEN enabled=1 THEN 1 ELSE 0 END) enabled,MAX(last_checked_at) last_checked_at,SUM(CASE WHEN enabled=1 AND last_error IS NOT NULL AND last_error<>'' THEN 1 ELSE 0 END) errors,SUM(CASE WHEN enabled=1 AND last_checked_at IS NULL THEN 1 ELSE 0 END) unchecked FROM website_monitors WHERE user_id=?`,[user.id]),
   read(env,`SELECT status,completed_at,item_count FROM alert_digest_runs WHERE user_id=? ORDER BY claimed_at DESC LIMIT 1`,[user.id]),
   read(env,`SELECT state,COUNT(*) count,MAX(delivered_at) last_delivered_at FROM lifecycle_monitor_messages WHERE user_id=? AND created_at>=? GROUP BY state`,[user.id,Date.now()-30*86400000])
  ]);
  return json({generated_at:new Date().toISOString(),scope:'account',inventory:{available:inventory.available,...inventory.rows[0]},remediation,findings,monitoring:{available:monitoring.available,...monitoring.rows[0]},notifications:{available:notifications.available,last_submission:notifications.rows[0]||null},provider_delivery:providerDelivery,capabilities:{active_environments:false,monitored_assets:false,asset_coverage:false,report_archive:false,report_schedules:false,report_drafts:false,export_archive:false,provider_delivery:providerDelivery.available}});
 }
 if(url.pathname==='/v1/workspace/items'){
  const view=url.searchParams.get('view')||'activity',raw=url.searchParams.get('offset')||'0';
  if(!/^\d{1,5}$/.test(raw)||Number(raw)>10000)return json({error:'Invalid page'},400);
  const offset=Number(raw),queries={
   activity:`SELECT h.id,c.name customer,e.name environment,h.asset_name name,h.technology,h.previous_version,h.version,h.recorded_at date,c.id customer_id FROM inventory_software_history h JOIN inventory_assets a ON a.id=h.asset_id AND a.user_id=h.user_id ${ownership} WHERE h.user_id=? AND h.customer_id=c.id AND h.environment_id=e.id ORDER BY h.id DESC LIMIT 6 OFFSET ?`,
   assets:`SELECT a.id,a.name,a.technology,a.version,a.created_at date,c.name customer,c.id customer_id,e.name environment FROM inventory_assets a ${ownership} WHERE a.user_id=?${observed} ORDER BY a.created_at DESC,a.id DESC LIMIT 6 OFFSET ?`,
   environments:`SELECT e.id,e.name,e.kind,e.created_at date,c.name customer,c.id customer_id FROM inventory_environments e JOIN inventory_customers c ON c.id=e.customer_id AND c.user_id=e.user_id WHERE e.user_id=? ORDER BY e.created_at DESC,e.id DESC LIMIT 6 OFFSET ?`,
   review:`SELECT s.asset_id id,s.cve_id,s.status,s.updated_at date,a.name,a.technology,c.name customer,c.id customer_id,e.name environment FROM customer_finding_statuses s JOIN inventory_assets a ON a.id=s.asset_id AND a.user_id=s.user_id ${ownership} WHERE s.user_id=?${observed} AND s.status='Needs Review' ORDER BY s.updated_at DESC,s.asset_id,s.cve_id LIMIT 6 OFFSET ?`
  };
  if(!Object.hasOwn(queries,view))return json({error:'Unknown view'},400);
  const result=await read(env,queries[view],[user.id,offset]);
  return json({available:result.available,view,items:result.rows.slice(0,5),offset,next_offset:result.rows.length>5?offset+5:null});
 }
 return json({error:'Not found'},404);
}
