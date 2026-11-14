// Bounded private reads. A cursor never grants access: owner and scope are
// rechecked on every page. Mutations invalidate the revision across pages.
export const INVENTORY_CAPACITY=50000;
export const INVENTORY_PAGE_SIZE=250;
import {WorkflowError} from './remediation-workflow.js';
import {activeAssets} from './agent-validation.js';
export class InventoryPageError extends WorkflowError{
 constructor(message,status=400){super(message,status);}
}
const fail=(message,status=400)=>{throw new InventoryPageError(message,status);};
const assetJoin=' JOIN inventory_assets a ON a.id=t.asset_id AND a.user_id=t.user_id JOIN inventory_environments e ON e.id=a.environment_id AND e.user_id=a.user_id';
const resources={
 customers:{table:'inventory_customers',keys:['id'],fields:'t.id,t.name',scope:'t.id'},
 environments:{table:'inventory_environments',keys:['id'],fields:'t.id,t.customer_id,t.name,t.kind',scope:'t.customer_id',env:'t.id'},
 assets:{table:'inventory_assets',keys:['environment_id','id'],fields:'t.id,t.environment_id,t.name,t.asset_type,t.technology,t.version,t.notes',join:' JOIN inventory_environments e ON e.id=t.environment_id AND e.user_id=t.user_id',scope:'e.customer_id',env:'t.environment_id'},
 statuses:{table:'customer_finding_statuses',keys:['asset_id','cve_id'],fields:'t.asset_id,t.cve_id,t.status,t.notes,t.updated_at',join:assetJoin,scope:'e.customer_id',env:'e.id'},
 tickets:{table:'customer_finding_ticket_history',keys:['asset_id','cve_id','ticket_number'],fields:'t.asset_id,t.cve_id,t.ticket_number,t.created_at',join:assetJoin,scope:'e.customer_id',env:'e.id'},
 sources:{table:'plugin_source_mappings',keys:['asset_id'],fields:'t.asset_id,t.vendor_url,t.release_url,t.advisory_url,t.plugin_slug,t.verification,t.updated_at',join:assetJoin,scope:'e.customer_id',env:'e.id'},
 installations:{table:'plugin_installation_status',keys:['asset_id'],fields:'t.asset_id,t.status',join:assetJoin,scope:'e.customer_id',env:'e.id'},
 checks:{table:'plugin_monitor_checks',keys:['asset_id'],fields:'t.asset_id,t.installed_version,t.plugin_slug,t.status,t.reason,t.findings_json,t.checked_at,t.next_check_at',join:assetJoin,scope:'e.customer_id',env:'e.id'},
 releases:{table:'plugin_release_checks',keys:['asset_id'],fields:'t.asset_id,t.installed_version,t.release_status,t.latest_version,t.update_status,t.release_source,t.last_updated,t.reason,t.checked_at',join:assetJoin,scope:'e.customer_id',env:'e.id'},
 networks:{table:'inventory_server_network',keys:['environment_id','server_key'],fields:'t.environment_id,t.server_key,t.snapshot,t.primary_adapter,t.primary_ip,t.revision',join:' JOIN inventory_environments e ON e.id=t.environment_id AND e.user_id=t.user_id',scope:'e.customer_id',env:'t.environment_id',extra:' AND EXISTS(SELECT 1 FROM inventory_assets a WHERE a.user_id=t.user_id AND a.environment_id=t.environment_id AND lower(trim(a.name))=t.server_key)'},
 packages:{table:'inventory_packages',keys:['id'],fields:'t.id,t.environment_id,t.asset_name,t.distribution,t.release,t.architecture,t.package_name,t.source_package,t.installed_version,t.collected_at,t.updated_at',join:' JOIN inventory_environments e ON e.id=t.environment_id AND e.user_id=t.user_id',scope:'e.customer_id',env:'t.environment_id'}
};
const uuid=x=>typeof x==='string'&&/^[a-f0-9-]{36}$/i.test(x);
const encode=x=>btoa(JSON.stringify(x)).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
function decode(raw){try{if(raw.length>2048||!/^[\w-]+$/.test(raw))throw Error();return JSON.parse(atob(raw.replaceAll('-','+').replaceAll('_','/')));}catch{fail('Invalid inventory cursor');}}
export async function capacityReady(db){
 try{return !!await db.prepare("SELECT version FROM inventory_capacity_schema WHERE version=1").first();}catch{return false;}
}
export async function inventoryPage(req,env,user,team=null){
 const params=new URL(req.url).searchParams,resource=params.get('resource')||'assets',def=Object.hasOwn(resources,resource)?resources[resource]:null;
 if(!def)fail('Invalid inventory resource');
 const customer=params.get('customer_id')||'',environment=params.get('environment_id')||'';
 if(customer&&!uuid(customer)||environment&&!uuid(environment))fail('Invalid inventory scope');
 if(team&&customer!==team.customer)fail('Invalid customer scope');
 const owner=team?.owner||user.id,scope=[owner,team?.org||'',team?.actor||'',customer,environment,resource];
 const raw=params.get('cursor'),cursor=raw?decode(raw):null;
 if(cursor&&(!Array.isArray(cursor.scope)||JSON.stringify(cursor.scope)!==JSON.stringify(scope)||!Number.isSafeInteger(cursor.revision)||cursor.revision<0||!Array.isArray(cursor.after)||cursor.after.length!==def.keys.length||cursor.after.some(x=>typeof x!=='string'||x.length>150)))fail('Invalid inventory cursor');
 const revisionParam=params.get('revision');
 if(revisionParam!==null&&!/^\d{1,15}$/.test(revisionParam))fail('Invalid inventory revision');
 const expected=cursor?.revision??(revisionParam===null?null:Number(revisionParam));
 if(cursor&&revisionParam!==null&&Number(revisionParam)!==cursor.revision)fail('Conflicting inventory revision');
 const clauses=['t.user_id=?'],args=[owner];
 const agents=resource==='assets'&&env.AGENT_INVENTORY_SCHEMA==='1';
 if(agents)clauses.push(activeAssets('t'));
 if(customer){clauses.push(def.scope+'=?');args.push(customer);}
 // Restrict indexed keys before joining; a selected customer must not scan
 // all other customers belonging to a large MSP account.
 if(customer&&['assets','packages','networks'].includes(resource)){
  clauses.push('t.environment_id IN (SELECT id FROM inventory_environments WHERE user_id=? AND customer_id=?)');args.push(owner,customer);
 }
 if(customer&&def.join===assetJoin){
  clauses.push('t.asset_id IN (SELECT id FROM inventory_assets WHERE user_id=? AND environment_id IN (SELECT id FROM inventory_environments WHERE user_id=? AND customer_id=?))');args.push(owner,owner,customer);
 }
 if(environment&&def.env){clauses.push(def.env+'=?');args.push(environment);}
 if(environment&&!def.env){clauses.push('EXISTS(SELECT 1 FROM inventory_environments x WHERE x.user_id=t.user_id AND x.customer_id=t.id AND x.id=?)');args.push(environment);}
 if(team){clauses.push('EXISTS(SELECT 1 FROM team_visible_customers v WHERE v.org=? AND v.actor=? AND v.data_owner=t.user_id AND v.customer_id='+def.scope+')');args.push(team.org,team.actor);}
 if(cursor){clauses.push('('+def.keys.map(k=>'t.'+k).join(',')+') > ('+def.keys.map(()=>'?').join(',')+')');args.push(...cursor.after);}
 // Guard, revision and page share one SQL statement/snapshot. This avoids the
 // per-statement overhead of a five-result D1 batch without reusing authority.
 const guard=team?'SELECT customer_id FROM team_visible_customers WHERE org=? AND actor=? AND data_owner=? AND customer_id=?':customer?'SELECT id FROM inventory_customers WHERE user_id=? AND id=?':'SELECT 1';
 const guardArgs=team?[team.org,team.actor,owner,customer]:customer?[owner,customer]:[];
 const environmentGuard=environment?'SELECT id FROM inventory_environments WHERE user_id=? AND id=?'+(customer?' AND customer_id=?':''):'SELECT 1';
 const environmentArgs=environment?[owner,environment,...customer?[customer]:[]]:[];
 const selected=def.fields+(agents?',ag.id AS agent_device_id,ag.primary_ip AS agent_primary_ip,ag.state AS agent_state,ag.last_sync AS agent_last_sync':'');
 const agentJoin=agents?' LEFT JOIN inventory_agent_assets aa ON aa.asset_id=t.id LEFT JOIN inventory_agents ag ON ag.id=aa.device_id AND ag.user_id=t.user_id AND ag.environment_id=t.environment_id':'';
 const query='SELECT '+selected+' FROM '+def.table+' t'+(def.join||'')+agentJoin+' WHERE '+clauses.join(' AND ')+(def.extra||'')+' ORDER BY '+def.keys.map(k=>'t.'+k).join(',')+' LIMIT '+(INVENTORY_PAGE_SIZE+1);
 // D1 serializes every returned object before sending it to the Worker. A
 // bounded array payload avoids repeating field names for every software row;
 // reconstruct the existing public shape here, without caching private data.
 const fields=selected.split(',').map(field=>field.split(' AS ').at(-1).split('.').at(-1));
 const compact='SELECT json_group_array(json_array('+fields.map(field=>'"'+field+'"').join(',')+')) AS packed FROM ('+query+')';
 const statement='SELECT EXISTS(SELECT 1 FROM inventory_capacity_schema WHERE version=1) AS schema_ready, EXISTS('+guard+') AS access_ready, EXISTS('+environmentGuard+') AS environment_ready, COALESCE((SELECT revision FROM inventory_capacity_revisions WHERE user_id=?),0) AS revision, ('+compact+') AS packed';
 let page;
 try{page=(await env.DB.prepare(statement).bind(...guardArgs,...environmentArgs,owner,...args).all()).results[0];}
 catch(error){if(/no such (table|column)/i.test([error?.message,error?.cause?.message].join(' ')))fail('Inventory capacity migration is required',503);throw error;}
 if(!page.schema_ready)fail('Inventory capacity migration is required',503);
 if(!page.access_ready||!page.environment_ready)fail('Customer or environment unavailable',404);
 const revision=Number(page.revision);
 if(expected!==null&&revision!==expected)fail('Inventory changed while loading. Refresh and retry.',409);
 const rows=JSON.parse(page.packed).map(values=>Object.fromEntries(fields.map((field,i)=>[field,values[i]]))),items=rows.slice(0,INVENTORY_PAGE_SIZE),last=items.at(-1);
 const next=rows.length>INVENTORY_PAGE_SIZE?encode({scope,revision,after:def.keys.map(k=>last[k])}):null;
 for(const row of items){if(resource==='checks'){row.findings=JSON.parse(row.findings_json||'[]');delete row.findings_json;}if(resource==='networks')row.snapshot=JSON.parse(row.snapshot);}
 return {resource,items,revision,next_cursor:next,complete:next===null,page_size:INVENTORY_PAGE_SIZE};
}
