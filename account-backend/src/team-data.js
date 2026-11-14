import {inventoryPage,capacityReady} from './inventory-pages.js';
import {activeAssets} from './agent-validation.js';
import {WorkflowError,requireWorkflow,workflowWriteStatements,runWorkflowWrite} from './remediation-workflow.js';
import {normalizeRecord} from './remediation.js';
import {inventoryRoute} from './inventory.js';
import {saveCustomerRemediation} from './customer-remediation.js';
import {networkRows,unpack,saveNetwork} from './server-network.js';

const visible='team_visible_customers v';
const environment=' JOIN inventory_environments e ON e.customer_id=v.customer_id AND e.user_id=v.data_owner';
const asset=' JOIN inventory_assets a ON a.environment_id=e.id AND a.user_id=e.user_id';
const record=' JOIN team_scoped_records s ON s.customer_id=v.customer_id AND s.data_owner=v.data_owner JOIN remediations r ON r.user_id=s.data_owner AND r.cve_id=s.record_id';
const where=' WHERE v.org=? AND v.actor=? AND v.customer_id=?';
const missing=()=>new WorkflowError('Customer or record unavailable.',404);
export async function teamDataRoute(req,env,user,org,action,id,data,response,auditGuard){
  const db=env.DB, method=req.method,args=[org.id,user.id,id];
  if(action==='inventory-page'&&method==='GET'&&id)return response(await inventoryPage(req,env,user,{owner:org.data_owner,org:org.id,actor:user.id,customer:id}));
  if(action==='customers'&&method==='GET'&&!id){
    const list=await db.prepare('SELECT customer_id AS id,name FROM '+visible+' WHERE org=? AND actor=? ORDER BY name').bind(org.id,user.id).all();
    return response({name:org.name,role:org.role,scope:org.scope,customers:list.results});
  }
  const canEdit=" AND v.role IN ('Owner','Editor')";
  if(action==='server-network'&&id){
    const allowed='EXISTS(SELECT 1 FROM '+visible+where+')';
    if(!(await db.prepare('SELECT '+allowed+' AS ok').bind(...args).first()).ok)throw missing();
    if(method==='GET')return response({networks:unpack((await networkRows(db,org.data_owner,'',{org:org.id,actor:user.id,customer:id}).all()).results||[])});
    if(['POST','PUT'].includes(method)){
      if(org.role==='Viewer')throw new WorkflowError('Editor access required.',403);
      const guard='EXISTS(SELECT 1 FROM '+visible+environment+where+canEdit+' AND e.id=?)';
      const params=[...args,data.environment_id||''];
      if(!(await db.prepare('SELECT '+guard+' AS ok').bind(...params).first()).ok)throw missing();
      return response(await saveNetwork(db,org.data_owner,data,method,[auditGuard(db,org.id,user,'update server network',id,id,guard,...params)]));
    }
    throw missing();
  }
  if(method==='POST'&&['customers','environments','assets','remediation'].includes(action)){
    if(org.role==='Viewer')throw new WorkflowError('Editor access required.',403);
    let guard,params;
    if(action==='customers'&&!id){
      guard="EXISTS(SELECT 1 FROM team_members WHERE org=? AND user_id=? AND role IN ('Editor','Owner') AND scope='all')";
      params=[org.id,user.id];
    }else if(id&&action!=='customers'){
      const checkEnvironment=action==='assets';
      guard='EXISTS(SELECT 1 FROM '+visible+(checkEnvironment?environment:'')+where+canEdit+(checkEnvironment?' AND e.id=?':'')+')';
      params=checkEnvironment?[...args,data.environment_id||'']:args;
    }else throw missing();
    if(!(await db.prepare('SELECT '+guard+' AS ok').bind(...params).first()).ok)throw missing();
    const check=auditGuard(db,org.id,user,'create '+action,id||org.id,id||null,guard,...params);
    const actor={id:org.data_owner,email:user.email};
    if(action==='remediation'){
      const item={customer_id:id,cve_id:data.cve_id,owner:data.owner,status:'Open',notes:data.notes||'',due:''};
      const result=await saveCustomerRemediation(env,actor,item,[check]);return response(await result.json(),result.status);
    }
    try{return await inventoryRoute(req,env,actor,'/v1/inventory/'+action,{...data,customer_id:id},statement=>db.batch([check,statement]));}
    catch(e){if(/constraint/i.test(e.message))throw new WorkflowError('Access or inventory changed. Refresh and try again.',409);throw e;}
  }
  if(!id)throw missing();
  if(action==='customers'&&method==='GET'){
    const pagination=new URL(req.url).searchParams.get('metadata')==='1'&&await capacityReady(db);
    const agentFilter=env.AGENT_INVENTORY_SCHEMA==='1'?' AND '+activeAssets('a'):'';
    const empty=()=>db.prepare('SELECT 1 WHERE 0');
    const read=(columns,joins,suffix='')=>db.prepare('SELECT '+columns+' FROM '+visible+joins+where+suffix).bind(...args);
    const [customer,environments,assets,findings,records,activity]=await db.batch([
      read('v.name,v.role',''),read('e.id,e.name,e.kind',environment,' ORDER BY e.name'),
      pagination?empty():read('a.id,a.environment_id,a.name,e.name AS environment,a.asset_type,a.technology,a.version,a.notes',environment+asset,agentFilter+' ORDER BY e.name,a.name LIMIT 3001'),
      pagination?empty():read('a.id AS asset_id,a.name AS asset,f.cve_id,f.status,f.notes',environment+asset+' JOIN customer_finding_statuses f ON f.asset_id=a.id AND f.user_id=a.user_id',agentFilter+' ORDER BY f.cve_id,a.name'),
      read('r.cve_id AS id,r.status,r.owner,r.due,r.notes,r.updated_at',record,' ORDER BY r.cve_id'),
      read('u.email,h.action,h.at',' JOIN team_audit h ON h.org=v.org AND h.customer_id=v.customer_id JOIN users u ON u.id=h.actor',' ORDER BY h.id DESC LIMIT 25')
    ]);
    if(!customer.results.length)throw missing();
    if(!pagination&&assets.results.length>3000)throw new WorkflowError('This inventory requires the updated paginated client. Refresh CVEHarbor.',409);
    return response({pagination,customer:customer.results[0],environments:environments.results,assets:assets.results,findings:findings.results,remediations:records.results,activity:activity.results});
  }
  if(method!=='PUT'||!['asset','remediation'].includes(action))throw missing();
  if(org.role==='Viewer')throw new WorkflowError('Editor access required.',403);
  if(action==='asset'){
    const old=data.expected,columns=['name','asset_type','technology','version','notes'];
    if(!old||columns.some(key=>typeof old[key]!=='string')||typeof data.asset_id!=='string')throw new WorkflowError('Refresh the asset before editing.');
    const guard='EXISTS(SELECT 1 FROM '+visible+environment+asset+where+canEdit+' AND a.id=? AND '+columns.map(key=>'a.'+key+'=?').join(' AND ')+')';
    const checks=[...args,data.asset_id,...columns.map(key=>old[key])];
    if(!(await db.prepare('SELECT '+guard+' AS ok').bind(...checks).first()).ok)throw new WorkflowError('Asset or access changed. Refresh before saving.',409);
    const check=auditGuard(db,org.id,user,'edit asset',data.asset_id,id,guard,...checks);
    return inventoryRoute(req,env,{id:org.data_owner},'/v1/inventory/assets/'+data.asset_id,data,statement=>db.batch([check,statement]));
  }
  if(typeof data.expected_updated!=='string'||typeof data.id!=='string')throw new WorkflowError('Refresh the remediation record before saving.',409);
  const guard='EXISTS(SELECT 1 FROM '+visible+record+where+canEdit+' AND s.record_id=? AND r.updated_at=?)';
  if(!await db.prepare('SELECT 1 FROM '+visible+record+where+canEdit+' AND s.record_id=?').bind(...args,data.id).first())throw missing();
  await requireWorkflow(env);
  const item=normalizeRecord(data.id,data);
  const updates=await workflowWriteStatements(env,{id:org.data_owner,email:user.email},item,data,new Date().toISOString());
  try{await runWorkflowWrite(env,[auditGuard(db,org.id,user,'update remediation',item.id,id,guard,...args,item.id,data.expected_updated),...updates]);}
  catch(e){if(/CHECK constraint/i.test(e.message))throw new WorkflowError('Record or access changed. Refresh before saving.',409);throw e;}
  return response({saved:true});
}
