import {WorkflowError} from './remediation-workflow.js';
import {deliverInvitation,invitationMessage} from './team-mail.js';
import {teamDataRoute} from './team-data.js';

const ownerPredicate="EXISTS(SELECT 1 FROM team_members WHERE org=? AND user_id=? AND role='Owner')";
const memberFields='m.id,m.email,m.role,m.scope,m.customers,m.revision,m.expires,m.user_id IS NOT NULL AS active';
const notFound=()=>new WorkflowError('Workspace or record unavailable.',404);
function required(value,max,label){
  if(typeof value!=='string'||!value.trim()||value.trim().length>max||/[\u0000-\u001f\u007f]/.test(value))throw new WorkflowError('Invalid '+label+'.');
  return value.trim();
}
function grant(data){
  const {role,scope,customers}=data;
  if(!['Owner','Editor','Viewer'].includes(role)||!['all','selected'].includes(scope)||role==='Owner'&&scope!=='all')throw new WorkflowError('Invalid access settings.');
  if(!Array.isArray(customers)||customers.length>100||scope==='selected'&&!customers.length||scope==='all'&&customers.length)throw new WorkflowError('Choose valid customers.');
  return [role,scope,JSON.stringify([...new Set(customers.map(id=>required(id,80,'customer')))])];
}
const stmt=(db,sql,...args)=>db.prepare(sql).bind(...args);
const rows=async statement=>(await statement.all()).results;
function auditGuard(db,org,user,action,target,customer,predicate,...params){
  return stmt(db,'INSERT INTO team_audit(org,actor,action,target,customer_id,authorized) VALUES(?,?,?,?,?,('+predicate+'))',org,user.id,action,target,customer,...params);
}
async function batch(db,list){
  try{return await db.batch(list);}
  catch(error){
    const message=String(error.message);
    if(message.includes('Keep an active workspace Owner'))throw new WorkflowError('Assign another active Owner first.',409);
    if(/CHECK constraint failed|Invalid team customer|UNIQUE constraint failed/i.test(message))throw new WorkflowError('Access or membership changed. Refresh and try again.',409);
    throw error;
  }
}
function member(row){
  return {...row,customers:JSON.parse(row.customers),status:row.active?'Active':row.expires<=Date.now()/1000?'Expired':'Pending'};
}
async function invitation(db,user,token,sha){
  if(typeof token!=='string'||!/^[a-f0-9]{64}$/.test(token))throw notFound();
  const row=await stmt(db,'SELECT '+memberFields+',o.id org,o.name organization,o.data_owner FROM team_members m JOIN team_organizations o ON o.id=m.org WHERE m.token_hash=? AND m.user_id IS NULL AND m.email=? AND m.expires>unixepoch()',await sha(token),user.email).first();
  if(!row)throw new WorkflowError('Invitation unavailable. Check the invited email or ask an Owner for a new invitation.',404);
  return row;
}
export async function teamRoute(req,env,user,path,helpers){
  const {response,body,token,sha,limit}=helpers, db=env.DB, method=req.method;
  if(env.TEAM_ACCESS_ENABLED!=='true')return response({error:'Team access is unavailable.'},404);
  const [,resource,org,action,id,extra]=path.slice('/v1/team'.length).split('/');
  const data=method==='GET'?{}:await body(req);
  if(!data||typeof data!=='object'||Array.isArray(data))throw new WorkflowError('Invalid request.');
  if(resource==='organizations'&&!org){
    if(method==='GET'){
      const organizations=await rows(stmt(db,'SELECT o.id,o.name,m.role,m.scope,o.data_owner=m.user_id AS founder FROM team_members m JOIN team_organizations o ON o.id=m.org WHERE m.user_id=? ORDER BY o.name',user.id));
      const created=await stmt(db,'SELECT id FROM team_organizations WHERE created_by=?',user.id).first();
      return response({organizations,can_create:!created});
    }
    if(method==='POST'){
      const name=required(data.name,100,'organization name'), key=crypto.randomUUID();
      const dedicated=data.include_existing!==true;
      const storage=dedicated?'org-'+key:user.id;
      const anchor=dedicated?[stmt(db,'INSERT INTO users(id,email) VALUES(?,?)',storage,key+'@workspace.cveharbor.invalid')]:[];
      await batch(db,[...anchor,stmt(db,'INSERT INTO team_organizations(id,created_by,data_owner,name) VALUES(?,?,?,?)',key,user.id,storage,name),
        stmt(db,"INSERT INTO team_members(id,org,email,user_id,role,scope,customers) VALUES(?,?,?,?,'Owner','all','[]')",crypto.randomUUID(),key,user.email,user.id)]);
      return response({id:key},201);
    }
  }
  if(resource==='invitation'&&!org&&method==='POST'){
    const row=await invitation(db,user,data.token,sha);
    const labels=await rows(stmt(db,'SELECT name FROM inventory_customers WHERE user_id=? AND id IN (SELECT value FROM json_each(?)) ORDER BY name',row.data_owner,row.customers));
    return response({org:row.org,organization:row.organization,email:row.email,role:row.role,scope:row.scope,customers:labels.map(c=>c.name),revision:row.revision});
  }
  if(resource==='accept'&&!org&&method==='POST'){
    const row=await invitation(db,user,data.token,sha);
    const allowed='EXISTS(SELECT 1 FROM team_members WHERE id=? AND email=? AND token_hash=? AND revision=? AND expires>unixepoch() AND user_id IS NULL)';
    await batch(db,[auditGuard(db,row.org,user,'accept',row.id,null,allowed,row.id,user.email,await sha(data.token),data.revision??0),
      stmt(db,'UPDATE team_members SET user_id=?,token_hash=NULL,expires=NULL,revision=revision+1 WHERE id=?',user.id,row.id)]);
    return response({org:row.org});
  }
  if(resource!=='organizations'||!org||extra)throw notFound();
  const current=await stmt(db,'SELECT o.id,o.name,o.data_owner,m.role,m.scope FROM team_organizations o JOIN team_members m ON m.org=o.id WHERE o.id=? AND m.user_id=?',org,user.id).first();
  if(!current)throw notFound();
  if(action==='preview'&&method==='POST'&&!id){
    if(current.role!=='Owner')throw notFound();
    const [role,scope,selected]=grant(data);
    const labels=await rows(stmt(db,'SELECT name FROM inventory_customers WHERE user_id=? AND id IN (SELECT value FROM json_each(?)) AND '+ownerPredicate+' ORDER BY name',current.data_owner,selected,org,user.id));
    if(labels.length!==JSON.parse(selected).length)throw new WorkflowError('Customer access has changed. Refresh the team list.',409);
    const message=invitationMessage({organization:current.name,inviter:user.email,email:required(data.email,254,'email address'),role,customers:scope==='all'?null:labels.map(c=>c.name),link:'#preview'});
    return response({subject:message.subject,html:message.html_body});
  }
  if(action!=='members')return teamDataRoute(req,env,user,current,action,id,data,response,auditGuard);
  if(current.role!=='Owner')throw new WorkflowError('Owner access required.',403);
  if(!id&&method==='GET'){
    const guard=' AND '+ownerPredicate;
    const result=await db.batch([
      stmt(db,'SELECT '+memberFields+',l.signed_at,m.user_id=o.data_owner AS founder FROM team_members m JOIN team_organizations o ON o.id=m.org LEFT JOIN team_last_login l ON l.user_id=m.user_id WHERE m.org=?'+guard+' ORDER BY m.email',org,org,user.id),
      stmt(db,'SELECT id,name FROM inventory_customers WHERE user_id=?'+guard+' ORDER BY name',current.data_owner,org,user.id)]);
    return response({members:result[0].results.map(member),customers:result[1].results});
  }
  let target;
  if(id){
    target=await stmt(db,'SELECT * FROM team_members WHERE org=? AND id=?',org,id).first();
    if(!target)throw notFound();
    if(data.revision!==target.revision)throw new WorkflowError('This member has changed. Refresh first.',409);
    if(target.user_id===current.data_owner&&(method==='DELETE'||data.role!=='Owner'))throw new WorkflowError('The account that owns the existing customer records must remain an Owner.',409);
  }
  const targetId=id||crypto.randomUUID();
  const predicate=ownerPredicate+(id?' AND EXISTS(SELECT 1 FROM team_members WHERE id=? AND org=? AND revision=?)':'');
  const args=[org,user.id,...(id?[id,org,target.revision]:[])];
  if(method==='DELETE'&&id){
    await batch(db,[auditGuard(db,org,user,'remove',id,null,predicate,...args),stmt(db,'DELETE FROM team_members WHERE org=? AND id=?',org,id)]);
    return response({removed:true});
  }
  if(id&&method==='PUT'){
    const settings=grant(data);
    await batch(db,[auditGuard(db,org,user,'edit access',id,null,predicate,...args),
      stmt(db,'UPDATE team_members SET role=?,scope=?,customers=?,revision=revision+1 WHERE org=? AND id=?',...settings,org,id)]);
    return response({saved:true});
  }
  if(method!=='POST'||id&&target.user_id)throw notFound();
  const [role,scope,customers]=id?[target.role,target.scope,target.customers]:grant(data);
  const email=id?target.email:required(data.email,254,'email address').toLowerCase();
  if(!/^[^\s@]{1,64}@[^\s@]+\.[^\s@]+$/.test(email))throw new WorkflowError('Enter a valid email address.');
  if(!await limit(env,'team-invite:'+org,30))throw new WorkflowError('Invitation limit reached. Try again later.',429);
  const raw=token(), hashed=await sha(raw), expires=Math.floor(Date.now()/1000)+7*86400;
  const change=id?stmt(db,'UPDATE team_members SET token_hash=?,expires=?,revision=revision+1 WHERE org=? AND id=?',hashed,expires,org,id):
    stmt(db,'INSERT INTO team_members(id,org,email,role,scope,customers,token_hash,expires) VALUES(?,?,?,?,?,?,?,?)',targetId,org,email,role,scope,customers,hashed,expires);
  await batch(db,[auditGuard(db,org,user,id?'reissue':'invite',targetId,null,predicate,...args),change]);
  const labels=await rows(stmt(db,'SELECT name FROM inventory_customers WHERE user_id=? AND id IN (SELECT value FROM json_each(?)) ORDER BY name',current.data_owner,customers));
  try{await deliverInvitation(env,{organization:current.name,inviter:user.email,email,role,customers:scope==='all'?null:labels.map(c=>c.name),link:'https://cveharbor.com/workspace/#team-invite='+raw});}
  catch{
    await stmt(db,'UPDATE team_members SET expires=0,revision=revision+1 WHERE id=? AND token_hash=?',targetId,hashed).run();
    throw new WorkflowError('Delivery could not be confirmed. Refresh the team list and reissue the invitation.',503);
  }
  return response({invited:true},201);
}
