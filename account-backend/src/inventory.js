// Private, account-owned customer and environment inventory. All mutations
// require an authenticated session, and every read is scoped by user ID.
const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{
  'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',
  'Access-Control-Allow-Origin':'https://cveharbor.com',
  'Access-Control-Allow-Credentials':'true','Vary':'Origin'
}});
export class InventoryError extends Error{
  constructor(message,status=400){super(message);this.status=status;}
}
function required(value,max,label){
  const text=String(value??'').trim();
  if(!text||text.length>max||/[\u0000-\u001f\u007f]/.test(text))
    throw new InventoryError('Invalid '+label);
  return text;
}
const id=value=>typeof value==='string'&&/^[0-9a-f-]{36}$/i.test(value)?value:null;
async function ready(env){
  try{await env.DB.prepare('SELECT id FROM inventory_customers LIMIT 1').first();return true;}
  catch(_){return false;}
}
async function ensureReady(env){
  if(!await ready(env))throw new InventoryError('Customer inventory database migration is required',503);
}
async function owned(env,table,owner,recordId,parentId){
  const clause=parentId===undefined?'':' AND '+(table==='inventory_environments'?'customer_id':'environment_id')+'=?';
  const q='SELECT id FROM '+table+' WHERE id=? AND user_id=?'+clause;
  const args=parentId===undefined?[recordId,owner]:[recordId,owner,parentId];
  const row=await env.DB.prepare(q).bind(...args).first();
  if(!row)throw new InventoryError('Record not found in your account',404);
}
async function cap(env,table,userId,max){
  const row=await env.DB.prepare('SELECT COUNT(*) AS total FROM '+table+' WHERE user_id=?').bind(userId).first();
  if(Number(row?.total||0)>=max)throw new InventoryError('Inventory limit reached',409);
}
export async function inventoryRoute(req,env,user,path,data={}){
  if(path==='/v1/inventory/status'&&req.method==='GET')
    return json({storage:'d1',ready:await ready(env),max_customers:100,max_environments:500,max_assets:3000});
  await ensureReady(env);
  if(path==='/v1/inventory'&&req.method==='GET'){
    // No public customer, host or software inventory is exposed.
    const [customers,environments,assets]=await Promise.all([
      env.DB.prepare('SELECT id,name FROM inventory_customers WHERE user_id=? ORDER BY name LIMIT 100').bind(user.id).all(),
      env.DB.prepare('SELECT id,customer_id,name,kind FROM inventory_environments WHERE user_id=? ORDER BY name LIMIT 500').bind(user.id).all(),
      env.DB.prepare('SELECT id,environment_id,name,asset_type,technology,version,notes FROM inventory_assets WHERE user_id=? ORDER BY name LIMIT 3000').bind(user.id).all()
    ]);
    return json({customers:customers.results||[],environments:environments.results||[],assets:assets.results||[]});
  }
  if(path==='/v1/inventory/customers'&&req.method==='POST'){
    const name=required(data.name,120,'customer name');await cap(env,'inventory_customers',user.id,100);
    const recordId=crypto.randomUUID();
    await env.DB.prepare('INSERT INTO inventory_customers(id,user_id,name) VALUES(?,?,?)').bind(recordId,user.id,name).run();
    return json({created:true,id:recordId},201);
  }
  if(path==='/v1/inventory/environments'&&req.method==='POST'){
    const customer=id(data.customer_id);
    if(!customer)throw new InventoryError('Invalid customer');
    await owned(env,'inventory_customers',user.id,customer);
    const name=required(data.name,100,'environment name');
    const kind=required(data.kind||'Production',32,'environment type');
    if(!['Production','Staging','Development','QA','UAT','Other'].includes(kind))
      throw new InventoryError('Invalid environment type');
    await cap(env,'inventory_environments',user.id,500);
    const recordId=crypto.randomUUID();
    await env.DB.prepare('INSERT INTO inventory_environments(id,user_id,customer_id,name,kind) VALUES(?,?,?,?,?)')
      .bind(recordId,user.id,customer,name,kind).run();
    return json({created:true,id:recordId},201);
  }
  if(path==='/v1/inventory/assets'&&req.method==='POST'){
    const environment=id(data.environment_id);
    if(!environment)throw new InventoryError('Invalid environment');
    await owned(env,'inventory_environments',user.id,environment);
    const name=required(data.name,120,'asset name');
    const assetType=required(data.asset_type||'Software',32,'asset type');
    if(!['Server','WEB','Application','Database','Cloud Service','Network Device','Software','Other'].includes(assetType))
      throw new InventoryError('Invalid asset type');
    const technology=required(data.technology,120,'technology');
    const version=String(data.version||'').trim(),notes=String(data.notes||'').trim();
    if(version.length>80||notes.length>500)throw new InventoryError('Asset details too long');
    await cap(env,'inventory_assets',user.id,3000);
    const recordId=crypto.randomUUID();
    await env.DB.prepare('INSERT INTO inventory_assets(id,user_id,environment_id,name,asset_type,technology,version,notes) VALUES(?,?,?,?,?,?,?,?)')
      .bind(recordId,user.id,environment,name,assetType,technology,version,notes).run();
    return json({created:true,id:recordId},201);
  }
  const match=/^\/v1\/inventory\/(customers|environments|assets)\/([0-9a-f-]{36})$/.exec(path);
  if(match&&req.method==='DELETE'){
    const table={customers:'inventory_customers',environments:'inventory_environments',assets:'inventory_assets'}[match[1]];
    await owned(env,table,user.id,match[2]);
    await env.DB.prepare('DELETE FROM '+table+' WHERE id=? AND user_id=?').bind(match[2],user.id).run();
    return json({removed:true});
  }
  if(match&&req.method==='PUT'&&match[1]==='assets'){
    await owned(env,'inventory_assets',user.id,match[2]);
    const name=required(data.name,120,'asset name'),technology=required(data.technology,120,'technology');
    const assetType=required(data.asset_type||'Software',32,'asset type');
    const version=String(data.version||'').trim(),notes=String(data.notes||'').trim();
    if(!['Server','WEB','Application','Database','Cloud Service','Network Device','Software','Other'].includes(assetType)||
      version.length>80||notes.length>500)throw new InventoryError('Invalid asset details');
    await env.DB.prepare('UPDATE inventory_assets SET name=?,asset_type=?,technology=?,version=?,notes=? WHERE id=? AND user_id=?')
      .bind(name,assetType,technology,version,notes,match[2],user.id).run();
    return json({saved:true});
  }
  return json({error:'Inventory endpoint not found'},404);
}
