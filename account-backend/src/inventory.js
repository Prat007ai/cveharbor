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
  if(path==='/v1/inventory/packages'&&req.method==='GET'){
    const environment=id(new URL(req.url).searchParams.get('environment_id'));
    if(!environment)throw new InventoryError('Select a valid environment');
    await owned(env,'inventory_environments',user.id,environment);
    try{
      const rows=await env.DB.prepare('SELECT asset_name,distribution,release,architecture,package_name,source_package,installed_version,collected_at,updated_at FROM inventory_packages WHERE user_id=? AND environment_id=? ORDER BY asset_name,package_name LIMIT 5000').bind(user.id,environment).all();
      return json({ready:true,packages:rows.results||[]});
    }catch(_){return json({ready:false,error:'Package inventory D1 migration required'},503)}
  }
  if(path==='/v1/inventory/packages/import'&&req.method==='POST'){
    const environment=id(data.environment_id);
    if(!environment)throw new InventoryError('Valid environment required');
    await owned(env,'inventory_environments',user.id,environment);
    const rows=data.packages;
    if(!Array.isArray(rows)||!rows.length||rows.length>200)throw new InventoryError('Import between 1 and 200 packages');
    const normalized=[],seen=new Set();
    for(const row of rows){
      const asset=required(row.asset_name,120,'asset name');
      const distribution=required(row.distribution,32,'distribution');
      if(!['Debian','Ubuntu'].includes(distribution))throw new InventoryError('Only Debian and Ubuntu packages supported');
      const release=required(row.release,40,'OS release');
      const architecture=required(row.architecture,32,'architecture');
      const pkg=required(row.package_name,120,'package name');
      const source=required(row.source_package,120,'source package');
      const version=required(row.installed_version,150,'installed version');
      const collected=required(row.collected_at,30,'collection date');
      if(!/^\d{4}-\d{2}-\d{2}$/.test(collected)||Number.isNaN(Date.parse(collected)))throw new InventoryError('Use YYYY-MM-DD collection date');
      const key=[asset,architecture,pkg].map(x=>x.toLowerCase()).join('|');
      if(seen.has(key))throw new InventoryError('Duplicate package in upload: '+pkg);
      seen.add(key);
      normalized.push([crypto.randomUUID(),user.id,environment,asset,distribution,release,architecture,pkg,source,version,collected]);
    }
    try{
      // D1 batch is transactional and prevents partial imports.
      const statements=normalized.map(row=>env.DB.prepare(
        'INSERT INTO inventory_packages(id,user_id,environment_id,asset_name,distribution,release,architecture,package_name,source_package,installed_version,collected_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id,environment_id,asset_name,architecture,package_name) DO UPDATE SET distribution=excluded.distribution,release=excluded.release,source_package=excluded.source_package,installed_version=excluded.installed_version,collected_at=excluded.collected_at,updated_at=CURRENT_TIMESTAMP'
      ).bind(...row));
      await env.DB.batch(statements);
    }catch(e){throw new InventoryError('Package inventory storage unavailable. Confirm the D1 migration before importing.',503)}
    return json({saved:normalized.length,environment_id:environment});
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
  if(match&&req.method==='PUT'&&match[1]==='customers'){
    await owned(env,'inventory_customers',user.id,match[2]);
    const name=required(data.name,120,'customer name');
    const duplicate=await env.DB.prepare('SELECT id FROM inventory_customers WHERE user_id=? AND lower(name)=lower(?) AND id<>? LIMIT 1').bind(user.id,name,match[2]).first();
    if(duplicate)throw new InventoryError('A customer with this name already exists',409);
    await env.DB.prepare('UPDATE inventory_customers SET name=? WHERE id=? AND user_id=?').bind(name,match[2],user.id).run();
    return json({saved:true});
  }
  if(match&&req.method==='PUT'&&match[1]==='environments'){
    await owned(env,'inventory_environments',user.id,match[2]);
    const name=required(data.name,100,'environment name');
    const kind=required(data.kind,32,'environment type');
    if(!['Production','Staging','Development','QA','UAT','Other'].includes(kind))throw new InventoryError('Invalid environment type');
    await env.DB.prepare('UPDATE inventory_environments SET name=?,kind=? WHERE id=? AND user_id=?').bind(name,kind,match[2],user.id).run();
    return json({saved:true});
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
