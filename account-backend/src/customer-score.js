const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true','Vary':'Origin'}});
const uuid=x=>typeof x==='string'&&/^[0-9a-f-]{36}$/i.test(x);
export async function customerScoreRoute(req,env,user,path,data={}){
 const customerId=req.method==='GET'?new URL(req.url).searchParams.get('customer_id'):data.customer_id;
 const environmentId=req.method==='GET'?(new URL(req.url).searchParams.get('environment_id')||''):(data.environment_id||'');
 if(!uuid(customerId)||(environmentId&&!uuid(environmentId)))return json({error:'Valid customer scope required'},400);
 const customer=await env.DB.prepare('SELECT id FROM inventory_customers WHERE id=? AND user_id=?').bind(customerId,user.id).first();
 if(!customer)return json({error:'Customer not found'},404);
 if(environmentId){
  const owned=await env.DB.prepare('SELECT id FROM inventory_environments WHERE id=? AND customer_id=? AND user_id=?').bind(environmentId,customerId,user.id).first();
  if(!owned)return json({error:'Environment not found'},404);
 }
 if(path==='/v1/customer-score-history'&&req.method==='GET'){
  try{
   const rows=await env.DB.prepare('SELECT score,confidence,coverage,method_version,recorded_at FROM customer_security_score_snapshots WHERE user_id=? AND customer_id=? AND environment_id=? ORDER BY recorded_at DESC LIMIT 120').bind(user.id,customerId,environmentId).all();
   return json({ready:true,history:(rows.results||[]).reverse()});
  }catch(_){return json({ready:false,history:[],message:'Score history D1 migration required'})}
 }
 if(path!=='/v1/customer-score-history'||req.method!=='POST')return json({error:'Not found'},404);
 if(data.method_version!=='1.0'||!(data.score===null||Number.isInteger(data.score)&&data.score>=0&&data.score<=100)||!['High','Medium','Low'].includes(data.confidence)||!Number.isInteger(data.coverage)||data.coverage<0||data.coverage>100)return json({error:'Invalid score snapshot'},400);
 const breakdown=data.breakdown,metrics=data.metrics;
 if(!breakdown||typeof breakdown!=='object'||!metrics||typeof metrics!=='object')return json({error:'Score details required'},400);
 const b=JSON.stringify(breakdown),m=JSON.stringify(metrics);
 if(b.length>1200||m.length>1600)return json({error:'Score details too large'},400);
 try{
  const latest=await env.DB.prepare('SELECT score,confidence,coverage,breakdown_json,metrics_json,recorded_at FROM customer_security_score_snapshots WHERE user_id=? AND customer_id=? AND environment_id=? ORDER BY recorded_at DESC LIMIT 1').bind(user.id,customerId,environmentId).first();
  if(latest&&latest.score===data.score&&latest.confidence===data.confidence&&latest.coverage===data.coverage&&latest.breakdown_json===b&&latest.metrics_json===m)return json({saved:true,unchanged:true});
  await env.DB.prepare('INSERT INTO customer_security_score_snapshots(id,user_id,customer_id,environment_id,method_version,score,confidence,coverage,breakdown_json,metrics_json) VALUES(?,?,?,?,?,?,?,?,?,?)').bind(crypto.randomUUID(),user.id,customerId,environmentId,data.method_version,data.score,data.confidence,data.coverage,b,m).run();
  return json({saved:true});
 }catch(_){return json({saved:false,error:'Score history D1 migration required'},503)}
}
