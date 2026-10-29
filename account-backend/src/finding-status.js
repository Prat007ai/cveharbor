// Status belongs to an account-owned asset and CVE, never the global CVE alone.
const allowed=new Set(['Needs Review','Fix in Progress','Fixed/Patched','Not Applicable','Accepted Risk']);
const response=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{
 'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',
 'Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true',
 'Vary':'Origin','X-Content-Type-Options':'nosniff'}});
const validAsset=x=>typeof x==='string'&&/^[0-9a-f-]{36}$/i.test(x);
const validCve=x=>typeof x==='string'&&/^CVE-\d{4}-\d{4,}$/i.test(x)&&x.length<=28;
export class FindingStatusError extends Error{constructor(message,status=400){super(message);this.status=status}}
async function ready(env){
 try{await env.DB.prepare('SELECT asset_id FROM customer_finding_statuses LIMIT 1').first();return true}
 catch(_){return false}
}
async function ticketReady(env){
 try{await env.DB.prepare('SELECT asset_id FROM customer_finding_tickets LIMIT 1').first();return true}
 catch(_){return false}
}
export async function findingTicketRoute(req,env,user,path,data={}){
 if(path==='/v1/finding-tickets'&&req.method==='GET'){
  if(!await ticketReady(env))return response({ready:false,tickets:[]});
  const rows=await env.DB.prepare('SELECT t.asset_id,t.cve_id,t.ticket_number,t.updated_at FROM customer_finding_tickets t JOIN inventory_assets a ON a.id=t.asset_id AND a.user_id=t.user_id WHERE t.user_id=? ORDER BY t.updated_at DESC LIMIT 10000').bind(user.id).all();
  return response({ready:true,tickets:rows.results||[]});
 }
 if(!await ticketReady(env))throw new FindingStatusError('DevOps ticket migration is required',503);
 const match=/^\/v1\/finding-tickets\/([0-9a-f-]{36})\/(CVE-\d{4}-\d{4,})$/.exec(path);
 if(!match||req.method!=='PUT')return response({error:'Not found'},404);
 const [,assetId,cveId]=match;
 if(!validAsset(assetId)||!validCve(cveId))throw new FindingStatusError('Invalid asset or CVE identifier');
 const ticket=String(data.ticket_number??'').trim();
 if(!/^[A-Za-z0-9][A-Za-z0-9._#/-]{0,63}$/.test(ticket))throw new FindingStatusError('Ticket number must be 1 to 64 characters and contain only letters, numbers, dots, underscores, slashes or #');
 const asset=await env.DB.prepare('SELECT id FROM inventory_assets WHERE id=? AND user_id=?').bind(assetId,user.id).first();
 if(!asset)throw new FindingStatusError('Asset not found in your account',404);
 const existing=await env.DB.prepare('SELECT ticket_number FROM customer_finding_tickets WHERE user_id=? AND asset_id=? AND cve_id=?').bind(user.id,assetId,cveId).first();
 const finding=await env.DB.prepare('SELECT status FROM customer_finding_statuses WHERE user_id=? AND asset_id=? AND cve_id=?').bind(user.id,assetId,cveId).first();
 if(existing&&finding?.status==='Fixed/Patched')throw new FindingStatusError('DevOps ticket is locked after the finding is fixed',409);
 await env.DB.prepare('INSERT INTO customer_finding_tickets(user_id,asset_id,cve_id,ticket_number,updated_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(user_id,asset_id,cve_id) DO UPDATE SET ticket_number=excluded.ticket_number,updated_at=CURRENT_TIMESTAMP').bind(user.id,assetId,cveId,ticket).run();
 return response({saved:true,asset_id:assetId,cve_id:cveId,ticket_number:ticket});
}
export async function findingStatusRoute(req,env,user,path,data={}){
 const available=await ready(env);
 if(path==='/v1/finding-statuses'&&req.method==='GET'){
  if(!available)return response({ready:false,statuses:[]});
  const rows=await env.DB.prepare('SELECT s.asset_id,s.cve_id,s.status,s.notes,s.updated_at FROM customer_finding_statuses s JOIN inventory_assets a ON a.id=s.asset_id AND a.user_id=s.user_id WHERE s.user_id=? ORDER BY s.updated_at DESC LIMIT 10000').bind(user.id).all();
  return response({ready:true,statuses:rows.results||[]});
 }
 if(!available)throw new FindingStatusError('Finding status migration is required',503);
 const match=/^\/v1\/finding-statuses\/([0-9a-f-]{36})\/(CVE-\d{4}-\d{4,})$/.exec(path);
 if(!match||req.method!=='PUT')return response({error:'Not found'},404);
 const [,assetId,cveId]=match;
 if(!validAsset(assetId)||!validCve(cveId)||!allowed.has(data.status))throw new FindingStatusError('Invalid finding status');
 const notes=String(data.notes||'').trim();
 if(notes.length>1200||/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(notes))throw new FindingStatusError('Invalid notes');
 const owned=await env.DB.prepare('SELECT id FROM inventory_assets WHERE id=? AND user_id=?').bind(assetId,user.id).first();
 if(!owned)throw new FindingStatusError('Asset not found in your account',404);
 await env.DB.prepare(
  'INSERT INTO customer_finding_statuses(user_id,asset_id,cve_id,status,notes,updated_at) VALUES(?,?,?,?,?,CURRENT_TIMESTAMP) '+
  'ON CONFLICT(user_id,asset_id,cve_id) DO UPDATE SET status=excluded.status,notes=excluded.notes,updated_at=CURRENT_TIMESTAMP'
 ).bind(user.id,assetId,cveId,data.status,notes).run();
 return response({saved:true,asset_id:assetId,cve_id:cveId,status:data.status,notes});
}
