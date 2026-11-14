import {AgentError,fail,hash,token,now,text,exact,readBody,snapshot,changes,roles} from './agent-validation.js';
const stmt=(db,sql,...args)=>db.prepare(sql).bind(...args);
const list=async q=>(await q.all()).results||[];
const reply=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
export function agentEnabled(env){return env.WINDOWS_AGENT_ENABLED==='true';}
function installed(env){if(!agentEnabled(env)||env.AGENT_INVENTORY_SCHEMA!=='1')fail('Windows agent is not available yet',503);}
const deviceColumns='id,hostname,agent_version,state,last_seen,last_sync,daily,primary_ip,primary_adapter,roles,revision,requested,completed_request';
async function scope(env,user,url,write=false){
 const customer=url.searchParams.get('customer_id')||'',environment=url.searchParams.get('environment_id')||'',org=url.searchParams.get('org')||'';
 if(!/^[a-f0-9-]{36}$/i.test(customer)||! /^[a-f0-9-]{36}$/i.test(environment))fail('Select a customer and environment');
 let predicate,args,owner,role;
 if(org){
  predicate="EXISTS(SELECT 1 FROM team_visible_customers v JOIN inventory_environments e ON e.customer_id=v.customer_id AND e.user_id=v.data_owner WHERE v.org=? AND v.actor=? AND v.customer_id=? AND e.id=?"+(write?" AND v.role IN ('Owner','Editor')":'')+')';args=[org,user.id,customer,environment];
  const row=await stmt(env.DB,'SELECT data_owner,role FROM team_visible_customers WHERE org=? AND actor=? AND customer_id=?',org,user.id,customer).first();owner=row?.data_owner;role=row?.role;
 }else{predicate='EXISTS(SELECT 1 FROM inventory_environments e JOIN inventory_customers c ON c.id=e.customer_id AND c.user_id=e.user_id WHERE e.id=? AND e.customer_id=? AND e.user_id=?)';args=[environment,customer,user.id];owner=user.id;role='Owner';}
 if(!owner||!(await stmt(env.DB,'SELECT '+predicate+' AS ok',...args).first()).ok)fail('Customer environment unavailable',404);
 return {owner,customer,environment,org,role,predicate,args};
}
function guard(db,s,user,action,device=null,extra='1',args=[]){return stmt(db,'INSERT INTO inventory_agent_audit(device_id,actor,action,at,authorized) VALUES(?,?,?,?,('+s.predicate+') AND ('+extra+'))',device,user.id,action,now(),...s.args,...args);}
async function scopedDevice(db,s,id){const d=await stmt(db,'SELECT * FROM inventory_agents WHERE id=? AND user_id=? AND customer_id=? AND environment_id=? AND org_id=?',id,s.owner,s.customer,s.environment,s.org).first();if(!d)fail('Device unavailable',404);return d;}
const revisionGuard=d=>['EXISTS(SELECT 1 FROM inventory_agents WHERE id=? AND revision=? AND state=?)',[d.id,d.revision,d.state]];
async function transaction(db,statements){try{return await db.batch(statements);}catch(error){if(/CHECK constraint|UNIQUE constraint/i.test(String(error.message)))fail('Device or access changed. Refresh and retry.',409);throw error;}}
async function projection(db,d,snap){
 const entries=[];
 for(const p of snap.products){const key=JSON.stringify([p.name.toLowerCase(),p.version.toLowerCase()]),digest=await hash(d.id+':'+key),id=[digest.slice(0,8),digest.slice(8,12),'4'+digest.slice(13,16),'8'+digest.slice(17,20),digest.slice(20,32)].join('-');entries.push({id,key,name:p.name,version:p.version,notes:('Server role: '+JSON.parse(d.roles).join(' / ')+'; Agent-managed; '+p.details).slice(0,500)});}
 const writes=[];
 if(snap.complete)writes.push(stmt(db,'UPDATE inventory_agent_assets SET active=0 WHERE device_id=?',d.id));
 for(let i=0;i<entries.length;i+=100){const json=JSON.stringify(entries.slice(i,i+100));
  writes.push(stmt(db,`INSERT INTO inventory_assets(id,user_id,environment_id,name,asset_type,technology,version,notes)
   SELECT json_extract(value,'$.id'),?,?,?,'Server',json_extract(value,'$.name'),json_extract(value,'$.version'),json_extract(value,'$.notes') FROM json_each(?) WHERE 1
   ON CONFLICT(id) DO UPDATE SET name=excluded.name,notes=excluded.notes`,d.user_id,d.environment_id,snap.hostname,json));
  writes.push(stmt(db,`INSERT INTO inventory_agent_assets(asset_id,device_id,product_key,active) SELECT json_extract(value,'$.id'),?,json_extract(value,'$.key'),1 FROM json_each(?) WHERE 1 ON CONFLICT(asset_id) DO UPDATE SET active=1`,d.id,json));
 }
 // Bump inventory revision even when only active flags changed.
 writes.push(stmt(db,'UPDATE inventory_capacity_revisions SET revision=revision+1 WHERE user_id=?',d.user_id));
 return writes;
}
async function accept(db,d,snap,guards=[]){
 const previous=d.accepted?JSON.parse(d.accepted):null,delta=changes(previous,snap);
 // Incomplete collections can add observations, but cannot remove earlier observations.
 if(!snap.complete&&previous){const keys=new Set(snap.products.map(p=>JSON.stringify([p.name.toLowerCase(),p.version.toLowerCase()])));snap={...snap,products:[...snap.products,...previous.products.filter(p=>!keys.has(JSON.stringify([p.name.toLowerCase(),p.version.toLowerCase()]))) ]};}
 if(snap.products.length>10000||new TextEncoder().encode(JSON.stringify(snap)).length>2097152)fail('Combined inventory exceeds the device limit',413);
 const network=snap.network,selected=network?.adapters.some(a=>a.id===d.primary_adapter&&a.addresses.some(p=>p.ip===d.primary_ip));
 const primary=selected?{adapter_id:d.primary_adapter,ip:d.primary_ip}:d.primary_ip?{adapter_id:d.primary_adapter,ip:d.primary_ip}:network?.suggested;
 await transaction(db,[...guards,...await projection(db,d,snap),
  stmt(db,'INSERT INTO inventory_agent_history(device_id,received_at,sequence,snapshot,changes) VALUES(?,?,?,?,?)',d.id,now(),snap.sequence,JSON.stringify(snap),JSON.stringify(delta)),
  stmt(db,"UPDATE inventory_agents SET state='active',hostname=?,agent_version=?,accepted=?,pending=NULL,pending_hash='',last_sync=?,completed_request=MAX(completed_request,?),primary_ip=?,primary_adapter=?,reviewed_large_change=0,revision=revision+1 WHERE id=?",snap.hostname,snap.agent_version,JSON.stringify(snap),now(),snap.request,primary?.ip||'',primary?.adapter_id||'',d.id)]);
}
async function recipients(db,d){
 const configured=await list(stmt(db,'SELECT email FROM inventory_agent_contacts WHERE user_id=? AND customer_id=?',d.user_id,d.customer_id));
 if(configured.length)return configured.map(r=>r.email);
 if(d.org_id)return (await list(stmt(db,"SELECT email FROM team_members WHERE org=? AND role='Owner' AND user_id IS NOT NULL",d.org_id))).map(r=>r.email);
 return [(await stmt(db,'SELECT email FROM users WHERE id=?',d.user_id).first())?.email].filter(Boolean);
}
export async function suspend(env,d,reason){
 const id=crypto.randomUUID(),targets=[...new Set([...(await recipients(env.DB,d)),env.AGENT_SUPPORT_EMAIL||'prat.mahen@gmail.com'])];
 await transaction(env.DB,[
  stmt(env.DB,"UPDATE inventory_agents SET state='suspended',revision=revision+1 WHERE id=? AND state IN ('review','active')",d.id),
  stmt(env.DB,"INSERT OR IGNORE INTO inventory_agent_incidents(id,device_id,reason,opened_at) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM inventory_agents WHERE id=? AND state='suspended')",id,d.id,reason,now(),d.id),
  ...targets.map(email=>stmt(env.DB,'INSERT OR IGNORE INTO inventory_agent_mail(incident_id,recipient) SELECT id,? FROM inventory_agent_incidents WHERE device_id=? AND resolved_at IS NULL',email,d.id))]);
}
async function invalid(env,d,error){
 const t=now();await stmt(env.DB,'UPDATE inventory_agents SET invalid_count=CASE WHEN invalid_since<? THEN 1 ELSE invalid_count+1 END,invalid_since=CASE WHEN invalid_since<? THEN ? ELSE invalid_since END WHERE id=?',t-3600,t-3600,t,d.id).run();
 const row=await stmt(env.DB,'SELECT invalid_count FROM inventory_agents WHERE id=?',d.id).first();
 if(row.invalid_count>=3||error.status===413)await suspend(env,d,error.status===413?'Upload exceeded the permitted size.':'Repeated invalid inventory uploads within one hour. Check agent logs, version and server integrity.');
}
export async function agentDeviceRoute(req,env){
 try{
  installed(env);if(req.headers.has('origin')||req.headers.has('cookie'))fail('Agent credentials required',403);
  const path=new URL(req.url).pathname;
  if(req.method!=='POST'||!['/v1/agent/enroll','/v1/agent/poll','/v1/agent/upload'].includes(path))return reply({error:'Not found'},404);
  if(!env.AGENT_RATE_LIMITER||!env.AGENT_SOURCE_RATE_LIMITER)fail('Agent protection unavailable',503);
  const ip=await hash(req.headers.get('CF-Connecting-IP')||'unknown');if(!(await env.AGENT_SOURCE_RATE_LIMITER.limit({key:'source:'+ip})).success)fail('Request limit exceeded',429);
  if(path.endsWith('/enroll')){
   const data=await readBody(req,4096);exact(data,['code','hostname','agent_version']);
   if(!/^[a-f0-9]{64}$/.test(data.code||''))fail('Enrollment unavailable',401);
   const hostname=text(data.hostname,120,'hostname'),version=text(data.agent_version,30,'agent version');if(!/^1\.\d+\.\d+$/.test(version))fail('Unsupported agent version');
   const digest=await hash(data.code),e=await stmt(env.DB,'SELECT n.*,c.name AS customer_name,v.name AS environment_name FROM inventory_agent_enrollments n JOIN inventory_customers c ON c.id=n.customer_id AND c.user_id=n.user_id JOIN inventory_environments v ON v.id=n.environment_id AND v.customer_id=c.id AND v.user_id=n.user_id WHERE token_hash=? AND consumed_at IS NULL AND expires_at>?',digest,now()).first();
   if(!e)fail('Enrollment unavailable or expired',401);
   if(e.org_id&&!await stmt(env.DB,"SELECT 1 FROM team_visible_customers WHERE org=? AND actor=? AND customer_id=? AND data_owner=? AND role IN ('Owner','Editor')",e.org_id,e.created_by,e.customer_id,e.user_id).first())fail('Enrollment unavailable',401);
   const id=crypto.randomUUID(),secret=token();
   const enrollmentScope=await scope(env,{id:e.created_by},new URL('https://api.cveharbor.com/?'+new URLSearchParams({customer_id:e.customer_id,environment_id:e.environment_id,org:e.org_id})),true);
   await transaction(env.DB,[guard(env.DB,enrollmentScope,{id:e.created_by},'enroll',null,"EXISTS(SELECT 1 FROM inventory_agent_enrollments WHERE token_hash=? AND consumed_at IS NULL AND expires_at>?) AND (SELECT COUNT(*) FROM inventory_agents WHERE user_id=? AND state!='revoked')<1000",[digest,now(),e.user_id]),
    stmt(env.DB,'INSERT INTO inventory_agents(id,user_id,customer_id,environment_id,org_id,token_hash,hostname,agent_version,created_at) VALUES(?,?,?,?,?,?,?,?,?)',id,e.user_id,e.customer_id,e.environment_id,e.org_id,await hash(secret),hostname,version,now()),
    stmt(env.DB,'UPDATE inventory_agent_enrollments SET consumed_at=? WHERE token_hash=?',now(),digest)]);
   return reply({device_id:id,credential:secret,customer:e.customer_name,environment:e.environment_name,poll_seconds:300},201);
  }
  const credential=/^Bearer ([a-f0-9]{64})$/.exec(req.headers.get('authorization')||'');if(!credential)fail('Agent authentication required',401);
  const d=await stmt(env.DB,'SELECT a.* FROM inventory_agents a JOIN inventory_environments e ON e.id=a.environment_id AND e.user_id=a.user_id AND e.customer_id=a.customer_id WHERE a.token_hash=?',await hash(credential[1])).first();
  if(!d||d.state==='revoked')fail('Agent credential unavailable',401);
  if(d.state==='suspended')return reply({error:'Uploads suspended. An authorized customer administrator must review the incident.',suspended:true},423);
  if(!(await env.AGENT_RATE_LIMITER.limit({key:'device:'+d.id})).success){await suspend(env,d,'Excessive authenticated agent requests. Check for a retry loop or unauthorized activity.');fail('Uploads suspended',423);}
  if(path.endsWith('/poll')){
   const data=await readBody(req,1024);exact(data,[]);
   await stmt(env.DB,'UPDATE inventory_agents SET last_seen=? WHERE id=?',now(),d.id).run();
   return reply({collect:!d.pending&&(d.requested>d.completed_request||!!d.daily&&(!d.last_sync||now()-d.last_sync>=86400)),request:d.requested,sequence:d.last_sequence+1,poll_seconds:300});
  }
  let snap;
  try{snap=snapshot(await readBody(req));}catch(error){if(error instanceof AgentError)await invalid(env,d,error);throw error;}
  const digest=await hash(JSON.stringify(snap));
  if(snap.sequence===d.last_sequence&&digest===d.last_hash)return reply({accepted:true,review_required:!!d.pending,sequence:snap.sequence});
  if(snap.sequence<=d.last_sequence||snap.request>d.requested||snap.sequence!==d.last_sequence+1)fail('Collection sequence changed. Poll before collecting again.',409);
  if(d.pending)fail('First inventory is waiting for customer review',409);
  const previous=d.accepted?JSON.parse(d.accepted):null,delta=changes(previous,snap);
  if(previous&&snap.complete&&!d.reviewed_large_change&&previous.products.length>=10&&delta.removed.length/previous.products.length>0.5){await suspend(env,d,'More than half of previously observed software disappeared in one complete collection. Verify maintenance or collection problems before accepting changes.');return reply({error:'Unexpected inventory removal; uploads suspended',suspended:true},423);}
  const [condition,args]=revisionGuard(d),writeGuard=stmt(env.DB,"INSERT INTO inventory_agent_audit(device_id,actor,action,at,authorized) VALUES(?,?,'upload',?,("+condition+'))',d.id,'agent:'+d.id,now(),...args);
  const received=stmt(env.DB,'UPDATE inventory_agents SET last_sequence=?,last_hash=?,last_seen=?,invalid_count=0 WHERE id=?',snap.sequence,digest,now(),d.id);
  if(d.state==='review')await transaction(env.DB,[writeGuard,received,stmt(env.DB,'UPDATE inventory_agents SET pending=?,pending_hash=?,revision=revision+1 WHERE id=?',JSON.stringify(snap),digest,d.id)]);
  else await accept(env.DB,d,snap,[writeGuard,received]);
  return reply({accepted:true,review_required:d.state==='review',sequence:snap.sequence});
 }catch(error){if(error instanceof AgentError)return reply({error:error.message},error.status);return reply({error:'Agent service temporarily unavailable'},503);}
}
export async function agentManagement(req,env,user){
 installed(env);const url=new URL(req.url),write=req.method!=='GET',s=await scope(env,user,url,write),db=env.DB;
 const route=/^\/v1\/agents(?:\/([a-f0-9-]{36}))?(?:\/(enrollment|contacts|confirm|sync|settings|history|incident|resume|revoke))?$/.exec(url.pathname);if(!route)fail('Not found',404);
 const id=route[1],action=route[2]||'';
 if(!id&&!action&&req.method==='GET'){
  const devices=await list(stmt(db,'SELECT '+deviceColumns+',json_array_length(json_extract(COALESCE(pending,accepted),\'$.products\')) AS software_count FROM inventory_agents WHERE user_id=? AND customer_id=? AND environment_id=? AND org_id=? ORDER BY hostname,id LIMIT 1000',s.owner,s.customer,s.environment,s.org));
  return {devices,can_edit:s.role!=='Viewer',can_admin:s.role==='Owner',installer: /^[a-f0-9]{64}$/.test(env.AGENT_INSTALLER_SHA256||'')?{url:'https://cveharbor.com/collectors/agent/CVEHarbor-Agent.msi',sha256:env.AGENT_INSTALLER_SHA256,channel:env.AGENT_DISTRIBUTION||'evaluation'}:null};
 }
 if(['contacts','resume','revoke'].includes(action)&&write&&s.org){s.predicate=s.predicate.replace("v.role IN ('Owner','Editor')","v.role='Owner'");}
 if(action==='contacts'){
  if(req.method==='GET')return {contacts:await list(stmt(db,'SELECT email FROM inventory_agent_contacts WHERE user_id=? AND customer_id=?',s.owner,s.customer))};
  if(req.method!=='POST'||s.role!=='Owner')fail('Owner access required',403);
  const data=await readBody(req,4096);exact(data,['emails']);if(!Array.isArray(data.emails)||data.emails.length>10)fail('Use up to ten security contacts');
  const emails=[...new Set(data.emails.map(e=>text(e,254,'email').toLowerCase()))];if(emails.some(e=>!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(e)))fail('Invalid email address');
  await transaction(db,[guard(db,s,user,'security contacts'),stmt(db,'DELETE FROM inventory_agent_contacts WHERE user_id=? AND customer_id=?',s.owner,s.customer),...emails.map(e=>stmt(db,'INSERT INTO inventory_agent_contacts VALUES(?,?,?)',s.owner,s.customer,e))]);return {saved:true};
 }
 if(!id&&action==='enrollment'&&req.method==='POST'){
  if(!/^[a-f0-9]{64}$/.test(env.AGENT_INSTALLER_SHA256||''))fail('Installer release is not ready',503);
  const consent=await readBody(req,1024);if((env.AGENT_DISTRIBUTION||'evaluation')==='evaluation'&&consent.evaluation_accepted!==true)fail('Acknowledge the unsigned evaluation installer before enrolling');
  const value=token(),expires=now()+900;
  const outstanding=await stmt(db,'SELECT COUNT(*) n FROM inventory_agent_enrollments WHERE user_id=? AND expires_at>? AND consumed_at IS NULL',s.owner,now()).first();if(outstanding.n>=20)fail('Too many unused enrollment codes. Use a code or wait for expiry.',429);
  await transaction(db,[guard(db,s,user,'create enrollment'),stmt(db,'INSERT INTO inventory_agent_enrollments(token_hash,user_id,customer_id,environment_id,org_id,expires_at,created_by) VALUES(?,?,?,?,?,?,?)',await hash(value),s.owner,s.customer,s.environment,s.org,expires,user.id)]);
  return {code:value,expires_at:expires};
 }
 const d=await scopedDevice(db,s,id);
 if(req.method==='GET'){
  if(action==='history')return {entries:await list(stmt(db,'SELECT sequence,received_at,changes FROM inventory_agent_history WHERE device_id=? ORDER BY sequence DESC LIMIT 90',d.id))};
  if(action==='incident')return {incidents:await list(stmt(db,'SELECT id,reason,opened_at,resolved_at,resolution FROM inventory_agent_incidents WHERE device_id=? ORDER BY opened_at DESC LIMIT 20',d.id)),notifications:await list(stmt(db,'SELECT m.state,m.attempts FROM inventory_agent_mail m JOIN inventory_agent_incidents i ON i.id=m.incident_id WHERE i.device_id=? AND i.resolved_at IS NULL',d.id))};
  if(!action)return {device:Object.fromEntries(deviceColumns.split(',').map(k=>[k,d[k]])),snapshot:JSON.parse(d.pending||d.accepted||'null'),pending_hash:d.pending_hash};
 }
 if(req.method!=='POST')fail('Not found',404);
 const data=await readBody(req,4096),[condition,args]=revisionGuard(d),check=guard(db,s,user,action,d.id,condition,args);
 if(data.revision!==d.revision)fail('Device changed. Refresh and retry.',409);
 if(action==='confirm'){
  if(d.state!=='review'||!d.pending||data.pending_hash!==d.pending_hash)fail('Inventory review changed',409);
  if(data.daily!==true)fail('Confirm daily synchronization before continuing');
  const snap=JSON.parse(d.pending);await accept(db,d,snap,[check]);return {accepted:true};
 }
 if(action==='sync'){
  if(!['active','review'].includes(d.state))fail('Resolve the incident or re-enroll the device first',409);
  if(d.pending)fail('Review the first inventory before requesting another collection',409);
  await transaction(db,[check,stmt(db,'UPDATE inventory_agents SET requested=requested+1,revision=revision+1 WHERE id=? AND requested=completed_request',d.id)]);return {queued:true};
 }
 if(action==='settings'){
  if(!Array.isArray(data.roles)||!data.roles.length||data.roles.length>8||data.roles.some(r=>!roles.includes(r))||typeof data.daily!=='boolean')fail('Invalid device settings');
  const snap=JSON.parse(d.pending||d.accepted||'null'),ip=data.primary_ip||'',adapter=data.primary_adapter||'';
  if(ip&&!snap?.network?.adapters.some(a=>a.id===adapter&&a.addresses.some(p=>p.ip===ip)))fail('Choose an address from this device inventory');
  const recordedRoles=JSON.stringify([...new Set(data.roles)]);
  await transaction(db,[check,stmt(db,'UPDATE inventory_agents SET roles=?,daily=?,primary_ip=?,primary_adapter=?,revision=revision+1 WHERE id=?',recordedRoles,data.daily?1:0,ip,adapter,d.id),
   stmt(db,"UPDATE inventory_assets SET notes='Server role: ' || ? || '; Agent-managed' WHERE id IN (SELECT asset_id FROM inventory_agent_assets WHERE device_id=? AND active=1)",JSON.parse(recordedRoles).join(' / '),d.id)]);return {saved:true};
 }
 if(action==='resume'){
  if(s.role!=='Owner')fail('Owner access required',403);if(d.state!=='suspended')fail('Device is not suspended',409);
  const reason=text(data.reason,500,'review reason');if(data.credential_safe!==true)fail('Revoke and re-enroll if the device credential may be compromised');
  await transaction(db,[check,stmt(db,"UPDATE inventory_agents SET state=?,requested=requested+1,invalid_count=0,reviewed_large_change=?,revision=revision+1 WHERE id=?",d.accepted?'active':'review',data.approve_large_change===true?1:0,d.id),stmt(db,'UPDATE inventory_agent_incidents SET resolved_at=?,resolved_by=?,resolution=? WHERE device_id=? AND resolved_at IS NULL',now(),user.id,reason,d.id)]);return {resumed:true};
 }
 if(action==='revoke'){
  if(s.role!=='Owner')fail('Owner access required',403);
  await transaction(db,[check,stmt(db,"UPDATE inventory_agents SET state='revoked',token_hash=?,revision=revision+1 WHERE id=?",await hash(token()),d.id)]);return {revoked:true};
 }
 fail('Not found',404);
}
