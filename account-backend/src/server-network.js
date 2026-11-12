// Private server identification metadata. Addresses are never scanned or sent to AI.
import {WorkflowError} from './remediation-workflow.js';
const fail=(message,status=400)=>{throw new WorkflowError(message,status);};
const text=(v,max,label)=>{if(typeof v!=='string'||!v.trim()||v.length>max||/[\x00-\x1f\x7f]/.test(v))fail('Invalid '+label);return v.trim();};
export const serverKey=name=>text(name,120,'hostname').toLowerCase();
export function address(value){
 const ip=text(value,64,'IP address');
 if(/^\d+\.\d+\.\d+\.\d+$/.test(ip)){if(!ip.split('.').every(n=>/^(0|[1-9]\d{0,2})$/.test(n)&&Number(n)<=255))fail('Invalid IPv4 address');return ip;}
 if(!/^[a-f0-9:]+$/i.test(ip)||!ip.includes(':'))fail('Invalid IPv6 address');
 try{return new URL('http://['+ip+']/').hostname.slice(1,-1);}catch{fail('Invalid IPv6 address');}
}
export function normalizeSnapshot(raw){
 if(!raw||raw.version!==1||!Array.isArray(raw.adapters)||!raw.adapters.length||raw.adapters.length>32)fail('Network inventory must contain 1–32 adapters.');
 const collected=text(raw.collected_at,40,'network collection date');
 if(!/^\d{4}-\d{2}-\d{2}T/.test(collected)||!Number.isFinite(Date.parse(collected))||Date.parse(collected)>Date.now()+86400000)fail('Invalid network collection date');
 const ids=new Set();let count=0;
 const adapters=raw.adapters.map(a=>{
  const id=text(a.id,80,'adapter ID'),name=text(a.name,120,'adapter name'),status=text(a.status,32,'adapter status');
  if(ids.has(id))fail('Duplicate adapter ID');ids.add(id);
  if(!Array.isArray(a.addresses)||a.addresses.length>64)fail('Invalid adapter addresses');
  const seen=new Set();
  const addresses=a.addresses.map(p=>{const ip=address(p.ip),family=ip.includes(':')?'IPv6':'IPv4';
   if(seen.has(ip))fail('Duplicate adapter address');seen.add(ip);count++;
   if(!Number.isInteger(p.prefix)||p.prefix<0||p.prefix>(family==='IPv4'?32:128))fail('Invalid address prefix');
   return {ip,family,prefix:p.prefix,state:text(p.state,32,'address state'),skip_source:p.skip_source===true};
  });
  return {id,name,status,addresses};
 });
 if(count>128)fail('Network inventory exceeds 128 addresses.');
 let suggested=null;
 if(raw.suggested){const ip=address(raw.suggested.ip);if(!adapters.some(a=>a.id===raw.suggested.adapter_id&&a.addresses.some(p=>p.ip===ip)))fail('Suggested primary is not in the inventory');suggested={adapter_id:raw.suggested.adapter_id,ip};}
 const value={version:1,collected_at:new Date(collected).toISOString(),adapters,suggested};
 if(JSON.stringify(value).length>14000)fail('Network inventory exceeds 14 KB.');return value;
}
const columns='n.environment_id,n.server_key,n.snapshot,n.primary_adapter,n.primary_ip,n.revision';
export function networkRows(db,owner,environment='',team){
 let joins=' JOIN inventory_environments e ON e.id=n.environment_id AND e.user_id=n.user_id',where='n.user_id=?',args=[owner];
 if(team){joins+=' JOIN team_visible_customers v ON v.customer_id=e.customer_id AND v.data_owner=e.user_id';where+=' AND v.org=? AND v.actor=? AND v.customer_id=?';args.push(team.org,team.actor,team.customer);}
 if(environment){where+=' AND e.id=?';args.push(environment);}
 return db.prepare('SELECT '+columns+' FROM inventory_server_network n'+joins+' WHERE '+where+' AND EXISTS(SELECT 1 FROM inventory_assets a WHERE a.user_id=n.user_id AND a.environment_id=n.environment_id AND lower(trim(a.name))=n.server_key) ORDER BY n.environment_id,n.server_key LIMIT 3000').bind(...args);
}
export function unpack(rows){return rows.map(r=>({...r,snapshot:JSON.parse(r.snapshot)}));}
export async function saveNetwork(db,owner,data,method,guards=[]){
 const key=serverKey(data.name),environment=text(data.environment_id,36,'environment'),scope=[owner,environment,key];
 if(!/^[a-f0-9-]{36}$/i.test(environment))fail('Invalid environment');
 const owned="EXISTS(SELECT 1 FROM inventory_assets a JOIN inventory_environments e ON e.id=a.environment_id AND e.user_id=a.user_id WHERE a.user_id=? AND a.environment_id=? AND lower(trim(a.name))=?)";
 if(!(await db.prepare('SELECT '+owned+' AS ok').bind(...scope).first()).ok)fail('Server unavailable in this environment.',404);
 const old=await db.prepare('SELECT snapshot,primary_adapter,primary_ip,revision FROM inventory_server_network WHERE user_id=? AND environment_id=? AND server_key=?').bind(...scope).first();
 let snapshot,adapter=old?.primary_adapter||'',ip=old?.primary_ip||'';
 if(method==='POST'){
  snapshot=normalizeSnapshot(data.snapshot);
  if(old){const prev=JSON.parse(old.snapshot);
   if(Date.parse(snapshot.collected_at)<Date.parse(prev.collected_at))fail('A newer network inventory is already saved. Collect again before importing.',409);
   if(snapshot.collected_at===prev.collected_at&&JSON.stringify(snapshot)!==JSON.stringify(prev))fail('Conflicting network inventories have the same collection date.',409);
  }
 }else{
  if(!old||data.revision!==old.revision)fail('Server details changed. Refresh before saving.',409);
  snapshot=JSON.parse(old.snapshot);adapter=text(data.adapter_id,80,'primary adapter');ip=address(data.ip);
  if(!snapshot.adapters.some(a=>a.id===adapter&&a.addresses.some(p=>p.ip===ip)))fail('Select an address present on the chosen adapter.');
 }
 const revision=crypto.randomUUID();
 const expected=old?'EXISTS(SELECT 1 FROM inventory_server_network WHERE user_id=? AND environment_id=? AND server_key=? AND revision=?)':'NOT EXISTS(SELECT 1 FROM inventory_server_network WHERE user_id=? AND environment_id=? AND server_key=?)';
 const admission=db.prepare('SELECT CASE WHEN '+owned+' AND '+expected+' THEN 1 ELSE abs(-9223372036854775808) END').bind(...scope,...scope,...(old?[old.revision]:[]));
 const statement=db.prepare('INSERT INTO inventory_server_network(user_id,environment_id,server_key,snapshot,primary_adapter,primary_ip,revision) VALUES(?,?,?,?,?,?,?) ON CONFLICT(user_id,environment_id,server_key) DO UPDATE SET snapshot=excluded.snapshot,primary_adapter=excluded.primary_adapter,primary_ip=excluded.primary_ip,revision=excluded.revision').bind(...scope,JSON.stringify(snapshot),adapter,ip,revision);
 try{await db.batch([...guards,admission,statement]);}catch(e){if(/constraint|overflow/i.test(e.message))fail('Server details or access changed. Refresh and try again.',409);throw e;}
 return {saved:true,environment_id:environment,server_key:key,snapshot,primary_adapter:adapter,primary_ip:ip,revision};
}
