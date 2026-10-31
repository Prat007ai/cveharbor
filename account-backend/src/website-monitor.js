import {lookupWebsiteThreat,assessHttpHeaders} from './website-threat.js';
// Tenant-scoped public website monitoring. Only low-impact HTTPS checks are enabled.
const json=(value,status=200)=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json','cache-control':'no-store','access-control-allow-origin':'https://cveharbor.com','access-control-allow-credentials':'true','vary':'Origin'}});
const now=()=>Math.floor(Date.now()/1000);
export function normalizeWebsite(input){
 const u=new URL(String(input||''));
 if(u.protocol!=='https:'||u.username||u.password||u.port||u.search||u.hash||u.pathname!=='/')throw Error('Use an HTTPS site origin without paths, ports or credentials');
 const host=u.hostname.toLowerCase().replace(/\.$/,'');
 if(host.length>253||!host.includes('.')||host==='localhost'||host.endsWith('.local')||host.endsWith('.internal')||host.endsWith('.test')||host.endsWith('.localhost')||host.endsWith('.onion')||host.endsWith('.example')||host.endsWith('.invalid')||host.endsWith('.arpa')||host.endsWith('.home')||host.endsWith('.lan')||host.endsWith('.corp')||host.endsWith('.localhost')||!(/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(host))||/^\d+(?:\.\d+){3}$/.test(host))throw Error('A public hostname is required');
 return 'https://'+host+'/';
}
export async function route(req,env,user,path,data={}){
 if(!env.DB)return json({error:'Storage unavailable'},503);
 try{
  if(path==='/v1/website-monitor/status'&&req.method==='GET'){
   await env.DB.prepare('SELECT id FROM website_monitors LIMIT 1').first();
   return json({ready:true,automatic_checks:env.WEBSITE_MONITOR_ENABLED==='true'});
  }
  if(path==='/v1/website-monitor'&&req.method==='GET'){
   const rows=await env.DB.prepare('SELECT id,url,label,profile,enabled,last_checked_at,last_status,last_error,created_at FROM website_monitors WHERE user_id=? ORDER BY created_at DESC LIMIT 100').bind(user.id).all();
   return json({monitors:rows.results||[]});
  }
  if(path==='/v1/website-monitor'&&req.method==='POST'){
   const url=normalizeWebsite(data.url);
   if(data.authorized!==true)return json({error:'Monitoring authorization confirmation required'},400);
   const profile=['basic','enhanced'].includes(data.profile)?data.profile:'basic';
   const label=String(data.label||new URL(url).hostname).trim().slice(0,100);
   const count=await env.DB.prepare('SELECT COUNT(*) AS n FROM website_monitors WHERE user_id=?').bind(user.id).first();
   if((count?.n||0)>=25)return json({error:'Website limit reached'},429);
   const id=crypto.randomUUID(),timestamp=now();
   await env.DB.prepare('INSERT INTO website_monitors(id,user_id,url,label,profile,enabled,created_at) VALUES(?,?,?,?,?,1,?)').bind(id,user.id,url,label,profile,timestamp).run();
   return json({id,url,label,profile,enabled:1},201);
  }
  const runMatch=/^\/v1\/website-monitor\/([0-9a-f-]{36})\/check$/.exec(path);
  if(runMatch&&req.method==='POST'){
   if(env.WEBSITE_MONITOR_MANUAL_ENABLED!=='true')return json({error:'Manual checks are not enabled on this deployment'},503);
   const id=runMatch[1],time=now();
   const claim=await env.DB.prepare('UPDATE website_monitors SET last_checked_at=? WHERE id=? AND user_id=? AND enabled=1 AND (last_checked_at IS NULL OR last_checked_at<?)').bind(time,id,user.id,time-600).run();
   if(claim.meta.changes!==1)return json({error:'Website not found or check cooldown active. Retry after 10 minutes.'},429);
   const site=await env.DB.prepare('SELECT id,user_id,url FROM website_monitors WHERE id=? AND user_id=?').bind(id,user.id).first();
   const result=await checkSite(env,site);
   return json({check:result});
  }
  const match=/^\/v1\/website-monitor\/([0-9a-f-]{36})$/.exec(path);
  if(match&&req.method==='DELETE'){
   const result=await env.DB.prepare('DELETE FROM website_monitors WHERE id=? AND user_id=?').bind(match[1],user.id).run();
   return json({deleted:result.meta.changes===1});
  }
  if(path==='/v1/website-monitor/history'&&req.method==='GET'){
   const id=new URL(req.url).searchParams.get('id')||'';
   if(!/^[0-9a-f-]{36}$/.test(id))return json({error:'Invalid monitor'},400);
   const rows=await env.DB.prepare('SELECT checked_at,http_status,content_type,security_headers,changed,error FROM website_monitor_checks WHERE monitor_id=? AND user_id=? ORDER BY checked_at DESC LIMIT 30').bind(id,user.id).all();
   return json({checks:rows.results||[]});
  }
  return json({error:'Not found'},404);
 }catch(e){if(/no such table/i.test(String(e.message)))return json({error:'Website monitoring database migration required'},503);return json({error:'Unable to process website monitoring request'},500)}
}
function publicIpv4(value){
 const parts=value.split('.');if(parts.length!==4||parts.some(p=>!/^\d{1,3}$/.test(p)||Number(p)>255))return false;
 const a=Number(parts[0]),b=Number(parts[1]),c=Number(parts[2]);
 return a!==0&&a!==10&&a!==127&&a<224&&!(a===169&&b===254)&&!(a===172&&b>=16&&b<=31)&&!(a===192&&b===168)&&!(a===100&&b>=64&&b<=127)&&!(a===192&&b===0&&c===0)&&!(a===192&&b===0&&c===2)&&!(a===198&&b===18)&&!(a===198&&b===19)&&!(a===198&&b===51&&c===100)&&!(a===203&&b===0&&c===113);
}
export function publicDnsAnswer(answer){
 const value=String(answer.data||'').toLowerCase();
 if(answer.type===1)return publicIpv4(value);
 if(answer.type===28)return /^[0-9a-f:]+$/.test(value)&&value.includes(':')&&!value.startsWith('fc')&&!value.startsWith('fd')&&!value.startsWith('fe8')&&!value.startsWith('fe9')&&!value.startsWith('fea')&&!value.startsWith('feb')&&value!=='::1'&&!value.startsWith('::ffff:');
 return true;
}
async function validateDns(origin){
 const hostname=new URL(origin).hostname;
 let found=false;
 for(const type of ['A','AAAA']){
  const url='https://cloudflare-dns.com/dns-query?name='+encodeURIComponent(hostname)+'&type='+type;
  const response=await fetch(url,{headers:{accept:'application/dns-json'},signal:AbortSignal.timeout(4000)});
  if(!response.ok)throw Error('DNS verification unavailable');
  const data=await response.json();
  if(data.Status!==0&&data.Status!==3)throw Error('DNS verification unavailable');
  for(const answer of data.Answer||[]){
   if(answer.type===1||answer.type===28){found=true;if(!publicDnsAnswer(answer))throw Error('DNS resolves to an unapproved IP range')}
  }
 }
 if(!found)throw Error('No public DNS address found');
}
export async function checkSite(env,site,fetcher=fetch){
  const checkedAt=now();let status=null,contentType='',headers={},error='';
  try{
   const url=normalizeWebsite(site.url);
   if(fetcher===fetch)await validateDns(url);
   const response=await fetcher(url,{method:'HEAD',redirect:'manual',signal:AbortSignal.timeout(7000),headers:{'user-agent':'CVEHarbor-SecurityMonitor/1.0'}});
   status=response.status;
   contentType=String(response.headers.get('content-type')||'').slice(0,150);
   for(const key of ['strict-transport-security','content-security-policy','x-content-type-options','referrer-policy','x-frame-options','location'])headers[key]=String(response.headers.get(key)||'').slice(0,500);
  }catch(e){error='Check failed: '+String(e.name||'network').slice(0,40)}
  const securityFindings=assessHttpHeaders(headers,status);
  const threat=error?{provider:'Google Web Risk',status:'not_checked',threats:[]}:await lookupWebsiteThreat(site.url,env);
  const evidence={http_headers:headers,http_findings:securityFindings,threat_intelligence:threat};
  const previous=await env.DB.prepare('SELECT http_status,security_headers FROM website_monitor_checks WHERE monitor_id=? AND user_id=? ORDER BY checked_at DESC LIMIT 1').bind(site.id,site.user_id).first();
  let previousHeaders={};
  try{const saved=JSON.parse(previous?.security_headers||'{}');previousHeaders=saved.http_headers||saved}catch{}
  const changed=previous&&((previous.http_status!==status)||(JSON.stringify(previousHeaders)!==JSON.stringify(headers)))?1:0;
  await env.DB.prepare('INSERT INTO website_monitor_checks(id,monitor_id,user_id,checked_at,http_status,content_type,security_headers,changed,error) VALUES(?,?,?,?,?,?,?,?,?)').bind(crypto.randomUUID(),site.id,site.user_id,checkedAt,status,contentType,JSON.stringify(evidence),changed,error).run();
  await env.DB.prepare('UPDATE website_monitors SET last_checked_at=?,last_status=?,last_error=? WHERE id=? AND user_id=?').bind(checkedAt,status,error,site.id,site.user_id).run();
  return {checked_at:checkedAt,http_status:status,content_type:contentType,security_headers:headers,http_findings:securityFindings,threat_intelligence:threat,changed:!!changed,error};
}
export async function scanDue(env,fetcher=fetch){
 if(env.WEBSITE_MONITOR_ENABLED!=='true'||!env.DB)return {checked:0};
 const due=now()-86400;
 const rows=await env.DB.prepare('SELECT id,user_id,url FROM website_monitors WHERE enabled=1 AND (last_checked_at IS NULL OR last_checked_at<?) ORDER BY last_checked_at ASC LIMIT 10').bind(due).all();
 let checked=0;
 for(const site of rows.results||[]){
  // Acquire a lease before calling an external site to prevent duplicate scheduled scans.
  const claim=await env.DB.prepare('UPDATE website_monitors SET last_checked_at=? WHERE id=? AND user_id=? AND enabled=1 AND (last_checked_at IS NULL OR last_checked_at<?)').bind(now(),site.id,site.user_id,due).run();
  if(claim.meta.changes!==1)continue;
  await checkSite(env,site,fetcher);checked++;
 }
 return {checked};
}
