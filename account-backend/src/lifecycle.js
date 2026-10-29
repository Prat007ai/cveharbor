// Private lifecycle watchlist and explicit opt-in. No public customer records.
import { sendEmail } from './delivery.js';
const SITE='https://cveharbor.com';
const DATA=SITE+'/lifecycle.js';
const now=()=>Math.floor(Date.now()/1000);
const response=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{
 'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',
 'Access-Control-Allow-Origin':SITE,'Access-Control-Allow-Credentials':'true','Vary':'Origin'
}});
export class LifecycleError extends Error{
 constructor(message,status=400){super(message);this.status=status;}
}
export const dateValid=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(s)&&
 !Number.isNaN(Date.parse(s+'T00:00:00Z'))&&new Date(s+'T00:00:00Z').toISOString().startsWith(s);
export function normalizeWatch(x){
 const product=String(x?.product||'').trim(),slug=String(x?.slug||'').trim().toLowerCase(),
 cycle=String(x?.cycle||'').trim(),installed=String(x?.installed_version||'').trim(),date=String(x?.custom_eol_date||'').trim(),
 source=String(x?.custom_source_url||'').trim();
 if(!product||product.length>120||cycle.length>80||installed.length>80||
   (slug&&!/^[a-z0-9-]{1,70}$/.test(slug))||
   (date&&!dateValid(date))||
   (!slug&&!date)||
   source.length>500||
   (source&&(!/^https:\/\/[a-z0-9.-]+(?:[:\/?#]|$)/i.test(source)||source.includes('@'))))
   throw new LifecycleError('Enter a product and either a monitored source or a verified custom support date');
 const id=String(x.id||'');
 if(id&&!/^[a-f0-9-]{36}$/i.test(id))throw new LifecycleError('Invalid watch identifier');
 return {id:id||crypto.randomUUID(),product,slug,cycle,installed_version:installed,custom_eol_date:date,custom_source_url:source};
}
export async function ready(env){
 try{await env.DB.prepare('SELECT user_id FROM lifecycle_watches LIMIT 1').first();return true;}
 catch(_){return false;}
}
export async function handler(req,env,user,path,data={}){
 if(path==='/v1/lifecycle/status'&&req.method==='GET')return response({
  ready:await ready(env),email_delivery_active:env.LIFECYCLE_DELIVERY_ENABLED==='true',
  source:'endoflife.date and explicit user supplied dates'
 });
 if(!await ready(env))throw new LifecycleError('Lifecycle D1 migration is required',503);
 if(path==='/v1/lifecycle'&&req.method==='GET'){
  const watches=await env.DB.prepare('SELECT id,product,slug,cycle,installed_version,custom_eol_date,custom_source_url FROM lifecycle_watches WHERE user_id=? ORDER BY product,cycle LIMIT 100').bind(user.id).all();
  const prefs=await env.DB.prepare('SELECT email_enabled,lead_days FROM lifecycle_preferences WHERE user_id=?').bind(user.id).first();
  return response({watches:watches.results||[],preferences:prefs||{email_enabled:0,lead_days:90},
    email_delivery_active:env.LIFECYCLE_DELIVERY_ENABLED==='true'});
 }
 if(path==='/v1/lifecycle/watches'&&req.method==='POST'){
  const watch=normalizeWatch(data);
  const count=await env.DB.prepare('SELECT COUNT(*) AS total FROM lifecycle_watches WHERE user_id=?').bind(user.id).first();
  if(Number(count?.total||0)>=100)throw new LifecycleError('Limit of 100 monitored products per account',409);
  await env.DB.prepare('INSERT INTO lifecycle_watches(user_id,id,product,slug,cycle,installed_version,custom_eol_date,custom_source_url,created_at) VALUES(?,?,?,?,?,?,?,?,?)')
   .bind(user.id,watch.id,watch.product,watch.slug,watch.cycle,watch.installed_version,watch.custom_eol_date,watch.custom_source_url,now()).run();
  return response({saved:true,id:watch.id},201);
 }
 if(path==='/v1/lifecycle/preferences'&&req.method==='PUT'){
  if(typeof data.email_enabled!=='boolean'||![30,60,90,180].includes(data.lead_days))
   throw new LifecycleError('Invalid lifecycle email preferences');
  // Only a signed-in user explicitly choosing the checkbox can enable it.
  await env.DB.prepare('INSERT INTO lifecycle_preferences(user_id,email_enabled,lead_days,updated_at) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET email_enabled=excluded.email_enabled,lead_days=excluded.lead_days,updated_at=excluded.updated_at')
   .bind(user.id,data.email_enabled?1:0,data.lead_days,now()).run();
  return response({saved:true,email_enabled:data.email_enabled,delivery_active:env.LIFECYCLE_DELIVERY_ENABLED==='true'});
 }
 const match=/^\/v1\/lifecycle\/watches\/([a-f0-9-]{36})$/i.exec(path);
 if(match&&req.method==='DELETE'){
  await env.DB.prepare('DELETE FROM lifecycle_watches WHERE user_id=? AND id=?').bind(user.id,match[1]).run();
  return response({deleted:true});
 }
 return response({error:'Not found'},404);
}
function newer(installed,latest){
 const valid=x=>/^\d+(?:\.\d+){1,4}$/.test(String(x||''));
 if(!valid(installed)||!valid(latest))return false;
 const a=installed.split('.').map(Number),b=latest.split('.').map(Number);
 for(let i=0;i<Math.max(a.length,b.length);i++){
  if((a[i]||0)!==(b[i]||0))return (b[i]||0)>(a[i]||0);
 }
 return false;
}
export function newerReleases(watches,cycles){
 const found=[];
 for(const w of watches){
  if(!w.slug||!w.cycle||!w.installed_version)continue;
  const c=cycles.find(c=>c.slug===w.slug&&String(c.cycle).toLowerCase()===w.cycle.toLowerCase());
  if(!c||!newer(w.installed_version,String(c.latest||'')))continue;
  found.push({watch_id:w.id,product:w.product,cycle:w.cycle,installed:w.installed_version,
   latest:c.latest,source_url:c.url,event_key:'release:'+w.id+':'+c.latest});
 }
 return found;
}
export function evaluate(watches,cycles,leadDays=90,current=new Date()){
 const today=current.toISOString().slice(0,10),start=Date.parse(today+'T00:00:00Z'),results=[];
 for(const w of watches){
  const candidates=w.custom_eol_date?
   [{product:w.product,cycle:w.cycle||'Custom schedule',eol_date:w.custom_eol_date,url:w.custom_source_url,origin:'user'}]:
   cycles.filter(c=>c.slug===w.slug&&(!w.cycle||String(c.cycle).toLowerCase()===w.cycle.toLowerCase()))
    .map(c=>({...c,origin:'source'}));
  for(const c of candidates){
   const date=c.eol_date;
   if(!dateValid(date))continue;
   const remaining=Math.floor((Date.parse(date+'T00:00:00Z')-start)/86400000);
   // The tool must not generate alerts for arbitrary versions or speculative dates.
   if(remaining>leadDays)continue;
   results.push({watch_id:w.id,product:w.product,cycle:String(c.cycle||''),
    eol_date:date,days:remaining,source_url:c.url||'',origin:c.origin,
    latest:c.latest||'',latest_release_date:c.latest_release_date||''});
  }
 }
 results.sort((a,b)=>a.days-b.days||a.product.localeCompare(b.product));
 return results;
}
export async function loadLifecycleFeed(){
 const response=await fetch(DATA,{headers:{Accept:'text/javascript'}});
 if(!response.ok)throw Error('Lifecycle source unavailable');
 const raw=await response.text();
 const match=/^window\.CVEHARBOR_LIFECYCLE\s*=\s*(\{[\s\S]*\})\s*;\s*$/.exec(raw.trim());
 if(!match)throw Error('Invalid lifecycle source');
 const obj=JSON.parse(match[1]);
 if(!Array.isArray(obj.cycles))throw Error('Missing lifecycle cycles');
 const stamp=Date.parse(obj.checked_at||'');
 if(!Number.isFinite(stamp)||Date.now()-stamp>3*86400000)
   throw Error('Lifecycle snapshot is too old to email');
 return obj;
}
export async function dispatchLifecycle(env,day=new Date()){
 if(env.LIFECYCLE_DELIVERY_ENABLED!=='true')return {status:'disabled'};
 if(!await ready(env))return {status:'migration_required'};
 const config=await env.DB.prepare('SELECT u.id,u.email,p.lead_days FROM users u JOIN lifecycle_preferences p ON p.user_id=u.id WHERE p.email_enabled=1 ORDER BY p.updated_at LIMIT 8').all();
 const people=config.results||[];if(!people.length)return {status:'none'};
 const feed=await loadLifecycleFeed();
 let sent=0,failed=0;
 for(const person of people){
  try{
   const rows=await env.DB.prepare('SELECT id,product,slug,cycle,installed_version,custom_eol_date,custom_source_url FROM lifecycle_watches WHERE user_id=?').bind(person.id).all();
   const watches=rows.results||[];
   const matches=evaluate(watches,feed.cycles,person.lead_days,day).slice(0,15);
   const patches=newerReleases(watches,feed.cycles).slice(0,15);
   const fresh=[];
   for(const m of matches){
    const key=[m.watch_id,m.cycle,m.eol_date].join(':');
    const previous=await env.DB.prepare('SELECT sent_at FROM lifecycle_delivery WHERE user_id=? AND event_key=?').bind(person.id,key).first();
    if(!previous)fresh.push({...m,key});
   }
   for(const p of patches){
    const prior=await env.DB.prepare('SELECT sent_at FROM lifecycle_delivery WHERE user_id=? AND event_key=?').bind(person.id,p.event_key).first();
    if(!prior)fresh.push({...p,key:p.event_key,release_notice:true});
   }
   if(!fresh.length)continue;
   const text=['CVEHarbor End of Support Notice','','Review these lifecycle dates and verify vendor licensing, extended support and product editions:','',
    ...fresh.map(m=>m.release_notice?m.product+' '+m.cycle+': newer release '+m.latest+' (installed '+m.installed+'). Verify vendor security bulletins. Release availability is not proof of a security patch. '+m.source_url:m.product+' '+m.cycle+': '+m.eol_date+' ('+(m.days<0?'past end of support':m.days+' days remaining')+') '+(m.origin==='user'?'User supplied date':'Public lifecycle source')+' '+m.source_url),
    '','Check vendor advisories for current patches. A lifecycle date is not proof that a specific installed system is insecure.',
    'Manage your preferences: '+SITE+'/#lifecycleMonitor','CVEHarbor | '+SITE].join('\n');
   const html='<html><body style="font-family:Arial,sans-serif;max-width:640px;margin:auto;padding:25px"><h2>CVEHarbor lifecycle notice</h2><p>Products on your watchlist may require an upgrade or a support review. Check vendor lifecycle terms and current patches.</p><pre style="white-space:pre-wrap">'+text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')+'</pre></body></html>';
   await sendEmail(env,person.email,{subject:'CVEHarbor product end of support review',text,html});
   await env.DB.batch(fresh.map(m=>env.DB.prepare('INSERT OR IGNORE INTO lifecycle_delivery(user_id,event_key,sent_at) VALUES(?,?,?)').bind(person.id,m.key,now())));
   sent++;
  }catch(_){failed++;}
 }
 return {status:'processed',sent,failed};
}
