import {lookupRelease} from './plugin-releases.js';
import {pluginAdvisoryRoute} from './plugin-advisories.js';
const response=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true','Vary':'Origin'}});
const seconds=()=>Math.floor(Date.now()/1000);
const validAsset=id=>/^[0-9a-f-]{36}$/i.test(String(id||''));
const aliases={'yoast seo':'wordpress-seo','wp file manager':'wp-file-manager','wps hide login':'wps-hide-login','autoptimize':'autoptimize','wp mail smtp':'wp-mail-smtp','advanced editor tools':'tinymce-advanced','addtoany share buttons':'add-to-any','events manager':'events-manager','wp store locator':'wp-store-locator'};
export const slugOf=technology=>{
 const name=String(technology||'').replace(/^WordPress Plugin: /,'').trim().toLowerCase();
 return aliases[name]||name.replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
};
async function ready(env){try{await env.DB.prepare('SELECT asset_id FROM plugin_monitor_checks LIMIT 1').first();return true}catch(_){return false}}
const plugin=x=>String(x?.technology||'').startsWith('WordPress Plugin: ');
export async function scanOne(env,asset,fetcher=fetch){
 const slug=slugOf(asset.technology),now=seconds(),installed=String(asset.version||'');
 let result={status:'unverified',reason:'Plugin identity unavailable',findings:[]};
 if(slug&&plugin(asset)){
  const url='https://api.cveharbor.com/v1/plugin-advisories?asset_id='+encodeURIComponent(asset.id)+'&slug='+encodeURIComponent(slug);
  try{
   const r=await pluginAdvisoryRoute(new Request(url),env,{id:asset.user_id},fetcher);
   result=await r.json();
  }catch(_){result={status:'unavailable',reason:'Advisory source request failed',findings:[]}}
 }
 const release=await lookupRelease(slug,installed,fetcher);
 await env.DB.prepare('INSERT INTO plugin_release_checks(user_id,asset_id,installed_version,slug,release_status,latest_version,update_status,release_source,last_updated,reason,checked_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id,asset_id) DO UPDATE SET installed_version=excluded.installed_version,slug=excluded.slug,release_status=excluded.release_status,latest_version=excluded.latest_version,update_status=excluded.update_status,release_source=excluded.release_source,last_updated=excluded.last_updated,reason=excluded.reason,checked_at=excluded.checked_at').bind(asset.user_id,asset.id,installed,slug,release.release_status,release.latest_version||'',release.update_status||'Unknown',release.release_source||'',release.last_updated||'',release.reason||'',now).run();
 const state=['checked','unverified','unavailable'].includes(result.status)?result.status:'unavailable';
 const findings=Array.isArray(result.findings)?result.findings.slice(0,100):[];
 const next=now+(state==='checked'?43200:3600);
 await env.DB.prepare('INSERT INTO plugin_monitor_checks(user_id,asset_id,installed_version,plugin_slug,status,reason,findings_json,checked_at,next_check_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id,asset_id) DO UPDATE SET installed_version=excluded.installed_version,plugin_slug=excluded.plugin_slug,status=excluded.status,reason=excluded.reason,findings_json=excluded.findings_json,checked_at=excluded.checked_at,next_check_at=excluded.next_check_at')
  .bind(asset.user_id,asset.id,installed,slug,state,String(result.reason||'').slice(0,300),JSON.stringify(findings),now,next).run();
 await env.DB.prepare('INSERT INTO plugin_monitor_history(id,user_id,asset_id,checked_at,status,finding_count,reason) VALUES(?,?,?,?,?,?,?)')
  .bind(crypto.randomUUID(),asset.user_id,asset.id,now,state,findings.length,String(result.reason||'').slice(0,300)).run();
 return {asset_id:asset.id,status:state,findings,checked_at:now,next_check_at:next,reason:result.reason||'',release};
}
export async function monitorRoute(req,env,user,path,data={}){
 if(!await ready(env))return response({ready:false,checks:[],message:'Plugin monitor D1 migration is required'},req.method==='GET'?200:503);
 if(path==='/v1/plugin-monitor'&&req.method==='GET'){
  const rows=await env.DB.prepare('SELECT m.asset_id,m.installed_version,m.plugin_slug,m.status,m.reason,m.findings_json,m.checked_at,m.next_check_at FROM plugin_monitor_checks m JOIN inventory_assets a ON a.id=m.asset_id AND a.user_id=m.user_id WHERE m.user_id=? LIMIT 3000').bind(user.id).all();
  let releases=[];
  try{const result=await env.DB.prepare('SELECT r.asset_id,r.installed_version,r.release_status,r.latest_version,r.update_status,r.release_source,r.last_updated,r.reason,r.checked_at FROM plugin_release_checks r JOIN inventory_assets a ON a.id=r.asset_id AND a.user_id=r.user_id WHERE r.user_id=? LIMIT 3000').bind(user.id).all();releases=result.results||[]}catch(_){}
  const byAsset=new Map(releases.map(r=>[r.asset_id,r]));
  return response({ready:true,checks:(rows.results||[]).map(r=>({...r,findings:JSON.parse(r.findings_json||'[]'),findings_json:undefined,release:byAsset.get(r.asset_id)||null}))});
 }
 if(path==='/v1/plugin-monitor/refresh-batch'&&req.method==='POST'){
  const ids=data.asset_ids;
  if(!Array.isArray(ids)||!ids.length||ids.length>3||new Set(ids).size!==ids.length||ids.some(id=>!validAsset(id)))
   return response({error:'Choose up to three valid, distinct plugin assets'},400);
  const output=[];
  for(const id of ids){
   const asset=await env.DB.prepare('SELECT id,user_id,technology,version FROM inventory_assets WHERE id=? AND user_id=?').bind(id,user.id).first();
   if(!asset||!plugin(asset)){output.push({asset_id:id,status:'unverified',reason:'Plugin is not in your inventory'});continue}
   const previous=await env.DB.prepare('SELECT checked_at,installed_version FROM plugin_monitor_checks WHERE user_id=? AND asset_id=?').bind(user.id,id).first();
   if(previous?.installed_version===asset.version&&seconds()-Number(previous.checked_at)<300){
    output.push({asset_id:id,status:'recent',reason:'Recently checked'});continue;
   }
   try{output.push(await scanOne(env,asset))}
   catch(_){output.push({asset_id:id,status:'unavailable',reason:'Check could not be saved'})}
  }
  return response({results:output});
 }
 if(path==='/v1/plugin-monitor/refresh'&&req.method==='POST'){
  if(!validAsset(data.asset_id))return response({error:'Valid asset ID required'},400);
  const asset=await env.DB.prepare('SELECT id,user_id,technology,version FROM inventory_assets WHERE id=? AND user_id=?').bind(data.asset_id,user.id).first();
  if(!asset)return response({error:'Asset not found'},404);
  if(!plugin(asset))return response({error:'Not a plugin asset'},400);
  const previous=await env.DB.prepare('SELECT checked_at,installed_version FROM plugin_monitor_checks WHERE user_id=? AND asset_id=?').bind(user.id,asset.id).first();
  if(previous?.installed_version===asset.version&&seconds()-Number(previous.checked_at)<60)return response({error:'Please wait before rechecking this plugin'},429);
  return response(await scanOne(env,asset));
 }
 return response({error:'Not found'},404);
}
export async function scanDue(env){
 if(!await ready(env))return {processed:0,ready:false};
 const now=seconds();
 const result=await env.DB.prepare("SELECT a.id,a.user_id,a.technology,a.version FROM inventory_assets a LEFT JOIN plugin_monitor_checks m ON m.asset_id=a.id AND m.user_id=a.user_id WHERE a.technology LIKE 'WordPress Plugin: %' AND (m.asset_id IS NULL OR m.installed_version != a.version OR m.next_check_at<=?) ORDER BY COALESCE(m.next_check_at,0) ASC LIMIT 20").bind(now).all();
 let processed=0;
 for(const asset of result.results||[]){await scanOne(env,asset);processed++}
 return {processed,ready:true};
}
