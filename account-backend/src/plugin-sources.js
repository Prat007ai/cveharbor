import {lookupRelease} from './plugin-releases.js';
// Stores source metadata only. Never fetch arbitrary customer-provided URLs.
const reply=(obj,status=200)=>new Response(JSON.stringify(obj),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true','Vary':'Origin'}});
const uuid=x=>typeof x==='string'&&/^[0-9a-f-]{36}$/i.test(x);
export const wordpressSlug=value=>{
 try{
  const u=new URL(value);
  if(u.protocol!=='https:'||!['wordpress.org','www.wordpress.org'].includes(u.hostname))return '';
  const m=/^\/plugins\/([a-z0-9]+(?:-[a-z0-9]+)*)\/?$/.exec(u.pathname);
  return m?m[1]:'';
 }catch(_){return ''}
};
export function safeSourceUrl(value){
 const raw=String(value??'').trim();
 if(!raw)return '';
 if(raw.length>500)throw Error('Source URL too long');
 let u;
 try{u=new URL(raw)}catch(_){throw Error('Invalid source URL')}
 if(u.protocol!=='https:'||u.username||u.password||u.port||u.hash)throw Error('Only standard HTTPS source URLs are accepted');
 const host=u.hostname.toLowerCase();
 if(host==='localhost'||host.endsWith('.local')||host.endsWith('.internal')||host.endsWith('.localhost')||host==='0.0.0.0'||host==='127.0.0.1'||host==='[::1]'||/^10\.|^192\.168\.|^169\.254\.|^172\.(1[6-9]|2\d|3[01])\./.test(host))throw Error('Private or local source URLs are not accepted');
 return u.href;
}
async function available(env){try{await env.DB.prepare('SELECT asset_id FROM plugin_source_mappings LIMIT 1').first();return true}catch(_){return false}}
export async function sourceRoute(req,env,user,path,data={}){
 if(path==='/v1/plugin-sources'&&req.method==='GET'){
  if(!await available(env))return reply({ready:false,sources:[]});
  const records=await env.DB.prepare('SELECT s.asset_id,s.vendor_url,s.release_url,s.advisory_url,s.plugin_slug,s.verification,s.updated_at FROM plugin_source_mappings s JOIN inventory_assets a ON a.id=s.asset_id AND a.user_id=s.user_id WHERE s.user_id=? LIMIT 3000').bind(user.id).all();
  return reply({ready:true,sources:records.results||[]});
 }
 if(path.match(/^\/v1\/plugin-sources\/([0-9a-f-]{36})\/verify$/)&&req.method==='POST'){
  if(!await available(env))return reply({ready:false,error:'Plugin source migration required'},503);
  const assetId=path.split('/')[3];
  const asset=await env.DB.prepare('SELECT id,version,technology FROM inventory_assets WHERE id=? AND user_id=?').bind(assetId,user.id).first();
  if(!asset||!String(asset.technology).startsWith('WordPress Plugin: '))return reply({error:'Plugin not found'},404);
  const mapping=await env.DB.prepare('SELECT vendor_url,release_url FROM plugin_source_mappings WHERE user_id=? AND asset_id=?').bind(user.id,assetId).first();
  const slug=wordpressSlug(mapping?.vendor_url||'')||wordpressSlug(mapping?.release_url||'');
  if(!slug)return reply({verification:'Needs Review',reason:'No verified WordPress.org plugin source. Commercial or custom vendors require a specific supported release integration.'});
  const latest=await lookupRelease(slug,asset.version);
  return reply({verification:latest.release_status==='verified'?'Release Verified':'Needs Review',slug,...latest});
 }
 if(!await available(env))return reply({ready:false,error:'Plugin source migration required'},503);
 const match=/^\/v1\/plugin-sources\/([0-9a-f-]{36})$/.exec(path);
 if(!match||req.method!=='PUT'||!uuid(match[1]))return reply({error:'Not found'},404);
 const asset=await env.DB.prepare('SELECT id,technology FROM inventory_assets WHERE id=? AND user_id=?').bind(match[1],user.id).first();
 if(!asset||!String(asset.technology).startsWith('WordPress Plugin: '))return reply({error:'WordPress plugin asset not found'},404);
 let vendor,release,advisory;
 try{
  vendor=safeSourceUrl(data.vendor_url);
  release=safeSourceUrl(data.release_url);
  advisory=safeSourceUrl(data.advisory_url);
 }catch(e){return reply({error:e.message},400)}
 const slug=wordpressSlug(vendor)||wordpressSlug(release);
 const verification=slug?'WordPress.org Slug Identified':'Needs Review';
 await env.DB.prepare('INSERT INTO plugin_source_mappings(user_id,asset_id,vendor_url,release_url,advisory_url,plugin_slug,verification,updated_at) VALUES(?,?,?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(user_id,asset_id) DO UPDATE SET vendor_url=excluded.vendor_url,release_url=excluded.release_url,advisory_url=excluded.advisory_url,plugin_slug=excluded.plugin_slug,verification=excluded.verification,updated_at=CURRENT_TIMESTAMP').bind(user.id,asset.id,vendor,release,advisory,slug,verification).run();
 return reply({saved:true,asset_id:asset.id,plugin_slug:slug,verification});
}
