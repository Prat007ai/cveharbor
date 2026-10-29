// Official WordPress.org release metadata. Unknown plugin identity is not a supported or current claim.
const numeric=value=>/^\d+(?:\.\d+){1,5}$/.test(String(value||''))?String(value):'';
export function compareVersions(a,b){
 if(!numeric(a)||!numeric(b))return null;
 const l=a.split('.').map(Number),r=b.split('.').map(Number);
 for(let i=0;i<Math.max(l.length,r.length);i++){const d=(l[i]||0)-(r[i]||0);if(d)return Math.sign(d)}
 return 0;
}
export function normalizeRelease(slug,installed,body){
 if(!body||body.error||body.slug!==slug||!numeric(body.version)){
  return {release_status:'unverified',latest_version:'',release_source:'',last_updated:'',update_status:'Unknown',reason:'Official plugin identity or release information not verified'};
 }
 const comparison=compareVersions(installed,body.version);
 return {release_status:'verified',latest_version:body.version,
  release_source:'https://wordpress.org/plugins/'+encodeURIComponent(slug)+'/',
  last_updated:String(body.last_updated||'').slice(0,40),
  update_status:comparison===null?'Unknown':comparison<0?'Update Available':comparison===0?'Up to Date':'Installed Newer',
  reason:''};
}
export async function lookupRelease(slug,installed,fetcher=fetch){
 if(!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug))return {release_status:'unverified',latest_version:'',update_status:'Unknown',reason:'Invalid plugin slug'};
 const url='https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]='+encodeURIComponent(slug);
 try{
  const r=await fetcher(url,{headers:{Accept:'application/json'},signal:AbortSignal.timeout(6500)});
  if(!r.ok)return {release_status:'unavailable',latest_version:'',update_status:'Unknown',reason:'Official release API returned '+r.status};
  const raw=await r.text();
  if(raw.length>200000)return {release_status:'unavailable',latest_version:'',update_status:'Unknown',reason:'Release response too large'};
  return normalizeRelease(slug,installed,JSON.parse(raw));
 }catch(_){return {release_status:'unavailable',latest_version:'',update_status:'Unknown',reason:'Official release source could not be reached'}}
}
