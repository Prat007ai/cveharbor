// Authenticated, bounded lookup of public WordPress plugin vulnerabilities.
// Returns only source-backed CVE records; does not claim that unknown slugs are safe.
const JSON_HEADERS={'Content-Type':'application/json; charset=utf-8','Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true','Cache-Control':'private, no-store','Vary':'Origin'};
const reply=(payload,status=200)=>new Response(JSON.stringify(payload),{status,headers:JSON_HEADERS});
const validSlug=s=>/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(s)&&s.length<=90;
const clean=s=>String(s??'').trim().slice(0,1200);
const CVE=/^CVE-\d{4}-\d{4,10}$/i;
const version=x=>/^\d+(?:\.\d+){1,5}$/.test(String(x||''))?String(x):null;
function compare(a,b){const left=a.split('.').map(Number),right=b.split('.').map(Number);for(let i=0;i<Math.max(left.length,right.length);i++){let d=(left[i]||0)-(right[i]||0);if(d)return Math.sign(d)}return 0}
function affected(v,installed){
 const target=version(v.version||v.fixed_in||v.fixed_version||v.patched_version);
 const operator=String(v.operator||v.version_operator||'').toLowerCase();
 if(!target||!version(installed)||!['lt','le','eq','ne','gt','ge'].includes(operator))return null;
 const n=compare(installed,target);
 return {lt:n<0,le:n<=0,eq:n===0,ne:n!==0,gt:n>0,ge:n>=0}[operator];
}
export function normalizePluginLookup(slug,installed,json){
 if(json?.error!==0)return {status:'unverified',slug,findings:[],reason:'Source did not provide a confirmed plugin record'};
 const data=json.data;
 if(!data||typeof data!=='object')return {status:'unverified',slug,findings:[],reason:'Source did not return structured plugin information'};
 // The public plugin endpoint is already scoped by the requested slug. Its
 // envelope does not always repeat the slug in data, so absence is not a mismatch.
 // Still reject any explicitly different identity.
 let item=Array.isArray(data)?data.find(x=>x&&typeof x==='object'&&String(x.slug||'').toLowerCase()===slug):data;
 if(!Array.isArray(data)&&Object.hasOwn(data,slug)&&data[slug]&&typeof data[slug]==='object')item=data[slug];
 if(!item||typeof item!=='object')return {status:'unverified',slug,findings:[],reason:'Plugin identity not confirmed by source'};
 if(item.slug&&String(item.slug).toLowerCase()!==slug)
  return {status:'unverified',slug,findings:[],reason:'Source returned a different plugin slug'};
 const hasList=Array.isArray(item.vulnerabilities);
 const entries=hasList?item.vulnerabilities:[];
 if(!item.slug&&!hasList)
  return {status:'unverified',slug,findings:[],reason:'Source returned no recognizable plugin vulnerability data'};
 const findings=[];
 for(const v of entries.slice(0,300)){
  const identifiers=[v.cve,v.cve_id,v.id,...(Array.isArray(v.cves)?v.cves:[])].filter(Boolean).map(x=>String(x).toUpperCase());
  const id=identifiers.find(x=>CVE.test(x));
  if(!id)continue;
  const applies=affected(v,installed);
  if(applies===false)continue;
  const source=Array.isArray(v.source)?v.source[0]:v.source;
  const url=String(v.url||v.link||source?.link||source?.url||'');
  findings.push({id,title:clean(v.title||v.name||id),summary:clean(v.description||v.title||id),severity:clean(v.impact?.cvss?.severity||v.severity||'unknown').toLowerCase(),affected:clean('Installed '+installed+'; upstream affected version rule: '+(v.operator||v.version_operator||'unknown')+' '+(v.version||'unknown')),published:clean(v.date||v.published||''),updated:clean(v.updated||''),remediation:clean(v.fixed_in||v.fixed_version?'Patched version '+(v.fixed_in||v.fixed_version):''),sources:url.startsWith('https://')?[{label:'WPVulnerability source',url}]:[],level:applies===true?'version_review':'category',known_exploited:false});
 }
 return {status:'checked',slug,findings,source_updated:json.updated||null,checked_version:installed};
}
export async function pluginAdvisoryRoute(req,env,user,fetcher=fetch){
 const url=new URL(req.url),assetId=url.searchParams.get('asset_id');
 if(!/^[0-9a-f-]{36}$/i.test(assetId||''))return reply({error:'Valid asset ID required'},400);
 const asset=await env.DB.prepare('SELECT id,technology,version FROM inventory_assets WHERE id=? AND user_id=?').bind(assetId,user.id).first();
 if(!asset)return reply({error:'Asset not found'},404);
 if(!String(asset.technology).startsWith('WordPress Plugin: '))return reply({error:'Not a WordPress plugin inventory entry'},400);
 const slug=String(url.searchParams.get('slug')||'');
 if(!validSlug(slug))return reply({error:'Valid plugin slug required'},400);
 // Do not send customer names, hostnames, or inventory to third-party services.
 const endpoint='https://www.wpvulnerability.net/plugin/'+slug+'/';
 try{
  const result=await fetcher(endpoint,{headers:{Accept:'application/json'},signal:AbortSignal.timeout(8500)});
  if(!result.ok)return reply({status:'unavailable',slug,findings:[],reason:'WPVulnerability API returned '+result.status});
  const raw=await result.text();
  if(raw.length>450000)return reply({status:'unavailable',slug,findings:[],reason:'Response exceeds size limit'});
  return reply(normalizePluginLookup(slug,String(asset.version||''),JSON.parse(raw)));
 }catch(_){return reply({status:'unavailable',slug,findings:[],reason:'Vulnerability source could not be reached'})}
}
