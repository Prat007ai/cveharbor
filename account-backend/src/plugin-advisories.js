// Authenticated, bounded lookup of public WordPress plugin vulnerabilities.
// Returns only source-backed CVE records; does not claim that unknown slugs are safe.
const JSON_HEADERS={'Content-Type':'application/json; charset=utf-8','Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true','Cache-Control':'private, no-store','Vary':'Origin'};
const reply=(payload,status=200)=>new Response(JSON.stringify(payload),{status,headers:JSON_HEADERS});
const validSlug=s=>/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(s)&&s.length<=90;
const clean=s=>String(s??'').trim().slice(0,1200);
const CVE=/^CVE-\d{4}-\d{4,10}$/i;
const version=x=>/^\d+(?:\.\d+){1,5}$/.test(String(x||''))?String(x):null;
function compare(a,b){const left=a.split('.').map(Number),right=b.split('.').map(Number);for(let i=0;i<Math.max(left.length,right.length);i++){let d=(left[i]||0)-(right[i]||0);if(d)return Math.sign(d)}return 0}
function checkBound(value,limit,operator){
 const n=compare(value,limit);
 return {lt:n<0,le:n<=0,eq:n===0,ne:n!==0,gt:n>0,ge:n>=0}[operator]??null;
}
function affected(v,installed){
 if(!version(installed))return null;
 const range=v.operator;
 if(range&&typeof range==='object'&&!Array.isArray(range)){
  const lo=range.min_version,hi=range.max_version;
  let low=true,high=true;
  if(lo){if(!version(lo))return null;low=checkBound(installed,lo,range.min_operator)}
  if(hi){if(!version(hi))return null;high=checkBound(installed,hi,range.max_operator)}
  return low===null||high===null?null:low&&high;
 }
 const target=version(v.version||v.fixed_in||v.fixed_version||v.patched_version);
 const op=String(range||v.version_operator||'').toLowerCase();
 if(!target)return null;
 return checkBound(installed,target,op);
}
function severityLabel(value){
 const s=String(value??'').trim().toLowerCase();
 const aliases={c:'critical',critical:'critical',h:'high',high:'high',m:'medium',medium:'medium',moderate:'medium',l:'low',low:'low',i:'informational',info:'informational'};
 return aliases[s]||'unknown';
}
function sourceDate(v,source){
 const candidates=[v.published,v.published_at,v.date,source?.published,source?.published_at,source?.date];
 for(const value of candidates){
  const s=String(value||'').trim();
  if(/^\d{4}-\d{2}-\d{2}(?:T|$)/.test(s)&&!Number.isNaN(Date.parse(s.slice(0,10))))return s.slice(0,10);
 }
 return '';
}
const sourceIds=v=>Array.isArray(v.source)?v.source:[v.source].filter(Boolean);
const validId=value=>typeof value==='string'&&CVE.test(value.toUpperCase());
export function normalizePluginLookup(slug,installed,json){
 if(json?.error!==0)return {status:'unverified',slug,findings:[],reason:'Source did not confirm successful retrieval'};
 const data=json.data;
 if(data===null||Array.isArray(data)&&data.length===0)
  return {status:'checked',slug,findings:[],reason:'Source returned no vulnerabilities, not a security assurance'};
 if(!data||typeof data!=='object')return {status:'unverified',slug,findings:[],reason:'Unexpected source payload'};
 let entries=null;
 if(Array.isArray(data)){
  const identified=data.filter(x=>x&&typeof x==='object'&&(x.plugin||x.slug));
  if(identified.length&&identified.some(x=>String(x.plugin||x.slug).toLowerCase()!==slug))
   return {status:'unverified',slug,findings:[],reason:'Source explicitly identifies a different plugin'};
  entries=data.flatMap(x=>Array.isArray(x?.vulnerability)?x.vulnerability:Array.isArray(x?.vulnerabilities)?x.vulnerabilities:[x]);
 }
 else{
  const item=data[slug]&&typeof data[slug]==='object'?data[slug]:data;
  const explicit=item.plugin||item.slug;
  if(explicit&&String(explicit).toLowerCase()!==slug)
   return {status:'unverified',slug,findings:[],reason:'Source explicitly identifies a different plugin'};
  if(Array.isArray(item.vulnerability))entries=item.vulnerability;
  else if(Array.isArray(item.vulnerabilities))entries=item.vulnerabilities;
  else if(Array.isArray(item.data))entries=item.data;
  else if(Object.keys(item).length===0)return {status:'checked',slug,findings:[],reason:'No source findings; not proof of safety'};
 }
 if(!Array.isArray(entries))return {status:'unverified',slug,findings:[],reason:'Source returned unsupported vulnerability data format'};
 const findings=[],seen=new Set();
 for(const v of entries.slice(0,300)){
  if(!v||typeof v!=='object')continue;
  const sources=sourceIds(v);
  const ids=[...(Array.isArray(v.cve)?v.cve:[v.cve]),v.cve_id,v.id,
    ...(Array.isArray(v.cves)?v.cves:[]),
    ...sources.flatMap(x=>x&&typeof x==='object'?[x.id,x.name]:[])].filter(validId).map(x=>x.toUpperCase());
  if(!ids.length)continue;
  const applies=affected(v,installed);
  if(applies===false)continue;
  const source=sources.find(x=>x&&typeof x==='object'&&validId(x.id))||sources.find(x=>x&&typeof x==='object'&&x.link)||{};
  const url=String(source.link||source.url||v.url||v.link||'');
  const range=v.operator&&typeof v.operator==='object'?v.operator:null;
  const rule=range?
   [range.min_operator&&range.min_version?range.min_operator+' '+range.min_version:'',
    range.max_operator&&range.max_version?range.max_operator+' '+range.max_version:''].filter(Boolean).join(' and '):
   String(v.operator||v.version_operator||'unknown')+' '+String(v.version||'unknown');
  for(const id of ids){
   if(seen.has(id))continue;seen.add(id);
   findings.push({id,title:clean(v.name||v.title||id),
    summary:clean(v.description||source.description||v.title||v.name||id),
    severity:severityLabel(v.impact?.cvss?.severity||v.impact?.cvss3?.severity||v.severity),
    affected:clean('Installed '+installed+'; source affected range: '+(rule||'not specified')),
    published:sourceDate(v,source),updated:clean(v.updated||''),
    remediation:clean(range?.max_version?'Review fixed release after '+range.max_version:'Verify vendor fix'),
    sources:url.startsWith('https://')?[{label:'Vulnerability source',url}]:[],
    level:applies===true?'version_review':'category',known_exploited:false});
  }
 }
 return {status:'checked',slug,findings,source_updated:json.updated||null,checked_version:installed,
  reason:findings.length?'':'No applicable CVE records identified by this source; not a guarantee of safety'};
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
