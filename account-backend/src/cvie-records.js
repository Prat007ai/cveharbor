// Reconcile authoritative evidence by CVE ID, retaining source-specific provenance.
import {evidenceReady,productFamilies,SOURCE_URLS} from './cvie-evidence.js';
const q=(db,sql,...args)=>db.prepare(sql).bind(...args);
const DAY=86400000;
function affectedDescription(rows,name){
 return rows.map(row=>{
  const versions=(row.versions||[]).filter(v=>v.status==='affected').map(v=>{
   const parts=[];
   if(v.version&&v.version!=='0'&&v.version!=='*')parts.push(v.lessThan||v.lessThanOrEqual?'>= '+v.version:v.version);
   if(v.lessThan)parts.push('< '+v.lessThan);if(v.lessThanOrEqual)parts.push('<= '+v.lessThanOrEqual);
   if(v.changes?.length)parts.push('(additional source conditions apply)');return parts.join(', ')||'version range not specified';
  });
  return name+': '+(versions.join('; ')||'consult the original affected-version statement')+(row.defaultStatus==='affected'?' (other versions may also be affected; check source exceptions)':'');
 }).join('\n').slice(0,4000);
}
export function cnaRanges(rows,cpe,name){
 const result=[];
 for(const row of rows){
  for(const version of row.versions||[]){
   if(version.status!=='affected')continue;
   const match={vulnerable:true,criteria:cpe,cvie_product_key:name};
   if(version.changes?.length){result.push({...match,comparison_unsupported:true});continue;}
   if(version.lessThan)match.versionEndExcluding=version.lessThan;
   if(version.lessThanOrEqual)match.versionEndIncluding=version.lessThanOrEqual;
   if(version.version&&version.version!=='0'&&version.version!=='*'){
    if(version.lessThan||version.lessThanOrEqual)match.versionStartIncluding=version.version;
    else if(cpe){const parts=cpe.split(':');parts[5]=version.version;match.criteria=parts.join(':');}
    else match.comparison_unsupported=true;
   }
   result.push(match);
  }
  // Default-affected products and unexpressed version branches cannot safely be excluded.
  if(row.defaultStatus==='affected'||!(row.versions||[]).length)result.push({vulnerable:true,criteria:cpe,cvie_product_key:name,comparison_unsupported:true});
 }
 return result;
}
export function reconcileRecord(nvd,cna,affected,product,kev,checks,now,cutoff){
 const references=new Map([...(nvd?.sources||[]),...(cna?.sources||[])].map(s=>[s.url,s]));
 const record={...(nvd||{}),...(cna||{})};
 if(!record.id)return null;
 const ranges=cna?cnaRanges(affected,product.cpe,product.name):[];
 if(cna){
  if(cna.cvss===null&&nvd){record.cvss=nvd.cvss;record.severity=nvd.severity;record.severity_source='NVD';}
  else record.severity_source='CVE Program / CNA';
 }
 const conflicts=[];
 if(cna&&nvd&&cna.cvss!==null&&nvd.cvss!==null&&cna.cvss!==nvd.cvss)conflicts.push('CNA and NVD publish different severity scores. CVIE displays the CNA score.');
 record.affected_cpes=cna?(ranges.length?ranges:[{criteria:product.cpe,cvie_product_key:product.name,comparison_unsupported:true}]):nvd?.affected_cpes||[];
 record.affected=cna?affectedDescription(affected,product.name):nvd?.affected||'';
 record.cna_affected=cna?affected:undefined;
 record.source_type='cvie_combined';record.categories=[product.name];record.cvie_products=[product.name];record.cvie_identities=[{name:product.name,cpe:product.cpe}];
 record.known_exploited=checks.cisa_kev?.last_success_at?Boolean(kev):Boolean(nvd?.known_exploited);
 record.kev_verified_at=checks.cisa_kev?.last_success_at||null;
 record.provenance=[...(nvd?[{source:'nvd',url:'https://nvd.nist.gov/vuln/detail/'+record.id,checked_at:nvd.nvd_checked_at||product.last_success_at,updated:nvd.updated}]:[]),
  ...(cna?[{source:'cve_program',url:'https://www.cve.org/CVERecord?id='+record.id,checked_at:checks.cna_checked_at,updated:cna.updated}]:[])];
 if(kev){
  references.set(SOURCE_URLS.cisa_kev,{label:'CISA Known Exploited Vulnerabilities catalogue',url:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'});
  record.kev_added=kev.dateAdded;record.kev_due_date=kev.dueDate;record.kev_required_action=kev.requiredAction;
  record.kev_ransomware=kev.knownRansomwareCampaignUse;
  record.provenance.push({source:'cisa_kev',url:SOURCE_URLS.cisa_kev,checked_at:checks.cisa_kev?.last_success_at,updated:kev.dateAdded});
  record.exploitation='Confirmed exploitation: included in the CISA KEV catalogue';
 }else record.exploitation=record.known_exploited?'NVD reports historical CISA KEV attribution; direct catalogue verification is pending':'No confirmed exploitation claim from the checked CISA catalogue';
 record.retained_exploited=Boolean(kev&&Date.parse(record.published)<Date.parse(cutoff));
 record.exploitation_verification_stale=!checks.cisa_kev?.last_success_at||checks.cisa_kev?.status==='unavailable'||now-checks.cisa_kev.last_success_at>30*60000;
 record.verification_pending=Boolean(checks.record_pending);
 record.evidence_status=record.verification_pending?'A source update is awaiting verification':record.exploitation_verification_stale?'CISA verification is pending or overdue':'Source-backed evidence';
 if(record.known_exploited&&record.exploitation_verification_stale)record.exploitation+='; current catalogue verification is pending or overdue';
 record.source_conflicts=conflicts;record.sources=[...references.values()];return record;
}
export async function sourceHealth(env,now=Date.now()){
 if(!await evidenceReady(env))return {ready:false,sources:[{id:'cve_program',label:'CVE Program / original disclosures',status:'setup_required'},{id:'cisa_kev',label:'CISA KEV',status:'setup_required'}]};
 const rows=(await env.DB.prepare('SELECT * FROM cvie_sources ORDER BY id').all()).results||[];
 const pending=await env.DB.prepare(`SELECT COUNT(*) AS total,SUM(CASE WHEN priority<=1 THEN 1 ELSE 0 END) AS current,
  SUM(CASE WHEN priority=0 THEN 1 ELSE 0 END) AS relevant_kev,SUM(CASE WHEN attempts>0 THEN 1 ELSE 0 END) AS failed FROM cvie_disclosure_queue`).first();
 return {ready:true,pending_records:pending.total,failed_records:pending.failed||0,sources:rows.map(row=>({
  id:row.id,label:row.id==='cisa_kev'?'CISA KEV':'CVE Program / original disclosures',url:row.source_url||SOURCE_URLS[row.id],
  status:row.status==='unavailable'?'unavailable':row.record_retry_at>now?'rate_limited':!row.last_success_at?'pending':now-row.last_success_at>(row.id==='cisa_kev'?30:15)*60000?'stale':
   row.id==='cve_program'&&pending.current>0?'catching_up':row.id==='cisa_kev'&&pending.relevant_kev>0?'verifying_products':'current',
  last_attempt_at:row.last_attempt_at,last_success_at:row.last_success_at,publisher_at:row.publisher_at,coverage_start_at:row.coverage_start_at,
  pending_records:row.id==='cisa_kev'?pending.relevant_kev||0:pending.current||0,error:row.error,
  retry_at:row.record_retry_at||row.next_attempt_at,
 }))};
}
export async function evidenceContext(env,userId){
 if(!await evidenceReady(env))return null;
 const products=(await q(env.DB,`SELECT p.* FROM cvie_products p WHERE p.user_id=? AND EXISTS(SELECT 1 FROM cvie_subscriptions s WHERE s.product_id=p.id)`,userId).all()).results||[];
 const families=products.flatMap(p=>productFamilies(p).map(key=>({product_id:p.id,key})));
 const sources=(await env.DB.prepare('SELECT * FROM cvie_sources').all()).results||[];
 return {products,families:JSON.stringify(families),sources:Object.fromEntries(sources.map(s=>[s.id,s]))};
}
// SQL keyset pagination limits both public evidence and private data to the requested page.
function unifiedCte(){return `WITH families AS (
 SELECT json_extract(value,'$.product_id') AS product_id,json_extract(value,'$.key') AS family_key FROM json_each(?)
), links AS (
 SELECT a.product_id,a.cve_id FROM cvie_advisories a JOIN cvie_products p ON p.id=a.product_id
 WHERE p.user_id=? AND EXISTS(SELECT 1 FROM cvie_subscriptions s WHERE s.product_id=p.id)
 UNION SELECT f.product_id,d.cve_id FROM families f JOIN cvie_disclosure_products d ON d.family_key=f.family_key
), unified AS (
 SELECT l.product_id,l.cve_id,COALESCE(CASE WHEN EXISTS(SELECT 1 FROM families f JOIN cvie_disclosure_products dp ON dp.family_key=f.family_key
  WHERE f.product_id=l.product_id AND dp.cve_id=l.cve_id) THEN d.published END,a.published) AS published,
 a.record_json AS nvd_json,d.record_json AS cna_json,d.checked_at AS cna_checked_at,k.record_json AS kev_json,j.cve_id AS queued_id
 FROM links l LEFT JOIN cvie_advisories a ON a.product_id=l.product_id AND a.cve_id=l.cve_id
 LEFT JOIN cvie_disclosures d ON d.cve_id=l.cve_id LEFT JOIN cvie_kev k ON k.cve_id=l.cve_id
 LEFT JOIN cvie_disclosure_queue j ON j.cve_id=l.cve_id
 WHERE COALESCE(d.state,'PUBLISHED')<>'REJECTED'
 AND NOT(EXISTS(SELECT 1 FROM families f JOIN cvie_disclosure_products dp ON dp.family_key=f.family_key WHERE f.product_id=l.product_id AND dp.cve_id=l.cve_id AND dp.applicability='unaffected')
  AND NOT EXISTS(SELECT 1 FROM families f JOIN cvie_disclosure_products dp ON dp.family_key=f.family_key WHERE f.product_id=l.product_id AND dp.cve_id=l.cve_id AND dp.applicability='affected'))
) `;}
export async function combinedPage(env,userId,cutoff,after='',productId='',now=Date.now(),context=null){
 const ctx=context||await evidenceContext(env,userId);if(!ctx)return null;
 const rows=(await q(env.DB,unifiedCte()+`SELECT * FROM unified WHERE (published>=? OR kev_json IS NOT NULL) AND published<=?
  AND (product_id||'/'||cve_id)>? ${productId?'AND product_id=?':''} ORDER BY product_id,cve_id LIMIT 101`,ctx.families,userId,cutoff,new Date(now).toISOString(),after,...(productId?[productId]:[])).all()).results||[];
 const page=rows.slice(0,100),keys=JSON.stringify(page.map(r=>r.product_id+'/'+r.cve_id));
 const matches=(await q(env.DB,`WITH families AS(SELECT json_extract(value,'$.product_id') AS product_id,json_extract(value,'$.key') AS family_key FROM json_each(?))
  SELECT f.product_id,d.cve_id,d.affected_json FROM families f JOIN cvie_disclosure_products d ON f.family_key=d.family_key
  WHERE (f.product_id||'/'||d.cve_id) IN(SELECT value FROM json_each(?)) AND d.applicability='affected'`,ctx.families,keys).all()).results||[];
 const matched=new Map();
 for(const row of matches){const key=row.product_id+'/'+row.cve_id;if(!matched.has(key))matched.set(key,[]);matched.get(key).push(...JSON.parse(row.affected_json));}
 const records=page.map(row=>{
  const affected=matched.get(row.product_id+'/'+row.cve_id),p=ctx.products.find(p=>p.id===row.product_id);
  return reconcileRecord(row.nvd_json?JSON.parse(row.nvd_json):null,affected&&row.cna_json?JSON.parse(row.cna_json):null,
   affected||[],p,row.kev_json?JSON.parse(row.kev_json):null,{...ctx.sources,cna_checked_at:row.cna_checked_at,record_pending:row.queued_id},now,cutoff);
 }).filter(Boolean);
 const last=page.at(-1);return {advisories:records,next:rows.length>100?last.product_id+'/'+last.cve_id:null};
}
export async function combinedCounts(env,userId,recent,history,now=Date.now(),context=null){
 const ctx=context||await evidenceContext(env,userId);if(!ctx)return null;
 return (await q(env.DB,unifiedCte()+`SELECT product_id,SUM(CASE WHEN published>=? THEN 1 ELSE 0 END) AS recent_count,
  SUM(CASE WHEN published>=? THEN 1 ELSE 0 END) AS history_count,
  SUM(CASE WHEN published<? AND kev_json IS NOT NULL THEN 1 ELSE 0 END) AS older_kev_recent_count,
  SUM(CASE WHEN published<? AND kev_json IS NOT NULL THEN 1 ELSE 0 END) AS older_kev_history_count
  FROM unified WHERE published<=? GROUP BY product_id`,ctx.families,userId,recent,history,recent,history,new Date(now).toISOString()).all()).results||[];
}
export async function withdrawnIds(env){
 if(!await evidenceReady(env))return [];
 return (await env.DB.prepare("SELECT cve_id FROM cvie_disclosures WHERE state='REJECTED'").all()).results.map(r=>r.cve_id);
}
export function mergeDigestEvidence(base,extra,withdrawn=[]){
 const removed=new Set(withdrawn),result=new Map();
 for(const record of [...base,...extra]){
  if(removed.has(record.id))continue;
  const prior=result.get(record.id);if(!prior){result.set(record.id,record);continue;}
  result.set(record.id,{...prior,...record,categories:[...new Set([...(prior.categories||[]),...(record.categories||[])])],
   known_exploited:record.kev_verified_at?record.known_exploited:Boolean(prior.known_exploited||record.known_exploited),
   cvie_products:[...new Set([...(prior.cvie_products||[]),...(record.cvie_products||[])])],
   cvie_identities:[...(prior.cvie_identities||[]),...(record.cvie_identities||[])],
   affected_cpes:[...(prior.affected_cpes||[]),...(record.affected_cpes||[])]});
 }
 return [...result.values()];
}
