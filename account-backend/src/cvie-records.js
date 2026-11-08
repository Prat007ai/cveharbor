// Reconcile authoritative evidence by CVE ID, retaining source-specific provenance.
import {evidenceReady,productFamilies,productLabels,SOURCE_URLS} from './cvie-evidence.js';
import {isHyperV,hyperVHost,hyperVStatementSql} from './hyperv.js';
import {dotnetProfile} from './dotnet.js';
import {rawProductLabels,coveragePlan,versionedLabelSql,cnaCoverageAdapters} from './product-coverage.js';
import {activeSubscription} from './catalogue-selection.js';
import {publicSourceStatus} from './public-source-status-cache.js';
import {sharedScans,ownedProductSql,overlaySharedProduct,validScopeLink} from './shared-scopes.js';
const q=(db,sql,...args)=>db.prepare(sql).bind(...args);
const DAY=86400000;
function affectedDescription(rows,name,preserveLabel=false){
 return rows.map(row=>{
  const versions=(row.versions||[]).filter(v=>v.status==='affected').map(v=>{
   const parts=[];
   if(v.version&&v.version!=='0'&&v.version!=='*')parts.push(v.lessThan||v.lessThanOrEqual?'>= '+v.version:v.version);
   if(v.lessThan)parts.push('< '+v.lessThan);if(v.lessThanOrEqual)parts.push('<= '+v.lessThanOrEqual);
   if(v.changes?.length)parts.push('(additional source conditions apply)');return parts.join(', ')||'version range not specified';
  });
  return (preserveLabel?String(row.product||name):name)+': '+(versions.join('; ')||'consult the original affected-version statement')+(row.defaultStatus==='affected'?' (other versions may also be affected; check source exceptions)':'');
 }).join('\n').slice(0,4000);
}
export function cnaRanges(rows,cpe,name){
 const result=[];
 for(const row of rows){
  for(const version of row.versions||[]){
   if(version.status!=='affected')continue;
   const match={vulnerable:true,criteria:cpe,cvie_product_key:name};
   if(version.changes?.length||version.versionType&&version.versionType!=='semver'||(row.versions||[]).some(v=>v.status==='unaffected')){result.push({...match,comparison_unsupported:true});continue;}
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
  if(row.defaultStatus!=='unaffected'||!(row.versions||[]).length||(row.versions||[]).some(v=>!['affected','unaffected'].includes(v.status)))result.push({vulnerable:true,criteria:cpe,cvie_product_key:name,comparison_unsupported:true});
 }
 return result;
}
export function reconcileRecord(nvd,cna,affected,product,kev,checks,now,cutoff){
 const references=new Map([...(nvd?.sources||[]),...(cna?.sources||[])].map(s=>[s.url,s]));
 const record={...(nvd||{}),...(cna||{})};
 if(!record.id)return null;
 const ranges=cna?cnaRanges(affected,product.cpe,product.name).map(range=>dotnetProfile(product)?{...range,comparison_unsupported:true}:range):[];
 if(cna){
  if(cna.cvss===null&&nvd){record.cvss=nvd.cvss;record.severity=nvd.severity;record.severity_source='NVD';}
  else record.severity_source=cna.cvss_provider||'CVE Program / CNA';
 }
 const conflicts=[];
 if(cna?.cvss_label_conflict)conflicts.push('The source severity label differs from its numeric CVSS score. CVIE uses the numeric score.');
 if(cna&&nvd&&cna.cvss!==null&&nvd.cvss!==null&&cna.cvss!==nvd.cvss)conflicts.push((cna.cvss_provider||'CVE Program / CNA')+' and NVD publish different severity scores. CVIE displays the CVE Program score.');
 record.affected_cpes=cna?(ranges.length?ranges:[{criteria:product.cpe,cvie_product_key:product.name,comparison_unsupported:true}]):nvd?.affected_cpes||[];
 record.affected=cna?affectedDescription(affected,product.name,Boolean(dotnetProfile(product))):nvd?.affected||'';
 record.cna_affected=cna?affected:undefined;
 record.source_type='cvie_combined';record.categories=[product.name];record.cvie_products=[product.name];record.cvie_identities=nvd?.cvie_identities?.map(identity=>({...identity,name:product.name}))||[{name:product.name,cpe:product.cpe}];
 const revisions=[nvd?.updated,cna?.updated,kev?.dateAdded].filter(value=>Number.isFinite(Date.parse(value)));
 if(revisions.length)record.source_updated_at=new Date(Math.max(...revisions.map(Date.parse))).toISOString();
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
 record.disclosure_verification_stale=Boolean(cna&&(!checks.cve_program?.last_success_at||checks.cve_program.status==='unavailable'||now-checks.cve_program.last_success_at>15*60000));
 record.evidence_status=record.verification_pending?'A source update is awaiting verification':record.disclosure_verification_stale?'Original disclosure feed is pending or overdue; last verified evidence retained':record.exploitation_verification_stale?'CISA verification is pending or overdue':'Source-backed evidence';
 if(record.known_exploited&&record.exploitation_verification_stale)record.exploitation+='; current catalogue verification is pending or overdue';
 record.source_conflicts=conflicts;record.sources=[...references.values()];return record;
}
export async function sourceHealth(env,now=Date.now()){
 return publicSourceStatus(env,now,()=>loadSourceHealth(env,now));
}
async function loadSourceHealth(env,now){
 if(!await evidenceReady(env))return {ready:false,sources:[{id:'cve_program',label:'CVE Program / original disclosures',status:'setup_required'},{id:'cisa_kev',label:'CISA KEV',status:'setup_required'}]};
 const rows=(await env.DB.prepare('SELECT * FROM cvie_sources ORDER BY id').all()).results||[];
 const pending=await env.DB.prepare(`SELECT COUNT(*) AS total,SUM(CASE WHEN priority<=1 THEN 1 ELSE 0 END) AS current,
  SUM(CASE WHEN priority=0 THEN 1 ELSE 0 END) AS relevant_kev,SUM(CASE WHEN attempts>0 THEN 1 ELSE 0 END) AS failed FROM cvie_disclosure_queue`).first();
 let queueAge={oldest_known_enqueued_at:null,age_unknown_records:pending.total};
 if(env.CVIE_METRICS_ENABLED==='true')try{queueAge=await env.DB.prepare(`SELECT MIN(o.enqueued_at) AS oldest_known_enqueued_at,
  SUM(CASE WHEN o.cve_id IS NULL THEN 1 ELSE 0 END) AS age_unknown_records,
  SUM(CASE WHEN j.attempts>0 THEN 1 ELSE 0 END) AS retrying_records,MAX(j.attempts) AS maximum_attempts
  FROM cvie_disclosure_queue j LEFT JOIN cvie_queue_observations o ON o.cve_id=j.cve_id`).first();}catch{/* Additive telemetry migration may not be installed yet. */}
 return {ready:true,queue_age:queueAge,pending_records:pending.total,failed_records:pending.failed||0,sources:rows.map(row=>({
  id:row.id,label:row.id==='cisa_kev'?'CISA KEV':'CVE Program / original disclosures',url:row.source_url||SOURCE_URLS[row.id],
  status:row.status==='unavailable'?'unavailable':row.record_retry_at>now?'rate_limited':!row.last_success_at?'pending':now-row.last_success_at>(row.id==='cisa_kev'?30:15)*60000?'stale':
   row.id==='cve_program'&&pending.current>0?'catching_up':row.id==='cisa_kev'&&pending.relevant_kev>0?'verifying_products':'current',
  last_attempt_at:row.last_attempt_at,last_success_at:row.last_success_at,publisher_at:row.publisher_at,coverage_start_at:row.coverage_start_at,
  pending_records:row.id==='cisa_kev'?pending.relevant_kev||0:pending.current||0,error:row.error,
  retry_at:row.record_retry_at||row.next_attempt_at,
 }))};
}
export async function evidenceContext(env,userId,scope='all'){
 if(!await evidenceReady(env))return null;
 const products=((await q(env.DB,ownedProductSql(env,'p.*',scope),userId).all()).results||[]).map(overlaySharedProduct);
 const families=products.flatMap(p=>{
  const scope=isHyperV(p)?'windows_hyperv':'';
  const keys=scope&&!hyperVHost(p.cpe)?['scope:windows_hyperv']:productFamilies(p);
  const rawLabels=coveragePlan(p).families.length?coveragePlan(p).families.flatMap(cpe=>rawProductLabels({...p,cpe})):rawProductLabels(p);
  return keys.map(key=>({product_id:p.id,key,labels:productLabels(p),raw_labels:rawLabels,scope}));
 });
 const sources=(await env.DB.prepare('SELECT * FROM cvie_sources').all()).results||[];
 return {products,scope,families:JSON.stringify(families),sources:Object.fromEntries(sources.map(s=>[s.id,s]))};
}
// SQL keyset pagination limits both public evidence and private data to the requested page.
function familiesCte(pageOnly=false){
 const disclosures=pageOnly?'page_disclosures':'cvie_disclosure_products';
 // Page enrichment only needs affected rows for the CVEs returned by pagination.
 const pageSource=pageOnly?`page_disclosures AS MATERIALIZED (
  SELECT d.* FROM json_each(?) ids CROSS JOIN cvie_disclosure_products d ON d.cve_id=ids.value
 ), `:'';
 return `WITH ${pageSource}families AS MATERIALIZED (
 SELECT json_extract(value,'$.product_id') AS product_id,json_extract(value,'$.key') AS family_key,json_extract(value,'$.labels') AS labels,COALESCE(json_extract(value,'$.raw_labels'),'[]') AS raw_labels,COALESCE(json_extract(value,'$.scope'),'') AS scope FROM json_each(?)
), verified_matches AS MATERIALIZED (
 SELECT DISTINCT f.product_id,d.cve_id,d.applicability,d.affected_json FROM families f CROSS JOIN ${disclosures} d ON d.family_key=f.family_key
 WHERE (substr(f.family_key,1,4)='cpe:' OR EXISTS(SELECT 1 FROM json_each(d.affected_json) a
  WHERE lower(replace(replace(json_extract(a.value,'$.product'),' ',''),'_','')) IN(SELECT value FROM json_each(f.labels))))
 AND (f.scope<>'windows_hyperv' OR EXISTS(SELECT 1 FROM cvie_disclosures c WHERE c.cve_id=d.cve_id AND ${hyperVStatementSql('c.record_json')}))
 UNION
 SELECT DISTINCT f.product_id,d.cve_id,d.applicability,d.affected_json FROM families f CROSS JOIN ${disclosures} d
  ON d.family_key>=f.family_key AND d.family_key<f.family_key||char(127)
 WHERE substr(f.family_key,1,5)='name:' AND EXISTS(SELECT 1 FROM json_each(d.affected_json) a WHERE ${versionedLabelSql('a.value','f.raw_labels')})
  AND (f.scope<>'windows_hyperv' OR EXISTS(SELECT 1 FROM cvie_disclosures c WHERE c.cve_id=d.cve_id AND ${hyperVStatementSql('c.record_json')}))
 ${cnaCoverageAdapters.map(adapter=>`UNION
 SELECT DISTINCT f.product_id,d.cve_id,d.applicability,d.affected_json FROM families f JOIN ${disclosures} d
  ON d.family_key LIKE 'name:microsoft:%'
 WHERE f.family_key='${adapter.key}' AND EXISTS(SELECT 1 FROM json_each(d.affected_json) a WHERE ${adapter.matchSql('a.value')})`).join('\n')}
) `;}
function unifiedCte(env,scope='all'){
 const shared=sharedScans(env);
 // Resolve ownership, subscription and the current shared mapping once. Keeping
 // catalogue checks out of correlated lookups keeps the plan within D1 limits.
 const ownership=shared?`LEFT JOIN cvie_product_scopes m ON ${validScopeLink()}
  LEFT JOIN cvie_shared_scopes s ON s.id=m.scope_id`:'';
 const sharedFields=shared?',m.scope_id,s.seed_state,s.history_complete_at':'';
 const sharedRows=shared?`SELECT p.id AS product_id,a.cve_id,a.published,a.record_json,p.cpe
  FROM owned p JOIN cvie_shared_advisories a ON a.scope_id=p.scope_id UNION ALL`:'';
 const legacyFilter=shared?`WHERE (p.scope_id IS NULL OR p.seed_state IS NOT 'complete' OR p.history_complete_at IS NULL)
  AND NOT EXISTS(SELECT 1 FROM cvie_shared_advisories s WHERE s.scope_id=p.scope_id AND s.cve_id=a.cve_id)`:'';
 return familiesCte()+`, owned AS MATERIALIZED (
  SELECT p.id,p.cpe${sharedFields} FROM json_each(?) ids JOIN cvie_products p ON p.id=ids.value
  ${ownership} WHERE p.user_id=? AND ${activeSubscription('p',scope)}
 ), nvd AS MATERIALIZED (
  ${sharedRows}
  SELECT p.id AS product_id,a.cve_id,a.published,a.record_json,p.cpe
  FROM owned p JOIN cvie_advisories a ON a.product_id=p.id ${legacyFilter}
 ), verdicts AS MATERIALIZED (
  SELECT product_id,cve_id,MAX(applicability='affected') AS affected,MAX(applicability='unaffected') AS unaffected
  FROM verified_matches GROUP BY product_id,cve_id
 ), unified AS (
  SELECT COALESCE(a.product_id,v.product_id) AS product_id,COALESCE(a.cve_id,v.cve_id) AS cve_id,
   COALESCE(CASE WHEN v.cve_id IS NOT NULL THEN d.published END,a.published) AS published,
   a.record_json AS nvd_json,CASE WHEN v.cve_id IS NOT NULL THEN d.record_json END AS cna_json,
   d.checked_at AS cna_checked_at,k.record_json AS kev_json,j.cve_id AS queued_id
  FROM nvd a FULL OUTER JOIN verdicts v ON v.product_id=a.product_id AND v.cve_id=a.cve_id
  LEFT JOIN cvie_disclosures d ON d.cve_id=COALESCE(a.cve_id,v.cve_id)
  LEFT JOIN cvie_kev k ON k.cve_id=COALESCE(a.cve_id,v.cve_id)
  LEFT JOIN cvie_disclosure_queue j ON j.cve_id=COALESCE(a.cve_id,v.cve_id)
  WHERE COALESCE(d.state,'PUBLISHED')<>'REJECTED' AND (v.unaffected IS NOT 1 OR v.affected IS 1)
  AND (v.cve_id IS NOT NULL OR NOT EXISTS(SELECT 1 FROM families f WHERE f.product_id=a.product_id AND f.scope='windows_hyperv')
   OR (EXISTS(SELECT 1 FROM families f WHERE f.product_id=a.product_id AND f.family_key='cpe:'||a.cpe)
    AND ${hyperVStatementSql('a.record_json')} AND (d.state IS NOT 'PUBLISHED' OR ${hyperVStatementSql('d.record_json')})))
 ) `;}
export async function combinedPage(env,userId,cutoff,after='',productId='',now=Date.now(),context=null){
 const ctx=context||await evidenceContext(env,userId);if(!ctx)return null;
 const recent=new Date(now-30*DAY).toISOString().slice(0,10);
 const severity=`CASE WHEN json_extract(cna_json,'$.cvss') IS NOT NULL THEN json_extract(cna_json,'$.severity') ELSE COALESCE(json_extract(nvd_json,'$.severity'),json_extract(cna_json,'$.severity')) END`;
 const ranked=ctx.digest?`, ranked AS(SELECT unified.*,ROW_NUMBER() OVER(PARTITION BY cve_id ORDER BY (cna_json IS NOT NULL) DESC,product_id) AS ordinal,
  json_group_array(product_id) OVER(PARTITION BY cve_id) AS digest_products,
  (CASE WHEN kev_json IS NOT NULL THEN '0' WHEN (${severity})='critical' THEN '1' ELSE '2' END)||'/'||cve_id AS sort_key
  FROM unified WHERE (published>=? OR kev_json IS NOT NULL) AND published<=?
  AND ((${severity}) IN('critical','high') OR json_extract(kev_json,'$.dateAdded')>=?)
  AND (substr(published,1,10)>=? OR substr(json_extract(cna_json,'$.updated'),1,10)>=? OR substr(json_extract(nvd_json,'$.updated'),1,10)>=? OR json_extract(kev_json,'$.dateAdded')>=?))
  SELECT * FROM ranked WHERE ordinal=1 AND sort_key>? ORDER BY sort_key LIMIT 101`:
  `SELECT * FROM unified WHERE (published>=? OR kev_json IS NOT NULL) AND published<=?
  AND (product_id||'/'||cve_id)>? ${productId?'AND product_id=?':''} ORDER BY product_id,cve_id LIMIT 101`;
 const args=ctx.digest?[cutoff,new Date(now).toISOString(),recent,recent,recent,recent,recent,after]:[cutoff,new Date(now).toISOString(),after,...(productId?[productId]:[])];
 const rows=(await q(env.DB,unifiedCte(env,ctx.scope)+ranked,ctx.families,JSON.stringify(ctx.products.map(p=>p.id)),userId,...args).all()).results||[];
 const page=rows.slice(0,100),keys=JSON.stringify(page.map(r=>r.product_id+'/'+r.cve_id));
 const pageIds=JSON.stringify([...new Set(page.map(row=>row.cve_id))]);
 const matches=page.length?(await q(env.DB,familiesCte(true)+`SELECT product_id,cve_id,affected_json FROM verified_matches
  WHERE (product_id||'/'||cve_id) IN(SELECT value FROM json_each(?)) AND applicability='affected'`,pageIds,ctx.families,keys).all()).results||[]:[];
 const matched=new Map();
 for(const row of matches){const key=row.product_id+'/'+row.cve_id;if(!matched.has(key))matched.set(key,[]);matched.get(key).push(...JSON.parse(row.affected_json));}
 const records=page.map(row=>{
  const affected=matched.get(row.product_id+'/'+row.cve_id),p=ctx.products.find(p=>p.id===row.product_id);
  const record=reconcileRecord(row.nvd_json?JSON.parse(row.nvd_json):null,affected&&row.cna_json?JSON.parse(row.cna_json):null,
   affected||[],p,row.kev_json?JSON.parse(row.kev_json):null,{...ctx.sources,cna_checked_at:row.cna_checked_at,record_pending:row.queued_id},now,cutoff);
  if(record&&ctx.digest){const ids=new Set(JSON.parse(row.digest_products));record.categories=ctx.products.filter(p=>ids.has(p.id)).map(p=>p.name);record.cvie_products=record.categories;}
  return record;
 }).filter(Boolean);
 const last=page.at(-1);return {advisories:records,next:rows.length>100?(ctx.digest?last.sort_key:last.product_id+'/'+last.cve_id):null};
}
export async function combinedCounts(env,userId,recent,history,now=Date.now(),context=null){
 const ctx=context||await evidenceContext(env,userId);if(!ctx)return null;
 return (await q(env.DB,unifiedCte(env,ctx.scope)+`SELECT product_id,SUM(CASE WHEN published>=? THEN 1 ELSE 0 END) AS recent_count,
  SUM(CASE WHEN published>=? THEN 1 ELSE 0 END) AS history_count,
  SUM(CASE WHEN published<? AND kev_json IS NOT NULL THEN 1 ELSE 0 END) AS older_kev_recent_count,
  SUM(CASE WHEN published<? AND kev_json IS NOT NULL THEN 1 ELSE 0 END) AS older_kev_history_count
  FROM unified WHERE published<=? GROUP BY product_id`,ctx.families,JSON.stringify(ctx.products.map(p=>p.id)),userId,recent,history,recent,history,new Date(now).toISOString()).all()).results||[];
}
export async function withdrawnIds(env){
 if(!await evidenceReady(env))return [];
 return (await env.DB.prepare("SELECT cve_id FROM cvie_disclosures WHERE state='REJECTED'").all()).results.map(r=>r.cve_id);
}
export async function excludedProductCves(env,userId,context=null){
 const ctx=context||await evidenceContext(env,userId);if(!ctx)return [];
 const rows=(await q(env.DB,familiesCte()+`SELECT product_id,cve_id FROM verified_matches
  GROUP BY product_id,cve_id HAVING MAX(applicability='unaffected')=1 AND MAX(applicability='affected')=0
  ORDER BY cve_id,product_id`,ctx.families).all()).results||[];
 return rows.map(row=>({id:row.cve_id,product:ctx.products.find(p=>p.id===row.product_id).name}));
}
export function mergeDigestEvidence(base,extra,withdrawn=[],excluded=[],componentProducts=[]){
 const removed=new Set(withdrawn),result=new Map();
 const normalize=value=>String(value).normalize('NFKC').trim().toLowerCase(),verified=new Map();
 for(const r of extra){if(!verified.has(r.id))verified.set(r.id,new Set());for(const name of r.cvie_products||[])verified.get(r.id).add(normalize(name));}
 const exclusions=new Map();for(const {id,product} of excluded){if(!exclusions.has(id))exclusions.set(id,[]);exclusions.get(id).push(product);}
 for(const record of [...base,...extra]){
  if(removed.has(record.id))continue;
  const prior=result.get(record.id);if(!prior){result.set(record.id,record);continue;}
  result.set(record.id,{...prior,...record,categories:[...new Set([...(prior.categories||[]),...(record.categories||[])])],
   known_exploited:record.kev_verified_at?record.known_exploited:Boolean(prior.known_exploited||record.known_exploited),
   cvie_products:[...new Set([...(prior.cvie_products||[]),...(record.cvie_products||[])])],
   cvie_identities:[...(prior.cvie_identities||[]),...(record.cvie_identities||[])],
   affected_cpes:[...(prior.affected_cpes||[]),...(record.affected_cpes||[])]});
 }
 return [...result.values()].map(record=>{
  const names=[...new Set([...(exclusions.get(record.id)||[]),...componentProducts.filter(name=>!verified.get(record.id)?.has(normalize(name)))])];if(!names.length)return record;
  return {...record,cvie_excluded_products:names,categories:(record.categories||[]).filter(name=>!names.some(product=>normalize(product)===normalize(name)))};
 });
}
