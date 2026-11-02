import {curatedProductFamily} from './product-identity.js';
import {resolveRegistry,registryEnabled,registryIdentity,searchRegistry,storedRegistryIdentity,registerVerifiedCpe} from './product-registry.js';
import {reconcileRecord} from './cvie-records.js';
import {coveragePlan} from './product-coverage.js';
import {activeSubscription} from './catalogue-selection.js';
const q=(env,sql,...args)=>env.DB.prepare(sql).bind(...args);
export const fastEvidenceEnabled=env=>registryEnabled(env)&&env.CVIE_FAST_EVIDENCE_ENABLED==='true';
export async function bindProductIdentities(env,userId){
 if(!registryEnabled(env))return;
 const rows=(await q(env,`SELECT p.id,p.name,p.vendor,p.cpe FROM cvie_products p
  LEFT JOIN cvie_product_identities b ON b.product_id=p.id AND b.source_name=p.name
   AND b.source_vendor=p.vendor AND b.source_cpe=p.cpe
   AND b.revision=(SELECT revision FROM cvie_identities i WHERE i.identity_id=b.identity_id)
  WHERE p.user_id=? AND b.product_id IS NULL`,userId).all()).results||[];
 const statements=[];
 for(const p of rows){
  const plan=coveragePlan(p);
  let identity=plan.families.length===1&&plan.type!=='identity_conflict'&&!plan.component?resolveRegistry(p)||await storedRegistryIdentity(env,{cpe:p.cpe}):!p.cpe?resolveRegistry(p):null;
  if(!identity&&plan.families.length===1&&plan.type!=='identity_conflict'&&!plan.component&&curatedProductFamily(p.cpe))identity=await registerVerifiedCpe(env,p.cpe);
  if(identity)statements.push(q(env,`INSERT INTO cvie_product_identities(product_id,identity_id,source_name,source_vendor,source_cpe,revision) VALUES(?,?,?,?,?,?)
   ON CONFLICT(product_id) DO UPDATE SET identity_id=excluded.identity_id,source_name=excluded.source_name,source_vendor=excluded.source_vendor,source_cpe=excluded.source_cpe,revision=excluded.revision
   WHERE identity_id IS NOT excluded.identity_id OR source_name<>excluded.source_name OR source_vendor<>excluded.source_vendor OR source_cpe<>excluded.source_cpe OR revision<>excluded.revision`,p.id,identity.id,p.name,p.vendor,p.cpe,identity.revision));
  else statements.push(q(env,'DELETE FROM cvie_product_identities WHERE product_id=?',p.id));
  if(!p.cpe){
   const choices=searchRegistry({q:p.name,vendor:p.vendor}).candidates.filter(i=>i.cpe).map(i=>({cpe:i.cpe,label:i.name,identity_id:i.id}));
   statements.push(q(env,`UPDATE cvie_products SET status='needs_identity',candidates_json=?,error='Exact product identity required; coverage is unknown.'
    WHERE id=? AND cpe='' AND (status<>'needs_identity' OR candidates_json<>?)`,JSON.stringify(choices),p.id,JSON.stringify(choices)));
  }
 }
 // Bound D1 batch size; all operations are idempotent and private.
 for(let i=0;i<statements.length;i+=50)await env.DB.batch(statements.slice(i,i+50));
}
export const evidencePageSql=`WITH page AS MATERIALIZED (
 SELECT cve_id,nvd_scope_id,cna_affected_json,sort_date FROM cvie_identity_evidence
 WHERE identity_id=? AND sort_date>=? AND (sort_date,cve_id)<(?,?) ORDER BY sort_date DESC,cve_id DESC LIMIT ?
) SELECT p.*,n.record_json AS nvd_json,d.record_json AS cna_json,d.state,d.checked_at,k.record_json AS kev_json,j.cve_id AS pending_id
 FROM page p LEFT JOIN cvie_shared_advisories n ON n.scope_id=p.nvd_scope_id AND n.cve_id=p.cve_id
 LEFT JOIN cvie_disclosures d ON d.cve_id=p.cve_id LEFT JOIN cvie_kev k ON k.cve_id=p.cve_id
 LEFT JOIN cvie_disclosure_queue j ON j.cve_id=p.cve_id ORDER BY p.sort_date DESC,p.cve_id DESC`;
export async function immediateEvidence(env,userId,productId,{after='',limit=100,scope='all',months=12}={}){
 if(!fastEvidenceEnabled(env))return {enabled:false};
 if(!/^[a-f0-9-]{36}$/.test(productId)||!['all','catalogue','inventory','stack'].includes(scope)||!Number.isInteger(limit)||limit<1||limit>100||after.length>300||![3,12].includes(months))throw Error('Invalid evidence page');
 const p=await q(env,`SELECT p.*,b.identity_id FROM cvie_products p LEFT JOIN cvie_product_identities b ON b.product_id=p.id
  AND b.source_name=p.name AND b.source_vendor=p.vendor AND b.source_cpe=p.cpe
  WHERE p.id=? AND p.user_id=? AND ${activeSubscription('p',scope)}`,productId,userId).first();
 if(!p)return {not_found:true};
 const identity=p.identity_id?await storedRegistryIdentity(env,{id:p.identity_id}):null;
 if(!identity||identity.kind==='group')return {enabled:true,advisories:[],next:null,coverage:'identity_required',guidance:'Confirm the exact vendor, product and release or component. No result does not establish safety.'};
 if(!identity.cpe)return {enabled:true,advisories:[],next:null,coverage:'package_sources_required',guidance:'Use the verified package identifier and installed version in package or plugin monitoring. This source index has incomplete package coverage.'};
 const now=Date.now(),cutoff=new Date(now),day=cutoff.getUTCDate();cutoff.setUTCDate(1);cutoff.setUTCMonth(cutoff.getUTCMonth()-months);cutoff.setUTCDate(Math.min(day,new Date(Date.UTC(cutoff.getUTCFullYear(),cutoff.getUTCMonth()+1,0)).getUTCDate()));
 let cursor=['~','~'];
 if(after){try{cursor=JSON.parse(atob(after));}catch{throw Error('Invalid evidence cursor');}if(!Array.isArray(cursor)||cursor.length!==2||typeof cursor[0]!=='string'||!Number.isFinite(Date.parse(cursor[0]))||!/^CVE-\d{4}-\d{4,}$/.test(cursor[1]))throw Error('Invalid evidence cursor');}
 const rows=(await q(env,evidencePageSql,identity.id,cutoff.toISOString(),...cursor,limit+1).all()).results||[];
 const sources=(await env.DB.prepare('SELECT id,status,last_success_at FROM cvie_sources').all()).results||[];
 const checks=Object.fromEntries(sources.map(s=>[s.id,s]));
 const negative=(await q(env,`SELECT e.cve_id FROM cvie_identity_evidence e JOIN cvie_disclosures d ON d.cve_id=e.cve_id
  WHERE e.identity_id=? AND e.sort_date='' AND (d.state='REJECTED' OR e.cna_affected_json IS NOT NULL AND d.published IS NOT NULL) ORDER BY e.cve_id LIMIT 101`,identity.id).all()).results||[];
 const advisories=[],excluded_product_cves=negative.slice(0,100).map(r=>({id:r.cve_id,product:p.name}));
 for(const r of rows.slice(0,limit)){
  if(r.state==='REJECTED')continue;
  const affected=JSON.parse(r.cna_affected_json||'[]');
  if(affected.length&&affected.every(a=>a.defaultStatus==='unaffected'&&(a.versions||[]).every(v=>v.status==='unaffected'))){excluded_product_cves.push({id:r.cve_id,product:p.name});continue;}
  const cna=r.state==='PUBLISHED'&&affected.length?JSON.parse(r.cna_json):null;
  const nvd=r.nvd_json?JSON.parse(r.nvd_json):null,kev=r.kev_json?JSON.parse(r.kev_json):null;
  const record=reconcileRecord(nvd,cna,affected,p,kev,{...checks,cna_checked_at:r.checked_at,record_pending:Boolean(r.pending_id)},now,cutoff.toISOString());
  if(!record||Date.parse(record.published)>now||Date.parse(record.published)<cutoff.getTime()&&!kev)continue;
  // Identity evidence is not an installed-version verdict. Preserve distro/backport uncertainty.
  if(!['numeric','semver'].includes(identity.version_scheme))record.affected_cpes=(record.affected_cpes||[]).map(c=>({...c,comparison_unsupported:true}));
  record.applicability='requires_version_review';record.coverage_limited=true;
  advisories.push(record);
 }
 return {enabled:true,identity_id:identity.id,product_id:p.id,advisories,excluded_product_cves,next:rows.length>limit?btoa(JSON.stringify([rows[limit-1].sort_date,rows[limit-1].cve_id])):null,
  negative_assertions_limited:negative.length>100,coverage:'indexed_partial',scanned:Math.min(rows.length,limit),guidance:'Stored source evidence; coverage is incomplete. Review installed versions, configurations and vendor fixes. Background discovery is shared.'};
}
