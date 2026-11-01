// Shared tables contain public source identities/history only. The separate
// product bridge and seed cursor are private and always joined through an owner.
import {coveragePlan,coverageMetadata,COVERAGE_VERSION} from './product-coverage.js';
import {curatedProductFamily} from './product-identity.js';
import {hyperVHost} from './hyperv.js';
import {dotnetProfile} from './dotnet.js';
const q=(db,sql,...args)=>db.prepare(sql).bind(...args);
export const SHARED_VERSION='shared-v1/'+COVERAGE_VERSION;
export const sharedScans=env=>env.CVIE_SHARED_SCANS_ENABLED==='true';
export const validScopeLink=(p='p',m='m')=>`${m}.product_id=${p}.id AND ${m}.source_name=${p}.name AND ${m}.source_vendor=${p}.vendor AND ${m}.source_cpe=${p}.cpe AND ${m}.version='${SHARED_VERSION}'`;
const idCache=new Map();
const readCursor=value=>{try{return JSON.parse(value||'{}');}catch{return {};}};
export const publicIdentityProof=(p='p')=>`EXISTS(SELECT 1 FROM cvie_advisories proof WHERE proof.product_id=${p}.id
 AND json_extract(proof.record_json,'$.source_type')='cvie_nvd' AND EXISTS(SELECT 1 FROM json_each(json_extract(proof.record_json,'$.cvie_identities')) i WHERE json_extract(i.value,'$.cpe')=${p}.cpe))`;
export function trustedSharedIdentity(product){
 return curatedProductFamily(product.cpe)||Boolean(hyperVHost(product.cpe))||Boolean(dotnetProfile({name:'.NET Core',cpe:product.cpe,vendor:product.cpe?.split(':')[3]}))||Boolean(product.public_identity_verified)||
  Boolean(readCursor(product.candidates_json)?.some?.(choice=>choice.cpe===product.cpe));
}
export async function sharedDescriptor(product){
 const plan=coveragePlan(product);
 if(!plan.families.length||plan.type==='identity_conflict')return null;
 const signature=JSON.stringify([SHARED_VERSION,[...plan.families].sort(),[...plan.terms].sort(),plan.component]);
 let id=idCache.get(signature);
 if(!id){id=[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(signature)))].map(n=>n.toString(16).padStart(2,'0')).join('');if(idCache.size>=2000)idCache.delete(idCache.keys().next().value);idCache.set(signature,id);}
 const canonical={name:plan.profile?'.NET Core':plan.component?'HyperV':plan.families[0].split(':').slice(3,5).join(' / ').replaceAll('_',' '),vendor:plan.primary.split(':')[3],cpe:plan.primary};
 return {id,signature,...canonical};
}
export function ownedProductSql(env,select='p.*'){
 if(!sharedScans(env))return `SELECT ${select} FROM cvie_products p WHERE p.user_id=? AND EXISTS(SELECT 1 FROM cvie_subscriptions s WHERE s.product_id=p.id) ORDER BY p.name`;
 const fields=['status','cursor_json','scan_started_at','last_attempt_at','last_success_at','recent_complete_at','history_complete_at','next_attempt_at','error'];
 return `SELECT ${select},j.id AS shared_scope_id,j.seed_state AS shared_seed_state,${fields.map(k=>`j.${k} AS shared_${k}`).join(',')}
  FROM cvie_products p LEFT JOIN cvie_product_scopes m ON ${validScopeLink()} LEFT JOIN cvie_shared_scopes j ON j.id=m.scope_id
  WHERE p.user_id=? AND EXISTS(SELECT 1 FROM cvie_subscriptions s WHERE s.product_id=p.id) ORDER BY p.name`;
}
export function overlaySharedProduct(row){
 if(!row.shared_scope_id)return row;
 const result={...row};
 for(const key of ['status','cursor_json','scan_started_at','last_attempt_at','last_success_at','recent_complete_at','history_complete_at','next_attempt_at','error'])result[key]=row['shared_'+key];
 if(row.shared_seed_state==='pending'){result.status='queued';result.recent_complete_at=null;result.history_complete_at=null;}
 return result;
}
function inheritedState(donor,descriptor,now){
 const plan=coveragePlan(descriptor),empty={status:'queued',cursor_json:JSON.stringify(coverageMetadata(plan)),next_attempt_at:0};
 if(!donor)return empty;
 let cursor;try{cursor=JSON.parse(donor.cursor_json);}catch{return empty;}
 if(cursor.coverage_signature!==coveragePlan(donor).signature)return empty;
 const windows=cursor.windows;
 if(windows&&(!Array.isArray(windows)||!Number.isInteger(cursor.position)||cursor.position<0||cursor.position>=windows.length||windows.some(w=>!Number.isFinite(w.start)||!Number.isFinite(w.end)||w.start>w.end||w.end>now||!Number.isSafeInteger(w.index)||w.index<0||!(w.cpe?plan.families.includes(w.cpe):plan.terms.includes(w.disclosures)))))return empty;
 const safe={...coverageMetadata(plan,cursor)};
 if(windows){safe.windows=windows.map(w=>Object.fromEntries(['start','end','index','cpe','disclosures','total','pages'].filter(k=>w[k]!==undefined).map(k=>[k,w[k]])));safe.position=cursor.position;safe.anchor=cursor.anchor;safe.recent_windows=cursor.recent_windows;safe.generation=crypto.randomUUID();}
 return {status:['queued','scanning','retrying','ready'].includes(donor.status)?donor.status:'queued',cursor_json:JSON.stringify(safe),
  ...Object.fromEntries(['scan_started_at','last_attempt_at','last_success_at','recent_complete_at','history_complete_at','next_attempt_at','error'].map(k=>[k,donor[k]]))};
}
function chunks(rows,size=50){const out=[];for(let i=0;i<rows.length;i+=size)out.push(JSON.stringify(rows.slice(i,i+size)));return out;}
export async function reconcileSharedScopes(env,userId=null,now=Date.now(),limit=userId?500:100){
 if(!sharedScans(env))return {linked:0};
 const rows=(await q(env.DB,`SELECT p.*,${publicIdentityProof()} AS public_identity_verified FROM cvie_products p LEFT JOIN cvie_product_scopes m ON ${validScopeLink()}
  WHERE (m.product_id IS NULL OR (m.scope_id IS NULL AND m.candidate_scope_id IS NOT NULL AND ${publicIdentityProof()}))
  AND EXISTS(SELECT 1 FROM cvie_subscriptions s WHERE s.product_id=p.id) ${userId?'AND p.user_id=?':''}
  ORDER BY p.history_complete_at DESC,p.last_success_at DESC,p.id LIMIT ?`,...(userId?[userId]:[]),limit).all()).results||[];
 if(!rows.length)return {linked:0};
 const entries=await Promise.all(rows.map(async p=>({p,d:await sharedDescriptor(p)}))),unique=new Map();
 for(const {p,d} of entries)if(d)unique.set(d.id,{...d,trusted:trustedSharedIdentity(p)||unique.get(d.id)?.trusted});
 const ids=JSON.stringify([...unique.keys()]);
 const existing=new Set(unique.size?(await q(env.DB,'SELECT id FROM cvie_shared_scopes WHERE id IN(SELECT value FROM json_each(?))',ids).all()).results.map(r=>r.id):[]);
 const missing=[...unique.values()].filter(d=>d.trusted&&!existing.has(d.id));
 // Choose compatible existing history, without copying private aliases into it.
 const donorRows=missing.length?(await q(env.DB,`SELECT p.* FROM cvie_products p WHERE p.cpe IN(SELECT value FROM json_each(?))
  AND p.last_success_at IS NOT NULL AND EXISTS(SELECT 1 FROM cvie_subscriptions s WHERE s.product_id=p.id)
  ORDER BY p.history_complete_at DESC,p.recent_complete_at DESC,p.last_success_at DESC LIMIT 500`,JSON.stringify([...new Set(missing.map(d=>d.cpe))])).all()).results:[];
 const donors=new Map();
 const score=p=>[readCursor(p.cursor_json).coverage_signature===coveragePlan(p).signature?1:0,p.history_complete_at?1:0,p.recent_complete_at?1:0,p.last_success_at||0];
 const better=(a,b)=>{const x=score(a),y=score(b);for(let i=0;i<x.length;i++)if(x[i]!==y[i])return x[i]>y[i];return false;};
 for(const p of [...donorRows,...rows.filter(p=>p.last_success_at)]){const d=await sharedDescriptor(p);if(d&&(!donors.has(d.id)||better(p,donors.get(d.id))))donors.set(d.id,p);}
 const scopes=missing.map(d=>{const donor=donors.get(d.id),state=inheritedState(donor,d,now);return {...d,...state,seed_state:donor?'pending':'complete',seed_token:donor?crypto.randomUUID():'',donor};});
 const statements=[];
 for(const payload of chunks(scopes.map(({donor,...r})=>r)))statements.push(q(env.DB,`INSERT OR IGNORE INTO cvie_shared_scopes(id,signature,name,vendor,cpe,status,cursor_json,scan_started_at,last_attempt_at,last_success_at,recent_complete_at,history_complete_at,next_attempt_at,error,seed_state,seed_token)
  SELECT json_extract(value,'$.id'),json_extract(value,'$.signature'),json_extract(value,'$.name'),json_extract(value,'$.vendor'),json_extract(value,'$.cpe'),json_extract(value,'$.status'),json_extract(value,'$.cursor_json'),json_extract(value,'$.scan_started_at'),json_extract(value,'$.last_attempt_at'),json_extract(value,'$.last_success_at'),json_extract(value,'$.recent_complete_at'),json_extract(value,'$.history_complete_at'),COALESCE(json_extract(value,'$.next_attempt_at'),0),COALESCE(json_extract(value,'$.error'),''),json_extract(value,'$.seed_state'),json_extract(value,'$.seed_token') FROM json_each(?)`,payload));
 const seeds=scopes.filter(s=>s.donor).map(s=>({id:s.id,product_id:s.donor.id,token:s.seed_token,name:s.donor.name,vendor:s.donor.vendor,cpe:s.donor.cpe,donor_generation:readCursor(s.donor.cursor_json).generation||'',generation:readCursor(s.cursor_json).generation||crypto.randomUUID(),status:s.status}));
 for(const payload of chunks(seeds))statements.push(q(env.DB,`INSERT OR IGNORE INTO cvie_shared_seeds(scope_id,product_id,token,source_name,source_vendor,source_cpe,donor_generation,generation,resume_status)
  SELECT json_extract(value,'$.id'),json_extract(value,'$.product_id'),json_extract(value,'$.token'),json_extract(value,'$.name'),json_extract(value,'$.vendor'),json_extract(value,'$.cpe'),json_extract(value,'$.donor_generation'),json_extract(value,'$.generation'),json_extract(value,'$.status') FROM json_each(?) r
  WHERE EXISTS(SELECT 1 FROM cvie_shared_scopes s WHERE s.id=json_extract(r.value,'$.id') AND s.seed_token=json_extract(r.value,'$.token') AND s.seed_state='pending')`,payload));
 const available=new Set([...existing,...missing.map(d=>d.id)]);
 for(const payload of chunks(entries.map(({p,d})=>({product_id:p.id,scope_id:d&&available.has(d.id)?d.id:null,candidate_scope_id:d?.id||null,name:p.name,vendor:p.vendor,cpe:p.cpe}))))statements.push(q(env.DB,`INSERT INTO cvie_product_scopes(product_id,scope_id,candidate_scope_id,source_name,source_vendor,source_cpe,version)
  SELECT p.id,json_extract(r.value,'$.scope_id'),json_extract(r.value,'$.candidate_scope_id'),p.name,p.vendor,p.cpe,? FROM json_each(?) r JOIN cvie_products p ON p.id=json_extract(r.value,'$.product_id')
  WHERE p.name=json_extract(r.value,'$.name') AND p.vendor=json_extract(r.value,'$.vendor') AND p.cpe=json_extract(r.value,'$.cpe')
  ON CONFLICT(product_id) DO UPDATE SET scope_id=excluded.scope_id,candidate_scope_id=excluded.candidate_scope_id,source_name=excluded.source_name,source_vendor=excluded.source_vendor,source_cpe=excluded.source_cpe,version=excluded.version`,SHARED_VERSION,payload));
 if(missing.length)statements.push(q(env.DB,`UPDATE cvie_product_scopes SET scope_id=candidate_scope_id WHERE scope_id IS NULL
  AND candidate_scope_id IN(SELECT value FROM json_each(?)) AND version=? AND EXISTS(SELECT 1 FROM cvie_products p WHERE ${validScopeLink('p','cvie_product_scopes')})`,JSON.stringify(missing.map(d=>d.id)),SHARED_VERSION));
 statements.push(q(env.DB,`UPDATE cvie_products SET lease_until=0,cursor_json=json_remove(cursor_json,'$.active_scan') WHERE lease_until<>0 AND (
  EXISTS(SELECT 1 FROM cvie_product_scopes m WHERE ${validScopeLink('cvie_products')} AND m.scope_id IS NOT NULL)
  OR id IN(SELECT product_id FROM cvie_shared_seeds))`));
 await env.DB.batch(statements);
 return {linked:entries.length,scopes_created:scopes.length};
}
// Legacy records were produced by normalizeNvd. Reconstruct only public NVD
// inputs and normalize again under the canonical scope, discarding all aliases.
function publicInput(record){
 if(record.source_type!=='cvie_nvd'||!Array.isArray(record.affected_cpes))return null;
 const keys=['vulnerable','criteria','versionStartIncluding','versionStartExcluding','versionEndIncluding','versionEndExcluding','matchCriteriaId'];
 return {id:record.id,published:record.published,lastModified:record.updated,vulnStatus:record.status,
  descriptions:[{lang:'en',value:record.summary}],configurations:[{nodes:[{cpeMatch:record.affected_cpes.map(m=>Object.fromEntries(keys.filter(k=>m[k]!==undefined).map(k=>[k,m[k]])))}]}],
  metrics:record.cvss===null?{}:{cvssMetricV31:[{cvssData:{baseScore:record.cvss}}]},
  references:(record.sources||[]).map(s=>({url:s.url,tags:s.label==='Vendor advisory'?['Vendor Advisory']:[]})),cisaExploitAdd:record.known_exploited||undefined};
}
export async function seedSharedHistory(env,scope,normalize,now=Date.now()){
 const owner=crypto.randomUUID(),lease=now+120000;
 const claimed=await q(env.DB,"UPDATE cvie_shared_scopes SET lease_until=?,cursor_json=json_set(cursor_json,'$.active_scan',?) WHERE id=? AND seed_token=? AND seed_state='pending' AND lease_until<?",lease,owner,scope.id,scope.seed_token,now).run();
 if(claimed.meta.changes!==1)return {busy:true,no_provider:true};
 const seed=await q(env.DB,`SELECT x.*,p.name AS donor_name,p.vendor AS donor_vendor,p.cpe AS donor_cpe,p.cursor_json AS donor_cursor_json FROM cvie_shared_seeds x LEFT JOIN cvie_products p ON p.id=x.product_id WHERE x.scope_id=? AND x.token=?`,scope.id,scope.seed_token).first();
 const valid=seed&&seed.source_name===seed.donor_name&&seed.source_vendor===seed.donor_vendor&&seed.source_cpe===seed.donor_cpe&&seed.donor_generation===(readCursor(seed.donor_cursor_json).generation||'');
 const rows=valid?(await q(env.DB,'SELECT * FROM cvie_advisories WHERE product_id=? AND cve_id>? ORDER BY cve_id LIMIT 101',seed.product_id,seed.after_cve).all()).results:[];
 const page=rows.slice(0,100),records=[];let invalid=valid?seed.invalid_records:1;
 for(const row of page){try{const old=JSON.parse(row.record_json),input=publicInput(old),record=input&&normalize(input,scope);
   if(!record||record.id!==row.cve_id||!Number.isFinite(Date.parse(record.published))){invalid++;continue;}
   records.push({...record,nvd_checked_at:old.nvd_checked_at||scope.last_success_at,generation:!seed.donor_generation||row.generation===seed.donor_generation?seed.generation:'older-public-history'});
  }catch{invalid++;}}
 const statements=[];
 if(records.length)statements.push(q(env.DB,`INSERT INTO cvie_shared_advisories(scope_id,cve_id,published,record_json,generation)
  SELECT ?,json_extract(value,'$.id'),json_extract(value,'$.published'),json_remove(value,'$.generation'),json_extract(value,'$.generation') FROM json_each(?)
  WHERE EXISTS(SELECT 1 FROM cvie_shared_scopes WHERE id=? AND seed_state='pending' AND seed_token=? AND lease_until=? AND json_extract(cursor_json,'$.active_scan')=?)
  ON CONFLICT(scope_id,cve_id) DO NOTHING`,scope.id,JSON.stringify(records),scope.id,scope.seed_token,lease,owner));
 const complete=rows.length<=100;
 if(complete){
  const metadata=JSON.stringify(coverageMetadata(coveragePlan(scope)));
  statements.push(q(env.DB,`UPDATE cvie_shared_seeds SET invalid_records=CASE WHEN EXISTS(SELECT 1 FROM cvie_products p
   WHERE p.id=product_id AND p.name=source_name AND p.vendor=source_vendor AND p.cpe=source_cpe
   AND COALESCE(json_extract(p.cursor_json,'$.generation'),'')=donor_generation) THEN MAX(invalid_records,?) ELSE 1 END
   WHERE scope_id=? AND token=? AND EXISTS(SELECT 1 FROM cvie_shared_scopes s WHERE s.id=scope_id AND s.lease_until=? AND json_extract(s.cursor_json,'$.active_scan')=?)`,invalid,scope.id,scope.seed_token,lease,owner));
  const reset="COALESCE((SELECT invalid_records FROM cvie_shared_seeds WHERE scope_id=cvie_shared_scopes.id),1)>0";
  statements.push(q(env.DB,`UPDATE cvie_shared_scopes SET seed_state='complete',seed_token='',lease_until=0,
   status=CASE WHEN ${reset} THEN 'queued' ELSE ? END,cursor_json=CASE WHEN ${reset} THEN ? ELSE json_remove(cursor_json,'$.active_scan') END,
   recent_complete_at=CASE WHEN ${reset} THEN NULL ELSE recent_complete_at END,history_complete_at=CASE WHEN ${reset} THEN NULL ELSE history_complete_at END,
   last_success_at=CASE WHEN ${reset} THEN NULL ELSE last_success_at END,
   next_attempt_at=CASE WHEN ${reset} THEN 0 ELSE next_attempt_at END WHERE id=? AND seed_token=? AND lease_until=? AND json_extract(cursor_json,'$.active_scan')=?`,seed?.resume_status||'queued',metadata,scope.id,scope.seed_token,lease,owner));
  statements.push(q(env.DB,"DELETE FROM cvie_shared_seeds WHERE scope_id=? AND token=? AND EXISTS(SELECT 1 FROM cvie_shared_scopes s WHERE s.id=scope_id AND s.seed_state='complete')",scope.id,scope.seed_token));
 }else{
  statements.push(q(env.DB,"UPDATE cvie_shared_seeds SET after_cve=?,invalid_records=? WHERE scope_id=? AND token=? AND EXISTS(SELECT 1 FROM cvie_shared_scopes s WHERE s.id=scope_id AND s.lease_until=? AND json_extract(s.cursor_json,'$.active_scan')=?)",page.at(-1).cve_id,invalid,scope.id,scope.seed_token,lease,owner));
  statements.push(q(env.DB,"UPDATE cvie_shared_scopes SET lease_until=0,cursor_json=json_remove(cursor_json,'$.active_scan') WHERE id=? AND lease_until=? AND json_extract(cursor_json,'$.active_scan')=?",scope.id,lease,owner));
 }
 await env.DB.batch(statements);return {seeded:records.length,seed_complete:complete,no_provider:true};
}

