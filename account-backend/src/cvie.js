import {registryEnabled,resolveRegistry,searchRegistry,searchDirectory,registerVerifiedCpe} from './product-registry.js';
import {bindProductIdentities,fastEvidenceEnabled,immediateEvidence} from './cvie-onboarding.js';
import {catalogueProducts,activeSubscription} from './catalogue-selection.js';
// CVIE: durable, account-scoped product identity resolution and NVD history.
// Every external URL is fixed here. Customer hosts/versions are never scanned or sent.
import {normalizeName,productCpe,cpeFamily,knownIdentity,logoFor,identityCandidates,vendorKey,directorySearch} from './product-identity.js';
import {queueRelevantKev} from './cvie-evidence.js';
import {combinedPage,combinedCounts,evidenceContext,sourceHealth,withdrawnIds,excludedProductCves} from './cvie-records.js';
import {isHyperV,hyperVHosts,hyperVHost,hyperVHelp,hyperVStatement} from './hyperv.js';
import {coveragePlan,coverageMetadata,coverageSummary,sourceWorkTypes,catalogueKind,DISCOVERY_PAGES} from './product-coverage.js';
import {disclosureCandidatesStatement} from './cvie-evidence.js';
import {sharedScans,reconcileSharedScopes,seedSharedHistory,ownedProductSql,overlaySharedProduct,validScopeLink,sharedDescriptor,trustedSharedIdentity,publicIdentityProof} from './shared-scopes.js';
const ORIGIN='https://cveharbor.com',DAY=86400000;
const iso=value=>new Date(value).toISOString();
const query=(db,sql,...args)=>db.prepare(sql).bind(...args);
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','Access-Control-Allow-Origin':ORIGIN,'Access-Control-Allow-Credentials':'true','Vary':'Origin'}});
export class CvieError extends Error{constructor(message,status=400){super(message);this.status=status;}}
export function monthsAgo(now,months){
 const result=new Date(now),day=result.getUTCDate();result.setUTCDate(1);result.setUTCMonth(result.getUTCMonth()-months);
 const last=new Date(Date.UTC(result.getUTCFullYear(),result.getUTCMonth()+1,0)).getUTCDate();
 result.setUTCDate(Math.min(day,last));return result.getTime();
}
export function scanWindows(now){
 const cutoff=monthsAgo(now,12),recent=monthsAgo(now,3),windows=[{start:recent,end:now,index:0}];
 for(let end=recent-1;end>=cutoff;){const start=Math.max(cutoff,end-90*DAY+1);windows.push({start,end,index:0});end=start-1;}
 return windows;
}
export async function cvieReady(env){
 try{
  const row=await env.DB.prepare(`SELECT provider,EXISTS(SELECT 1 FROM cvie_products LIMIT 1) AS products,
   EXISTS(SELECT 1 FROM cvie_advisories LIMIT 1) AS advisories,EXISTS(SELECT 1 FROM cvie_subscriptions LIMIT 1) AS subscriptions
   ${sharedScans(env)?',EXISTS(SELECT 1 FROM cvie_shared_scopes LIMIT 1) AS shared_scopes,EXISTS(SELECT 1 FROM cvie_product_scopes LIMIT 1) AS shared_links':''}
   FROM cvie_provider_budget WHERE provider='nvd'`).first();return row?.provider==='nvd';
 }catch{return false;}
}
export async function subscribeProducts(env,userId,products,origin='catalogue',expectedCatalogue=null){
 if(!await cvieReady(env))return {ready:false};
 if(!['catalogue','inventory','stack'].includes(origin))throw new CvieError('Invalid product source');
 const normalized=new Map();
 for(const item of products){
  const name=String(item.name||item.technology||'').trim(),vendor=String(item.vendor||'').trim();
  if(!name||name.length>120||vendor.length>100||/[\u0000-\u001f]/.test(name+vendor))throw new CvieError('Invalid product identity');
  if(item.cpe&&!productCpe(item.cpe))throw new CvieError('Use a product-family CPE 2.3 identifier with wildcard versions');
  if(item.cpe&&vendor&&vendorKey(vendor)!==vendorKey(productCpe(item.cpe).split(':')[3]))throw new CvieError('The vendor does not match the selected source identity');
  const registry=registryEnabled(env)?resolveRegistry(item)||(await searchDirectory(env,{q:name,vendor})).identity:null;
  if(item.identity_id&&(!registry||registry.id!==item.identity_id))throw new CvieError('Select a compatible verified identity');
  const selected=item.cpe?productCpe(item.cpe):registry?.cpe||knownIdentity(name,vendor)?.cpe||'';
  // A reviewed multi-family scope has one durable primary identity. Replaying a
  // saved legacy member must not undo the scope upgrade and restart its history.
  const cpe=coveragePlan({name,vendor,cpe:selected}).primary||selected;
  normalized.set(normalizeName(name),{name,vendor,cpe,explicitCpe:Boolean(item.cpe),vendorProvided:item.vendor!==undefined});
 }
 if(normalized.size>500)throw new CvieError('CVIE supports up to 500 distinct products per account',409);
 // One consistent read snapshot and one D1 round trip for private subscription state.
 const [savedProducts,savedSubscriptions,otherSubscriptions]=await env.DB.batch([
  query(env.DB,'SELECT id,name_key,cpe,vendor FROM cvie_products WHERE user_id=?',userId),
  query(env.DB,'SELECT product_id FROM cvie_subscriptions WHERE user_id=? AND origin=?',userId,origin),
  query(env.DB,'SELECT DISTINCT p.name_key FROM cvie_products p JOIN cvie_subscriptions s ON p.id=s.product_id WHERE s.user_id=? AND s.origin<>?',userId,origin)
 ]);
 const existing=savedProducts.results||[],subscribed=savedSubscriptions.results||[];
 const ids=new Map(existing.map(x=>[x.name_key,x.id]));
 const other=otherSubscriptions.results||[];
 if(new Set([...other.map(x=>x.name_key),...normalized.keys()]).size>500)throw new CvieError('CVIE product capacity reached; remove unused products before adding more',409);
 const guard=origin==='catalogue'&&expectedCatalogue!==null;
 const guardSql=guard?' AND EXISTS(SELECT 1 FROM user_technology_catalogue WHERE user_id=? AND preferences_json=?)':'';
 const guarded=(sql,...args)=>query(env.DB,sql+guardSql,...args,...(guard?[userId,expectedCatalogue]:[]));
 const statements=[],inserts=[],changes=[];
 for(const [key,p] of normalized){
  const id=ids.get(key)||crypto.randomUUID();ids.set(key,id);
  const prior=existing.find(x=>x.name_key===key);
  if(!prior)inserts.push({id,key,name:p.name,vendor:p.vendor,cpe:p.cpe});
  if(prior&&(p.explicitCpe&&p.cpe!==prior.cpe||p.vendorProvided&&p.vendor!==prior.vendor)){
   changes.push({id,cpe:p.explicitCpe?p.cpe:knownIdentity(p.name,p.vendor)?.cpe||'',vendor:p.vendorProvided?p.vendor:prior.vendor});
  }
 }
 if(inserts.length)statements.push(guarded(`INSERT OR IGNORE INTO cvie_products(id,user_id,name_key,name,vendor,cpe)
  SELECT json_extract(value,'$.id'),?,json_extract(value,'$.key'),json_extract(value,'$.name'),json_extract(value,'$.vendor'),json_extract(value,'$.cpe') FROM json_each(?) WHERE 1=1`,userId,JSON.stringify(inserts)));
 if(changes.length){
  const payload=JSON.stringify(changes);
  statements.push(guarded("DELETE FROM cvie_advisories WHERE product_id IN(SELECT json_extract(value,'$.id') FROM json_each(?))",payload));
  statements.push(guarded(`UPDATE cvie_products SET
   cpe=(SELECT json_extract(value,'$.cpe') FROM json_each(?) WHERE json_extract(value,'$.id')=cvie_products.id),
   vendor=(SELECT json_extract(value,'$.vendor') FROM json_each(?) WHERE json_extract(value,'$.id')=cvie_products.id),
   status='queued',cursor_json='{}',candidates_json='[]',recent_complete_at=NULL,history_complete_at=NULL,last_success_at=NULL,next_attempt_at=0,lease_until=0,error=''
   WHERE user_id=? AND id IN(SELECT json_extract(value,'$.id') FROM json_each(?))`,payload,payload,userId,payload));
 }
 const desired=new Set([...normalized.keys()].map(key=>ids.get(key))),current=new Set(subscribed.map(s=>s.product_id));
 const added=[...desired].filter(id=>!current.has(id)),removed=[...current].filter(id=>!desired.has(id));
 if(removed.length)statements.push(guarded('DELETE FROM cvie_subscriptions WHERE user_id=? AND origin=? AND product_id IN(SELECT value FROM json_each(?))',userId,origin,JSON.stringify(removed)));
 if(added.length)statements.push(guarded('INSERT OR IGNORE INTO cvie_subscriptions(user_id,product_id,origin) SELECT ?,p.id,? FROM cvie_products p WHERE p.user_id=? AND p.name_key IN(SELECT value FROM json_each(?))',userId,origin,userId,JSON.stringify([...normalized.keys()])));
 // Retain historical evidence; revoke only obsolete private work's commit lease.
 if(removed.length)statements.push(guarded(`UPDATE cvie_products SET lease_until=0,cursor_json=json_remove(cursor_json,'$.active_scan') WHERE user_id=? AND lease_until<>0 AND NOT ${activeSubscription('cvie_products')}`,userId));
 // Set-based JSON bindings keep bulk imports within D1's per-invocation query budget.
 const applied=statements.length?await env.DB.batch(statements):[];
 if(guard&&statements.length&&!applied.some(r=>r.meta.changes))return {ready:true,queued:0,changed:false};
 const updatedIds=new Set([...inserts,...changes].map(p=>p.id));
 const relevant=[...normalized.entries()].filter(([key])=>updatedIds.has(ids.get(key))).map(([,p])=>p);
 if(relevant.length)await queueRelevantKev(env,relevant);
 if(registryEnabled(env))await bindProductIdentities(env,userId);
 if(updatedIds.size&&sharedScans(env))await reconcileSharedScopes(env,userId);
 return {ready:true,queued:updatedIds.size,changed:statements.length>0};
}
export async function repairAccountCoverage(env,userId,scope='all'){
 const repairRows=(await query(env.DB,`SELECT p.* FROM cvie_products p WHERE p.user_id=? AND ${activeSubscription('p',scope)}`,userId).all()).results||[];
 const hostRepair=await prepareHyperVHosts(env,userId,repairRows);
 const coverageRepair=await prepareProductCoverage(env,userId,repairRows);
 return hostRepair||coverageRepair;
}
export async function syncAccountProducts(env,userId,scope='all'){
 const results=[];
 if(scope==='all'||scope==='catalogue'){
  const catalogue=await query(env.DB,'SELECT preferences_json FROM user_technology_catalogue WHERE user_id=?',userId).first();
  results.push(await subscribeProducts(env,userId,catalogueProducts(JSON.parse(catalogue?.preferences_json||'{}')),'catalogue',catalogue?.preferences_json??null));
 }
 if(scope==='all'||scope==='inventory'){
  const inventory=await query(env.DB,'SELECT DISTINCT technology FROM inventory_assets WHERE user_id=?',userId).all();
  results.push(await subscribeProducts(env,userId,(inventory.results||[]).map(x=>({name:x.technology})),'inventory'));
 }
 if(scope==='all'||scope==='stack'){
  const stack=await query(env.DB,'SELECT technology FROM user_stack WHERE user_id=?',userId).all();
  results.push(await subscribeProducts(env,userId,(stack.results||[]).map(x=>({name:x.technology})),'stack'));
 }
 const repaired=await repairAccountCoverage(env,userId,scope);
 const shared=await reconcileSharedScopes(env,userId);
 return {ready:results.every(r=>r.ready),changed:results.some(r=>r.changed)||shared.linked>0||Boolean(repaired),queued:results.reduce((n,r)=>n+(r.queued||0),0)};
}
function configurations(cve){
 const result=[];
 const walk=node=>{if(node.negate===true)return;for(const m of node.cpeMatch||[])if(m.vulnerable&&cpeFamily(m.criteria))result.push(m);for(const child of node.nodes||node.children||[])walk(child);};
 for(const node of cve.configurations||[])walk(node);
 return result;
}
export function normalizeNvd(cve,product){
 if(!/^CVE-\d{4}-\d{4,10}$/i.test(cve?.id||'')||/rejected/i.test(cve.vulnStatus||''))return null;
 const plan=coveragePlan(product),matches=configurations(cve).filter(m=>plan.families.includes(cpeFamily(m.criteria)));
 if(!matches.length)return null; // Mentioning a product in the summary is insufficient evidence.
 const published=Date.parse(cve.published);if(!Number.isFinite(published))return null;
 const metrics=['cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2'].flatMap(key=>[...(cve.metrics?.[key]||[])].sort((a,b)=>Number(b.type==='Primary')-Number(a.type==='Primary')));
 const metric=metrics.find(m=>typeof m.cvssData?.baseScore==='number'&&Number.isFinite(m.cvssData.baseScore)&&m.cvssData.baseScore>=0&&m.cvssData.baseScore<=10)?.cvssData;
 const score=metric?.baseScore,cvss=typeof score==='number'&&Number.isFinite(score)&&score>=0&&score<=10?score:null;
 const severity=cvss===null?'unrated':cvss>=9?'critical':cvss>=7?'high':cvss>=4?'medium':'low';
 const summary=String(cve.descriptions?.find(x=>x.lang==='en')?.value||cve.descriptions?.[0]?.value||'See the source advisory for details.').slice(0,12000);
 if(isHyperV(product)&&(!hyperVHost(product.cpe)||!hyperVStatement({summary})))return null;
 const sources=[{label:'NVD CVE record',url:'https://nvd.nist.gov/vuln/detail/'+cve.id}];
 for(const ref of cve.references||[]){try{const url=new URL(ref.url);if(url.protocol==='https:'&&!url.username&&!url.password&&sources.length<12)sources.push({label:(ref.tags||[]).includes('Vendor Advisory')?'Vendor advisory':'Source reference',url:url.href});}catch{}}
 return {id:cve.id,kind:'cve',title:summary.slice(0,180),summary,published:iso(published),updated:cve.lastModified||cve.published,
  severity,cvss,known_exploited:Boolean(cve.cisaExploitAdd),status:cve.vulnStatus||'NVD indexed CVE',source_type:'cvie_nvd',
  categories:[product.name],cvie_products:[product.name],cvie_identities:[...new Set(matches.map(m=>cpeFamily(m.criteria)))].map(cpe=>({name:product.name,cpe})),affected_cpes:matches,nvd_configurations:cve.configurations||[],
  affected:matches.map(m=>(plan.families.length>1?plan.familyLabel(m.criteria):product.name)+' '+[m.versionStartIncluding&&'>= '+m.versionStartIncluding,m.versionStartExcluding&&'> '+m.versionStartExcluding,m.versionEndIncluding&&'<= '+m.versionEndIncluding,m.versionEndExcluding&&'< '+m.versionEndExcluding].filter(Boolean).join(', ')).join('; '),
  remediation:'Review the linked vendor advisory for affected versions, prerequisites and the appropriate fix.',sources,
  action:'Confirm the installed version and deployment prerequisites before remediation.',
  exploitation:cve.cisaExploitAdd?'Listed in CISA KEV':'No exploitation claim made by CVIE'};
}
async function prepareProductCoverage(env,userId,products){
 const repairs=products.flatMap(p=>{
  if(p.shared_scope_id)return [];
  const plan=coveragePlan(p),cursor=JSON.parse(p.cursor_json||'{}');
  if(!plan.families.length||cursor.coverage_signature===plan.signature||!plan.profile&&!p.last_success_at&&!cursor.windows?.length)return [];
  return [{id:p.id,before_cpe:p.cpe,vendor:p.vendor,cursor:p.cursor_json,cpe:plan.primary,metadata:JSON.stringify(coverageMetadata(plan))}];
 });
 if(!repairs.length)return false;
 // Keep verified cached evidence while resetting only the incomplete coverage claim.
 const result=await query(env.DB,`UPDATE cvie_products SET cpe=(SELECT json_extract(value,'$.cpe') FROM json_each(?) WHERE json_extract(value,'$.id')=cvie_products.id),
  cursor_json=(SELECT json_extract(value,'$.metadata') FROM json_each(?) WHERE json_extract(value,'$.id')=cvie_products.id),
  status='queued',candidates_json='[]',recent_complete_at=NULL,history_complete_at=NULL,next_attempt_at=0,lease_until=0,error=''
  WHERE user_id=? AND EXISTS(SELECT 1 FROM json_each(?) r WHERE json_extract(r.value,'$.id')=cvie_products.id
   AND json_extract(r.value,'$.before_cpe')=cvie_products.cpe AND json_extract(r.value,'$.vendor')=cvie_products.vendor
   AND json_extract(r.value,'$.cursor')=cvie_products.cursor_json)`,JSON.stringify(repairs),JSON.stringify(repairs),userId,JSON.stringify(repairs)).run();
 return result.meta.changes>0;
}
async function prepareHyperVHosts(env,userId,products){
 const candidates=JSON.stringify(hyperVHosts());
 const repairs=products.filter(p=>isHyperV(p)&&!hyperVHost(p.cpe)&&
  (p.cpe||p.status!=='needs_identity'||p.candidates_json!==candidates)).map(p=>({id:p.id,cpe:p.cpe,vendor:p.vendor,candidates:p.candidates_json}));
 if(!repairs.length)return false;
 // Repair only this account's unresolved/invalid component identities. A host chosen
 // concurrently wins; valid existing Microsoft host selections are preserved.
 const result=await env.DB.batch([
  query(env.DB,`UPDATE cvie_products SET cpe='',status='needs_identity',candidates_json=?,cursor_json='{}',
   recent_complete_at=NULL,history_complete_at=NULL,last_success_at=NULL,next_attempt_at=0,lease_until=0,error=?
   WHERE user_id=? AND EXISTS(SELECT 1 FROM json_each(?) r WHERE json_extract(r.value,'$.id')=cvie_products.id
    AND json_extract(r.value,'$.cpe')=cvie_products.cpe AND json_extract(r.value,'$.vendor')=cvie_products.vendor
    AND json_extract(r.value,'$.candidates')=cvie_products.candidates_json)`,candidates,hyperVHelp,userId,JSON.stringify(repairs)),
  query(env.DB,`DELETE FROM cvie_advisories WHERE product_id IN(SELECT id FROM cvie_products WHERE user_id=? AND cpe=''
   AND status='needs_identity' AND candidates_json=? AND id IN(SELECT json_extract(value,'$.id') FROM json_each(?)))`,userId,candidates,JSON.stringify(repairs)),
 ]);
 return result[0].meta.changes>0;
}
class ProviderError extends Error{constructor(message,delay=60000){super(message);this.delay=delay;}}
async function requestNvd(env,path,params,fetcher){
 const url=new URL('https://services.nvd.nist.gov/rest/json/'+path+'/2.0');
 for(const [key,value] of Object.entries(params))url.searchParams.set(key,String(value));
 const response=await fetcher(url.href,{headers:{Accept:'application/json',...(env.NVD_API_KEY?{apiKey:env.NVD_API_KEY}:{})},signal:AbortSignal.timeout(20000)});
 if(!response.ok){
  const retry=response.headers.get('Retry-After');
  const seconds=/^\d+$/.test(retry||'')?Number(retry)*1000:Date.parse(retry||'')-Date.now();
  throw new ProviderError(response.status===429?'NVD rate limit reached. CVIE will retry automatically.':'NVD is unavailable (HTTP '+response.status+'). Saved results remain available.',Math.max(60000,Math.min(3600000,seconds||60000)));
 }
 const raw=await response.text();if(raw.length>12000000)throw new ProviderError('NVD response exceeded the safe response size');
 let data;try{data=JSON.parse(raw);}catch{throw new ProviderError('NVD returned an invalid response');}
 return data;
}
// One resumable page per invocation. Leases and provider slots survive restarts and concurrent pollers.
export async function runCvieStep(env,fetcher=fetch,now=Date.now(),userId=null,scope='all',directoryProductId=null){
 if(!await cvieReady(env))return {ready:false};
 const shared=sharedScans(env);
 let product=await query(env.DB,`SELECT p.* ${shared?`,${publicIdentityProof()} AS public_identity_verified`:''} FROM cvie_products p ${shared?`JOIN cvie_product_scopes m ON ${validScopeLink()}`:''} WHERE p.status<>'needs_identity' AND p.next_attempt_at<=? AND p.lease_until<?
  ${shared?"AND m.scope_id IS NULL AND NOT EXISTS(SELECT 1 FROM cvie_shared_seeds x WHERE x.product_id=p.id)":''}
  AND ${activeSubscription('p',scope)} ${userId?'AND p.user_id=?':''} ${directoryProductId?"AND p.id=? AND p.cpe=''":''}
  ORDER BY CASE WHEN p.recent_complete_at IS NULL THEN 0 WHEN p.history_complete_at IS NULL THEN 1 ELSE 2 END,p.next_attempt_at,COALESCE(p.last_attempt_at,0),p.id LIMIT 1`,now,now,...(userId?[userId]:[]),...(directoryProductId?[directoryProductId]:[])).first();
 let sharedJob=false;
 if(shared&&!directoryProductId){
  const candidate=await query(env.DB,`SELECT j.* FROM cvie_shared_scopes j WHERE (j.seed_state='pending' OR j.next_attempt_at<=?) AND j.lease_until<?
   AND EXISTS(SELECT 1 FROM cvie_product_scopes m JOIN cvie_products p ON ${validScopeLink()} WHERE m.scope_id=j.id
    AND ${activeSubscription('p',scope)} ${userId?'AND p.user_id=?':''})
   ORDER BY CASE WHEN j.seed_state='pending' THEN -1 WHEN j.recent_complete_at IS NULL THEN 0 WHEN j.history_complete_at IS NULL THEN 1 ELSE 2 END,j.next_attempt_at,COALESCE(j.last_attempt_at,0),j.id LIMIT 1`,now,now,...(userId?[userId]:[])).first();
  const rank=p=>[p.seed_state==='pending'?-1:p.recent_complete_at==null?0:p.history_complete_at==null?1:2,p.last_attempt_at||0];
  if(candidate&&(!product||rank(candidate)[0]<rank(product)[0]||rank(candidate)[0]===rank(product)[0]&&rank(candidate)[1]<=rank(product)[1])){product=candidate;sharedJob=true;}
 }
 if(!product)return {idle:true};
 if(!sharedJob&&shared&&product.cpe&&trustedSharedIdentity(product)&&await sharedDescriptor(product)){
  await reconcileSharedScopes(env,product.user_id,now);return {resolved:true,no_provider:true};
 }
 if(sharedJob&&product.seed_state==='pending')return seedSharedHistory(env,product,normalizeNvd,now);
 const jobs=sharedJob?'cvie_shared_scopes':'cvie_products',advisories=sharedJob?'cvie_shared_advisories':'cvie_advisories',foreign=sharedJob?'scope_id':'product_id';
 if(!sharedJob&&await prepareProductCoverage(env,product.user_id,[product]))return {requeued:true};
 if(isHyperV(product)&&!hyperVHost(product.cpe)){
  await prepareHyperVHosts(env,product.user_id,[product]);return {resolved:false};
 }
 const budget=await query(env.DB,'UPDATE cvie_provider_budget SET next_request_at=? WHERE provider=? AND next_request_at<=?',now+(env.NVD_API_KEY?1000:6500),'nvd',now).run();
 if(budget.meta.changes!==1)return {waiting:true};
 const lease=now+120000;
 const owner=crypto.randomUUID();
 if((await query(env.DB,`UPDATE ${jobs} SET lease_until=?,status=?,last_attempt_at=?,cursor_json=json_set(cursor_json,'$.active_scan',?) WHERE id=? AND lease_until<?`,lease,'scanning',now,owner,product.id,now).run()).meta.changes!==1)return {busy:true};
 try{
  const stillSelected=async()=>sharedJob||Boolean(await query(env.DB,`SELECT id FROM cvie_products p WHERE id=? AND ${activeSubscription()}`,product.id).first());
  if(!await stillSelected())return {cancelled:true};
  if(shared&&!sharedJob&&product.cpe&&await sharedDescriptor(product)){
   const data=await requestNvd(env,'cpes',{cpeMatchString:product.cpe,resultsPerPage:1},fetcher);
   if(!await stillSelected())return {cancelled:true};
   if(!Array.isArray(data.products)||!Number.isSafeInteger(data.totalResults)||data.totalResults<0)throw new ProviderError('NVD product identity verification returned an incomplete response.');
   const choices=identityCandidates(data,{vendor:product.cpe.split(':')[3]});
   if(data.products.some(item=>cpeFamily(item.cpe?.cpeName)===product.cpe)&&!choices.some(c=>c.cpe===product.cpe))choices.push({cpe:product.cpe,label:product.cpe.split(':').slice(3,5).join(' / ').replaceAll('_',' ')});
   const verified=choices.some(c=>c.cpe===product.cpe);
   await env.DB.batch([
    query(env.DB,"UPDATE cvie_products SET candidates_json=?,status=?,lease_until=0,error=? WHERE id=? AND lease_until=? AND json_extract(cursor_json,'$.active_scan')=?",JSON.stringify(choices),verified?'queued':'needs_identity',verified?'':'The selected product family was not confirmed in the NVD directory. Confirm the exact vendor and product.',product.id,lease,owner),
    query(env.DB,'DELETE FROM cvie_product_scopes WHERE product_id=? AND scope_id IS NULL',product.id),
   ]);
   await reconcileSharedScopes(env,product.user_id,now);return {resolved:verified};
  }
  if(!product.cpe){
   const cursor=JSON.parse(product.cursor_json||'{}'),index=cursor.directory_index||0;
   const data=await requestNvd(env,'cpes',{keywordSearch:directorySearch(product),startIndex:index,resultsPerPage:500},fetcher);
   if(!await stillSelected())return {cancelled:true};
   if(!Array.isArray(data.products)||!Number.isSafeInteger(data.totalResults)||data.totalResults<0||
    (data.startIndex??0)!==index||!data.products.length&&index<data.totalResults)throw new ProviderError('NVD product directory response is incomplete');
   const candidates=[...new Map([...JSON.parse(product.candidates_json||'[]'),...identityCandidates(data,product)].map(c=>[c.cpe,c])).values()];
   const next=index+data.products.length,finished=next>=data.totalResults,limited=!finished&&(next>=10000||candidates.length>=500);
   // A unique result can only be accepted if the directory was fully searched.
   const sameName=candidates.length===1&&[candidates[0].cpe.split(':')[4],candidates[0].cpe.split(':').slice(3,5).join(' ')].some(x=>normalizeName(x.replaceAll('_',' '))===normalizeName(product.name));
   const cpe=finished&&sameName&&catalogueKind(product.name)==='product'?candidates[0].cpe:'';
   const status=cpe?'queued':finished||limited?'needs_identity':'scanning';
   await query(env.DB,"UPDATE cvie_products SET cpe=?,status=?,candidates_json=?,cursor_json=?,lease_until=0,error=? WHERE id=? AND lease_until=? AND json_extract(cursor_json,'$.active_scan')=?",cpe,status,JSON.stringify(candidates.slice(0,500)),JSON.stringify({directory_query:directorySearch(product),directory_complete:finished,directory_limited:limited,...(status==='scanning'?{directory_index:next,directory_total:data.totalResults}:{})}),cpe||status==='scanning'?'':limited?'The product directory is broad and only partially searched. Add the vendor or a more specific product name, or confirm an exact listed identity.':'Choose the exact vendor/product identity to continue; a name search alone is not a vulnerability match.',product.id,lease,owner).run();
   if(shared&&cpe)await reconcileSharedScopes(env,product.user_id,now);
   return {resolved:Boolean(cpe),directory_complete:finished||limited};
  }
  let cursor=JSON.parse(product.cursor_json||'{}');
  const plan=coveragePlan(product);
  if(!cursor.windows?.length){
   const dates=scanWindows(now),types=sourceWorkTypes(plan);
   cursor={...coverageMetadata(plan),generation:crypto.randomUUID(),anchor:now,windows:dates.flatMap(date=>types.map(type=>({...date,...type}))),position:0,recent_windows:types.length};
  }
  const window=cursor.windows[cursor.position];
   const data=await requestNvd(env,'cves',{...(window.disclosures?{keywordSearch:window.disclosures,keywordExactMatch:''}:{virtualMatchString:window.cpe||product.cpe}),...(isHyperV(product)?{keywordSearch:'Windows Hyper-V',keywordExactMatch:''}:{}),pubStartDate:iso(window.start),pubEndDate:iso(window.end),startIndex:window.index,resultsPerPage:50},fetcher);
  if(!await stillSelected())return {cancelled:true};
  if(!Array.isArray(data.vulnerabilities)||!Number.isSafeInteger(data.totalResults)||data.totalResults<0||data.startIndex!==window.index||
     (!data.vulnerabilities.length&&window.index<data.totalResults)||data.vulnerabilities.some(entry=>!/^CVE-\d{4}-\d{4,10}$/i.test(entry?.cve?.id||'')||!Number.isFinite(Date.parse(entry.cve.published))||Date.parse(entry.cve.published)<window.start||Date.parse(entry.cve.published)>window.end))throw new ProviderError('NVD returned an incomplete page; CVIE has not marked this scan complete.');
  const statements=[],pageRecords=[];
  if(window.disclosures&&data.vulnerabilities.length)statements.push(disclosureCandidatesStatement(env,data.vulnerabilities.map(e=>e.cve.id)));
  for(const entry of data.vulnerabilities){
   const record=normalizeNvd(entry.cve,product);
   if(record&&Date.parse(record.published)>=monthsAgo(cursor.anchor,12)&&Date.parse(record.published)<=cursor.anchor)
    pageRecords.push({...record,nvd_checked_at:now});
  }
  if(pageRecords.length)statements.push(query(env.DB,`INSERT INTO ${advisories}(${foreign},cve_id,published,record_json,generation)
   SELECT ?,json_extract(value,'$.id'),json_extract(value,'$.published'),value,? FROM json_each(?)
   WHERE EXISTS(SELECT 1 FROM ${jobs} WHERE id=? AND lease_until=? AND cpe=? AND json_extract(cursor_json,'$.active_scan')=?)
   ON CONFLICT(${foreign},cve_id) DO UPDATE SET published=excluded.published,record_json=excluded.record_json,generation=excluded.generation`,product.id,cursor.generation,JSON.stringify(pageRecords),product.id,lease,product.cpe,owner));
  window.index+=data.vulnerabilities.length;window.total=data.totalResults;
  window.pages=(window.pages||0)+1;
  let recent=product.recent_complete_at,history=product.history_complete_at;
  if(window.disclosures&&window.index<data.totalResults&&window.pages>=DISCOVERY_PAGES){cursor.discovery_limited=true;cursor.position++;if(cursor.position===(cursor.recent_windows||1))recent=now;}
  else if(window.index>=data.totalResults){cursor.position++;if(cursor.position===(cursor.recent_windows||1))recent=now;}
  const complete=cursor.position===cursor.windows.length;
  if(complete){
   history=now;
   statements.push(query(env.DB,`DELETE FROM ${advisories} WHERE ${foreign}=? AND (generation<>? OR published<?) AND EXISTS(SELECT 1 FROM ${jobs} WHERE id=? AND lease_until=? AND cpe=? AND json_extract(cursor_json,'$.active_scan')=?)`,product.id,cursor.generation,iso(monthsAgo(cursor.anchor,12)),product.id,lease,product.cpe,owner));
  }
  // Cursor + page records commit together, so a crash never advances past unsaved results.
  statements.push(query(env.DB,`UPDATE ${jobs} SET status=?,cursor_json=?,scan_started_at=COALESCE(scan_started_at,?),last_success_at=?,
   recent_complete_at=?,history_complete_at=?,next_attempt_at=?,lease_until=0,error='' WHERE id=? AND lease_until=? AND json_extract(cursor_json,'$.active_scan')=?`,
   complete?'ready':'scanning',JSON.stringify(complete?coverageMetadata(plan,cursor):cursor),cursor.anchor,now,recent,history,complete?now+6*3600000:0,product.id,lease,owner));
  await env.DB.batch(statements);
  return {complete,processed:data.vulnerabilities.length};
 }catch(error){
  const delay=error instanceof ProviderError?error.delay:60000;
  const message=error instanceof ProviderError?error.message:'CVIE could not complete the source check. Saved results remain available; retry is scheduled.';
  if(error instanceof ProviderError)await query(env.DB,'UPDATE cvie_provider_budget SET next_request_at=MAX(next_request_at,?) WHERE provider=?',now+delay,'nvd').run();
  await query(env.DB,`UPDATE ${jobs} SET status=?,error=?,next_attempt_at=?,lease_until=0 WHERE id=? AND lease_until=? AND json_extract(cursor_json,'$.active_scan')=?`,'retrying',message,now+delay,product.id,lease,owner).run();
  return {retrying:true};
 }
}
// A chooser can finish a small directory lookup promptly without running CVE history.
// The existing lease and global provider budget still govern every page.
export async function runIdentityLookup(env,userId,scope,productId,fetcher=fetch,pause=ms=>new Promise(resolve=>setTimeout(resolve,ms))){
 const started=Date.now();let pages=0;
 for(let attempt=0;attempt<6&&pages<3&&Date.now()-started<20000;attempt++){
  const result=await runCvieStep(env,fetcher,Date.now(),userId,scope,productId);
  if(result.waiting){
   const budget=await query(env.DB,"SELECT next_request_at FROM cvie_provider_budget WHERE provider='nvd'").first();
   const delay=Math.max(100,Number(budget?.next_request_at||0)-Date.now()+100);
   if(delay>7000||Date.now()-started+delay>=20000)break;
   await pause(delay);continue;
  }
  if(result.directory_complete!==false)break;
  pages++;if(pages<3)await pause(env.NVD_API_KEY?1050:6600);
 }
}
export async function dispatchCvie(env){
 // Cron continues unfinished scans even after all browsers close. Budget is global.
 for(let i=0;i<(sharedScans(env)?5:6);i++){
  const result=await runCvieStep(env);
  if(result.idle||result.waiting||result.ready===false)break;
  if(result.seeded!==undefined)break;
  if(sharedScans(env)&&result.resolved!==undefined)break;
  if(i<5)await new Promise(resolve=>setTimeout(resolve,env.NVD_API_KEY?1050:6600));
 }
}
export async function loadCvieDigest(env,userId,now=Date.now(),selected=null){
 if(!await cvieReady(env))return {records:[],degraded:true,coverageLimited:false};
 const ctx=await evidenceContext(env,userId);
 if(ctx){
  if(selected){const names=new Set(selected.map(normalizeName));ctx.products=ctx.products.filter(p=>names.has(normalizeName(p.name)));const ids=new Set(ctx.products.map(p=>p.id));ctx.families=JSON.stringify(JSON.parse(ctx.families).filter(f=>ids.has(f.product_id)));}
  ctx.digest=true;
  const cutoff=iso(monthsAgo(now,12));let after='',records=[];
  do{const page=await combinedPage(env,userId,cutoff,after,'',now,ctx);records.push(...page.advisories);after=page.next||'';}while(after&&records.length<1000);
  const health=await sourceHealth(env,now);
  return {records,withdrawn_ids:await withdrawnIds(env),excluded_product_cves:await excludedProductCves(env,userId,ctx),component_products:ctx.products.map(p=>p.name),degraded:health.sources.some(s=>s.status!=='current')||ctx.products.some(p=>p.status!=='ready'||!p.last_success_at||now-p.last_success_at>DAY),coverageLimited:Boolean(after)||ctx.products.some(p=>coverageSummary(p).limited)};
 }
 const recent=iso(now-30*DAY);
 const result=await query(env.DB,`SELECT a.record_json FROM cvie_advisories a JOIN cvie_products p ON p.id=a.product_id
  WHERE p.user_id=? AND a.published>=? AND (a.published>=? OR json_extract(a.record_json,'$.updated')>=?)
  AND ${activeSubscription()}
  ORDER BY json_extract(a.record_json,'$.known_exploited') DESC,
   CASE json_extract(a.record_json,'$.severity') WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,a.published DESC LIMIT 1001`,userId,iso(monthsAgo(now,12)),recent,recent).all();
 const pending=await query(env.DB,`SELECT id FROM cvie_products p WHERE user_id=? AND (status<>'ready' OR last_success_at<?) AND ${activeSubscription()} LIMIT 1`,userId,now-24*3600000).first();
 return {records:(result.results||[]).slice(0,1000).map(row=>JSON.parse(row.record_json)),degraded:Boolean(pending),coverageLimited:(result.results||[]).length>1000};
}
function savedProgress(p,now){
 const cursor=JSON.parse(p.cursor_json||'{}'),window=cursor.windows?.[cursor.position];
 return {id:p.id,name:p.name,vendor:p.vendor,cpe:p.cpe,status:p.status,error:p.error,
  shared_scan:Boolean(p.shared_scope_id),
  last_success_at:p.last_success_at,recent_complete_at:p.recent_complete_at,history_complete_at:p.history_complete_at,
  next_attempt_at:p.next_attempt_at,stale:!p.last_success_at||now-p.last_success_at>24*3600000,
  progress:{windows_complete:cursor.position||0,windows_total:cursor.windows?.length||0,records_checked:window?.index||0,
   records_in_window:window?.total??null,directory_checked:cursor.directory_index||0,directory_total:cursor.directory_total||0}};
}
async function productSourceHealth(env,products,now){
 const evidence=await sourceHealth(env,now),attempted=products.map(p=>p.last_success_at).filter(Boolean);
 evidence.sources.unshift({id:'nvd',label:'NVD product history',url:'https://nvd.nist.gov/',
  status:!products.length?'no_products':products.some(p=>p.status==='retrying')?'unavailable':products.some(p=>['queued','scanning'].includes(p.status))?'scanning':products.some(p=>p.status==='needs_identity')?'needs_identity':products.some(p=>p.stale&&p.status==='ready')?'stale':'current',
  last_success_at:attempted.length?Math.min(...attempted):null});
 return evidence;
}
export async function cvieRoute(req,env,user,ctx,data={}){
 if(!await cvieReady(env))return json({ready:false,error:'CVIE database setup is required. Your saved products and inventory are unchanged.'},503);
 const url=new URL(req.url),path=url.pathname,scope=url.searchParams.get('scope')||'all';
 if(!['all','catalogue','inventory','stack'].includes(scope))throw new CvieError('Invalid product scope');
 if(path==='/v1/cvie/directory'&&req.method==='GET')return json(registryEnabled(env)?await searchDirectory(env,{q:url.searchParams.get('q')||'',vendor:url.searchParams.get('vendor')||'',ecosystem:url.searchParams.get('ecosystem')||'',identifier:url.searchParams.get('identifier')||'',scheme:url.searchParams.get('scheme')||''}):{enabled:false,candidates:[]});
 const fast=/^\/v1\/cvie\/products\/([a-f0-9-]{36})\/evidence$/.exec(path);
 if(fast&&req.method==='GET'){
  const result=await immediateEvidence(env,user.id,fast[1],{scope,after:url.searchParams.get('after')||'',months:Number(url.searchParams.get('months')||12),limit:Number(url.searchParams.get('limit')||100)});
  return json({...result,account_id:user.id},result.not_found?404:result.enabled?200:503);
 }
 if(path==='/v1/cvie/sync'&&req.method==='POST'){
  const sync=await syncAccountProducts(env,user.id,scope);
  if(sync.changed)ctx?.waitUntil(runCvieStep(env,fetch,Date.now(),user.id,scope));
  return json({...sync,status:sync.changed?'updated':'unchanged'},sync.changed?202:200);
 }
 if((path==='/v1/cvie/progress'||path==='/v1/cvie'&&url.searchParams.get('view')==='bounded'&&fastEvidenceEnabled(env))&&req.method==='GET'){
  const now=Date.now();
 const rows=(await query(env.DB,ownedProductSql(env,'p.*',scope),user.id).all()).results||[];
  const products=rows.map(overlaySharedProduct).map(p=>savedProgress(p,now));
  return json({ready:true,fast_evidence:fastEvidenceEnabled(env),account_id:user.id,products,...(fastEvidenceEnabled(env)?{withdrawn_ids:await withdrawnIds(env)}:{}),evidence:await productSourceHealth(env,products,now)});
 }
 const options=/^\/v1\/cvie\/products\/([a-f0-9-]{36})\/identity-options$/.exec(path);
 if(options&&['GET','POST'].includes(req.method)){
  const product=await query(env.DB,`SELECT p.* FROM cvie_products p WHERE p.id=? AND p.user_id=? AND ${activeSubscription('p',scope)}`,options[1],user.id).first();
  if(!product)throw new CvieError('Product not found',404);
  const snapshot=()=>({id:product.id,status:product.status,cpe:product.cpe,error:product.error,candidates:product.cpe?[]:JSON.parse(product.candidates_json||'[]'),
   directory_complete:JSON.parse(product.cursor_json||'{}').directory_complete===true,directory_limited:JSON.parse(product.cursor_json||'{}').directory_limited===true,
   retry_at:product.next_attempt_at,lease_until:product.lease_until});
  if(req.method==='GET')return json(snapshot());
  if(product.cpe)return json(snapshot());
  if(['queued','scanning'].includes(product.status)||product.status==='retrying'&&product.next_attempt_at<=Date.now()){
   ctx?.waitUntil(runIdentityLookup(env,user.id,scope,product.id));return json(snapshot(),202);
  }
  if(product.status==='retrying'&&product.next_attempt_at>Date.now())return json(snapshot());
  const cursor=JSON.parse(product.cursor_json||'{}'),search=directorySearch(product);
  if(product.status==='needs_identity'&&cursor.directory_query===search&&!data.retry)return json(snapshot());
  if(data.retry&&product.last_attempt_at&&Date.now()-product.last_attempt_at<60000)throw new CvieError('Please wait a minute before retrying the product directory.',429);
  const result=await query(env.DB,`UPDATE cvie_products SET status='queued',candidates_json='[]',cursor_json=?,next_attempt_at=0,lease_until=0,error=''
   WHERE id=? AND user_id=? AND status IN('needs_identity','retrying') AND cpe='' AND cursor_json=? AND ${activeSubscription('cvie_products',scope)}`,JSON.stringify({directory_query:search}),product.id,user.id,product.cursor_json).run();
  if(result.meta.changes)ctx?.waitUntil(runIdentityLookup(env,user.id,scope,product.id));
  return json(result.meta.changes?{...snapshot(),status:'queued',candidates:[],directory_complete:false,directory_limited:false,error:''}:snapshot(),result.meta.changes?202:200);
 }
 const identity=/^\/v1\/cvie\/products\/([a-f0-9-]{36})\/identity$/.exec(path);
 if(identity&&req.method==='PUT'){
  const product=await query(env.DB,`SELECT p.* FROM cvie_products p WHERE p.id=? AND p.user_id=? AND ${activeSubscription('p',scope)}`,identity[1],user.id).first();
  if(!product)throw new CvieError('Product not found',404);
  if(product.status!=='needs_identity'&&!(['queued','scanning','retrying'].includes(product.status)&&!product.cpe))throw new CvieError('This product identity is already being scanned',409);
  const cpe=productCpe(data.cpe);
  if(!cpe||!JSON.parse(product.candidates_json).some(x=>x.cpe===cpe))throw new CvieError('Select an identity returned by the product directory');
  if(isHyperV(product)&&!hyperVHost(cpe))throw new CvieError('Select the Microsoft Windows host running Hyper-V');
  if(registryEnabled(env))await registerVerifiedCpe(env,cpe);
  const saved=await query(env.DB,`UPDATE cvie_products SET cpe=?,status='queued',cursor_json='{}',candidates_json='[]',lease_until=0,error='',next_attempt_at=0
   WHERE id=? AND user_id=? AND cpe=? AND candidates_json=? AND ${activeSubscription('cvie_products',scope)}`,cpe,product.id,user.id,product.cpe,product.candidates_json).run();
  if(!saved.meta.changes)throw new CvieError('The product changed while you were choosing. Refresh options and try again.',409);
  if(registryEnabled(env))await bindProductIdentities(env,user.id);
  if(sharedScans(env))await reconcileSharedScopes(env,user.id);
  ctx?.waitUntil(runCvieStep(env,fetch,Date.now(),user.id,scope));return json({queued:true},202);
 }
 if(path==='/v1/cvie'&&req.method==='GET'){
  const now=Date.now();
  const loadProducts=async()=>sharedScans(env)?{results:(await query(env.DB,ownedProductSql(env,'p.*',scope),user.id).all()).results.map(overlaySharedProduct)}:query(env.DB,`SELECT p.*,
   (SELECT COUNT(*) FROM cvie_advisories a WHERE a.product_id=p.id AND a.published>=?) AS recent_count,
   (SELECT COUNT(*) FROM cvie_advisories a WHERE a.product_id=p.id AND a.published>=?) AS history_count
   FROM cvie_products p WHERE p.user_id=? AND ${activeSubscription('p',scope)} ORDER BY p.name`,iso(monthsAgo(now,3)),iso(monthsAgo(now,12)),user.id).all();
  const result=await loadProducts(); // GET is strictly read-only; repairs run on sync/scan work.
  const evidenceCtx=await evidenceContext(env,user.id,scope),counts=evidenceCtx?await combinedCounts(env,user.id,iso(monthsAgo(now,3)),iso(monthsAgo(now,12)),now,evidenceCtx):null;
  const products=(result.results||[]).map(p=>{
   return {...savedProgress(p,now),icon_slug:logoFor(p.name,p.cpe),
    component_scope:coveragePlan(p).component||'verified_product',coverage:coverageSummary(p),identity_label:coveragePlan(p).label,
    ...(isHyperV(p)?{component_scope:'windows_hyperv',identity_prompt:'Select the Windows host for Hyper-V',identity_label:hyperVHost(p.cpe)?.label||''}:{}),
    ...(coveragePlan(p).profile?{component_scope:'modern_dotnet'}:{}),
    recent_count:counts?(counts.find(c=>c.product_id===p.id)?.recent_count||0):p.recent_count,history_count:counts?(counts.find(c=>c.product_id===p.id)?.history_count||0):p.history_count,
    older_kev_recent_count:counts?.find(c=>c.product_id===p.id)?.older_kev_recent_count||0,older_kev_history_count:counts?.find(c=>c.product_id===p.id)?.older_kev_history_count||0,
    directory_complete:JSON.parse(p.cursor_json||'{}').directory_complete===true,directory_limited:JSON.parse(p.cursor_json||'{}').directory_limited===true,
    candidates:!p.cpe?JSON.parse(p.candidates_json):[]};
  });
  const evidence=await productSourceHealth(env,products,now),withdrawn=await withdrawnIds(env);
  return json({ready:true,engine:'CVIE',account_id:user.id,products,evidence,withdrawn_ids:withdrawn,excluded_product_cves:await excludedProductCves(env,user.id,evidenceCtx),default_months:3});
 }
 if(path==='/v1/cvie/advisories'&&req.method==='GET'){
  const months=Number(url.searchParams.get('months')||3),after=url.searchParams.get('after')||'';
  if(![3,12].includes(months)||after.length>100)throw new CvieError('Choose a 3 or 12 month history');
  const product=url.searchParams.get('product')||'';
  const combined=await combinedPage(env,user.id,iso(monthsAgo(Date.now(),months)),after,product,Date.now(),await evidenceContext(env,user.id,scope));
  if(combined)return json({ready:true,account_id:user.id,months,...combined});
  const rows=(await query(env.DB,`SELECT a.product_id,a.cve_id,a.record_json FROM cvie_advisories a JOIN cvie_products p ON p.id=a.product_id
   WHERE p.user_id=? AND a.published>=? AND a.published<=? AND (a.product_id||'/'||a.cve_id)>?
   AND ${activeSubscription('p',scope)} ${product?'AND p.id=?':''}
   ORDER BY a.product_id,a.cve_id LIMIT 101`,user.id,iso(monthsAgo(Date.now(),months)),iso(Date.now()),after,...(product?[product]:[])).all()).results||[];
  const page=rows.slice(0,100),last=page.at(-1);
  return json({ready:true,account_id:user.id,months,advisories:page.map(row=>JSON.parse(row.record_json)),next:rows.length>100?last.product_id+'/'+last.cve_id:null});
 }
 return json({error:'CVIE endpoint not found'},404);
}

