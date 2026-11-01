// CVIE: durable, account-scoped product identity resolution and NVD history.
// Every external URL is fixed here. Customer hosts/versions are never scanned or sent.
import {normalizeName,productCpe,cpeFamily,knownIdentity,logoFor,identityCandidates} from './product-identity.js';
import {queueRelevantKev} from './cvie-evidence.js';
import {combinedPage,combinedCounts,evidenceContext,sourceHealth,withdrawnIds,excludedProductCves} from './cvie-records.js';
import {isHyperV,hyperVHosts,hyperVHost,hyperVHelp,hyperVStatement} from './hyperv.js';
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
   FROM cvie_provider_budget WHERE provider='nvd'`).first();return row?.provider==='nvd';
 }catch{return false;}
}
export async function subscribeProducts(env,userId,products,origin='catalogue'){
 if(!await cvieReady(env))return {ready:false};
 if(!['catalogue','inventory','stack'].includes(origin))throw new CvieError('Invalid product source');
 const normalized=new Map();
 for(const item of products){
  const name=String(item.name||item.technology||'').trim(),vendor=String(item.vendor||'').trim();
  if(!name||name.length>120||vendor.length>100||/[\u0000-\u001f]/.test(name+vendor))throw new CvieError('Invalid product identity');
  if(item.cpe&&!productCpe(item.cpe))throw new CvieError('Use a product-family CPE 2.3 identifier with wildcard versions');
  normalized.set(normalizeName(name),{name,vendor,cpe:item.cpe?productCpe(item.cpe):knownIdentity(name,vendor)?.cpe||'',explicitCpe:Boolean(item.cpe),vendorProvided:item.vendor!==undefined});
 }
 if(normalized.size>500)throw new CvieError('CVIE supports up to 500 distinct products per account',409);
 const existing=(await query(env.DB,'SELECT id,name_key,cpe,vendor FROM cvie_products WHERE user_id=?',userId).all()).results||[];
 const ids=new Map(existing.map(x=>[x.name_key,x.id]));
 const other=(await query(env.DB,'SELECT DISTINCT p.name_key FROM cvie_products p JOIN cvie_subscriptions s ON p.id=s.product_id WHERE s.user_id=? AND s.origin<>?',userId,origin).all()).results||[];
 if(new Set([...other.map(x=>x.name_key),...normalized.keys()]).size>500)throw new CvieError('CVIE product capacity reached; remove unused products before adding more',409);
 const statements=[],inserts=[],changes=[];
 for(const [key,p] of normalized){
  const id=ids.get(key)||crypto.randomUUID();ids.set(key,id);
  inserts.push({id,key,name:p.name,vendor:p.vendor,cpe:p.cpe});
  const prior=existing.find(x=>x.name_key===key);
  if(prior&&(p.explicitCpe&&p.cpe!==prior.cpe||p.vendorProvided&&p.vendor!==prior.vendor)){
   changes.push({id,cpe:p.explicitCpe?p.cpe:knownIdentity(p.name,p.vendor)?.cpe||'',vendor:p.vendorProvided?p.vendor:prior.vendor});
  }
 }
 statements.push(query(env.DB,`INSERT OR IGNORE INTO cvie_products(id,user_id,name_key,name,vendor,cpe)
  SELECT json_extract(value,'$.id'),?,json_extract(value,'$.key'),json_extract(value,'$.name'),json_extract(value,'$.vendor'),json_extract(value,'$.cpe') FROM json_each(?)`,userId,JSON.stringify(inserts)));
 if(changes.length){
  const payload=JSON.stringify(changes);
  statements.push(query(env.DB,"DELETE FROM cvie_advisories WHERE product_id IN(SELECT json_extract(value,'$.id') FROM json_each(?))",payload));
  statements.push(query(env.DB,`UPDATE cvie_products SET
   cpe=(SELECT json_extract(value,'$.cpe') FROM json_each(?) WHERE json_extract(value,'$.id')=cvie_products.id),
   vendor=(SELECT json_extract(value,'$.vendor') FROM json_each(?) WHERE json_extract(value,'$.id')=cvie_products.id),
   status='queued',cursor_json='{}',candidates_json='[]',recent_complete_at=NULL,history_complete_at=NULL,last_success_at=NULL,next_attempt_at=0,lease_until=0,error=''
   WHERE user_id=? AND id IN(SELECT json_extract(value,'$.id') FROM json_each(?))`,payload,payload,userId,payload));
 }
 statements.push(query(env.DB,'DELETE FROM cvie_subscriptions WHERE user_id=? AND origin=?',userId,origin));
 statements.push(query(env.DB,'INSERT INTO cvie_subscriptions(user_id,product_id,origin) SELECT ?,value,? FROM json_each(?)',userId,origin,JSON.stringify([...normalized.keys()].map(key=>ids.get(key)))));
 statements.push(query(env.DB,'DELETE FROM cvie_products WHERE user_id=? AND NOT EXISTS(SELECT 1 FROM cvie_subscriptions s WHERE s.product_id=cvie_products.id)',userId));
 // Set-based JSON bindings keep bulk imports within D1's per-invocation query budget.
 await env.DB.batch(statements);
 await queueRelevantKev(env,[...normalized.values()]);
 return {ready:true,queued:normalized.size};
}
export async function syncAccountProducts(env,userId){
 const catalogue=await query(env.DB,'SELECT preferences_json FROM user_technology_catalogue WHERE user_id=?',userId).first();
 const inventory=await query(env.DB,'SELECT DISTINCT technology FROM inventory_assets WHERE user_id=?',userId).all();
 const stack=await query(env.DB,'SELECT technology FROM user_stack WHERE user_id=?',userId).all();
 await subscribeProducts(env,userId,JSON.parse(catalogue?.preferences_json||'{}').products||[],'catalogue');
 await subscribeProducts(env,userId,(inventory.results||[]).map(x=>({name:x.technology})),'inventory');
 await subscribeProducts(env,userId,(stack.results||[]).map(x=>({name:x.technology})),'stack');
}
function configurations(cve){
 const result=[];
 const walk=node=>{if(node.negate===true)return;for(const m of node.cpeMatch||[])if(m.vulnerable&&cpeFamily(m.criteria))result.push(m);for(const child of node.nodes||node.children||[])walk(child);};
 for(const node of cve.configurations||[])walk(node);
 return result;
}
export function normalizeNvd(cve,product){
 if(!/^CVE-\d{4}-\d{4,10}$/i.test(cve?.id||'')||/rejected/i.test(cve.vulnStatus||''))return null;
 const matches=configurations(cve).filter(m=>cpeFamily(m.criteria)===product.cpe);
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
  categories:[product.name],cvie_products:[product.name],cvie_identities:[{name:product.name,cpe:product.cpe}],affected_cpes:matches,
  affected:matches.map(m=>product.name+' '+[m.versionStartIncluding&&'>= '+m.versionStartIncluding,m.versionStartExcluding&&'> '+m.versionStartExcluding,m.versionEndIncluding&&'<= '+m.versionEndIncluding,m.versionEndExcluding&&'< '+m.versionEndExcluding].filter(Boolean).join(', ')).join('; '),
  remediation:'Review the linked vendor advisory for affected versions, prerequisites and the appropriate fix.',sources,
  action:'Confirm the installed version and deployment prerequisites before remediation.',
  exploitation:cve.cisaExploitAdd?'Listed in CISA KEV':'No exploitation claim made by CVIE'};
}
async function prepareHyperVHosts(env,userId,products){
 const candidates=JSON.stringify(hyperVHosts());
 const repairs=products.filter(p=>isHyperV(p)&&!hyperVHost(p.cpe)&&
  (p.cpe||p.status!=='needs_identity'||p.candidates_json!==candidates)).map(p=>({id:p.id,cpe:p.cpe,candidates:p.candidates_json}));
 if(!repairs.length)return false;
 // Repair only this account's unresolved/invalid component identities. A host chosen
 // concurrently wins; valid existing Microsoft host selections are preserved.
 const result=await env.DB.batch([
  query(env.DB,`UPDATE cvie_products SET cpe='',status='needs_identity',candidates_json=?,cursor_json='{}',
   recent_complete_at=NULL,history_complete_at=NULL,last_success_at=NULL,next_attempt_at=0,lease_until=0,error=?
   WHERE user_id=? AND EXISTS(SELECT 1 FROM json_each(?) r WHERE json_extract(r.value,'$.id')=cvie_products.id
    AND json_extract(r.value,'$.cpe')=cvie_products.cpe AND json_extract(r.value,'$.candidates')=cvie_products.candidates_json)`,candidates,hyperVHelp,userId,JSON.stringify(repairs)),
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
export async function runCvieStep(env,fetcher=fetch,now=Date.now(),userId=null){
 if(!await cvieReady(env))return {ready:false};
 const product=await query(env.DB,`SELECT p.* FROM cvie_products p WHERE p.status<>'needs_identity' AND p.next_attempt_at<=? AND p.lease_until<?
  AND EXISTS(SELECT 1 FROM cvie_subscriptions s WHERE s.product_id=p.id) ${userId?'AND p.user_id=?':''}
  ORDER BY CASE WHEN p.recent_complete_at IS NULL THEN 0 WHEN p.history_complete_at IS NULL THEN 1 ELSE 2 END,p.next_attempt_at,COALESCE(p.last_attempt_at,0),p.id LIMIT 1`,now,now,...(userId?[userId]:[])).first();
 if(!product)return {idle:true};
 if(isHyperV(product)&&!hyperVHost(product.cpe)){
  await prepareHyperVHosts(env,product.user_id,[product]);return {resolved:false};
 }
 const budget=await query(env.DB,'UPDATE cvie_provider_budget SET next_request_at=? WHERE provider=? AND next_request_at<=?',now+(env.NVD_API_KEY?1000:6500),'nvd',now).run();
 if(budget.meta.changes!==1)return {waiting:true};
 const lease=now+120000;
 if((await query(env.DB,'UPDATE cvie_products SET lease_until=?,status=?,last_attempt_at=? WHERE id=? AND lease_until<?',lease,'scanning',now,product.id,now).run()).meta.changes!==1)return {busy:true};
 try{
  if(!product.cpe){
   const data=await requestNvd(env,'cpes',{keywordSearch:[product.vendor,product.name].filter(Boolean).join(' '),resultsPerPage:500},fetcher);
   if(!Array.isArray(data.products)||!Number.isSafeInteger(data.totalResults))throw new ProviderError('NVD product directory response is incomplete');
   const candidates=identityCandidates(data);
   // A unique result can only be accepted if the directory was fully searched.
   const cpe=candidates.length===1&&data.totalResults<=data.products.length?candidates[0].cpe:'';
   await query(env.DB,'UPDATE cvie_products SET cpe=?,status=?,candidates_json=?,lease_until=0,error=? WHERE id=? AND lease_until=?',cpe,cpe?'queued':'needs_identity',JSON.stringify(candidates.slice(0,100)),cpe?'':'Choose the exact vendor/product identity to continue; a name search alone is not a vulnerability match.',product.id,lease).run();
   return {resolved:Boolean(cpe)};
  }
  let cursor=JSON.parse(product.cursor_json||'{}');
  if(!cursor.windows?.length){cursor={generation:crypto.randomUUID(),anchor:now,windows:scanWindows(now),position:0};}
  const window=cursor.windows[cursor.position];
   const data=await requestNvd(env,'cves',{virtualMatchString:product.cpe,...(isHyperV(product)?{keywordSearch:'Windows Hyper-V',keywordExactMatch:''}:{}),pubStartDate:iso(window.start),pubEndDate:iso(window.end),startIndex:window.index,resultsPerPage:50},fetcher);
  if(!Array.isArray(data.vulnerabilities)||!Number.isSafeInteger(data.totalResults)||data.totalResults<0||data.startIndex!==window.index||
     (!data.vulnerabilities.length&&window.index<data.totalResults)||data.vulnerabilities.some(entry=>!/^CVE-\d{4}-\d{4,10}$/i.test(entry?.cve?.id||'')||!Number.isFinite(Date.parse(entry.cve.published))||Date.parse(entry.cve.published)<window.start||Date.parse(entry.cve.published)>window.end))throw new ProviderError('NVD returned an incomplete page; CVIE has not marked this scan complete.');
  const statements=[],pageRecords=[];
  for(const entry of data.vulnerabilities){
   const record=normalizeNvd(entry.cve,product);
   if(record&&Date.parse(record.published)>=monthsAgo(cursor.anchor,12)&&Date.parse(record.published)<=cursor.anchor)
    pageRecords.push({...record,nvd_checked_at:now});
  }
  if(pageRecords.length)statements.push(query(env.DB,`INSERT INTO cvie_advisories(product_id,cve_id,published,record_json,generation)
   SELECT ?,json_extract(value,'$.id'),json_extract(value,'$.published'),value,? FROM json_each(?)
   WHERE EXISTS(SELECT 1 FROM cvie_products WHERE id=? AND lease_until=? AND cpe=?)
   ON CONFLICT(product_id,cve_id) DO UPDATE SET published=excluded.published,record_json=excluded.record_json,generation=excluded.generation`,product.id,cursor.generation,JSON.stringify(pageRecords),product.id,lease,product.cpe));
  window.index+=data.vulnerabilities.length;window.total=data.totalResults;
  let recent=product.recent_complete_at,history=product.history_complete_at;
  if(window.index>=data.totalResults){if(cursor.position===0)recent=now;cursor.position++;}
  const complete=cursor.position===cursor.windows.length;
  if(complete){
   history=now;
   statements.push(query(env.DB,'DELETE FROM cvie_advisories WHERE product_id=? AND (generation<>? OR published<?) AND EXISTS(SELECT 1 FROM cvie_products WHERE id=? AND lease_until=? AND cpe=?)',product.id,cursor.generation,iso(monthsAgo(cursor.anchor,12)),product.id,lease,product.cpe));
  }
  // Cursor + page records commit together, so a crash never advances past unsaved results.
  statements.push(query(env.DB,`UPDATE cvie_products SET status=?,cursor_json=?,scan_started_at=COALESCE(scan_started_at,?),last_success_at=?,
   recent_complete_at=?,history_complete_at=?,next_attempt_at=?,lease_until=0,error='' WHERE id=? AND lease_until=?`,
   complete?'ready':'scanning',JSON.stringify(complete?{}:cursor),cursor.anchor,now,recent,history,complete?now+6*3600000:0,product.id,lease));
  await env.DB.batch(statements);
  return {complete,processed:data.vulnerabilities.length};
 }catch(error){
  const delay=error instanceof ProviderError?error.delay:60000;
  const message=error instanceof ProviderError?error.message:'CVIE could not complete the source check. Saved results remain available; retry is scheduled.';
  if(error instanceof ProviderError)await query(env.DB,'UPDATE cvie_provider_budget SET next_request_at=MAX(next_request_at,?) WHERE provider=?',now+delay,'nvd').run();
  await query(env.DB,'UPDATE cvie_products SET status=?,error=?,next_attempt_at=?,lease_until=0 WHERE id=? AND lease_until=?','retrying',message,now+delay,product.id,lease).run();
  return {retrying:true};
 }
}
export async function dispatchCvie(env){
 // Cron continues unfinished scans even after all browsers close. Budget is global.
 for(let i=0;i<6;i++){
  const result=await runCvieStep(env);
  if(result.idle||result.waiting||result.ready===false)break;
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
  return {records,withdrawn_ids:await withdrawnIds(env),excluded_product_cves:await excludedProductCves(env,userId,ctx),component_products:ctx.products.filter(isHyperV).map(p=>p.name),degraded:health.sources.some(s=>s.status!=='current')||ctx.products.some(p=>p.status!=='ready'||!p.last_success_at||now-p.last_success_at>DAY),coverageLimited:Boolean(after)};
 }
 const recent=iso(now-30*DAY);
 const result=await query(env.DB,`SELECT a.record_json FROM cvie_advisories a JOIN cvie_products p ON p.id=a.product_id
  WHERE p.user_id=? AND a.published>=? AND (a.published>=? OR json_extract(a.record_json,'$.updated')>=?)
  AND EXISTS(SELECT 1 FROM cvie_subscriptions s WHERE s.product_id=p.id)
  ORDER BY json_extract(a.record_json,'$.known_exploited') DESC,
   CASE json_extract(a.record_json,'$.severity') WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,a.published DESC LIMIT 1001`,userId,iso(monthsAgo(now,12)),recent,recent).all();
 const pending=await query(env.DB,"SELECT id FROM cvie_products p WHERE user_id=? AND (status<>'ready' OR last_success_at<?) AND EXISTS(SELECT 1 FROM cvie_subscriptions s WHERE s.product_id=p.id) LIMIT 1",userId,now-24*3600000).first();
 return {records:(result.results||[]).slice(0,1000).map(row=>JSON.parse(row.record_json)),degraded:Boolean(pending),coverageLimited:(result.results||[]).length>1000};
}
export async function cvieRoute(req,env,user,ctx,data={}){
 if(!await cvieReady(env))return json({ready:false,error:'CVIE database setup is required. Your saved products and inventory are unchanged.'},503);
 const url=new URL(req.url),path=url.pathname;
 if(path==='/v1/cvie/sync'&&req.method==='POST'){
  await syncAccountProducts(env,user.id);ctx?.waitUntil(runCvieStep(env,fetch,Date.now(),user.id));return json({ready:true,status:'queued'},202);
 }
 const identity=/^\/v1\/cvie\/products\/([a-f0-9-]{36})\/identity$/.exec(path);
 if(identity&&req.method==='PUT'){
  const product=await query(env.DB,'SELECT * FROM cvie_products WHERE id=? AND user_id=?',identity[1],user.id).first();
  if(!product)throw new CvieError('Product not found',404);
  if(product.status!=='needs_identity')throw new CvieError('This product identity is already being scanned',409);
  const cpe=productCpe(data.cpe);
  if(!cpe||!JSON.parse(product.candidates_json).some(x=>x.cpe===cpe))throw new CvieError('Select an identity returned by the product directory');
  if(isHyperV(product)&&!hyperVHost(cpe))throw new CvieError('Select the Microsoft Windows host running Hyper-V');
  await query(env.DB,"UPDATE cvie_products SET cpe=?,status='queued',cursor_json='{}',error='',next_attempt_at=0 WHERE id=? AND user_id=?",cpe,product.id,user.id).run();
  ctx?.waitUntil(runCvieStep(env,fetch,Date.now(),user.id));return json({queued:true},202);
 }
 if(path==='/v1/cvie'&&req.method==='GET'){
  const now=Date.now();
  const loadProducts=()=>query(env.DB,`SELECT p.*,
   (SELECT COUNT(*) FROM cvie_advisories a WHERE a.product_id=p.id AND a.published>=?) AS recent_count,
   (SELECT COUNT(*) FROM cvie_advisories a WHERE a.product_id=p.id AND a.published>=?) AS history_count
   FROM cvie_products p WHERE p.user_id=? AND EXISTS(SELECT 1 FROM cvie_subscriptions s WHERE s.product_id=p.id) ORDER BY p.name`,iso(monthsAgo(now,3)),iso(monthsAgo(now,12)),user.id).all();
  let result=await loadProducts();
  if(await prepareHyperVHosts(env,user.id,result.results||[]))result=await loadProducts();
  const evidenceCtx=await evidenceContext(env,user.id),counts=evidenceCtx?await combinedCounts(env,user.id,iso(monthsAgo(now,3)),iso(monthsAgo(now,12)),now,evidenceCtx):null;
  const products=(result.results||[]).map(p=>{
   const cursor=JSON.parse(p.cursor_json||'{}'),window=cursor.windows?.[cursor.position];
   return {id:p.id,name:p.name,vendor:p.vendor,cpe:p.cpe,status:p.status,error:p.error,icon_slug:logoFor(p.name,p.cpe),
    ...(isHyperV(p)?{component_scope:'windows_hyperv',identity_prompt:'Select the Windows host for Hyper-V',identity_label:hyperVHost(p.cpe)?.label||''}:{}),
    recent_count:counts?(counts.find(c=>c.product_id===p.id)?.recent_count||0):p.recent_count,history_count:counts?(counts.find(c=>c.product_id===p.id)?.history_count||0):p.history_count,
    older_kev_recent_count:counts?.find(c=>c.product_id===p.id)?.older_kev_recent_count||0,older_kev_history_count:counts?.find(c=>c.product_id===p.id)?.older_kev_history_count||0,
    last_success_at:p.last_success_at,recent_complete_at:p.recent_complete_at,
    history_complete_at:p.history_complete_at,next_attempt_at:p.next_attempt_at,stale:!p.last_success_at||now-p.last_success_at>24*3600000,
    progress:{windows_complete:cursor.position||0,windows_total:cursor.windows?.length||0,records_checked:window?.index||0,records_in_window:window?.total??null},
    candidates:p.status==='needs_identity'?JSON.parse(p.candidates_json):[]};
  });
  const evidence=await sourceHealth(env,now),withdrawn=await withdrawnIds(env);
  const attempted=products.map(p=>p.last_success_at).filter(Boolean);
  evidence.sources.unshift({id:'nvd',label:'NVD product history',url:'https://nvd.nist.gov/',
   status:!products.length?'no_products':products.every(p=>p.status==='needs_identity')?'needs_identity':products.some(p=>p.status==='retrying')?'unavailable':products.some(p=>p.stale&&p.status==='ready')?'stale':products.some(p=>p.status!=='ready')?'scanning':'current',
   last_success_at:attempted.length?Math.min(...attempted):null});
  ctx?.waitUntil(runCvieStep(env,fetch,now,user.id));return json({ready:true,engine:'CVIE',account_id:user.id,products,evidence,withdrawn_ids:withdrawn,excluded_product_cves:await excludedProductCves(env,user.id,evidenceCtx),default_months:3});
 }
 if(path==='/v1/cvie/advisories'&&req.method==='GET'){
  const months=Number(url.searchParams.get('months')||3),after=url.searchParams.get('after')||'';
  if(![3,12].includes(months)||after.length>100)throw new CvieError('Choose a 3 or 12 month history');
  const product=url.searchParams.get('product')||'';
  const combined=await combinedPage(env,user.id,iso(monthsAgo(Date.now(),months)),after,product);
  if(combined)return json({ready:true,account_id:user.id,months,...combined});
  const rows=(await query(env.DB,`SELECT a.product_id,a.cve_id,a.record_json FROM cvie_advisories a JOIN cvie_products p ON p.id=a.product_id
   WHERE p.user_id=? AND a.published>=? AND a.published<=? AND (a.product_id||'/'||a.cve_id)>?
   AND EXISTS(SELECT 1 FROM cvie_subscriptions s WHERE s.product_id=p.id) ${product?'AND p.id=?':''}
   ORDER BY a.product_id,a.cve_id LIMIT 101`,user.id,iso(monthsAgo(Date.now(),months)),iso(Date.now()),after,...(product?[product]:[])).all()).results||[];
  const page=rows.slice(0,100),last=page.at(-1);
  return json({ready:true,account_id:user.id,months,advisories:page.map(row=>JSON.parse(row.record_json)),next:rows.length>100?last.product_id+'/'+last.cve_id:null});
 }
 return json({error:'CVIE endpoint not found'},404);
}
