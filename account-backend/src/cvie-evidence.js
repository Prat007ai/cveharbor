// Original CVE Program records from vendors/authorized CNAs and independent CISA KEV.
// URLs from provider content are never fetched: all request destinations are fixed.
import {cveMirrorUrl,simplifyCve,normalizeCveId} from './cve-lookup.js';
import {cpeFamily,vendorKey} from './product-identity.js';
const q=(db,sql,...args)=>db.prepare(sql).bind(...args);
const DAY=86400000;
const validAddedDate=(value,now)=>{
 if(!/^\d{4}-\d{2}-\d{2}$/.test(value||''))return false;
 const date=Date.parse(value+'T00:00:00Z');
 return Number.isFinite(date)&&date<=now&&new Date(date).toISOString().slice(0,10)===value;
};
class SourceError extends Error{
 constructor(response){super('Source returned HTTP '+response.status);const value=response.headers.get('Retry-After');
  const delay=/^\d+$/.test(value||'')?Number(value)*1000:Date.parse(value||'')-Date.now();
  this.delay=Math.max(60000,Math.min(6*3600000,delay||60000));this.throttled=response.status===429;
 }
}
export const SOURCE_URLS={
 cve_program:'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json',
 cisa_kev:'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
};
export const wordKey=value=>String(value||'').normalize('NFKC').toLowerCase().replace(/[^a-z0-9]/g,'');
export const productLabel=value=>String(value||'').normalize('NFKC').toLowerCase().replace(/[\s_]/g,'');
export function productLabels(product){
 const parts=String(product.cpe||'').split(':');
 return [...new Set((parts.length===13?[parts[4],parts[3]+parts[4]]:[product.name]).map(productLabel))];
}
function jsonChunks(values,max=800000){
 const chunks=[];let items=[],size=2;
 for(const value of values){const encoded=JSON.stringify(value),bytes=new TextEncoder().encode(encoded).length+1;
  if(bytes>max)throw Error('Source record exceeds the safe database binding size');
  if(items.length&&size+bytes>max){chunks.push('['+items.join(',')+']');items=[];size=2;}
  items.push(encoded);size+=bytes;
 }
 if(items.length)chunks.push('['+items.join(',')+']');return chunks;
}
export function productFamilies(product){
 const parts=String(product.cpe||'').split(':');
 if(parts.length!==13){
  const vendor=vendorKey(product.vendor),name=wordKey(product.name);
  return vendor&&name?['name:'+vendor+':'+name]:[];
 }
 const vendor=vendorKey(parts[3]),name=wordKey(parts[4]);
 return [...new Set(['cpe:'+product.cpe,'name:'+vendor+':'+name,'name:'+vendor+':'+wordKey(parts[3]+parts[4]),'name:'+vendor+':'+wordKey(product.name)])];
}
export function affectedFamilies(affected){
 const cpes=(affected.cpes||[]).map(cpeFamily).filter(Boolean);
 if(cpes.length)return [...new Set(cpes.map(cpe=>'cpe:'+cpe))];
 const vendor=vendorKey(affected.vendor),product=wordKey(affected.product);
 return vendor&&product&&!['na','unknown','unspecified'].includes(vendor)&&!['na','unknown','unspecified'].includes(product)?['name:'+vendor+':'+product]:[];
}
export function cnaApplicability(rows){
 return rows.every(row=>row.defaultStatus==='unaffected'&&(row.versions||[]).every(v=>v.status==='unaffected'))?'unaffected':'affected';
}
export function normalizeDisclosure(raw){
 const simple=simplifyCve(raw,'CVE Program / CNA disclosure');
 if(!simple||!['published','rejected'].includes(simple.status))throw Error('CVE Program record is not published or rejected');
 const metadata=raw.cveMetadata,cna=raw.containers?.cna||{};
 const original=simplifyCve({...raw,containers:{cna}},'CVE Program / CNA disclosure');
 const scored=original?.cvss!==null?original:simple;
 const updated=Date.parse(metadata.dateUpdated||metadata.datePublished);
 if(!Number.isFinite(updated)||updated>Date.now()+300000)throw Error('CVE Program record has no valid revision timestamp');
 if(simple.status==='rejected')return {id:simple.id,state:'REJECTED',published:null,updated_at:new Date(updated).toISOString(),base:{id:simple.id,status:'rejected'},families:[]};
 const published=Date.parse(metadata.datePublished||cna.datePublic);
 if(!Number.isFinite(published)||published>Date.now()+300000)throw Error('CVE Program record has no valid disclosure date');
 const families=new Map();
 for(const row of cna.affected||[])for(const key of affectedFamilies(row)){
  if(!families.has(key))families.set(key,[]);families.get(key).push(row);
 }
 const references=[{label:'CVE Program / original CNA record',url:'https://www.cve.org/CVERecord?id='+simple.id},...simple.references];
 return {id:simple.id,state:'PUBLISHED',published:new Date(published).toISOString(),updated_at:new Date(updated).toISOString(),
  base:{id:simple.id,kind:'cve',title:simple.title,summary:String(cna.descriptions?.find(x=>x.lang==='en')?.value||simple.description).slice(0,12000),
   published:new Date(published).toISOString(),updated:new Date(updated).toISOString(),severity:scored.severity,cvss:scored.cvss,
   cvss_provider:original?.cvss!==null?'CVE Program / CNA':'CVE Program / ADP',
   cvss_label_conflict:Boolean(scored.cvssSeverityLabel&&scored.cvssSeverityLabel!==scored.severity),
   remediation:simple.remediation||'Review the original vendor advisory for affected versions and the appropriate fix.',
   action:'Verify the installed product, version and prerequisites against the original advisory.',
   status:'Published CNA disclosure',source_type:'cvie_cna',sources:references},
  families:[...families].map(([family_key,rows])=>({family_key,applicability:cnaApplicability(rows),rows}))};
}
export async function evidenceReady(env){
 try{return !!await env.DB.prepare(`SELECT id,EXISTS(SELECT 1 FROM cvie_disclosures) AS records,
  EXISTS(SELECT 1 FROM cvie_disclosure_products) AS products,EXISTS(SELECT 1 FROM cvie_disclosure_queue) AS queued,
  EXISTS(SELECT 1 FROM cvie_kev) AS kev FROM cvie_sources WHERE id='cve_program'`).first();}catch{return false;}
}
async function fetchJson(url,fetcher,max=3000000){
 const response=await fetcher(url,{headers:{Accept:'application/json','User-Agent':'CVEHarbor-CVIE/1.0'},signal:AbortSignal.timeout(20000)});
 if(!response.ok)throw new SourceError(response);
 const raw=await response.text();if(raw.length>max)throw Error('Source exceeded its safe response size');return JSON.parse(raw);
}
// Stream just the required prefix of the 30+ MB official change log.
export async function readDeltaLog(response,checkpoint,now=Date.now()){
 if(!response.ok)throw new SourceError(response);if(!response.body)throw Error('CVE change feed has no response body');
 const reader=response.body.getReader(),decode=new TextDecoder(),entries=new Map();
 const target=checkpoint||now-DAY;
 let bytes=0,object='',depth=0,inString=false,escape=false,started=false,ended=false,newest=null,oldest=null,previous=Infinity,boundary=false;
 try{
  while(!boundary&&!ended){
   const chunk=await reader.read();if(chunk.done)break;bytes+=chunk.value.length;
   if(bytes>8000000)throw Error('CVE catch-up exceeded the streaming limit; the checkpoint has not advanced');
   const text=decode.decode(chunk.value,{stream:true});
   for(const ch of text){
    if(!started){if(/\s/.test(ch))continue;if(ch!=='[')throw Error('Invalid CVE change-feed array');started=true;continue;}
    if(depth===0){if(ch===']'){ended=true;break;}if(ch===','||/\s/.test(ch))continue;if(ch!=='{')throw Error('Invalid CVE change-feed entry');}
    object+=ch;
    if(inString){if(escape)escape=false;else if(ch==='\\')escape=true;else if(ch==='"')inString=false;}
    else if(ch==='"')inString=true;else if(ch==='{')depth++;else if(ch==='}')depth--;
    if(object.length>2000000)throw Error('Oversized CVE change-feed entry');
    if(depth!==0)continue;
    const row=JSON.parse(object);object='';const timestamp=Date.parse(row.fetchTime);
    if(!Number.isFinite(timestamp)||timestamp>now+300000||timestamp>previous)throw Error('Invalid or unordered CVE change-feed timestamps');
    previous=timestamp;newest??=timestamp;oldest=timestamp;
    if(timestamp<=target){boundary=true;break;}
    if(!Array.isArray(row.new)||!Array.isArray(row.updated)||(row.error||[]).length)throw Error('Publisher reported incomplete CVE change data');
    if(!Number.isInteger(row.numberOfChanges)||row.numberOfChanges!==row.new.length+row.updated.length)throw Error('CVE change-feed entry count is incomplete');
    for(const entry of [...row.new,...row.updated]){
     const id=normalizeCveId(entry.cveId),revision=Date.parse(entry.dateUpdated);
     if(!id||!Number.isFinite(revision)||revision>now+300000)throw Error('Invalid CVE identifier or revision in change feed');
     const value={id,revision:new Date(revision).toISOString(),priority:1};
     if(!entries.has(id)||value.revision>entries.get(id).revision)entries.set(id,value);
    }
   }
  }
 }finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
 if(!started||(!ended&&!boundary)||object||!newest)throw Error('Truncated CVE change feed; checkpoint unchanged');
 if(checkpoint&&ended&&!boundary)throw Error('CVE change history does not reach the saved checkpoint; coverage gap needs review');
 if(checkpoint&&newest<checkpoint)throw Error('CVE publisher snapshot is older than the saved checkpoint; prior evidence retained');
 return {entries:[...entries.values()],newest,oldest,coverageStart:checkpoint?undefined:oldest};
}
function queueSql(env,items,sourceId=null,lease=null){
 return q(env.DB,`INSERT INTO cvie_disclosure_queue(cve_id,revision,priority)
  SELECT json_extract(value,'$.id'),json_extract(value,'$.revision'),json_extract(value,'$.priority') FROM json_each(?)
  WHERE NOT EXISTS(SELECT 1 FROM cvie_disclosures d WHERE d.cve_id=json_extract(value,'$.id') AND d.updated_at>=json_extract(value,'$.revision'))
  ${sourceId?'AND EXISTS(SELECT 1 FROM cvie_sources WHERE id=? AND lease_until=?)':''}
  ON CONFLICT(cve_id) DO UPDATE SET priority=MIN(priority,excluded.priority),
   next_attempt_at=CASE WHEN excluded.revision>revision THEN 0 ELSE next_attempt_at END,
   attempts=CASE WHEN excluded.revision>revision THEN 0 ELSE attempts END,
   error=CASE WHEN excluded.revision>revision THEN '' ELSE error END,
   revision=MAX(revision,excluded.revision)`,JSON.stringify(items),...(sourceId?[sourceId,lease]:[]));
}
export function relevantKev(kev,products){
 const vendor=vendorKey(kev.vendorProject),name=wordKey(kev.product);
 if(!vendor||!name)return false;
 // Broad KEV product labels are used only to prioritize original-record lookups.
 return products.some(p=>{
  const parts=String(p.cpe||'').split(':');if(vendorKey(parts[3]||p.vendor)!==vendor)return false;
  return [wordKey(parts[4]),wordKey(p.name)].filter(Boolean).some(value=>value===name||value.startsWith(name)||name===vendor+value);
 });
}
export async function queueRelevantKev(env,products){
 if(!products.length||!await evidenceReady(env))return;
 const rows=(await env.DB.prepare('SELECT record_json FROM cvie_kev').all()).results||[];
 const items=rows.map(row=>JSON.parse(row.record_json)).filter(k=>relevantKev(k,products)).map(k=>({id:k.cveID,revision:'',priority:0}));
 if(items.length)await queueSql(env,items).run();
}
export async function refreshEvidence(env,fetcher=fetch,now=Date.now()){
 if(!await evidenceReady(env))return {ready:false};
 const source=await q(env.DB,'SELECT * FROM cvie_sources WHERE next_attempt_at<=? AND lease_until<? ORDER BY next_attempt_at,id LIMIT 1',now,now).first();
 if(!source)return {idle:true};const lease=now+120000;
 const claimed=await q(env.DB,'UPDATE cvie_sources SET last_attempt_at=?,lease_until=? WHERE id=? AND lease_until<?',now,lease,source.id,now).run();
 if(claimed.meta.changes!==1)return {busy:true};
 try{
  const statements=[];let publisher,checkpoint=source.checkpoint,coverage=source.coverage_start_at;
  if(source.id==='cve_program'){
   const response=await fetcher(SOURCE_URLS.cve_program,{headers:{Accept:'application/json'},signal:AbortSignal.timeout(20000)});
   const feed=await readDeltaLog(response,checkpoint,now);publisher=feed.newest;checkpoint=feed.newest;coverage??=feed.coverageStart;
   statements.push(queueSql(env,feed.entries,source.id,lease));
  }else{
   const feed=await fetchJson(SOURCE_URLS.cisa_kev,fetcher);
   publisher=Date.parse(feed.dateReleased);
   if(!Array.isArray(feed.vulnerabilities)||!feed.vulnerabilities.length||feed.count!==feed.vulnerabilities.length||!Number.isFinite(publisher)||publisher>now+300000)throw Error('CISA KEV catalogue is empty or incomplete');
   if(source.publisher_at&&publisher<source.publisher_at)throw Error('CISA publisher snapshot is older than the saved catalogue; prior evidence retained');
   const seen=new Set();
   for(const k of feed.vulnerabilities){
    if(!normalizeCveId(k.cveID)||seen.has(k.cveID)||!validAddedDate(k.dateAdded,now)||typeof k.vendorProject!=='string'||typeof k.product!=='string')throw Error('Invalid CISA KEV entry');seen.add(k.cveID);
   }
   const old=await env.DB.prepare('SELECT COUNT(*) AS total FROM cvie_kev').first();
   if(old.total>10&&feed.count<old.total/2)throw Error('Unexpected large CISA catalogue reduction; saved evidence retained for review');
   const products=(await env.DB.prepare('SELECT DISTINCT name,cpe FROM cvie_products WHERE cpe<>\'\'').all()).results||[];
   const items=feed.vulnerabilities.map(k=>({id:k.cveID,revision:'',priority:relevantKev(k,products)?0:2}));
   const values=feed.vulnerabilities.map(k=>({id:k.cveID,date:k.dateAdded,vendor:k.vendorProject,product:k.product,record:k}));
   statements.push(q(env.DB,'DELETE FROM cvie_kev WHERE EXISTS(SELECT 1 FROM cvie_sources WHERE id=? AND lease_until=?)',source.id,lease));
   for(const chunk of jsonChunks(values))statements.push(q(env.DB,`INSERT INTO cvie_kev(cve_id,date_added,vendor,product,record_json,checked_at)
    SELECT json_extract(value,'$.id'),json_extract(value,'$.date'),json_extract(value,'$.vendor'),json_extract(value,'$.product'),json_extract(value,'$.record'),?
    FROM json_each(?) WHERE EXISTS(SELECT 1 FROM cvie_sources WHERE id=? AND lease_until=?)`,now,chunk,source.id,lease));
   statements.push(queueSql(env,items,source.id,lease));
  }
  statements.push(q(env.DB,`UPDATE cvie_sources SET status='ok',last_success_at=?,publisher_at=?,checkpoint=?,coverage_start_at=?,
   next_attempt_at=?,lease_until=0,error='',source_url=? WHERE id=? AND lease_until=?`,now,publisher,checkpoint,coverage,now+(source.id==='cisa_kev'?15:5)*60000,SOURCE_URLS[source.id],source.id,lease));
  await env.DB.batch(statements);return {source:source.id,ok:true};
 }catch(error){
  const retry=now+(error.delay||60000);
  await q(env.DB,"UPDATE cvie_sources SET status='unavailable',error=?,next_attempt_at=?,record_retry_at=MAX(record_retry_at,?),lease_until=0 WHERE id=? AND lease_until=?",String(error.message).slice(0,220),retry,source.id==='cve_program'&&error.throttled?retry:0,source.id,lease).run();return {source:source.id,ok:false};
 }
}
export async function ingestDisclosures(env,fetcher=fetch,now=Date.now(),limit=15){
 if(!await evidenceReady(env))return {ready:false};
 const provider=await env.DB.prepare("SELECT record_retry_at FROM cvie_sources WHERE id='cve_program'").first();
 if(provider.record_retry_at>now)return {waiting:true};
 const jobs=(await q(env.DB,'SELECT * FROM cvie_disclosure_queue WHERE next_attempt_at<=? AND lease_until<? ORDER BY priority,next_attempt_at,revision DESC,cve_id LIMIT ?',now,now,Math.min(15,limit)).all()).results||[];
 if(!jobs.length)return {processed:0};const lease=now+120000;
 const ids=JSON.stringify(jobs.map(j=>j.cve_id));
 const claimed=(await q(env.DB,'UPDATE cvie_disclosure_queue SET lease_until=? WHERE cve_id IN(SELECT value FROM json_each(?)) AND lease_until<? RETURNING *',lease,ids,now).all()).results||[];
 const successes=[],failures=[];let throttledUntil=0;
 // Bounded batches avoid overwhelming CVE Program endpoints or the Worker.
 for(let i=0;i<claimed.length;i+=5)await Promise.all(claimed.slice(i,i+5).map(async job=>{
  try{
   let raw;try{raw=await fetchJson(cveMirrorUrl(job.cve_id),fetcher,1500000);}catch(error){if(error.throttled)throttledUntil=Math.max(throttledUntil,now+error.delay);raw=await fetchJson('https://cveawg.mitre.org/api/cve/'+job.cve_id,fetcher,1500000);}
   const record=normalizeDisclosure(raw);if(record.id!==job.cve_id)throw Error('CVE source returned the wrong identifier');
   successes.push(record);
  }catch(error){if(error.throttled)throttledUntil=Math.max(throttledUntil,now+error.delay);failures.push({id:job.cve_id,error:String(error.message).slice(0,180),delay:Math.max(error.delay||60000,Math.min(6*3600000,60000*2**Math.min(job.attempts,9)))});}
 }));
 const records=successes.map(r=>({id:r.id,state:r.state,published:r.published,updated:r.updated_at,record:r.base}));
 const families=successes.flatMap(r=>r.families.map(f=>({id:r.id,updated:r.updated_at,key:f.family_key,applicability:f.applicability,rows:f.rows})));
 const revisions=JSON.stringify(successes.map(r=>({id:r.id,updated:r.updated_at})));
 const successIds=JSON.stringify(successes.map(r=>r.id));
 const statements=[];
 for(const chunk of jsonChunks(records))statements.push(q(env.DB,`INSERT INTO cvie_disclosures(cve_id,state,published,updated_at,record_json,checked_at)
   SELECT json_extract(value,'$.id'),json_extract(value,'$.state'),json_extract(value,'$.published'),json_extract(value,'$.updated'),json_extract(value,'$.record'),?
   FROM json_each(?) WHERE EXISTS(SELECT 1 FROM cvie_disclosure_queue j WHERE j.cve_id=json_extract(value,'$.id') AND j.lease_until=?)
   ON CONFLICT(cve_id) DO UPDATE SET state=excluded.state,published=COALESCE(excluded.published,published),updated_at=excluded.updated_at,record_json=excluded.record_json,checked_at=excluded.checked_at
   WHERE excluded.updated_at>=cvie_disclosures.updated_at`,now,chunk,lease));
 statements.push(q(env.DB,`DELETE FROM cvie_disclosure_products WHERE cve_id IN(SELECT value FROM json_each(?))
  AND EXISTS(SELECT 1 FROM cvie_disclosure_queue j WHERE j.cve_id=cvie_disclosure_products.cve_id AND j.lease_until=?)
  AND EXISTS(SELECT 1 FROM cvie_disclosures d JOIN json_each(?) r ON json_extract(r.value,'$.id')=d.cve_id
   WHERE d.cve_id=cvie_disclosure_products.cve_id AND d.updated_at=json_extract(r.value,'$.updated') AND d.checked_at=?)`,successIds,lease,revisions,now));
 for(const chunk of jsonChunks(families))statements.push(q(env.DB,`INSERT INTO cvie_disclosure_products(cve_id,family_key,applicability,affected_json)
   SELECT json_extract(value,'$.id'),json_extract(value,'$.key'),json_extract(value,'$.applicability'),json_extract(value,'$.rows') FROM json_each(?)
   WHERE EXISTS(SELECT 1 FROM cvie_disclosure_queue j WHERE j.cve_id=json_extract(value,'$.id') AND j.lease_until=?)
   AND EXISTS(SELECT 1 FROM cvie_disclosures d WHERE d.cve_id=json_extract(value,'$.id') AND d.updated_at=json_extract(value,'$.updated') AND d.checked_at=?)`,chunk,lease,now));
 statements.push(q(env.DB,`DELETE FROM cvie_disclosure_queue WHERE cve_id IN(SELECT value FROM json_each(?)) AND lease_until=?
   AND revision<=(SELECT updated_at FROM cvie_disclosures d WHERE d.cve_id=cvie_disclosure_queue.cve_id)`,successIds,lease),
  q(env.DB,`UPDATE cvie_disclosure_queue SET lease_until=0,next_attempt_at=?+COALESCE((SELECT json_extract(value,'$.delay') FROM json_each(?) WHERE json_extract(value,'$.id')=cvie_disclosure_queue.cve_id),60000),attempts=attempts+1,
   error=COALESCE((SELECT json_extract(value,'$.error') FROM json_each(?) WHERE json_extract(value,'$.id')=cvie_disclosure_queue.cve_id),'A newer revision is queued')
   WHERE cve_id IN(SELECT value FROM json_each(?)) AND lease_until=?`,now,JSON.stringify(failures),JSON.stringify(failures),ids,lease));
 if(throttledUntil)statements.push(q(env.DB,"UPDATE cvie_sources SET record_retry_at=MAX(record_retry_at,?) WHERE id='cve_program'",throttledUntil));
 await env.DB.batch(statements);return {processed:successes.length,failed:failures.length};
}
export async function dispatchEvidence(env){
 // Separate minute tick keeps this source-ingestion budget independent of NVD backfills.
 await refreshEvidence(env);await refreshEvidence(env);
 return ingestDisclosures(env,fetch,Date.now(),5);
}
