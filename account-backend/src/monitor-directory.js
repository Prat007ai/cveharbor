import {searchRegistry} from './product-registry.js';
// Bounded shared Cache API storage of public lifecycle identities. Customer names, versions,
// URLs and failed queries never enter the shared directory. No new D1 tables.
import common from '../../data/lifecycle-products.json' with {type:'json'};
import {q,sha} from './monitor-engine.js';
import {fetchVendor,lifecycleSource,normalizeVendor,DAY} from './monitor-sources.js';
export {common};
export const DIRECTORY_LIMIT=500, CYCLE_LIMIT=40;
const key=s=>String(s||'').normalize('NFKC').toLowerCase().replace(/[^a-z0-9]+/g,' ').trim();
export function directoryIdentity(name){
 const query=key(name),matches=common.filter(p=>[p.slug,p.name,...p.aliases].some(n=>key(n)===query));
 const known=matches.length===1?matches[0]:null;
 const slug=known?.slug||query.replaceAll(' ','-');
 if(!/^[a-z0-9][a-z0-9-]{0,69}$/.test(slug))throw Error('Enter the official product name (up to 70 letters, numbers or hyphens).');
 const identity=known?searchRegistry({scheme:'lifecycle',identifier:known.slug}).identity:null;
 return known?{...known,...(identity?{cvie_identity_id:identity.id}: {})}:{slug,name:slug.split('-').map(w=>w[0].toUpperCase()+w.slice(1)).join(' '),category:'Other',aliases:[]};
}
const date=value=>typeof value==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(value)&&Number.isFinite(Date.parse(value))&&new Date(value+'T00:00:00Z').toISOString().slice(0,10)===value?value:null;
export function directoryCycles(raw){
 if(!Array.isArray(raw)||!raw.length||raw.length>2000)throw Error('No published release history was found.');
 const seen=new Set(),cycles=[];
 for(const row of raw){
  if(!row||typeof row!=='object'||!['string','number'].includes(typeof row.cycle))throw Error('Invalid release history response');
  const cycle=String(row.cycle);if(!cycle||cycle.length>80||/[\u0000-\u001f]/.test(cycle)||seen.has(cycle))throw Error('Invalid or ambiguous release branch');seen.add(cycle);
  if(cycles.length<CYCLE_LIMIT)cycles.push({cycle,latest:typeof row.latest==='string'?row.latest.slice(0,80):'',eol_date:date(row.eol),support_date:date(row.support),extended_date:date(row.extendedSupport),eol:typeof row.eol==='boolean'?row.eol:null,release_date:date(row.releaseDate),latest_release_date:date(row.latestReleaseDate)});
 }
 return cycles;
}
const cacheFor=env=>env.DIRECTORY_CACHE||globalThis.caches?.default;
const cacheUrl=slot=>'https://api.cveharbor.com/_public-lifecycle-directory/v1/'+slot;
async function slotFor(slug){return Number.parseInt((await sha(slug)).slice(0,8),16)%DIRECTORY_LIMIT;}
async function readCache(env,slot){try{const response=await cacheFor(env)?.match(cacheUrl(slot));return response?await response.json():null;}catch{return null;}}
async function writeCache(env,slot,record){const cache=cacheFor(env);if(!cache)throw Error('Directory cache unavailable');await cache.put(cacheUrl(slot),Response.json(record,{headers:{'Cache-Control':'public,max-age=604800'}}));}
export async function cachedDirectory(env){
 const index=await readCache(env,'index');return Array.isArray(index)?index.slice(0,DIRECTORY_LIMIT).map(({product})=>product):[];
}
export async function directoryRecord(env,slug){
 const record=await readCache(env,await slotFor(slug));return record?.product?.slug===slug?record:null;
}
export async function lookupDirectory(env,name,now=Date.now(),fetcher=fetch){
 const product=directoryIdentity(name),slot=await slotFor(product.slug),saved=await directoryRecord(env,product.slug);
 if(saved&&now-saved.checked_at<DAY)return {...saved,cached:true,stale:false};
 // One small provider-budget row, independent of the NVD request slot.
 // Public payloads use 500 fixed expiring Cache API slots, not D1 rows.
 await q(env.DB,"INSERT OR IGNORE INTO cvie_provider_budget(provider,next_request_at) VALUES('lifecycle-directory',0)").run();
 const claimed=await q(env.DB,"UPDATE cvie_provider_budget SET next_request_at=? WHERE provider='lifecycle-directory' AND next_request_at<=?",now+3000,now).run();
 if(claimed.meta.changes!==1)return saved?{...saved,cached:true,stale:true}:{product,cycles:[],status:'retry',message:'Product lookup is busy. Retry in a few seconds.'};
 try{
  const raw=await fetchVendor({url:'https://endoflife.date/api/'+product.slug+'.json'},fetcher),cycles=directoryCycles(raw);
  const result={product,cycles,status:'found',source_url:'https://endoflife.date/'+product.slug,checked_at:now,limited:raw.length>CYCLE_LIMIT,source_label:'endoflife.date (community-maintained; verify vendor terms)'};
  if(new TextEncoder().encode(JSON.stringify(result)).length>24000)throw Error('Product release history is too large');
  await writeCache(env,slot,result);
  const index=await readCache(env,'index')||[];
  await writeCache(env,'index',[...index.filter(p=>p.slot!==slot),{slot,product}].slice(-DIRECTORY_LIMIT));
  return result;
 }catch{
  return saved?{...saved,cached:true,stale:true,message:'Live lookup unavailable; showing the last checked history.'}:{product,cycles:[],status:'unavailable',message:'No matching release history could be retrieved. Check the official name and vendor, or retry later. No results does not mean the product is supported or has no vulnerabilities.'};
 }
}
export async function directoryWatchInfo(env,watch){
 const entry=watch.slug?await directoryRecord(env,watch.slug):null,cycle=entry?.cycles.find(c=>c.cycle===watch.cycle);
 return cycle?{...cycle,source_url:entry.source_url,source_label:entry.source_label,checked_at:entry.checked_at}:null;
}
export async function directoryMonitor(env,watch){
 if(watch.edition||!watch.slug||!watch.cycle)return null;
 const entry=await directoryRecord(env,watch.slug);
 if(!entry?.cycles.some(c=>c.cycle===watch.cycle))return null;
 const source=lifecycleSource(entry.product.slug),product={id:await sha(JSON.stringify(['lifecycle',entry.product.slug,watch.cycle])),slug:entry.product.slug,name:entry.product.name,vendor:'',branch:watch.cycle,edition:'',source_id:source.id,source,official_url:entry.source_url};
 const raw=entry.cycles.map(c=>({...c,eol:c.eol_date||c.eol,support:c.support_date,extendedSupport:c.extended_date,latestReleaseDate:c.latest_release_date}));
 return {product,record:normalizeVendor('lifecycle',raw,product),checked_at:entry.checked_at};
}
export async function directoryWatchStatements(env,resolved){
 const {product:p,record,checked_at}=resolved,serialized=JSON.stringify(record);
 return [q(env.DB,'INSERT OR IGNORE INTO lifecycle_monitor_sources(id,adapter,url,last_attempt_at,last_success_at,next_due_at) VALUES(?,?,?,?,?,?)',p.source_id,p.source.adapter,p.source.url,checked_at,checked_at,checked_at+DAY),
  q(env.DB,'INSERT OR IGNORE INTO lifecycle_monitor_products(id,source_id,slug,name,vendor,branch,edition,official_url) VALUES(?,?,?,?,?,?,?,?)',p.id,p.source_id,p.slug,p.name,p.vendor,p.branch,p.edition,p.official_url),
  q(env.DB,'INSERT OR IGNORE INTO lifecycle_monitor_state(product_id,semantic_hash,record_json,verified_at) VALUES(?,?,?,?)',p.id,await sha(serialized),serialized,checked_at)];
}
