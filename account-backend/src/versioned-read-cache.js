// Bounded per-isolate data results, never authentication or maintenance state.
// Callers require either a fresh primary bookmark and identical SQL/bindings,
// or a fresh primary revision/ownership check before returning a saved page.
// No promises, database capabilities or bookmarks leave
// this module's caller. Cold isolates and missing bookmarks read D1 normally.
const databases=new WeakMap();
export const READ_CACHE_TTL=5000,READ_CACHE_BYTES=24*1024*1024,READ_CACHE_ENTRIES=1024;
function state(identity){let s=databases.get(identity);if(!s){s={rows:new Map(),bytes:0};databases.set(identity,s);}return s;}
const keyFor=(bookmark,query)=>JSON.stringify([bookmark,query]);
export function cachedRead(identity,bookmark,query,now=Date.now()){
 if(!identity||typeof bookmark!=='string'||!bookmark)return null;
 const s=state(identity),key=keyFor(bookmark,query),row=s.rows.get(key);
 if(!row)return null;
 if(now<row.started||now-row.started>=READ_CACHE_TTL){s.rows.delete(key);s.bytes-=row.bytes;return null;}
 s.rows.delete(key);s.rows.set(key,row);
 const value=JSON.parse(row.json);
 for(const r of Array.isArray(value)?value:[value])if(r?.success===true&&r.meta){
  r.meta={...r.meta,rows_read:0,rows_written:0,duration:0,cache_hit:true};delete r.meta.served_by_primary;delete r.meta.served_by_region;
 }
 return {value};
}
export function rememberRead(identity,bookmark,query,value,now=Date.now()){
 if(!identity||typeof bookmark!=='string'||!bookmark||value===undefined)return;
 // No negative/error cache and no shared in-flight I/O between requests.
 const rows=Array.isArray(value)?value:[value];
 if(rows.some(r=>r?.success===false||r?.error))return;
 const json=JSON.stringify(value),bytes=2*(json.length+query.length+bookmark.length);
 if(bytes>256*1024)return;
 const s=state(identity),key=keyFor(bookmark,query),old=s.rows.get(key);
 if(old){s.rows.delete(key);s.bytes-=old.bytes;}
 for(const [k,r] of s.rows)if(now<r.started||now-r.started>=READ_CACHE_TTL){s.rows.delete(k);s.bytes-=r.bytes;}
 while(s.rows.size>=READ_CACHE_ENTRIES||s.bytes+bytes>READ_CACHE_BYTES){const [k,r]=s.rows.entries().next().value;s.rows.delete(k);s.bytes-=r.bytes;}
 s.rows.set(key,{json,bytes,started:now});s.bytes+=bytes;
}
export const deterministicRead=sql=>! /\b(random|randomblob|unixepoch|julianday|strftime|datetime|date|time|current_timestamp|current_date|current_time)\b/i.test(sql);
// Per-request time bounds have no useful reuse. Do not let those large result
// sets evict stable inventory pages, or normalize away a query's time semantics.
export const stableReadBindings=args=>args.every(v=>v===null||typeof v==='string'&&!/^\d{4}-\d{2}-\d{2}T\d{2}:/.test(v)||typeof v==='number'&&Number.isFinite(v)&&Math.abs(v)<946684800000);
