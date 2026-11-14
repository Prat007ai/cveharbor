// Capability restricted to SELECTs for the two explicitly read-only inventory
// endpoints. No writes, arbitrary batches, exec, exposed sessions or background work.
import {cachedRead,rememberRead} from './versioned-read-cache.js';
export function inventoryReadDatabase(db,{sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms)),random=Math.random,cacheIdentity=db}={}){
 const native=new WeakMap();let bookmark=null;
 const pageQuery=sql=>sql.startsWith('SELECT EXISTS(SELECT 1 FROM inventory_capacity_schema WHERE version=1) AS schema_ready,')&&sql.endsWith(' AS packed');
 const transient=error=>/overload|queued for too long|transient issue|object.*reset|7500/.test([error?.message,error?.cause?.message].join(' ').toLowerCase());
 async function read(fn){
  for(let attempt=0;;attempt++){
   try{return await fn();}catch(error){
    if(attempt===3||!transient(error))throw error;
    await sleep(50*3**attempt+Math.floor(random()*50));
   }
  }
 }
 function wrap(statement,session,primary,sql,bindings=[]){
  const result={bind:(...args)=>wrap(statement.bind(...args),session,primary,sql,args)};
  for(const method of ['first','all','raw'])result[method]=(...args)=>read(async()=>{
   const query=!primary?JSON.stringify([sql,bindings,method,args]):null;
   const hit=!primary&&cachedRead(cacheIdentity,bookmark,query);
   if(hit)return hit.value;
   const value=await statement[method](...args);
   // Bookmarks never leave this request. Each authority check starts a fresh
   // primary session, even if an earlier primary check has already completed.
   if(session!==db){const seen=session.getBookmark();if(primary)bookmark=seen;else if(seen){bookmark=bookmark>seen?bookmark:seen;rememberRead(cacheIdentity,seen,query,value);}}
   return value;
  });
  native.set(result,statement);return Object.freeze(result);
 }
 return Object.freeze({
  prepare(sql){
   if(typeof sql!=='string'||!/^SELECT\b/i.test(sql.trim())||sql.includes(';'))throw Error('Inventory read capability accepts one SELECT only');
   // Only the bounded page query may use a replica, anchored to the latest
   // primary authorization read. Holds, sessions/MFA and all other reads use
   // first-primary, never an unconstrained or client-supplied bookmark.
   const primary=!pageQuery(sql)||!bookmark;
   const session=typeof db.withSession==='function'?db.withSession(primary?'first-primary':bookmark):db;
   return wrap(session.prepare(sql),session,primary,sql);
  },
  batch(statements){if(!Array.isArray(statements)||!statements.length||statements.some(s=>!native.has(s)))throw Error('Inventory read batch requires SELECT capabilities');return read(()=>db.batch(statements.map(s=>native.get(s))));}
 });
}
