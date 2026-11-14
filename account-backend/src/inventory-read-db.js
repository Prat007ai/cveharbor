// Capability restricted to SELECTs for the two explicitly read-only inventory
// endpoints. No writes, arbitrary batches, exec, exposed sessions or background work.
export function inventoryReadDatabase(db,{sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms)),random=Math.random}={}){
 const native=new WeakMap();let bookmark=null,replicaUnavailable=false;
 const pageQuery=sql=>sql.startsWith('SELECT EXISTS(SELECT 1 FROM inventory_capacity_schema WHERE version=1) AS schema_ready,')&&sql.endsWith(' AS packed');
 const transient=error=>/overload|too many resources consumed|10 second window|queued for too long|transient issue|object.*reset|7500/.test([error?.message,error?.cause?.message].join(' ').toLowerCase());
 async function read(fn){
  for(let attempt=0;;attempt++){
   try{return await fn(attempt);}catch(error){
    if(attempt===3||!transient(error))throw error;
    await sleep(50*3**attempt+Math.floor(random()*50));
   }
  }
 }
 function wrap(sql,bindings=[]){
  const result={bind:(...args)=>wrap(sql,args)};
  for(const method of ['first','all','raw'])result[method]=(...args)=>read(async attempt=>{
   const authority=!pageQuery(sql)||!bookmark,primary=authority||replicaUnavailable||attempt>0;
   const session=typeof db.withSession==='function'?db.withSession(primary?'first-primary':bookmark):db;
   const statement=session.prepare(sql),bound=bindings.length?statement.bind(...bindings):statement;
   let value;
   try{value=await bound[method](...args);}catch(error){if(!primary&&transient(error))replicaUnavailable=true;throw error;}
   // Bookmarks never leave this request. Each authority check starts a fresh
   // primary session, even if an earlier primary check has already completed.
   if(session!==db){const seen=session.getBookmark();if(authority)bookmark=seen;else if(seen)bookmark=bookmark>seen?bookmark:seen;}
   return value;
  });
  native.set(result,{sql,bindings});return Object.freeze(result);
 }
 return Object.freeze({
  prepare(sql){
   if(typeof sql!=='string'||!/^SELECT\b/i.test(sql.trim())||sql.includes(';'))throw Error('Inventory read capability accepts one SELECT only');
   // Only the bounded page query may use a replica, anchored to the latest
   // primary authorization read. Holds, sessions/MFA and all other reads use
   // first-primary, never an unconstrained or client-supplied bookmark.
   return wrap(sql);
  },
  batch(statements){if(!Array.isArray(statements)||!statements.length||statements.some(s=>!native.has(s)))throw Error('Inventory read batch requires SELECT capabilities');return read(async()=>{
   const session=typeof db.withSession==='function'?db.withSession('first-primary'):db;
   const value=await session.batch(statements.map(s=>{const {sql,bindings}=native.get(s);const p=session.prepare(sql);return bindings.length?p.bind(...bindings):p;}));
   if(session!==db)bookmark=session.getBookmark();return value;
  });}
 });
}
