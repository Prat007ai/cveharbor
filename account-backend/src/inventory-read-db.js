// Capability restricted to SELECTs for the two explicitly read-only inventory
// endpoints. No writes, arbitrary batches, exec, sessions or background work.
export function inventoryReadDatabase(db,{sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms)),random=Math.random}={}){
 const native=new WeakMap();
 const transient=error=>/overload|queued for too long|transient issue|object.*reset|7500/.test([error?.message,error?.cause?.message].join(' ').toLowerCase());
 async function read(fn){
  for(let attempt=0;;attempt++){
   try{return await fn();}catch(error){
    if(attempt===3||!transient(error))throw error;
    await sleep(50*3**attempt+Math.floor(random()*50));
   }
  }
 }
 function wrap(statement){
  const result={bind:(...args)=>wrap(statement.bind(...args))};
  for(const method of ['first','all','raw'])result[method]=(...args)=>read(()=>statement[method](...args));
  native.set(result,statement);return Object.freeze(result);
 }
 return Object.freeze({
  prepare(sql){if(typeof sql!=='string'||!/^SELECT\b/i.test(sql.trim())||sql.includes(';'))throw Error('Inventory read capability accepts one SELECT only');return wrap(db.prepare(sql));},
  batch(statements){if(!Array.isArray(statements)||!statements.length||statements.some(s=>!native.has(s)))throw Error('Inventory read batch requires SELECT capabilities');return read(()=>db.batch(statements.map(s=>native.get(s))));}
 });
}
