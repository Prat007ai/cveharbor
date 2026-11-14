// Used only by the isolated fictional load-test adapter, never production.
// Emit closed categories and numeric timings, never SQL, bindings or messages.
export function classifyDatabaseError(error){
 const message=[error?.message,error?.cause?.message].filter(x=>typeof x==='string').join(' ');
 if(/too many resources consumed|10 second window/i.test(message))return 'resource_window';
 if(/too many requests queued/i.test(message))return 'queue_full';
 if(/queued for too long/i.test(message))return 'queue_wait';
 if(/overload|queued|7429/i.test(message))return 'overloaded';
 if(/quota|daily.*limit|usage.*limit/i.test(message))return 'quota';
 if(/transient|reset|restart|7500|internal error/i.test(message))return 'transient';
 if(/no such (table|column)|syntax error/i.test(message))return 'schema';
 if(/constraint/i.test(message))return 'constraint';
 if(/network|fetch failed|disconnected/i.test(message))return 'transport';
 if(/timeout|timed out/i.test(message))return 'timeout';
 return 'unknown';
}
const operation=sql=>/operations_control/.test(sql)?'recovery_state':/INSERT INTO operations_leases/.test(sql)?'lease_start':/DELETE FROM operations_leases/.test(sql)?'lease_end':/FROM sessions|JOIN users ON users.id=sessions/.test(sql)?'session_auth':/ AS packed/.test(sql)?'page_query':/inventory_capacity_schema/.test(sql)?'capacity_marker':'query';
export function observeDatabase(db){
 const native=new WeakMap(),state={calls:0,elapsed_ms:0,rows_read:0,rows_written:0,query_ms:0,primary_results:0,replica_results:0,session_constraints:{primary:0,bookmark:0,unconstrained:0},bookmark_present:0,bookmark_missing:0,errors:[]};
 async function call(kind,fn){
  const start=Date.now();state.calls++;
  try{const result=await fn();for(const row of Array.isArray(result)?result:[result])if(row?.meta){state.rows_read+=Number(row.meta.rows_read)||0;state.rows_written+=Number(row.meta.rows_written)||0;state.query_ms+=Number(row.meta.duration)||0;if(row.meta.served_by_primary===true)state.primary_results++;if(row.meta.served_by_primary===false)state.replica_results++;}return result;}
  catch(error){state.errors.push({operation:kind,category:classifyDatabaseError(error)});throw error;}
  finally{state.elapsed_ms+=Date.now()-start;}
 }
 function statement(target,kind){
  const proxy=new Proxy(target,{get(obj,key){
   if(key==='bind')return(...args)=>statement(obj.bind(...args),kind);
   if(['first','all','run','raw'].includes(key))return(...args)=>call(kind,()=>obj[key](...args));
   const value=obj[key];return typeof value==='function'?value.bind(obj):value;
  }});native.set(proxy,target);return proxy;
 }
 const observed=obj=>new Proxy(obj,{get(obj,key){
  if(key==='withSession'&&typeof obj.withSession==='function')return constraint=>{state.session_constraints[constraint==='first-primary'?'primary':!constraint||constraint==='first-unconstrained'?'unconstrained':'bookmark']++;return observed(obj.withSession(constraint));};
  if(key==='getBookmark'&&typeof obj.getBookmark==='function')return()=>{const value=obj.getBookmark();state[value?'bookmark_present':'bookmark_missing']++;return value;};
  if(key==='prepare')return sql=>statement(obj.prepare(sql),operation(sql));
  if(key==='batch')return statements=>call('page_batch',()=>obj.batch(statements.map(s=>native.get(s)||s)));
  const value=obj[key];return typeof value==='function'?value.bind(obj):value;
 }});
 return {binding:observed(db),state};
}
