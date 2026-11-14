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
export function queryFingerprint(sql){let n=2166136261;for(const ch of sql)n=Math.imul(n^ch.charCodeAt(0),16777619);return (n>>>0).toString(16).padStart(8,'0');}
export function mergeQueryProfiles(target,source){for(const [key,value] of Object.entries(source||{})){if(!/^[a-z_]+:[a-f0-9]{8}$/.test(key))continue;const row=target[key]??={};for(const [field,n] of Object.entries(value)){if(typeof n!=='number'||!Number.isFinite(n))continue;row[field]=field.startsWith('max_')?Math.max(row[field]||0,n):(row[field]||0)+n;}}return target;}
export function observeDatabase(db,{detailed=false}={}){
 const native=new WeakMap(),state={calls:0,elapsed_ms:0,rows_read:0,rows_written:0,query_ms:0,primary_results:0,replica_results:0,session_constraints:{primary:0,bookmark:0,unconstrained:0},bookmark_present:0,bookmark_missing:0,errors:[]};
 if(detailed)state.queries={};
 async function call(kind,fn,fingerprint='00000000'){
  const start=Date.now();let finished;state.calls++;
  const detail=detailed?(state.queries[kind+':'+fingerprint]??={calls:0,errors:0,elapsed_ms:0,sql_ms:0,rows_read:0,result_bytes:0,max_sql_ms:0,max_result_bytes:0,primary:0,replica:0}):null;
  if(detail)detail.calls++;
  try{const result=await fn();finished=Date.now();for(const row of Array.isArray(result)?result:[result])if(row?.meta){
   const reads=Number(row.meta.rows_read)||0,ms=Number(row.meta.duration)||0;state.rows_read+=reads;state.rows_written+=Number(row.meta.rows_written)||0;state.query_ms+=ms;
   if(row.meta.served_by_primary===true)state.primary_results++;if(row.meta.served_by_primary===false)state.replica_results++;
   if(detail){const bytes=new TextEncoder().encode(JSON.stringify(row.results??[])).byteLength;detail.rows_read+=reads;detail.sql_ms+=ms;detail.result_bytes+=bytes;detail.max_sql_ms=Math.max(detail.max_sql_ms,ms);detail.max_result_bytes=Math.max(detail.max_result_bytes,bytes);detail.primary+=Number(row.meta.served_by_primary===true);detail.replica+=Number(row.meta.served_by_primary===false);}
  }return result;}
  catch(error){if(detail)detail.errors++;state.errors.push({operation:kind,category:classifyDatabaseError(error)});throw error;}
  finally{const elapsed=(finished??Date.now())-start;state.elapsed_ms+=elapsed;if(detail)detail.elapsed_ms+=elapsed;}
 }

 function statement(target,kind,fingerprint){
  const proxy=new Proxy(target,{get(obj,key){
   if(key==='bind')return(...args)=>statement(obj.bind(...args),kind,fingerprint);
   // Native D1 first() selects row zero from all(); retain its result shape
   // while observing the metadata normally discarded by that convenience API.
   if(detailed&&key==='first'&&typeof obj.all==='function')return async column=>{const result=await call(kind,()=>obj.all(),fingerprint),row=result.results?.[0]??null;if(column&&row){if(!Object.hasOwn(row,column))throw Error('D1_COLUMN_NOTFOUND');return row[column];}return row;};
   if(['first','all','run','raw'].includes(key))return(...args)=>call(kind,()=>obj[key](...args),fingerprint);
   const value=obj[key];return typeof value==='function'?value.bind(obj):value;
  }});native.set(proxy,target);return proxy;
 }
 const observed=obj=>new Proxy(obj,{get(obj,key){
  if(key==='withSession'&&typeof obj.withSession==='function')return constraint=>{state.session_constraints[constraint==='first-primary'?'primary':!constraint||constraint==='first-unconstrained'?'unconstrained':'bookmark']++;return observed(obj.withSession(constraint));};
  if(key==='getBookmark'&&typeof obj.getBookmark==='function')return()=>{const value=obj.getBookmark();state[value?'bookmark_present':'bookmark_missing']++;return value;};
  if(key==='prepare')return sql=>statement(obj.prepare(sql),operation(sql),queryFingerprint(sql));
  if(key==='batch')return statements=>call('page_batch',()=>obj.batch(statements.map(s=>native.get(s)||s)));
  const value=obj[key];return typeof value==='function'?value.bind(obj):value;
 }});
 return {binding:observed(db),state};
}
