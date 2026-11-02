// Operation-level D1 telemetry. Never log SQL, bindings, account IDs or errors.
const operations=new Set(['status','progress','evidence','directory','onboard','catalogue','inventory','stack','nvd_dispatch','disclosure_dispatch']);
export async function observeCvie(env,operation,work){
 if(!operations.has(operation))throw Error('Unknown CVIE metric operation');
 if(env.CVIE_METRICS_ENABLED!=='true'||env.CVIE_METRIC_CONTEXT)return work(env);
 const start=performance.now(),metric={event:'cvie_operation',trace_id:crypto.randomUUID(),operation,statements:0,rows_read:0,rows_written:0,d1_duration_ms:0,metadata_complete:true};
 const capture=result=>{for(const r of Array.isArray(result)?result:[result]){
  metric.statements++;const m=r?.meta;
  if(!Number.isFinite(m?.rows_read)||!Number.isFinite(m?.rows_written))metric.metadata_complete=false;
  else{metric.rows_read+=m.rows_read;metric.rows_written+=m.rows_written;}
  if(Number.isFinite(m?.duration))metric.d1_duration_ms+=m.duration;
 }return result;};
 const wrap=statement=>({
  inner:statement,bind(...args){return wrap(statement.bind(...args));},
  async all(){return capture(await statement.all());},
  async run(){return capture(await statement.run());},
  async first(column){const row=(await this.all()).results?.[0]??null;return column&&row?row[column]:row;},
 });
 const DB={prepare(sql){return wrap(env.DB.prepare(sql));},async batch(statements){return capture(await env.DB.batch(statements.map(s=>s.inner||s)));}};
 let ok=false;
 try{const result=await work({...env,DB,CVIE_METRIC_CONTEXT:metric,CVIE_UNWRAPPED_DB:env.DB});ok=!(result instanceof Response)||result.ok;for(const key of ['processed','failed'])if(Number.isFinite(result?.[key]))metric['records_'+key]=result[key];return result;}
 finally{
  metric.ok=ok;metric.duration_ms=Math.round((performance.now()-start)*100)/100;
  if(!metric.metadata_complete){metric.rows_read=null;metric.rows_written=null;}
  // An injectable sink is useful for staging assertions without producing private logs.
  if(env.CVIE_METRIC_SINK)env.CVIE_METRIC_SINK(metric);else console.log(JSON.stringify(metric));
 }
}
