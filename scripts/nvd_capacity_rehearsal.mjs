import assert from 'node:assert/strict';
import {fixtureId} from '../account-backend/tests/helpers/capacity-db.mjs';
import {mergeQueryProfiles} from './capacity_db_observer.mjs';
import {outageBrowser} from './nvd_capacity_browser.mjs';
const stats=values=>{const sorted=[...values].sort((a,b)=>a-b),q=p=>Math.round(sorted[Math.min(sorted.length-1,Math.floor(sorted.length*p))]||0);return {count:sorted.length,p50_ms:q(.5),p95_ms:q(.95),p99_ms:q(.99),max_ms:q(1)};};
export async function outageRehearsal({base,tokens,controlKey,site,seconds=30,onProgress=()=>{},browserProbe=outageBrowser}){
 const result={concurrent_sessions:50,customers:50,environments:100,software_entries:50000,host_names:10000,phases:[],browser:[],errors:[]};
 let database={};
 const get=async(i,suffix)=>{const start=performance.now(),r=await fetch(base+suffix,{headers:{Cookie:'cvh_session='+tokens[i],Origin:'https://cveharbor.com'},signal:AbortSignal.timeout(15000)});
  const observed=r.headers.get('X-Capacity-Database');
  if(observed){const data=JSON.parse(observed),key=new URL(suffix,'http://localhost').pathname,totals=database[key]??={requests:0,calls:0,rows_read:0,rows_written:0,primary_results:0,replica_results:0,bookmark_present:0,bookmark_missing:0,session_constraints:{primary:0,bookmark:0,unconstrained:0},errors:{}};totals.requests++;
   if(data.queries){mergeQueryProfiles(totals.queries??={},data.queries);for(const k of ['binding_seen_before','first_bookmark_reused'])totals[k]=(totals[k]||0)+(Number(data[k])||0);totals.multi_snapshot_requests=(totals.multi_snapshot_requests||0)+Number(data.distinct_bookmarks>1);}
   for(const name of ['calls','rows_read','rows_written','primary_results','replica_results','bookmark_present','bookmark_missing'])totals[name]+=Number(data[name])||0;
   for(const name of ['primary','bookmark','unconstrained'])totals.session_constraints[name]+=Number(data.session_constraints?.[name])||0;
   for(const e of data.errors||[]){const category=e.operation+':'+e.category;totals.errors[category]=(totals.errors[category]||0)+1;}
  }
  assert.equal(r.status,200,suffix+' HTTP '+r.status);return {body:await r.json(),ms:performance.now()-start};};
 for(const mode of ['timeout','503']){
  database={};const samples={},journeys=[],start=performance.now();let active=0,maxActive=0,completed=0,stop=false,failedSessions=0;
  const step=()=>fetch(base+'/__outage/step?mode='+mode,{method:'POST',headers:{'X-Outage-Control':controlKey},signal:AbortSignal.timeout(45000)}).then(async r=>{assert.equal(r.status,200);return r.json();});
  // Fifty concurrent schedulers must share the durable provider budget.
  const source=Promise.allSettled(Array.from({length:50},step));
  const clients=Promise.all(Array.from({length:50},(_,i)=>(async()=>{
   while(!stop){const began=performance.now();try{
    for(const [label,suffix] of [['customers','/v1/inventory/page?resource=customers'],['environments','/v1/inventory/page?resource=environments'],['workspace','/v1/workspace/summary'],['cvie','/v1/cvie'],['saved_advisories','/v1/cvie/advisories']]){
     active++;maxActive=Math.max(maxActive,active);let data;try{data=await get(i,suffix);}finally{active--;}(samples[label]??=[]).push(data.ms);
     if(label==='customers'){assert.equal(data.body.items.length,1);assert.equal(data.body.items[0].id,fixtureId(i+1));}
     if(label==='environments')assert.equal(data.body.items.length,2);
     if(label==='workspace'){assert.equal(data.body.inventory.available,true);assert.equal(data.body.inventory.inventory_entries,1000);}
     if(label==='cvie'){assert.equal(data.body.ready,true);assert.equal(data.body.products.length,1);}
     if(label==='saved_advisories')assert.ok(data.body.advisories.length>0,'Saved evidence disappeared');
    }
    let cursor=null,ids=new Set();do{
     const params=new URLSearchParams({resource:'assets',customer_id:fixtureId(i+1)});if(cursor)params.set('cursor',cursor);
     const data=await get(i,'/v1/inventory/page?'+params);(samples.assets??=[]).push(data.ms);
     for(const row of data.body.items){assert.ok(!ids.has(row.id));ids.add(row.id);assert.equal((parseInt(row.environment_id.slice(0,8),16)-1000)%50,i);}cursor=data.body.next_cursor;
    }while(cursor);assert.equal(ids.size,1000);completed++;journeys.push(performance.now()-began);
   }catch(error){failedSessions++;result.errors.push({mode,session:i,error:error.message});break;}}
  })()));
  let sourceResults=[];
  try{
   const browser=browserProbe(base,tokens[0],site,mode);
   const outcomes=await Promise.allSettled([source,browser,new Promise(resolve=>setTimeout(resolve,seconds*1000))]);
   if(outcomes[0].status==='fulfilled'){
    sourceResults=outcomes[0].value.filter(r=>r.status==='fulfilled').map(r=>r.value);
    for(const r of outcomes[0].value)if(r.status==='rejected')result.errors.push({mode,component:'scheduler',error:r.reason.message});
   }
   if(outcomes[1].status==='fulfilled')result.browser.push(...outcomes[1].value);
   for(const [i,outcome] of outcomes.entries())if(outcome.status==='rejected')result.errors.push({mode,component:i===0?'scheduler':'browser',error:outcome.reason.message});
  }finally{stop=true;await clients;}
  const attempts=sourceResults.reduce((n,r)=>n+r.calls,0);
  const blocked=await Promise.allSettled(Array.from({length:50},step));
  const cooldownAttempts=blocked.reduce((n,r)=>n+(r.status==='fulfilled'?r.value.calls:0),0);
  for(const r of blocked)if(r.status==='rejected')result.errors.push({mode,component:'cooldown',error:r.reason.message});
  if(attempts!==1||cooldownAttempts!==0)result.errors.push({mode,error:'Expected one provider attempt and zero cooldown attempts',attempts,cooldownAttempts});
  const phase={mode,duration_seconds:Math.round((performance.now()-start)/1000),max_active_read_requests:maxActive,completed_journeys:completed,nvd_attempts:attempts,cooldown_attempts:cooldownAttempts,source_wait_ms:Math.max(0,...sourceResults.map(r=>r.elapsed_ms)),latencies:Object.fromEntries(Object.entries(samples).map(([k,v])=>[k,stats(v)])),whole_journey:stats(journeys)};
  phase.sessions_surviving=50-failedSessions;phase.database=database;
  result.phases.push(phase);onProgress(result);console.log(JSON.stringify(phase));
  if(completed<50)result.errors.push({mode,error:'Fewer than 50 completed journeys'});
  if(!Object.values(phase.latencies).every(s=>s.p95_ms<1000))result.errors.push({mode,error:'Read p95 exceeds 1 second'});
 }
 onProgress(result);
 assert.equal(result.errors.length,0,JSON.stringify(result.errors));
 return result;
}
