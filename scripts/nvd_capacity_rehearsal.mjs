import assert from 'node:assert/strict';
import {fixtureId} from '../account-backend/tests/helpers/capacity-db.mjs';
import {outageBrowser} from './nvd_capacity_browser.mjs';
const stats=values=>{const sorted=[...values].sort((a,b)=>a-b),q=p=>Math.round(sorted[Math.min(sorted.length-1,Math.floor(sorted.length*p))]||0);return {count:sorted.length,p50_ms:q(.5),p95_ms:q(.95),p99_ms:q(.99),max_ms:q(1)};};
export async function outageRehearsal({base,tokens,controlKey,site,seconds=30,onProgress=()=>{}}){
 const result={concurrent_sessions:50,customers:50,environments:100,software_entries:50000,host_names:10000,phases:[],browser:[],errors:[]};
 const get=async(i,suffix)=>{const start=performance.now(),r=await fetch(base+suffix,{headers:{Cookie:'cvh_session='+tokens[i],Origin:'https://cveharbor.com'},signal:AbortSignal.timeout(15000)});assert.equal(r.status,200,suffix+' HTTP '+r.status);return {body:await r.json(),ms:performance.now()-start};};
 for(const mode of ['timeout','503']){
  const samples={},journeys=[],start=performance.now();let active=0,maxActive=0,completed=0,stop=false;
  const step=()=>fetch(base+'/__outage/step?mode='+mode,{method:'POST',headers:{'X-Outage-Control':controlKey},signal:AbortSignal.timeout(45000)}).then(async r=>{assert.equal(r.status,200);return r.json();});
  // Fifty concurrent schedulers must share the durable provider budget.
  const source=Promise.all(Array.from({length:50},step));
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
   }catch(error){result.errors.push({mode,session:i,error:error.message});break;}}
  })()));
  let sourceResults;
  try{
   const browser=outageBrowser(base,tokens[0],site,mode);
   [sourceResults]=await Promise.all([source,browser.then(rows=>{result.browser.push(...rows);onProgress(result);}),new Promise(resolve=>setTimeout(resolve,seconds*1000))]);
  }catch(error){result.errors.push({mode,error:error.message});onProgress(result);throw error;}finally{stop=true;await clients;}
  const attempts=sourceResults.reduce((n,r)=>n+r.calls,0);assert.equal(attempts,1,'Shared budget must admit exactly one NVD request');
  const blocked=await Promise.all(Array.from({length:50},step));assert.equal(blocked.reduce((n,r)=>n+r.calls,0),0,'Outage cooldown must prevent repeat requests');
  const phase={mode,duration_seconds:Math.round((performance.now()-start)/1000),max_active_read_requests:maxActive,completed_journeys:completed,nvd_attempts:attempts,cooldown_attempts:0,source_wait_ms:Math.max(...sourceResults.map(r=>r.elapsed_ms)),latencies:Object.fromEntries(Object.entries(samples).map(([k,v])=>[k,stats(v)])),whole_journey:stats(journeys)};
  result.phases.push(phase);onProgress(result);console.log(JSON.stringify(phase));
  assert.ok(completed>=50);assert.equal(result.errors.length,0,JSON.stringify(result.errors));
  assert.ok(Object.values(phase.latencies).every(s=>s.p95_ms<1000),'Read p95 exceeds 1 second');
 }
 return result;
}
