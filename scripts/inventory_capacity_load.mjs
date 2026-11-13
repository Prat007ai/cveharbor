// Local loopback rehearsal of the real inventory route/SQL, not a Cloudflare
// capacity certificate. No production URLs, credentials, emails or AI calls.
import http from 'node:http';
import {performance} from 'node:perf_hooks';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import worker from '../account-backend/src/index.js';
import {capacityFixture,capacitySessions,fixtureId} from '../account-backend/tests/helpers/capacity-db.mjs';
const duration=Number(process.env.CAPACITY_SECONDS||30);
assert.ok(duration>=5&&duration<=300);
const env=capacityFixture({owners:50,customers:50,environments:100,assets:50000});
const sessions=capacitySessions(env.sql);
let active=0,maxActive=0,serverErrors=0;
const server=http.createServer(async(req,res)=>{
 active++;maxActive=Math.max(maxActive,active);
 try{
  const response=await worker.fetch(new Request('https://api.cveharbor.com'+req.url,{headers:{Cookie:req.headers.cookie||'',Origin:'https://cveharbor.com'}}),{DB:env.DB,RECOVERY_CONTROL_REQUIRED:'true'});
  if(response.status>=500)serverErrors++;res.writeHead(response.status,{'Content-Type':'application/json'});res.end(await response.text());
 }catch(error){if(error.status!==409)serverErrors++;res.writeHead(error.status||500);res.end(JSON.stringify({error:error.message}));}
 finally{active--;}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const base='http://127.0.0.1:'+server.address().port+'/v1/inventory/page?';
const samples=[],journeys=[],errors=[];let completed=0,totalRows=0;
const began=performance.now(),until=began+duration*1000;
try{
 await Promise.all(Array.from({length:50},(_,i)=>(async()=>{
  while(performance.now()<until){
   const start=performance.now();let cursor=null,ids=new Set();
   try{
    do{
     const params=new URLSearchParams({resource:'assets',customer_id:fixtureId(i+1)});if(cursor)params.set('cursor',cursor);
     const at=performance.now(),r=await fetch(base+params,{headers:{Cookie:'cvh_session='+sessions[i]}}),data=await r.json();samples.push(performance.now()-at);
     assert.equal(r.status,200,JSON.stringify(data));
     assert.ok(data.items.length<=250);
     for(const row of data.items){assert.ok(!ids.has(row.id));ids.add(row.id);assert.equal((parseInt(row.environment_id.slice(0,8),16)-1000)%50,i);}
     cursor=data.next_cursor;
    }while(cursor);
    assert.equal(ids.size,1000);totalRows+=ids.size;completed++;journeys.push(performance.now()-start);
   }catch(error){errors.push({session:i,error:error.message});break;}
  }
 })()));
 const stats=values=>{const rows=[...values].sort((a,b)=>a-b),q=p=>Math.round(rows[Math.min(rows.length-1,Math.floor(rows.length*p))]||0);return {count:rows.length,p50_ms:q(.5),p95_ms:q(.95),p99_ms:q(.99),max_ms:q(1)};};
 const result={environment:'local Node HTTP and SQLite, full Worker with session/MFA and recovery checks; Cloudflare not measured',concurrent_sessions:50,max_active_requests:maxActive,customers:50,environments:100,software_entries:50000,host_names:10000,duration_seconds:Math.round((performance.now()-began)/1000),request_latency:stats(samples),complete_customer_load:stats(journeys),completed_journeys:completed,rows_verified:totalRows,server_errors:serverErrors,errors};
 console.log(JSON.stringify(result,null,2));
 if(process.env.CAPACITY_OUTPUT)fs.writeFileSync(process.env.CAPACITY_OUTPUT,JSON.stringify(result,null,2)+'\n');
 assert.equal(errors.length,0);assert.equal(serverErrors,0);assert.equal(journeys.length>=50,true);
}finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));env.close();}
