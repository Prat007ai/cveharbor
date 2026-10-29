import test from 'node:test';
import assert from 'node:assert/strict';
import {findingStatusRoute,FindingStatusError} from '../src/finding-status.js';

const user={id:'u1'};
const asset='11111111-1111-4111-8111-111111111111';
const cve='CVE-2026-12345';
class DB {
 constructor(ready=true,owned=true){this.ready=ready;this.owned=owned;this.items=new Map()}
 prepare(sql){
  if(/LIMIT 1$/.test(sql)&&!this.ready)return {first:async()=>{throw Error('no table')}};
  if(/LIMIT 1$/.test(sql))return {first:async()=>null};
  const db=this;
  return {bind(...args){return {
   first:async()=>sql.includes('SELECT id FROM inventory_assets')?(db.owned?{id:asset}:null):null,
   all:async()=>({results:[...db.items.values()]}),
   run:async()=>{db.items.set(args[1]+'|'+args[2],{asset_id:args[1],cve_id:args[2],status:args[3],notes:args[4]});return {meta:{changes:1}}}
  }}};
 }
}
test('status migration not applied keeps read safe and prevents writes',async()=>{
 const env={DB:new DB(false)};
 const list=await findingStatusRoute({method:'GET'},env,user,'/v1/finding-statuses');
 assert.deepEqual(await list.json(),{ready:false,statuses:[]});
 await assert.rejects(()=>findingStatusRoute({method:'PUT'},env,user,'/v1/finding-statuses/'+asset+'/'+cve,{status:'Fixed/Patched'}),e=>e instanceof FindingStatusError&&e.status===503);
});
test('saves and returns status per asset for an authenticated owner',async()=>{
 const env={DB:new DB()};
 const put=await findingStatusRoute({method:'PUT'},env,user,'/v1/finding-statuses/'+asset+'/'+cve,{status:'Fix in Progress',notes:'Being patched'});
 assert.equal((await put.json()).saved,true);
 const list=await findingStatusRoute({method:'GET'},env,user,'/v1/finding-statuses');
 assert.equal((await list.json()).statuses[0].status,'Fix in Progress');
});
test('does not allow status updates for assets outside the account',async()=>{
 const env={DB:new DB(true,false)};
 await assert.rejects(()=>findingStatusRoute({method:'PUT'},env,user,'/v1/finding-statuses/'+asset+'/'+cve,{status:'Not Applicable'}),e=>e instanceof FindingStatusError&&e.status===404);
 assert.equal(env.DB.items.size,0);
});
test('rejects unknown statuses',async()=>{
 const env={DB:new DB()};
 await assert.rejects(()=>findingStatusRoute({method:'PUT'},env,user,'/v1/finding-statuses/'+asset+'/'+cve,{status:'Ignored'}),FindingStatusError);
});
