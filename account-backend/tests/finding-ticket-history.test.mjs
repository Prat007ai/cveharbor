import test from 'node:test';
import assert from 'node:assert/strict';
import {findingTicketRoute} from '../src/finding-status.js';
const asset='11111111-1111-4111-8111-111111111111',cve='CVE-2026-12345',user={id:'owner'};
test('append only ticket references never allow replacement even after CVE status changes',async()=>{
 const saved=new Set();
 const env={DB:{prepare(sql){
  if(sql.includes('SELECT asset_id FROM customer_finding_tickets LIMIT 1'))return {first:async()=>null};
  return {bind(...args){return {
   first:async()=>sql.includes('SELECT id FROM inventory_assets')?{id:asset}:null,
   run:async()=>{const ticket=args[3];if(saved.has(ticket))return {meta:{changes:0}};saved.add(ticket);return {meta:{changes:1}}}
  }}};
 }}};
 const path='/v1/finding-tickets/'+asset+'/'+cve;
 for(const ticket of ['1234','5678']){
  const res=await findingTicketRoute({method:'POST'},env,user,path,{ticket_number:ticket});
  assert.equal(res.status,201);
 }
 assert.deepEqual([...saved],['1234','5678']);
 const overwrite=await findingTicketRoute({method:'PUT'},env,user,path,{ticket_number:'0000'});
 assert.equal(overwrite.status,405);
 assert.equal(saved.has('0000'),false);
 await assert.rejects(()=>findingTicketRoute({method:'POST'},env,user,path,{ticket_number:'1234'}),e=>e.status===409);
});
