import test from 'node:test';
import assert from 'node:assert/strict';
import {customerRemediationFixture,customerA,customerB,customerOther,assetTwo} from '../../scripts/customer_remediation_fixture.mjs';
import {fixtureCve} from './helpers/assignment-db.mjs';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import worker from '../src/index.js';
const data=customer_id=>({customer_id,cve_id:fixtureCve,status:'Open',owner:'Fictional review engineer',due:'2026-12-15',notes:'Fictional test only'});
async function create(f,customer,patch={}){const r=await f.call('/customer-remediations','POST',{...data(customer),...patch});const result=await r.json();assert.equal(r.status,200,JSON.stringify(result));return result.id;}
const list=async(f,customer='all')=>(await(await f.call('/remediations?customer_id='+encodeURIComponent(customer))).json()).remediations;
test('same CVE has independent customer records, persistent filters, history and tickets',async()=>{
 const f=await customerRemediationFixture();try{
  const a=await create(f,customerA),b=await create(f,customerB);assert.notEqual(a,b);
  let records=await list(f);assert.equal(records.length,3);assert.equal((await list(f,'unassigned'))[0].id,fixtureCve);
  assert.equal((await list(f,customerA))[0].id,a);assert.equal((await list(f,customerB))[0].id,b);
  const row=records.find(r=>r.id===a);
  assert.equal((await f.call('/remediations/'+a,'PUT',{...row,status:'Remediated',owner:'North engineer',notes:'North verified patch',expected_updated:row.updated,status_change_reason:'Fictional patch verified'})).status,200);
  assert.equal((await list(f,customerA))[0].status,'Remediated');assert.equal((await list(f,customerB))[0].status,'Open');
  assert.equal((await(await f.call('/remediations/'+a+'/status-history')).json()).changes.length,1);
  assert.equal((await(await f.call('/remediations/'+b+'/status-history')).json()).changes.length,0);
  assert.equal((await f.call('/remediation-records/'+a+'/tickets','POST',{ticket_number:'NORTH-101'})).status,200);
  assert.equal((await(await f.call('/remediation-records/'+a)).json()).tickets[0].ticket_number,'NORTH-101');
  assert.equal((await(await f.call('/remediation-records/'+b)).json()).tickets.length,0);
  assert.equal((await f.call('/customer-remediations','POST',data(customerA))).status,409);
  assert.equal((await list(f,customerA)).length,1);
 }finally{f.DB.sql.close();}
});
test('explicit association keeps the original ID, notes, assignment IDs and all history',async()=>{
 const f=await customerRemediationFixture(),native=globalThis.fetch;globalThis.fetch=f.fetcher;try{
  const sent=await f.call('/remediations/'+fixtureCve+'/assign','POST',{email:'fictional-reviewer@example.test',confirmed:true,expected_updated:'2026-11-01'});assert.equal(sent.status,200);
  const before=f.DB.sql.prepare('SELECT id,token_hash FROM remediation_assignment_requests WHERE cve_id=?').get(fixtureCve);
  const row=(await list(f,'unassigned'))[0];
  assert.equal((await f.call('/customer-remediations','POST',{...data(customerA),existing_id:fixtureCve,expected_updated:row.updated})).status,400);
  const saved=await create(f,customerA,{...row,cve_id:fixtureCve,existing_id:fixtureCve,expected_updated:row.updated,confirm_association:true});assert.equal(saved,fixtureCve);
  assert.deepEqual(f.DB.sql.prepare('SELECT id,token_hash FROM remediation_assignment_requests WHERE cve_id=?').get(fixtureCve),before);
  assert.equal((await list(f,'unassigned')).length,0);assert.equal((await list(f,customerA))[0].notes,row.notes);
  assert.equal((await f.call('/customer-remediations','POST',{...data(customerB),existing_id:fixtureCve,expected_updated:(await list(f,customerA))[0].updated,confirm_association:true})).status,409);
 }finally{globalThis.fetch=native;f.DB.sql.close();}
});
test('foreign customer/environment/asset IDs never allow another tenant record access',async()=>{
 const f=await customerRemediationFixture();try{
  const a=await create(f,customerA);
  for(const patch of [{customer_id:customerOther},{customer_id:customerA,environment_id:'e-'+assetTwo},{customer_id:customerA,environment_id:'e-'+assetTwo,asset_id:assetTwo}])assert.equal((await f.call('/customer-remediations','POST',{...data(customerA),...patch})).status,404);
  assert.equal((await f.call('/remediations?customer_id='+customerOther)).status,404);
  assert.equal((await f.call('/remediation-records/'+a,'GET',null,'b')).status,404);
  assert.ok((await f.call('/remediations/'+a,'PUT',{status:'Open',owner:'Attacker'},'b')).status>=400);
  assert.equal((await f.call('/remediation-records/'+a+'/tickets','POST',{ticket_number:'BAD'},'b')).status,404);
  assert.equal((await list(f,customerA)).length,1);
 }finally{f.DB.sql.close();}
});
test('proposed migration is additive and capabilities fail closed without it',async()=>{
 const f=await customerRemediationFixture({migration:false});try{
  const before=await list(f);assert.equal((await(await f.call('/remediations/features')).json()).customer_records_available,false);
  assert.equal((await f.call('/customer-remediations','POST',data(customerA))).status,503);assert.deepEqual(await list(f),before);
  assert.equal((await f.call('/customer-remediations','POST',{...data('unassigned'),cve_id:'CVE-2026-99999'})).status,200);
  assert.equal((await list(f,'unassigned')).length,2);
 }finally{f.DB.sql.close();}
});
test('customer assignments and acknowledgements stay separate for the same CVE',async()=>{
 const f=await customerRemediationFixture(),native=globalThis.fetch;globalThis.fetch=f.fetcher;try{
  const a=await create(f,customerA),b=await create(f,customerB);
  for(const [id,email] of [[a,'north-reviewer@example.test'],[b,'south-reviewer@example.test']])assert.equal((await f.call('/remediations/'+id+'/assign','POST',{email,reviewer_notes:'Fictional customer review'})).status,200);
  const assignments=f.DB.sql.prepare('SELECT id,cve_id,token_hash FROM remediation_assignment_requests ORDER BY seq').all();assert.equal(assignments.length,2);assert.notEqual(assignments[0].id,assignments[1].id);assert.notEqual(assignments[0].token_hash,assignments[1].token_hash);
  const url=f.emails[0].text_body.match(/https:\/\/[^\s]+\/acknowledge\/[a-f0-9]{64}/)[0],proof=createHash('sha256').update('confirm:'+url.split('/').pop()).digest('hex');
  const response=await worker.fetch(new Request(url,{method:'POST',headers:{Origin:new URL(url).origin,'Content-Type':'application/x-www-form-urlencoded'},body:'confirm=receipt&proof='+proof}),f.env,{});assert.equal(response.status,200);
  assert.equal((await list(f,customerA))[0].acknowledgements.states.Acknowledged,1);
  assert.equal((await list(f,customerB))[0].acknowledgements.states.Pending,1);
 }finally{globalThis.fetch=native;f.DB.sql.close();}
});
test('environment/asset contexts reuse owned inventory and do not overwrite an existing finding',async()=>{
 const f=await customerRemediationFixture();try{
  const assetId=await create(f,customerB,{environment_id:'e-'+assetTwo,asset_id:assetTwo,status:'Investigating',status_change_reason:'Fictional asset investigation started'});
  const record=(await list(f,customerB))[0];assert.equal(record.scope.asset_id,assetTwo);assert.equal(record.owner,'Fictional review engineer');assert.equal(record.status,'Investigating');
  assert.equal((await f.call('/customer-remediations','POST',{...data(customerB),environment_id:'e-'+assetTwo,asset_id:assetTwo,owner:'Do not overwrite'})).status,409);assert.equal((await list(f,customerB))[0].id,assetId);assert.equal((await list(f,customerB))[0].owner,record.owner);
  const environmentId=await create(f,customerB,{environment_id:'e-'+assetTwo});assert.notEqual(environmentId,assetId);assert.equal((await list(f,customerB)).length,2);
 }finally{f.DB.sql.close();}
});
test('migration preserves rows, refuses foreign ownership and retains scoped history on deletion/import',async()=>{
 const f=await customerRemediationFixture({migration:false});try{
  const before=JSON.stringify(f.DB.sql.prepare('SELECT * FROM remediations').all());
  f.DB.sql.exec(fs.readFileSync(new URL('../../deployment/proposals/customer-remediation/schema.sql',import.meta.url),'utf8'));
  assert.equal(JSON.stringify(f.DB.sql.prepare('SELECT * FROM remediations').all()),before);assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediation_customer_scopes').get().n,0);
  const row=(await list(f,'unassigned'))[0];await create(f,customerA,{...row,cve_id:fixtureCve,existing_id:fixtureCve,expected_updated:row.updated,confirm_association:true});
  assert.equal((await f.call('/remediations','PUT',{remediations:[{...data('unassigned'),id:fixtureCve,owner:'Wrong import'}]})).status,409);
  assert.throws(()=>f.DB.sql.prepare('UPDATE remediation_customer_scopes SET customer_id=?').run(customerB),/immutable/);
  assert.throws(()=>f.DB.sql.prepare('DELETE FROM remediations WHERE user_id=? AND cve_id=?').run('a',fixtureCve),/history/);
  assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM pragma_foreign_key_check').get().n,0);
 }finally{f.DB.sql.close();}
});
test('stale edits are rejected and explicit account deletion still cascades only that account',async()=>{
 const f=await customerRemediationFixture();try{
  const a=await create(f,customerA),before=(await list(f,customerA))[0];
  assert.equal((await f.call('/remediations/'+a,'PUT',{...before,owner:'New owner',expected_updated:before.updated})).status,200);
  assert.equal((await f.call('/remediations/'+a,'PUT',{...before,owner:'Stale owner',expected_updated:before.updated})).status,409);
  assert.equal((await f.call('/remediation-records/'+a+'/tickets','POST',{ticket_number:'ACCOUNT-ONLY'})).status,200);
  assert.equal((await f.call('/account','DELETE')).status,200);
  assert.equal(f.DB.sql.prepare("SELECT count(*) n FROM users WHERE id='b'").get().n,1);
  assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediation_customer_scopes').get().n,0);
 }finally{f.DB.sql.close();}
});
