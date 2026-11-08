import test from 'node:test';
import assert from 'node:assert/strict';
import {customerRemediationFixture, customerA, customerB, customerOther, assetOne} from '../../scripts/customer_remediation_fixture.mjs';
import {fixtureCve} from './helpers/assignment-db.mjs';
import {dispatchProgress} from '../src/assignment-progress-mail.js';
import {dispatchFyi} from '../src/assignment-fyi.js';
import worker from '../src/index.js';

test('selected customer and environment are tenant-bound and appear in both assignment emails', async t=>{
 const f=await customerRemediationFixture();
 const previous=globalThis.fetch;
 globalThis.fetch=f.fetcher;
 t.after(()=>{globalThis.fetch=previous;f.DB.sql.close();});
 const assignment={email:'reviewer@example.test',fyi_recipients:['observer@example.test'],
  reviewer_notes:'Private investigation note',customer_id:customerA,environment_id:'e-'+assetOne,share_customer_context:true};
 const assign=body=>worker.fetch(f.request('/remediations/'+fixtureCve+'/assign','POST',body),f.env,{});
 assert.equal((await assign({...assignment,customer_id:customerOther})).status,404);
 assert.equal((await assign({...assignment,customer_id:customerB})).status,404);
 assert.equal(f.emails.length,0);
 const response=await assign(assignment), result=await response.json();
 assert.equal(response.status,200,JSON.stringify(result));
 await dispatchFyi(f.env);
 assert.equal(f.emails.length,2);
 const reviewer=f.emails.find(m=>m.to.includes(assignment.email)),observer=f.emails.find(m=>m.to.includes(assignment.fyi_recipients[0]));
 for(const msg of [reviewer,observer]){
  assert.match(msg.text_body,/Customer: Customer North/);
  assert.match(msg.text_body,/Environment: Production/);
  assert.match(msg.html_body,/Customer North/);
  assert.match(msg.html_body,/Production/);
 }
 assert.match(reviewer.text_body,/Private investigation note/);
 assert.doesNotMatch(observer.text_body+observer.html_body,/Private investigation note|\/acknowledge\//);
 const filtered=await(await f.call('/remediations?customer_id='+customerA)).json();
 assert.equal(filtered.remediations[0].id,result.id);
 assert.equal((await(await f.call('/remediations?customer_id='+customerB)).json()).remediations.length,0);
 assert.equal((await(await assign(assignment)).json()).duplicate,true);
});

test('Medium reminders use the original shared customer and environment for both audiences', async t=>{
 const f=await customerRemediationFixture(), clock=Date.now, previous=globalThis.fetch;
 let stamp=clock();
 Date.now=()=>stamp;
 globalThis.fetch=f.fetcher;
 t.after(()=>{Date.now=clock;globalThis.fetch=previous;f.DB.sql.close();});
 const body={email:'reviewer@example.test',fyi_recipients:['observer@example.test'],assigned_severity:'medium',
  customer_id:customerA,environment_id:'e-'+assetOne,share_customer_context:true,reviewer_notes:'Private investigation note'};
 const response=await worker.fetch(f.request('/remediations/'+fixtureCve+'/assign','POST',body),f.env,{});
 assert.equal(response.status,200);
 await dispatchFyi(f.env);
 const start=f.emails.length;
 assert.equal(start,2);
 stamp+=14399000;
 await dispatchProgress(f.env);
 assert.equal(f.emails.length,start);
 stamp+=1000;
 await dispatchProgress(f.env);
 const notices=f.emails.slice(start);
 assert.equal(notices.length,2);
 for(const m of notices){
  assert.match(m.text_body,/Customer: Customer North/);
  assert.match(m.text_body,/Environment: Production/);
  assert.match(m.html_body,/Customer North/);
  assert.match(m.html_body,/Production/);
  assert.doesNotMatch(m.html_body+m.text_body,/Private investigation note/);
 }
 assert.match(notices.find(m=>m.to.includes(body.email)).subject,/Update requested/);
 assert.match(notices.find(m=>m.to.includes(body.fyi_recipients[0])).subject,/Manager Attention/);
 await dispatchProgress(f.env);
 assert.equal(f.emails.length,start+2);
});
