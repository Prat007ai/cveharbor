import assert from 'node:assert/strict';import fs from 'node:fs';import worker from '../src/index.js';
import {unifiedFixture,assetOne,assetTwo} from './helpers/unified-db.mjs';import {fixtureCve} from './helpers/assignment-db.mjs';
const f=await unifiedFixture(),old=globalThis.fetch;globalThis.fetch=f.fetcher;
for(const x of ['0029_finding_assignment_links.sql','0030_status_update_notifications.sql'])f.DB.sql.exec(fs.readFileSync(new URL('../migrations/'+x,import.meta.url),'utf8'));
const call=async(path,method='GET',data,account='a')=>{const pending=[];const r=await worker.fetch(f.request(path,method,data,account),f.env,{waitUntil:p=>pending.push(p)});await Promise.all(pending);return {status:r.status,body:await r.json()};};
const ok=async(...a)=>{const r=await call(...a);assert.equal(r.status,200,JSON.stringify(r.body));return r.body;};const mails=()=>f.emails.filter(m=>m.subject.includes(' status changed: '));
try{
 await ok('/remediations/'+fixtureCve+'/assign','POST',{email:'reviewer@example.net',assigned_severity:'high',fyi_recipients:['manager@example.net']});
 const base='/finding-remediations/'+assetOne+'/'+fixtureCve;const key=(await ok(base,'POST',{})).id;let row=await ok('/remediation-records/'+key);
 await ok('/finding-statuses/'+assetOne+'/'+fixtureCve,'PUT',{status:'Not Applicable',status_change_reason:'Earlier asset applicability review.',expected_updated:row.updated});
 row=await ok('/remediation-records/'+key);await ok('/remediation-records/'+key+'/comments','POST',{comment:'Retain the earlier supporting evidence.',expected_updated:row.updated});
 const originalChanges=f.DB.sql.prepare('SELECT * FROM remediation_status_changes WHERE cve_id=?').all(key),originalComments=f.DB.sql.prepare('SELECT * FROM remediation_owner_comments WHERE record_id=?').all(key);
 assert.equal(mails().length,0);let p=await ok(base);assert.equal(p.can_link,true);assert.deepEqual(p.mail.recipients,[]);assert.deepEqual(p.manual_mail.recipients,['manager@example.net','reviewer@example.net','sender@example.test']);
 const data={confirm:true,status:'Not Applicable',status_change_reason:'Asset is excluded after validation.',expected_source:p.manual.updated,expected_target:p.record.updated,expected_finding:JSON.stringify(p.finding)};
 await ok(base+'/link-existing','POST',data);assert.equal(mails().length,3);assert.ok(mails().every(m=>m.text_body.includes('Asset is excluded after validation.')));
 for(const r of originalChanges){const now=f.DB.sql.prepare('SELECT * FROM remediation_status_changes WHERE id=?').get(r.id);assert.deepEqual({...now,cve_id:key},{...r});}
 for(const r of originalComments){const now=f.DB.sql.prepare('SELECT * FROM remediation_owner_comments WHERE id=?').get(r.id);assert.deepEqual({...now,record_id:key},{...r});}
 row=await ok('/remediation-records/'+fixtureCve);assert.equal(row.status_mail.notifications.length,3);assert.equal(row.status_mail.recipients.length,3);assert.equal(row.comments[0].comment,'Retain the earlier supporting evidence.');assert.match(row.link_history[0].snapshot_json,/retained_history/);
 assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediation_status_notifications WHERE change_id=?').get(originalChanges[0].id).n,0,'No historical emails replayed');
 assert.equal((await ok(base)).mail.recipients.length,3);
 assert.equal((await call(base,'GET',undefined,'b')).status,404);
 assert.deepEqual((await ok('/finding-remediations/'+assetTwo+'/'+fixtureCve)).mail.recipients,[]);
 assert.equal((await call(base+'/link-existing','POST',data)).status,200);assert.equal(mails().length,3,'Repeated confirmation is idempotent');
 console.log('PASS: reproduced zero-recipient update; linking after status/comments preserves IDs and history; previews actual participants; one current notification per person; no historical replay or cross-customer recipients.');
}finally{globalThis.fetch=old;f.DB.sql.close();}
