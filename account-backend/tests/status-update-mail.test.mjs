import assert from 'node:assert/strict';import fs from 'node:fs';
import worker from '../src/index.js';import {unifiedFixture,assetOne,assetTwo,assetOther} from './helpers/unified-db.mjs';import {fixtureCve} from './helpers/assignment-db.mjs';
import {dispatchStatusMail,renderStatusUpdate,statusMailHistory} from '../src/status-update-mail.js';
import {saveReviewerProgress} from '../src/assignment-progress.js';import {activeReviewSQL,reviewHash,reviewNow} from '../src/assignment-progress-common.js';
import {verifyStatusMailSchema} from '../../scripts/verify_status_mail_d1.mjs';
const f=await unifiedFixture(),old=globalThis.fetch;globalThis.fetch=f.fetcher;
for(const name of ['0029_finding_assignment_links.sql','0030_status_update_notifications.sql'])f.DB.sql.exec(fs.readFileSync(new URL('../migrations/'+name,import.meta.url),'utf8'));
// Collect background work without running it twice; fetch promises already start immediately.
const pending=[];const ctx={waitUntil:p=>pending.push(p)};
const req=async(path,method='GET',data,account='a')=>{const r=await worker.fetch(f.request(path,method,data,account),f.env,ctx);await Promise.all(pending.splice(0));return r;};
const ok=async(path,method='GET',data,account='a')=>{const r=await req(path,method,data,account),b=await r.json();assert.equal(r.status,200,JSON.stringify(b));return b;};
const queue=()=>f.DB.sql.prepare('SELECT * FROM remediation_status_notifications ORDER BY id').all();
const statusMails=()=>f.emails.filter(x=>x.subject.includes(' status changed: '));
try{
 assert.equal((await verifyStatusMailSchema(f.DB)).ok,true);assert.equal(queue().length,0);
 const key=(await ok('/finding-remediations/'+assetOne+'/'+fixtureCve,'POST',{})).id;
 const other=(await ok('/finding-remediations/'+assetTwo+'/'+fixtureCve,'POST',{})).id;
 await ok('/remediations/'+key+'/assign','POST',{email:'alex@example.net',assigned_severity:'critical',fyi_recipients:['manager@example.net']});
 await ok('/remediations/'+key+'/assign','POST',{email:'second@example.net',assigned_severity:'high',fyi_recipients:['MANAGER@example.net','alex@example.net']});
 const expected=['alex@example.net','manager@example.net','second@example.net','sender@example.test'];
 let row=await ok('/remediation-records/'+key);const update={status:'Fixed/Patched',status_change_reason:'Patch deployed and verified on the customer server.',expected_updated:row.updated};
 await ok('/finding-statuses/'+assetOne+'/'+fixtureCve,'PUT',update);
 assert.deepEqual(statusMails().map(m=>m.to[0]).sort(),expected);assert.equal(queue().length,4);assert.ok(queue().every(n=>n.state==='sent'));
 assert.equal(f.DB.sql.prepare("SELECT count(*) n FROM remediation_review_notifications WHERE event_key LIKE 'status:%'").get().n,0,'No old progress-email duplicate');
 for(const m of statusMails()){assert.match(m.text_body,/Previous status: Fix in Progress/);assert.match(m.text_body,/New status: Fixed\/Patched/);assert.match(m.text_body,/Customer North.*Production.*Web Server 01/);assert.match(m.text_body,/Updated by: sender@example.test/);assert.match(m.text_body,/Patch deployed and verified/);assert.doesNotMatch(m.text_body,/Customer South|Private Other/);}
 assert.match(statusMails().find(x=>x.to[0]==='alex@example.net').text_body,/https:\/\/confirm.cveharbor.com\/assignment\//);
 const manager=statusMails().find(x=>x.to[0]==='manager@example.net');assert.match(manager.text_body,/remediation\/\?record=/);assert.doesNotMatch(manager.text_body,/confirm.cveharbor.com\/assignment\//);
 row=await ok('/remediation-records/'+key);await ok('/finding-statuses/'+assetOne+'/'+fixtureCve,'PUT',{...update,expected_updated:row.updated});assert.equal(statusMails().length,4,'No email for unchanged save');
 assert.equal((await req('/finding-statuses/'+assetOne+'/'+fixtureCve,'PUT',update)).status,409);assert.equal(statusMails().length,4,'Failed/stale updates send nothing');
 assert.equal((await ok('/remediation-records/'+other)).status,'Open');assert.equal((await req('/remediation-records/'+key,'GET',undefined,'b')).status,404);
 assert.equal((await ok('/remediation-records/'+key)).status_mail.notifications.length,4);
 // Reviewer status changes use the identical participant set, including the author.
 const a=f.DB.sql.prepare("SELECT id FROM remediation_assignment_requests WHERE recipient_email='alex@example.net'").get(),time=reviewNow(),hash=await reviewHash('d'.repeat(64));
 f.DB.sql.prepare('INSERT INTO remediation_review_sessions VALUES(?,?,?,?)').run(hash,a.id,time,time+1000);
 const active=await f.DB.prepare(activeReviewSQL).bind(a.id,time).first();await saveReviewerProgress(f.env,active,{tokenHash:hash},{status:'Investigating',reason:'Further validation required before closure.',comment:'Testing an additional affected component.',expected_updated:active.updated_at});
 await Promise.all([dispatchStatusMail(f.env),dispatchStatusMail(f.env)]);assert.equal(statusMails().length,8);assert.deepEqual(statusMails().slice(4).map(m=>m.to[0]).sort(),expected);
 // Expired reviewer access does not silently remove existing assignment participants.
 f.DB.sql.prepare('UPDATE remediation_review_access SET expires_at=1').run();row=await ok('/remediation-records/'+key);await ok('/remediations/'+key,'PUT',{...row,status:'Not Applicable',status_change_reason:'Asset applicability reviewed and excluded.',expected_updated:row.updated});assert.equal(statusMails().length,12);
 // Failure is isolated per recipient; uncertain sends are not automatically repeated.
 f.setMailFailed(true);row=await ok('/remediation-records/'+key);await ok('/remediations/'+key,'PUT',{...row,status:'Accepted Risk',status_change_reason:'Risk decision documented by the accountable owner.',expected_updated:row.updated});assert.ok(queue().slice(-4).every(n=>n.state==='unconfirmed'));const failedCount=statusMails().length;f.setMailFailed(false);await dispatchStatusMail(f.env);assert.equal(statusMails().length,failedCount);
 // Queued recipients are checked again after a revocation, not just when enqueued.
 row=await ok('/remediation-records/'+key);const noDispatch={...f.env,ASSIGNMENT_EMAIL_ENABLED:'false'};const response=await worker.fetch(f.request('/remediations/'+key,'PUT',{...row,status:'Open',status_change_reason:'Reopened for updated applicability review.',expected_updated:row.updated}),noDispatch,ctx);assert.equal(response.status,200);await Promise.all(pending.splice(0));
 f.DB.sql.prepare('UPDATE remediation_assignment_requests SET revoked_at=? WHERE cve_id=?').run(time,key);await dispatchStatusMail(f.env);assert.ok(queue().slice(-4).every(n=>n.state==='cancelled'));assert.equal(statusMails().length,failedCount);
 // Same CVE in a separate unassigned asset does not borrow these recipients.
 row=await ok('/remediation-records/'+other);await ok('/remediations/'+other,'PUT',{...row,status:'Investigating',status_change_reason:'Review started for a different customer asset.',expected_updated:row.updated});assert.equal(statusMails().length,failedCount);
 // Templates escape customer text and status reasons; no acknowledgement tokens are used.
 const template=renderStatusUpdate({cve_id:key,previous_status:'Open',new_status:'Investigating',changed_by:'sender@example.test',changed_at:new Date().toISOString(),recipient_email:'manager@example.net',reason:'<script>alert(1)</script>',scope:{customer_name:'<img src=x>',environment_name:'Production',asset_name:'Server'}});assert.match(template.html,/&lt;script&gt;/);assert.doesNotMatch(template.html,/<script>|<img src=x>/);
 f.DB.sql.exec(fs.readFileSync(new URL('../migrations/0030_status_update_notifications.sql',import.meta.url),'utf8'));assert.equal(queue().length,20,'Migration does not replay historical changes');
 assert.equal((await statusMailHistory(f.env,{id:'b'},key)).notifications.length,0);
 console.log('PASS: all reviewers/requester/FYI including author; deduplication; inline/shared/reviewer paths; no unchanged/stale email; scope isolation; revocation; expired access; concurrent workers; failure safety; escaped professional template.');
}finally{globalThis.fetch=old;f.DB.sql.close();}
