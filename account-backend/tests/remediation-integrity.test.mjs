import assert from 'node:assert/strict';
import {test} from 'node:test';
import fs from 'node:fs';
import worker from '../src/index.js';
import {verifyIntegrity} from '../../scripts/verify_remediation_integrity_d1.mjs';
import {unifiedFixture,assetOne,assetTwo,assetOther} from './helpers/unified-db.mjs';
import {fixtureCve} from './helpers/assignment-db.mjs';
import {reviewHash,activeReviewSQL} from '../src/assignment-progress-common.js';
import {saveReviewerProgress} from '../src/assignment-progress.js';
const migration=name=>fs.readFileSync(new URL('../migrations/'+name,import.meta.url),'utf8');
const endpoint=asset=>'/finding-remediations/'+asset+'/'+fixtureCve;
async function fixture(t){
 const f=await unifiedFixture();for(const name of ['0029_finding_assignment_links.sql','0030_status_update_notifications.sql','0031_remediation_integrity.sql'])f.DB.sql.exec(migration(name));
 const old=globalThis.fetch;globalThis.fetch=f.fetcher;t.after(()=>{globalThis.fetch=old;f.DB.sql.close();});
 f.call=async(path,method='GET',data,account='a')=>{const pending=[];const r=await worker.fetch(f.request(path,method,data,account),f.env,{waitUntil:p=>pending.push(p)});await Promise.all(pending);return {status:r.status,body:await r.json()};};
 f.ok=async(...args)=>{const r=await f.call(...args);assert.equal(r.status,200,JSON.stringify(r.body));return r.body;};
 f.create=async(asset=assetOne)=>{const p=await f.ok(endpoint(asset));return f.ok(endpoint(asset),'POST',{keep_separate:true,expected_manual:p.manual?.updated});};
 f.linkData=p=>({confirm:true,status:p.record?.status||p.manual.status,status_change_reason:'Retain the reviewed asset decision while connecting this assignment.',expected_source:p.manual.updated,expected_target:p.record?.updated||'',expected_finding:JSON.stringify(p.finding),expected_asset:JSON.stringify(p.asset)});
 f.link=async(asset=assetOne)=>{const p=await f.ok(endpoint(asset));return f.ok(endpoint(asset)+'/link-existing','POST',f.linkData(p));};
 return f;
}
test('migration is additive and repeatable with existing assignments, receipts, access, notifications, and history',async t=>{
 const f=await fixture(t);await f.create();await f.ok('/remediations/'+fixtureCve+'/assign','POST',{email:'alex@example.net',assigned_severity:'critical',fyi_recipients:['manager@example.net']});
 const tables=['remediations','remediation_finding_links','customer_finding_statuses','customer_finding_ticket_history','remediation_assignment_requests','remediation_assignment_fyi','remediation_review_access','remediation_status_changes','remediation_status_notifications'];
 const snapshot=()=>tables.map(name=>f.DB.sql.prepare('SELECT * FROM '+name).all());const before=snapshot();f.DB.sql.exec(migration('0031_remediation_integrity.sql'));assert.deepEqual(snapshot(),before);assert.deepEqual(f.DB.sql.prepare('PRAGMA foreign_key_check').all(),[]);
});
test('standalone work requires an explicit keep-separate decision; repeated creation returns one stable record',async t=>{
 const f=await fixture(t);assert.equal((await f.call(endpoint(assetOne),'POST',{})).status,409);
 const key=(await f.create()).id;assert.equal((await f.ok(endpoint(assetOne),'POST',{})).id,key);assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediation_finding_links WHERE asset_id=?').get(assetOne).n,1);
 f.DB.sql.prepare("UPDATE inventory_assets SET version='2.0',name='Renamed server' WHERE id=?").run(assetOne);assert.equal((await f.ok(endpoint(assetOne),'POST',{})).id,key);
 assert.notEqual((await f.create(assetTwo)).id,key);assert.equal((await f.call(endpoint(assetOther),'POST',{})).status,404);
});
test('competing create/link returns the canonical winner without leaving a duplicate row',async t=>{
 const f=await fixture(t),p=await f.ok(endpoint(assetOne)),batch=f.DB.batch.bind(f.DB);
 f.DB.batch=async ops=>{f.DB.batch=batch;await f.ok(endpoint(assetOne)+'/link-existing','POST',f.linkData(p));return batch(ops);};
 const r=await f.ok(endpoint(assetOne),'POST',{keep_separate:true,expected_manual:p.manual.updated});assert.equal(r.id,fixtureCve);
 assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediations').get().n,1);assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediation_finding_write_context').get().n,0);
});
test('competing create/create is idempotent and an unscoped investigation appearing mid-flight blocks creation',async t=>{
 const f=await fixture(t);f.DB.sql.prepare('DELETE FROM remediations').run();const batch=f.DB.batch.bind(f.DB);
 f.DB.batch=async ops=>{f.DB.batch=batch;await f.ok(endpoint(assetOne),'POST',{});return batch(ops);};
 const one=await f.ok(endpoint(assetOne),'POST',{});assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediations').get().n,1);assert.equal((await f.ok(endpoint(assetOne),'POST',{})).id,one.id);
 f.DB.batch=async ops=>{f.DB.batch=batch;f.DB.sql.prepare("INSERT INTO remediations VALUES('a',?,'Open','Alex','','','new')").run(fixtureCve);return batch(ops);};
 assert.equal((await f.call(endpoint(assetTwo),'POST',{})).status,409);assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediation_finding_links WHERE asset_id=?').get(assetTwo).n,0);
});
test('first finding status update uses a shared record, reason, and atomic history; no fabricated recipients',async t=>{
 const f=await fixture(t);f.DB.sql.prepare('DELETE FROM remediations').run();let p=await f.ok(endpoint(assetOne));const input={status:'Not Applicable',expected_finding:JSON.stringify(p.finding)};
 assert.equal((await f.call('/finding-statuses/'+assetOne+'/'+fixtureCve,'PUT',input)).status,400);assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediations').get().n,0);
 await f.ok('/finding-statuses/'+assetOne+'/'+fixtureCve,'PUT',{...input,status_change_reason:'Installed version is excluded after review.'});p=await f.ok(endpoint(assetOne));assert.equal(p.record.fix_status,'Not Applicable');
 const changes=f.DB.sql.prepare('SELECT * FROM remediation_status_changes').all();assert.equal(changes.length,1);assert.equal(changes[0].previous_status,'Investigating');assert.equal(changes[0].new_status,'Not Applicable');assert.equal(changes[0].changed_by,'sender@example.test');
 assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediation_status_notifications').get().n,0);assert.equal(p.record.notes,'Existing finding notes');
 assert.equal((await f.call('/finding-statuses/'+assetOne+'/'+fixtureCve,'PUT',{...input,status_change_reason:'Stale concurrent update.'})).status,409);
});
test('a failed first status transaction leaves no record, link, history, or notification behind',async t=>{
 const f=await fixture(t);f.DB.sql.prepare('DELETE FROM remediations').run();const p=await f.ok(endpoint(assetOne)),batch=f.DB.batch.bind(f.DB);
 f.DB.batch=async ops=>{f.DB.batch=batch;f.DB.sql.prepare("UPDATE customer_finding_statuses SET status='Accepted Risk' WHERE asset_id=?").run(assetOne);return batch(ops);};
 assert.equal((await f.call('/finding-statuses/'+assetOne+'/'+fixtureCve,'PUT',{status:'Not Applicable',expected_finding:JSON.stringify(p.finding),status_change_reason:'Outdated review.'})).status,409);
 for(const name of ['remediations','remediation_finding_links','remediation_status_changes','remediation_status_notifications','remediation_finding_write_context'])assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM '+name).get().n,0,name);
 assert.equal(f.DB.sql.prepare('SELECT status FROM customer_finding_statuses WHERE asset_id=?').get(assetOne).status,'Accepted Risk');
});
test('linking retains original rows, history IDs, acknowledgement tokens, reviewer access, tickets, and email records',async t=>{
 const f=await fixture(t),key=(await f.create()).id;await f.ok('/remediations/'+fixtureCve+'/assign','POST',{email:'alex@example.net',assigned_severity:'critical',fyi_recipients:['manager@example.net']});
 const assignment=f.DB.sql.prepare('SELECT * FROM remediation_assignment_requests').get(),time=Math.floor(Date.now()/1000),hash=await reviewHash('c'.repeat(64));f.DB.sql.prepare('UPDATE remediation_assignment_requests SET acknowledged_at=? WHERE id=?').run(time,assignment.id);f.DB.sql.prepare('INSERT INTO remediation_review_sessions VALUES(?,?,?,?)').run(hash,assignment.id,time,time+1000);
 let row=await f.ok('/remediation-records/'+key);await f.ok('/finding-statuses/'+assetOne+'/'+fixtureCve,'PUT',{status:'Not Applicable',status_change_reason:'Original asset decision.',expected_updated:row.updated});row=await f.ok('/remediation-records/'+key);await f.ok('/remediation-records/'+key+'/comments','POST',{comment:'Original supporting evidence is retained.',expected_updated:row.updated});
 const retired=f.DB.sql.prepare('SELECT * FROM remediations WHERE cve_id=?').get(key),history=f.DB.sql.prepare('SELECT * FROM remediation_status_changes WHERE cve_id=?').all(key),comments=f.DB.sql.prepare('SELECT * FROM remediation_owner_comments WHERE record_id=?').all(key);
 const preserve=['remediation_assignment_requests','remediation_assignment_fyi','remediation_review_access','remediation_review_sessions','remediation_assignment_metadata','remediation_record_metadata','customer_finding_ticket_history'];
 const before=preserve.map(n=>f.DB.sql.prepare('SELECT * FROM '+n).all());
 const linkPreview=await f.ok(endpoint(assetOne));await f.ok(endpoint(assetOne)+'/link-existing','POST',f.linkData(linkPreview));assert.deepEqual(f.DB.sql.prepare('SELECT * FROM remediations WHERE cve_id=?').get(key),retired);
 // Only the intended status change advances reminder timing; all invitation/access identities stay intact.
 const after=preserve.map(n=>f.DB.sql.prepare('SELECT * FROM '+n).all());for(let i=0;i<preserve.length;i++)if(preserve[i]!=='remediation_review_access')assert.deepEqual(after[i],before[i],preserve[i]);
 assert.equal(after[2][0].assignment_id,before[2][0].assignment_id);assert.equal(after[2][0].expires_at,before[2][0].expires_at);
 for(const r of history)assert.deepEqual({...f.DB.sql.prepare('SELECT * FROM remediation_status_changes WHERE id=?').get(r.id),cve_id:key},{...r});
 for(const r of comments)assert.deepEqual({...f.DB.sql.prepare('SELECT * FROM remediation_owner_comments WHERE id=?').get(r.id),record_id:key},{...r});
 const queue=await f.ok('/remediations');assert.equal(queue.remediations.length,1);assert.equal(queue.remediations[0].id,fixtureCve);assert.equal((await f.ok('/workspace/summary')).remediation.rows.reduce((n,r)=>n+r.count,0),1);
 assert.equal((await f.ok('/remediation-records/'+key)).id,fixtureCve);assert.equal((await f.ok('/remediations/'+key+'/status-history')).changes.length,2);
 assert.equal((await f.call('/remediations/'+key,'PUT',{status:'Open',owner:'Wrong'})).status,409);assert.equal((await f.call('/remediations/'+key+'/assign','POST',{email:'wrong@example.net'})).status,409);assert.equal((await f.call('/remediation-records/'+key,'GET',undefined,'b')).status,404);
 const notifications=f.DB.sql.prepare('SELECT * FROM remediation_status_notifications').all();assert.equal(notifications.length,3);await f.ok(endpoint(assetOne)+'/link-existing','POST',f.linkData(linkPreview));assert.deepEqual(f.DB.sql.prepare('SELECT * FROM remediation_status_notifications').all(),notifications);
 const active=await f.DB.prepare(activeReviewSQL).bind(assignment.id,time).first();await saveReviewerProgress(f.env,active,{tokenHash:hash},{status:'Investigating',reason:'Continue the explicitly scoped investigation.',expected_updated:active.updated_at});assert.equal((await f.ok(endpoint(assetOne))).record.fix_status,'Fix in Progress');
 assert.equal((await f.ok(endpoint(assetTwo))).record,null);assert.deepEqual(f.DB.sql.prepare('PRAGMA foreign_key_check').all(),[]);
});
test('status conflicts and stale asset context cannot silently reopen Not Applicable or Accepted Risk',async t=>{
 const f=await fixture(t);const key=(await f.create()).id;let row=await f.ok('/remediation-records/'+key);await f.ok('/remediations/'+key,'PUT',{...row,status:'Accepted Risk',status_change_reason:'Existing approved treatment.',expected_updated:row.updated});
 let p=await f.ok(endpoint(assetOne));assert.equal((await f.call(endpoint(assetOne)+'/link-existing','POST',{...f.linkData(p),status:'Open',status_change_reason:''})).status,400);assert.equal((await f.ok(endpoint(assetOne))).record.status,'Accepted Risk');
 f.DB.sql.prepare("UPDATE inventory_assets SET version='changed-after-preview' WHERE id=?").run(assetOne);assert.equal((await f.call(endpoint(assetOne)+'/link-existing','POST',f.linkData(p))).status,409);
 p=await f.ok(endpoint(assetOne));const batch=f.DB.batch.bind(f.DB);f.DB.batch=async ops=>{f.DB.batch=batch;f.DB.sql.prepare("UPDATE inventory_assets SET name='Concurrent rename' WHERE id=?").run(assetOne);return batch(ops);};assert.equal((await f.call(endpoint(assetOne)+'/link-existing','POST',f.linkData(p))).status,409);
 assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediation_link_audit').get().n,0);assert.equal((await f.ok(endpoint(assetOne))).record.status,'Accepted Risk');
});
test('database rejects mismatched identity, reassignment, drift, and destructive cascades',async t=>{
 const f=await fixture(t);const key=(await f.create()).id;
 assert.throws(()=>f.DB.sql.prepare('INSERT INTO remediation_finding_links VALUES(?,?,?,?,CURRENT_TIMESTAMP)').run('a',fixtureCve,assetTwo,'CVE-2026-99999'),/invalid finding identity/);
 assert.throws(()=>f.DB.sql.prepare('UPDATE remediation_finding_links SET asset_id=? WHERE record_id=?').run(assetTwo,key),/cannot be reassigned/);
 assert.throws(()=>f.DB.sql.prepare("UPDATE customer_finding_statuses SET status='Fixed/Patched' WHERE asset_id=?").run(assetOne),/shared remediation/);
 for(const [table,id] of [['inventory_assets',assetOne],['inventory_environments','e-'+assetOne],['inventory_customers','c-'+assetOne]])assert.throws(()=>f.DB.sql.prepare('DELETE FROM '+table+' WHERE id=?').run(id),/retained history/);
 assert.ok(f.DB.sql.prepare('SELECT * FROM remediations WHERE cve_id=?').get(key));
 // Deleting a genuinely empty asset remains supported.
 f.DB.sql.prepare('DELETE FROM inventory_assets WHERE id=?').run(assetTwo);
 await f.ok('/remediations/'+fixtureCve+'/assign','POST',{email:'alex@example.net'});assert.equal((await f.call('/remediations/'+fixtureCve,'DELETE')).status,409);
});

test('unchanged linking preserves reminder timing and every prior notification state; audit stays read-only',async t=>{
 const f=await fixture(t);await f.create();await f.ok('/remediations/'+fixtureCve+'/assign','POST',{email:'alex@example.net',assigned_severity:'high',fyi_recipients:['manager@example.net']});
 const tables=['remediation_assignment_requests','remediation_assignment_fyi','remediation_review_access','remediation_status_notifications','remediation_review_notifications'];const snapshot=()=>tables.map(n=>f.DB.sql.prepare('SELECT * FROM '+n).all());const before=snapshot();
 await f.link();assert.deepEqual(snapshot(),before);
 const changes=f.DB.sql.prepare('SELECT total_changes() n').get().n;assert.equal((await verifyIntegrity(f.DB)).ok,true);assert.equal(f.DB.sql.prepare('SELECT total_changes() n').get().n,changes);
 // Existing corruption is reported, never repaired or guessed from matching CVE numbers.
 f.DB.sql.exec('DROP TRIGGER linked_finding_status_update');f.DB.sql.prepare("UPDATE customer_finding_statuses SET status='Accepted Risk' WHERE asset_id=?").run(assetOne);
 const audit=await verifyIntegrity(f.DB,{preflight:true});assert.equal(audit.ok,false);assert.equal(audit.counts.status_drift,1);
});
test('record retention guards do not interfere with explicit account deletion',async t=>{
 const f=await fixture(t);await f.create();await f.link();f.DB.sql.prepare('DELETE FROM users WHERE id=?').run('a');assert.equal(f.DB.sql.prepare("SELECT count(*) n FROM remediations WHERE user_id='a'").get().n,0);assert.deepEqual(f.DB.sql.prepare('PRAGMA foreign_key_check').all(),[]);
});
