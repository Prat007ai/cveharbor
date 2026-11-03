import assert from 'node:assert/strict';import fs from 'node:fs';
import worker from '../src/index.js';import {unifiedFixture,assetOne,assetTwo,assetOther} from './helpers/unified-db.mjs';import {fixtureCve} from './helpers/assignment-db.mjs';
import {recordScope} from '../src/remediation-identity.js';import {reviewHash,activeReviewSQL} from '../src/assignment-progress-common.js';import {saveReviewerProgress} from '../src/assignment-progress.js';
import {verifyLinkSchema} from '../../scripts/verify_finding_links_d1.mjs';
const f=await unifiedFixture(),old=globalThis.fetch;globalThis.fetch=f.fetcher;
const migration=fs.readFileSync(new URL('../migrations/0029_finding_assignment_links.sql',import.meta.url),'utf8');f.DB.sql.exec(migration);
const req=async(path,method='GET',data,account='a')=>{const pending=[];const response=await worker.fetch(f.request(path,method,data,account),f.env,{waitUntil:p=>pending.push(p)});await Promise.all(pending);return response;};
const ok=async(path,method='GET',data,account='a')=>{const r=await req(path,method,data,account),b=await r.json();assert.equal(r.status,200,JSON.stringify(b));return b;};
const endpoint='/finding-remediations/'+assetOne+'/'+fixtureCve;
const data=p=>({confirm:true,status:'Investigating',expected_source:p.manual.updated,expected_target:p.record?.updated||'',expected_finding:JSON.stringify(p.finding)});
try{
 assert.equal((await verifyLinkSchema(f.DB)).ok,true);
 const key=(await ok(endpoint,'POST',{})).id;
 const other=(await ok('/finding-remediations/'+assetTwo+'/'+fixtureCve,'POST',{})).id;
 await ok('/remediations/'+fixtureCve+'/assign','POST',{email:'alex@example.net',assigned_severity:'critical',fyi_recipients:['manager@example.net']});
 const assignment=f.DB.sql.prepare('SELECT * FROM remediation_assignment_requests WHERE cve_id=?').get(fixtureCve),time=Math.floor(Date.now()/1000),hash=await reviewHash('c'.repeat(64));
 f.DB.sql.prepare('UPDATE remediation_assignment_requests SET acknowledged_at=? WHERE id=?').run(time,assignment.id);
 f.DB.sql.prepare('INSERT INTO remediation_review_sessions VALUES(?,?,?,?)').run(hash,assignment.id,time,time+1000);
 const access=f.DB.sql.prepare('SELECT * FROM remediation_review_access WHERE assignment_id=?').get(assignment.id),mailCount=f.emails.length;
 let p=await ok(endpoint);assert.equal(p.can_link,true);assert.equal(p.asset.customer_name,'Customer North');
 let summary=await ok('/finding-assignments');assert.equal(summary.standalone[0].assignments[0].status,'Acknowledged');assert.equal(summary.findings.find(x=>x.asset_id===assetOne).assignments.length,0);
 assert.equal((await req('/finding-assignments','GET',undefined,null)).status,401);
 assert.equal((await ok('/finding-assignments','GET',undefined,'b')).standalone.length,0);
 assert.equal((await req('/finding-remediations/'+assetOther+'/'+fixtureCve+'/link-existing','POST',data(p))).status,404);
 assert.equal((await req(endpoint+'/link-existing','POST',{...data(p),confirm:false})).status,400);
 assert.equal((await req(endpoint+'/link-existing','POST',{...data(p),expected_source:'stale'})).status,409);
 // A separately owned target cannot be combined. Comments are retained when an otherwise unassigned target is linked.
 f.DB.sql.prepare('INSERT INTO remediation_owner_comments(user_id,record_id,author_email,comment,created_at) VALUES(?,?,?,?,?)').run('a',key,'sender@example.test','Retain this existing work history.',time);
 f.DB.sql.prepare("UPDATE remediations SET owner='Different owner' WHERE cve_id=?").run(key);assert.equal((await ok(endpoint)).can_link,false);assert.equal((await req(endpoint+'/link-existing','POST',data(p))).status,409);
 f.DB.sql.prepare("UPDATE remediations SET owner='Unassigned' WHERE cve_id=?").run(key);
 // Check optimistic guards inside the atomic batch, after the preview was loaded.
 const originalBatch=f.DB.batch.bind(f.DB);
 for(const edit of [()=>f.DB.sql.prepare('UPDATE remediations SET updated_at=? WHERE cve_id=?').run('concurrent-source',fixtureCve),()=>f.DB.sql.prepare('UPDATE customer_finding_statuses SET updated_at=? WHERE asset_id=?').run('concurrent-finding',assetOne),()=>f.DB.sql.prepare('UPDATE remediations SET updated_at=? WHERE cve_id=?').run('concurrent-target',key)]){
  p=await ok(endpoint);f.DB.batch=async statements=>{f.DB.batch=originalBatch;edit();return originalBatch(statements)};
  assert.equal((await req(endpoint+'/link-existing','POST',data(p))).status,409);
  assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediation_link_audit').get().n,0);assert.ok(f.DB.sql.prepare('SELECT cve_id FROM remediations WHERE cve_id=?').get(key));
 }
 p=await ok(endpoint);const linked=await ok(endpoint+'/link-existing','POST',data(p));assert.equal(linked.id,fixtureCve);
 assert.equal(f.emails.length,mailCount,'Linking does not send an assignment email');
 const after=f.DB.sql.prepare('SELECT * FROM remediation_assignment_requests WHERE id=?').get(assignment.id);assert.equal(after.token_hash,assignment.token_hash);assert.equal(after.acknowledged_at,time);
 assert.deepEqual(f.DB.sql.prepare('SELECT * FROM remediation_review_access WHERE assignment_id=?').get(assignment.id),access,'Unchanged status/link does not reset inactivity');
 assert.ok(f.DB.sql.prepare('SELECT * FROM remediation_review_sessions WHERE token_hash=?').get(hash));
 assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediation_assignment_fyi WHERE assignment_id=?').get(assignment.id).n,1);
 assert.equal(f.DB.sql.prepare('SELECT assigned_severity FROM remediation_record_metadata WHERE cve_id=?').get(fixtureCve).assigned_severity,'critical');
 assert.equal(f.DB.sql.prepare('SELECT cve_id FROM remediations WHERE cve_id=?').get(key),undefined);
 assert.equal((await recordScope(f.env,'a',fixtureCve)).asset_id,assetOne);
 let row=await ok('/remediation-records/'+fixtureCve);assert.equal(row.due,'2026-11-20');assert.equal(row.link_history.length,1);assert.equal(row.comments.length,1);assert.equal(row.comments[0].comment,'Retain this existing work history.');assert.match(row.link_history[0].snapshot_json,/Existing finding notes/);assert.equal(row.tickets[0].ticket_number,'SEC-248');
 summary=await ok('/finding-assignments');assert.equal(summary.standalone.length,0);assert.equal(summary.findings.find(x=>x.asset_id===assetOne).assignments[0].email,'alex@example.net');assert.equal(summary.findings.find(x=>x.asset_id===assetOne).assignments[0].status,'Acknowledged');
 assert.equal((await ok(endpoint,'POST',{})).id,fixtureCve);assert.equal((await ok(endpoint+'/link-existing','POST',data(p))).duplicate,true);
 assert.equal((await req('/remediations/'+fixtureCve,'DELETE')).status,409);assert.equal((await req('/remediations/'+fixtureCve,'PUT',{status:'Investigating',owner:'Alex'})).status,409);
 assert.equal((await req('/remediations','PUT',{remediations:[{id:fixtureCve,status:'Investigating',owner:'Alex'}]})).status,409);
 assert.equal((await req('/finding-remediations/'+assetTwo+'/'+fixtureCve+'/link-existing','POST',data(p))).status,409);
 assert.equal((await req('/remediation-records/'+fixtureCve,'GET',undefined,'b')).status,404);
 assert.throws(()=>f.DB.sql.prepare("INSERT INTO remediations(user_id,cve_id,status,owner,due,notes,updated_at) VALUES('a',?,'Open','Unassigned','','','now')").run(key),/linked to an existing assignment/);
 // The original reviewer session continues to update the newly linked finding only.
 const active=await f.DB.prepare(activeReviewSQL).bind(assignment.id,time).first();await saveReviewerProgress(f.env,active,{tokenHash:hash},{status:'Remediated',reason:'Patch installed and verified on the linked asset.',comment:'Completed asset validation successfully.',expected_updated:active.updated_at});
 assert.equal(f.DB.sql.prepare('SELECT status FROM customer_finding_statuses WHERE asset_id=?').get(assetOne).status,'Fixed/Patched');assert.equal((await ok('/remediation-records/'+other)).status,'Open');
 f.DB.sql.exec(migration);assert.equal((await verifyLinkSchema(f.DB)).ok,true);
 console.log('PASS: explicit scoped linking; receipt, reviewer session, FYI and severity preserved; customer isolation; no resend; transaction race guards; history retained; original reviewer updates shared finding.');
}finally{globalThis.fetch=old;f.DB.sql.close();}
