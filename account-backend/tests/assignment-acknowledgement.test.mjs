import {createHash} from 'node:crypto';import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import worker from '../src/index.js';
import {assignmentFixture,fixtureCve} from './helpers/assignment-db.mjs';
import {hashToken,acknowledgementStatus} from '../src/assignment-acknowledgement.js';
import {publicSnapshot,trustedReference} from '../src/assignment-template.js';
async function setup(t){const f=await assignmentFixture(),original=globalThis.fetch;globalThis.fetch=f.fetcher;t.after(()=>{globalThis.fetch=original;f.DB.sql.close()});return f;}
const assign=(f,email='reviewer@example.net',extra={})=>worker.fetch(f.request('/remediations/'+fixtureCve+'/assign','POST',{email,reviewer_notes:'Verify official versions.\n<script>private email note</script>',...extra}),f.env,{});
const post=(url,extra={})=>new Request(url,{method:'POST',headers:{Origin:'https://api.cveharbor.com','Content-Type':'application/x-www-form-urlencoded',...extra},body:'confirm=receipt&proof='+createHash('sha256').update('confirm:'+new URL(url).pathname.split('/').pop()).digest('hex')});
const count=f=>f.DB.sql.prepare('SELECT total_changes() n').get().n;
test('migration is repeatable and preserves records; verified public data and secure email replace placeholders',async t=>{
 const f=await setup(t);f.DB.sql.exec(fs.readFileSync(new URL('../migrations/0024_assignment_acknowledgements.sql',import.meta.url),'utf8'));
 const result=await assign(f);assert.equal(result.status,200);const mail=f.emails[0];assert.equal(mail.sender,'alerts@cveharbor.com');assert.equal(mail.subject,'[CVEHarbor] Action required: Review '+fixtureCve);
 for(const text of ['Acknowledgement requested','You have been assigned to review a security vulnerability','8.8','CWE-79','2026-10-13','2026-11-20','sender@example.test','&lt;script&gt;'])assert.ok(mail.html_body.includes(text),text);
 assert.doesNotMatch(mail.html_body,/<script|<svg|display:\s*(flex|grid)|untrusted\.example|Private customer note|\{\{/i);
 assert.match(mail.html_body,/\[if mso\]/);assert.match(mail.html_body,/width="620"/);assert.match(mail.text_body,/\nWhat you need to do\n/);assert.match(mail.text_body,/does not change remediation status/);
 const token=f.link().split('/').pop(),row=f.DB.sql.prepare('SELECT * FROM remediation_assignment_requests').get();assert.equal(token.length,64);assert.equal(row.token_hash,await hashToken(token));assert.ok(!JSON.stringify(row).includes(token));assert.equal(row.expires_at-row.created_at,604800);
 assert.equal(row.delivery_status,'sent');assert.equal(row.acknowledged_at,null);assert.doesNotMatch(row.public_advisory_json,/private email note|Private customer/);
 assert.deepEqual(f.DB.sql.prepare('SELECT event FROM remediation_assignment_events ORDER BY id').all().map(x=>x.event),['created','sent']);
});
test('guest GET and HEAD never write; page has no private notes, raw tokens, full recipient or account requirements',async t=>{
 const f=await setup(t);await assign(f);const before=count(f),url=f.link();
 for(const method of ['GET','HEAD','GET']){const r=await worker.fetch(new Request(url,{method}),f.env,{});assert.equal(r.status,200);assert.match(r.headers.get('Cache-Control'),/no-store/);assert.equal(r.headers.get('Referrer-Policy'),'no-referrer');assert.match(r.headers.get('Content-Security-Policy'),/default-src 'none'.*form-action 'self'.*frame-ancestors 'none'/);const html=await r.text();assert.doesNotMatch(html,/private email note|Private customer|reviewer@example.net|sender@example.test|<script|<img|<iframe/);assert.ok(!html.includes(url.split('/').pop()));if(method==='GET'){assert.match(html,/I acknowledge receipt/);assert.match(html,/No CVEHarbor account required/);}}
 assert.equal(count(f),before,'GET and HEAD execute no D1 mutations');
});
test('explicit POST acknowledges once, records one event and never changes remediation status',async t=>{
 const f=await setup(t);await assign(f);const url=f.link();
 const results=await Promise.all(Array.from({length:8},()=>worker.fetch(post(url),f.env,{})));
 for(const response of results){assert.equal(response.status,200);assert.match(await response.text(),/Assignment acknowledged/);}
 const record=f.DB.sql.prepare('SELECT * FROM remediations').get();assert.equal(record.status,'Investigating');assert.equal(record.owner,'Review owner');assert.equal(record.notes,'Private customer note NEVER public');
 assert.equal(f.DB.sql.prepare("SELECT COUNT(*) n FROM remediation_assignment_events WHERE event='acknowledged'").get().n,1);
 const rows=await(await worker.fetch(f.request('/remediations'),f.env,{})).json();assert.deepEqual(rows.remediations[0].acknowledgements,{total:1,states:{Acknowledged:1}});
 const history=await(await worker.fetch(f.request('/remediations/'+fixtureCve+'/assignments'),f.env,{})).json();assert.equal(history.assignments[0].recipient_email,'reviewer@example.net');assert.ok(history.assignments[0].acknowledged_at);assert.equal(history.assignments[0].acknowledgement_evidence,'Acknowledged via emailed link');assert.doesNotMatch(JSON.stringify(history),/token_hash|provider_id|Private customer/);
});
test('multiple recipients are independent; resend rotates links and retains history and acknowledgements',async t=>{
 const f=await setup(t);await assign(f);const first=f.link();await worker.fetch(post(first),f.env,{});await assign(f,'second@example.net');const second=f.link();
 let summary=await(await worker.fetch(f.request('/remediations'),f.env,{})).json();assert.deepEqual(summary.remediations[0].acknowledgements,{total:2,states:{Acknowledged:1,Pending:1}});
 const duplicate=await(await assign(f)).json();assert.equal(duplicate.duplicate,true);assert.equal(f.emails.length,2);
 await assign(f,'reviewer@example.net',{resend:true});const rotated=f.link();assert.notEqual(first,rotated);assert.equal((await worker.fetch(post(first),f.env,{})).status,410);assert.equal((await worker.fetch(post(second),f.env,{})).status,200);assert.equal((await worker.fetch(post(rotated),f.env,{})).status,200);
 assert.equal(f.DB.sql.prepare('SELECT COUNT(*) n FROM remediation_assignment_requests').get().n,3);assert.equal(f.DB.sql.prepare("SELECT COUNT(*) n FROM remediation_assignment_events WHERE event='acknowledged'").get().n,3);
});
test('expired, invalid and revoked tokens are neutral, cannot acknowledge, and expose no public or private details',async t=>{
 const f=await setup(t);await assign(f);const url=f.link();f.DB.sql.exec('UPDATE remediation_assignment_requests SET expires_at=1');
 for(const method of ['GET','POST']){const r=await worker.fetch(method==='GET'?new Request(url):post(url),f.env,{});assert.equal(r.status,410);assert.match(await r.text(),/link has expired/);}
 assert.equal((await worker.fetch(new Request(url.slice(0,-1)+'z'),f.env,{})).status,404);
 assert.equal((await worker.fetch(post('https://api.cveharbor.com/v1/acknowledge/'+'c'.repeat(64)),f.env,{})).status,404);
 assert.equal(f.DB.sql.prepare('SELECT acknowledged_at FROM remediation_assignment_requests').get().acknowledged_at,null);
});
test('cross-tenant listing and revocation cannot read or alter another account; explicit revoke and deletion invalidate tokens',async t=>{
 const f=await setup(t);await assign(f);const id=f.DB.sql.prepare('SELECT id FROM remediation_assignment_requests').get().id,url=f.link();
 const response=await worker.fetch(f.request('/remediations/'+fixtureCve+'/assignments?user_id=a','GET',null,'b'),f.env,{});assert.deepEqual((await response.json()).assignments,[]);
 assert.equal((await worker.fetch(f.request('/remediations/'+fixtureCve+'/assignments/'+id+'/revoke','POST',{},'b'),f.env,{})).status,404);
 assert.equal((await worker.fetch(f.request('/remediations/'+fixtureCve+'/assignments/'+id+'/revoke','POST',{}),f.env,{})).status,200);
 assert.equal((await worker.fetch(post(url),f.env,{})).status,410);
 await assign(f,'reviewer@example.net',{resend:true});const next=f.link();await worker.fetch(f.request('/remediations/'+fixtureCve,'DELETE'),f.env,{});
 assert.equal((await worker.fetch(post(next),f.env,{})).status,404);assert.equal(f.DB.sql.prepare('SELECT COUNT(*) n FROM remediation_assignment_requests').get().n,0);assert.equal(f.DB.sql.prepare('SELECT COUNT(*) n FROM remediation_assignment_events').get().n,0);
});
test('CSRF, wrong method, insecure URL, oversized payload and public rate limits are enforced without acknowledgement',async t=>{
 const f=await setup(t);await assign(f);const url=f.link(),before=count(f);
 for(const origin of ['https://evil.example'])assert.equal((await worker.fetch(post(url,{Origin:origin}),f.env,{})).status,403);
 assert.equal((await worker.fetch(new Request(url,{method:'DELETE'}),f.env,{})).status,405);
 assert.equal((await worker.fetch(new Request(url.replace('https:','http:')),f.env,{})).status,400);
 assert.equal((await worker.fetch(post(url,{'Content-Type':'application/json'}),f.env,{})).status,403);
 assert.equal((await worker.fetch(new Request(url,{method:'POST',headers:{Origin:'https://api.cveharbor.com','Content-Type':'application/x-www-form-urlencoded'},body:'x'.repeat(500)}),f.env,{})).status,400);
 f.env.ASSIGNMENT_ACK_RATE_LIMITER.limit=async({key})=>{assert.ok(!key.includes(url.split('/').pop()));assert.match(key,/^ack:[a-f0-9]{64}$/);return {success:false}};
 const limited=await worker.fetch(post(url),f.env,{});assert.equal(limited.status,429);assert.equal(limited.headers.get('Retry-After'),'60');assert.equal(count(f),before);
});
test('delivery failure is distinct from pending; failed tokens cannot acknowledge',async t=>{
 const f=await setup(t);f.setMailFailed(true);assert.equal((await assign(f)).status,502);
 const row=f.DB.sql.prepare('SELECT * FROM remediation_assignment_requests').get();assert.equal(acknowledgementStatus(row),'Delivery failed');assert.equal(row.sent_at,null);assert.equal((await worker.fetch(post(f.link()),f.env,{})).status,410);
 assert.ok(f.DB.sql.prepare("SELECT id FROM remediation_assignment_events WHERE event='delivery_failed'").get());
});
test('missing schema fails closed before sending; TTL is configurable; owner rules remain enforced',async t=>{
 const f=await setup(t);f.env.ASSIGNMENT_ACK_TTL_SECONDS='3600';await assign(f);let row=f.DB.sql.prepare('SELECT * FROM remediation_assignment_requests').get();assert.equal(row.expires_at-row.created_at,3600);
 f.DB.sql.exec("UPDATE remediations SET owner=''");const r=await assign(f,'new@example.net');assert.equal(r.status,400);assert.match((await r.json()).error,/Please select an owner/);
 f.DB.sql.exec('DROP TABLE remediation_assignment_requests');const before=f.emails.length;assert.equal((await assign(f,'new@example.net')).status,503);assert.equal(f.emails.length,before);
});
test('trusted links reject redirects and scheme/domain tricks; unavailable source fields stay neutral',()=>{
 for(const url of ['javascript:alert(1)','http://nvd.nist.gov/x','https://nvd.nist.gov.evil.test/x','https://evil.test/?next=https://nvd.nist.gov','https://user:pass@nvd.nist.gov/x','https://github.com/evil/project','https://nvd.nist.gov:444/x'])assert.equal(trustedReference(url),'');
 const data=publicSnapshot(fixtureCve,{id:'CVE-2026-99999',status:'published',severity:'critical',cvss:10,title:'Wrong CVE'});assert.equal(data.title,'Advisory details not available');assert.equal(data.cvss,null);assert.equal(data.severity,'');
});
test('history pagination remains scoped and token hashes never enter authenticated responses',async t=>{
 const f=await setup(t);await assign(f);const seed=f.DB.sql.prepare('SELECT * FROM remediation_assignment_requests').get();
 for(let i=0;i<53;i++)f.DB.sql.prepare("INSERT INTO remediation_assignment_requests(id,user_id,cve_id,recipient_email,requester_email,token_hash,delivery_status,created_at,expires_at) VALUES(?,'a',?,?,'sender@example.test',?,'failed',1,2)").run(crypto.randomUUID(),fixtureCve,'test'+i+'@example.net',String(i).padStart(64,'0'));
 const first=await(await worker.fetch(f.request('/remediations/'+fixtureCve+'/assignments'),f.env,{})).json();assert.equal(first.assignments.length,50);assert.ok(first.next);
 const second=await(await worker.fetch(f.request('/remediations/'+fixtureCve+'/assignments?before='+first.next),f.env,{})).json();assert.equal(second.assignments.length,4);assert.equal(second.next,null);assert.ok(!JSON.stringify(first).includes(seed.token_hash));
 for(const cursor of ['-1','1 OR 1=1','0','9999999999999999'])assert.equal((await worker.fetch(f.request('/remediations/'+fixtureCve+'/assignments?before='+encodeURIComponent(cursor)),f.env,{})).status,400);
});
test('public errors do not log raw tokens and private routes still require MFA sessions',async t=>{
 const f=await setup(t);await assign(f);const original=console.error,logs=[];console.error=(...args)=>logs.push(args);t.after(()=>console.error=original);
 const db=f.env.DB;f.env.DB={prepare(){throw Error('simulated database failure')}};const r=await worker.fetch(new Request(f.link()),f.env,{});assert.equal(r.status,503);assert.deepEqual(logs,[]);f.env.DB=db;
 assert.equal((await worker.fetch(f.request('/remediations/'+fixtureCve+'/assignments','GET',null,null),f.env,{})).status,401);
});

test('concurrent sends serialize and existing sender/recipient quotas still apply',async t=>{
 const f=await setup(t);const results=await Promise.all([assign(f),assign(f)]);assert.deepEqual(results.map(r=>r.status).sort(),[200,409]);assert.equal(f.emails.length,1);
 f.DB.sql.prepare("UPDATE remediation_assignment_limits SET count=10 WHERE key='assignment-sender:a'").run();assert.equal((await assign(f,'third@example.net')).status,429);assert.equal(f.emails.length,1);
 f.DB.sql.prepare("UPDATE remediation_assignment_limits SET count=0 WHERE key='assignment-sender:a'").run();f.DB.sql.prepare('UPDATE remediation_assignment_limits SET count=20 WHERE key=?').run('assignment-target:'+await hashToken('reviewer@example.net'));assert.equal((await assign(f,'reviewer@example.net',{resend:true})).status,429);assert.equal(f.emails.length,1);
});

test('expired link cannot replay, but an acknowledgement completed before expiry stays a friendly read-only success',async t=>{
 const f=await setup(t);await assign(f);await worker.fetch(post(f.link()),f.env,{});f.DB.sql.exec('UPDATE remediation_assignment_requests SET expires_at=1');const before=count(f);const response=await worker.fetch(post(f.link()),f.env,{});assert.equal(response.status,200);assert.match(await response.text(),/Assignment acknowledged/);assert.equal(count(f),before);
});

test('release schema probe executes only SELECTs with a nonexistent account',async t=>{
 const f=await setup(t),{verifyAssignmentSchema}=await import('../../scripts/verify_assignment_ack_d1.mjs');f.DB.queries=[];const before=count(f);assert.equal((await verifyAssignmentSchema(f.DB)).ok,true);assert.equal(count(f),before);assert.ok(f.DB.queries.every(sql=>sql.startsWith('SELECT')));
});

test('no-referrer forms require a separate token-bound confirmation proof and reject cross-site metadata',async t=>{
 const f=await setup(t);await assign(f);const url=f.link();
 for(const site of ['cross-site','same-site','none'])assert.equal((await worker.fetch(post(url,{Origin:'null','Sec-Fetch-Site':site}),f.env,{})).status,403);
 assert.equal((await worker.fetch(post(url,{Origin:'https://evil.example','Sec-Fetch-Site':'same-origin'}),f.env,{})).status,403);
 for(const proof of ['', '0'.repeat(64)]){
  const req=new Request(url,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Origin:'null'},body:'confirm=receipt&proof='+proof});
  assert.equal((await worker.fetch(req,f.env,{})).status,403);
 }
 assert.equal(f.DB.sql.prepare('SELECT acknowledged_at FROM remediation_assignment_requests').get().acknowledged_at,null);
 assert.equal((await worker.fetch(post(url,{Origin:'null'}),f.env,{})).status,200);
 assert.equal(f.DB.sql.prepare("SELECT count(*) n FROM remediation_assignment_events WHERE event='acknowledged'").get().n,1);
});
