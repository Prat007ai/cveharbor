import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import worker from '../src/index.js';import {hashToken} from '../src/assignment-acknowledgement.js';
import {normalizeFyi,dispatchFyi,scheduleFyi,renderFyiNotice} from '../src/assignment-fyi.js';
import {assignmentFixture,fixtureCve} from './helpers/assignment-db.mjs';
async function setup(t){const f=await assignmentFixture(),original=globalThis.fetch;globalThis.fetch=f.fetcher;f.env.ASSIGNMENT_FYI_ENABLED='true';t.after(()=>{globalThis.fetch=original;f.DB.sql.close()});return f;}
const assign=(f,emails=['team@example.net'],extra={})=>worker.fetch(f.request('/remediations/'+fixtureCve+'/assign','POST',{email:'reviewer@example.net',fyi_recipients:emails,reviewer_notes:'Private reviewer notes NEVER FYI',...extra}),f.env,{});
const link=f=>f.emails.find(e=>e.to[0]==='reviewer@example.net')?.text_body.match(/https:\/\/api\.cveharbor\.com\/v1\/acknowledge\/[a-f0-9]{64}/)?.[0];
const post=async url=>new Request(url,{method:'POST',headers:{Origin:'https://api.cveharbor.com','Content-Type':'application/x-www-form-urlencoded'},body:'confirm=receipt&proof='+await hashToken('confirm:'+url.split('/').pop())});
const rows=f=>f.DB.sql.prepare('SELECT * FROM remediation_assignment_notifications ORDER BY id').all();
const id=f=>f.DB.sql.prepare('SELECT id FROM remediation_assignment_requests ORDER BY seq DESC LIMIT 1').get().id;
const history=f=>worker.fetch(f.request('/remediations/'+fixtureCve+'/assignments'),f.env,{}).then(r=>r.json());
const retry=(f,account='a')=>worker.fetch(f.request('/remediations/'+fixtureCve+'/assignments/'+id(f)+'/fyi/retry','POST',{},account),f.env,{});
test('FYI recipients are optional, bounded, normalized, deduplicated and exclude the assignee',()=>{
 assert.deepEqual(normalizeFyi(undefined,'a@b.test'),[]);assert.deepEqual(normalizeFyi([' TEAM@example.net ','team@example.net','a@b.test'],'a@b.test'),['team@example.net']);
 for(const input of [null,'team@example.net',[null],['bad'],['<a@b.test>'],['a@b.test\r\nBcc:evil@example.net'],Array.from({length:6},(_,i)=>i+'@example.net')])assert.throws(()=>normalizeFyi(input,'a@b.test'));
});
test('invalid or unsupported FYI recipients fail before primary mail, quotas and records change',async t=>{
 const f=await setup(t),before=f.DB.sql.prepare('SELECT total_changes() n').get().n;
 assert.equal((await assign(f,['bad'])).status,400);assert.equal(f.emails.length,0);assert.equal(f.DB.sql.prepare('SELECT total_changes() n').get().n,before);
 f.env.ASSIGNMENT_FYI_ENABLED='false';assert.equal((await assign(f)).status,503);assert.equal(f.emails.length,0);
 f.env.ASSIGNMENT_FYI_ENABLED='true';f.DB.sql.exec('DROP TABLE remediation_assignment_notifications');assert.equal((await assign(f)).status,503);assert.equal(f.emails.length,0);
});
test('migration is repeatable; an assignment with no FYI observers remains unchanged',async t=>{
 const f=await setup(t);f.DB.sql.exec(fs.readFileSync(new URL('../migrations/0025_assignment_fyi.sql',import.meta.url),'utf8'));
 assert.equal((await assign(f,[])).status,200);await dispatchFyi(f.env);assert.equal(f.emails.length,1);assert.equal(rows(f).length,0);
 assert.equal((await worker.fetch(await post(link(f)),f.env,{})).status,200);await dispatchFyi(f.env);assert.equal(f.emails.length,1);
});
test('two observers get independent FYI emails without tokens, notes or the other observer address; concurrent dispatch sends once',async t=>{
 const f=await setup(t);const r=await assign(f,['team@example.net','lead@example.net','TEAM@example.net','reviewer@example.net']);assert.equal((await r.json()).fyi_queued,2);assert.equal(rows(f).length,2);assert.equal(f.emails.length,1);
 await Promise.all([dispatchFyi(f.env),dispatchFyi(f.env)]);assert.equal(f.emails.length,3);assert.ok(rows(f).every(x=>x.state==='sent'));
 const rawToken=link(f).split('/').pop();
 for(const mail of f.emails.slice(1)){assert.equal(mail.to.length,1);assert.equal(mail.cc,undefined);assert.doesNotMatch(mail.html_body,/acknowledge\/|Private reviewer|Private customer|I acknowledge|Acknowledge Assignment/);assert.ok(!mail.html_body.includes(rawToken));assert.match(mail.text_body,/No acknowledgement or action is required/);assert.match(mail.text_body,/reviewer@example.net/);assert.ok(!mail.text_body.includes(mail.to[0]==='team@example.net'?'lead@example.net':'team@example.net'));}
 await dispatchFyi(f.env);assert.equal(f.emails.length,3);
});
test('GET/HEAD do not enqueue or send notifications; repeated acknowledgement queues only one update per observer',async t=>{
 const f=await setup(t);await assign(f,['team@example.net','lead@example.net']);await dispatchFyi(f.env);const url=link(f),before=f.DB.sql.prepare('SELECT total_changes() n').get().n,background=[];
 for(const method of ['GET','HEAD']){const r=await worker.fetch(new Request(url,{method}),f.env,{waitUntil:p=>background.push(p)});assert.equal(r.status,200);assert.doesNotMatch(await r.text(),/team@example.net|lead@example.net|Private/);}
 assert.equal(background.length,0);assert.equal(f.DB.sql.prepare('SELECT total_changes() n').get().n,before);
 f.DB.sql.exec("UPDATE remediations SET status='Open'");
 const results=await Promise.all([worker.fetch(await post(url),f.env,{}),worker.fetch(await post(url),f.env,{})]);assert.ok(results.every(r=>r.status===200));assert.equal(rows(f).filter(x=>x.kind==='acknowledged').length,2);
 f.DB.sql.exec("UPDATE remediations SET status='Investigating'");await dispatchFyi(f.env);assert.equal(f.emails.length,5);
 for(const mail of f.emails.slice(3)){assert.match(mail.text_body,/acknowledged receipt/);assert.match(mail.text_body,/UTC/);assert.match(mail.text_body,/at acknowledgement: Open/);assert.doesNotMatch(mail.text_body,/is working on|In Progress/);}
 await worker.fetch(await post(url),f.env,{});await dispatchFyi(f.env);assert.equal(f.emails.length,5);
});
test('history and retry enforce authenticated account scope and never return tokens',async t=>{
 const f=await setup(t);await assign(f);f.setMailFailed(true);await dispatchFyi(f.env);
 const h=await history(f);assert.equal(h.assignments[0].fyi[0].recipient_email,'team@example.net');assert.equal(h.assignments[0].fyi[0].state,'unconfirmed');assert.doesNotMatch(JSON.stringify(h),/token_hash|provider_id/);
 assert.equal((await retry(f,'b')).status,404);assert.equal((await retry(f,'')).status,401);
 const foreign=await(await worker.fetch(f.request('/remediations/'+fixtureCve+'/assignments','GET',undefined,'b'),f.env,{})).json();assert.deepEqual(foreign.assignments,[]);
});
test('FYI provider failures do not affect acknowledgement or other observers; explicit retries are bounded',async t=>{
 const f=await setup(t);await assign(f,['team@example.net','lead@example.net']);const base=f.fetcher;
 globalThis.fetch=async(url,opt)=>{if(String(url).includes('smtp2go')&&JSON.parse(opt.body).to[0]==='team@example.net')throw Error('provider timeout contains private token must never log');return base(url,opt)};
 await dispatchFyi(f.env);assert.equal(rows(f).find(x=>x.recipient_email==='team@example.net').state,'unconfirmed');assert.equal(rows(f).find(x=>x.recipient_email==='lead@example.net').state,'sent');
 const sent=f.emails.length;await dispatchFyi(f.env);assert.equal(f.emails.length,sent);
 assert.equal((await worker.fetch(await post(link(f)),f.env,{})).status,200);assert.equal(f.DB.sql.prepare('SELECT status FROM remediations').get().status,'Investigating');
 await dispatchFyi(f.env);assert.equal(rows(f).find(x=>x.kind==='acknowledged'&&x.recipient_email==='lead@example.net').state,'sent');
 for(let i=0;i<2;i++){assert.equal((await retry(f)).status,200);await dispatchFyi(f.env);await dispatchFyi(f.env);}
 assert.ok(rows(f).filter(x=>x.recipient_email==='team@example.net').every(x=>x.attempts===3));assert.equal((await(await retry(f)).json()).queued,0);
});
test('primary delivery failure never queues FYI messages',async t=>{
 const f=await setup(t);f.setMailFailed(true);assert.equal((await assign(f)).status,502);assert.equal(rows(f).length,0);await dispatchFyi(f.env);assert.equal(f.emails.length,1);
});
test('revocation/rotation cancel unsent FYIs, and record deletion cascades observers and notifications',async t=>{
 const f=await setup(t);await assign(f);const old=id(f),oldLink=link(f);await assign(f,['new-team@example.net'],{resend:true});assert.equal(rows(f).find(x=>x.assignment_id===old).state,'cancelled');
 await dispatchFyi(f.env);assert.ok(!f.emails.some(x=>x.to[0]==='team@example.net'));assert.ok(f.emails.some(x=>x.to[0]==='new-team@example.net'));assert.equal((await worker.fetch(await post(oldLink),f.env,{})).status,410);
 await worker.fetch(f.request('/remediations/'+fixtureCve,'DELETE'),f.env,{});assert.equal(rows(f).length,0);assert.equal(f.DB.sql.prepare('SELECT count(*) n FROM remediation_assignment_fyi').get().n,0);
});
test('existing recipient limits defer FYI mail; scheduled work resumes it without resending accepted mail',async t=>{
 const f=await setup(t);await assign(f);const stamp=Math.floor(Date.now()/1000);
 f.DB.sql.prepare('INSERT INTO remediation_assignment_limits(key,window_start,count) VALUES(?,?,20)').run('assignment-target:'+await hashToken('team@example.net'),stamp);
 await dispatchFyi(f.env);assert.equal(f.emails.length,1);assert.equal(rows(f)[0].state,'queued');assert.ok(rows(f)[0].not_before>stamp);
 f.DB.sql.exec('DELETE FROM remediation_assignment_limits; UPDATE remediation_assignment_notifications SET not_before=0');const tasks=[];scheduleFyi(f.env,{waitUntil:p=>tasks.push(p)});await Promise.all(tasks);assert.equal(f.emails.length,2);assert.equal(rows(f)[0].state,'sent');
});
test('interrupted provider calls become unconfirmed and require a deliberate retry',async t=>{
 const f=await setup(t);await assign(f);f.DB.sql.exec("UPDATE remediation_assignment_notifications SET state='sending',claimed_at=1,attempts=1");await dispatchFyi(f.env);assert.equal(f.emails.length,1);assert.equal(rows(f)[0].state,'unconfirmed');await retry(f);await dispatchFyi(f.env);assert.equal(f.emails.length,2);assert.equal(rows(f)[0].attempts,2);
});
test('FYI HTML escapes all dynamic values and excludes unsafe references and notes',()=>{
 const mail=renderFyiNotice({kind:'acknowledged',created_at:1,cve_id:'<script>CVE</script>',assignee_email:'<img>@example.net',requester_email:'<b>@example.net',remediation_status:'Open',notes:'SHOULD NOT APPEAR',public_advisory_json:JSON.stringify({title:'<script>bad</script>',severity:'high',references:[{label:'bad',url:'javascript:alert(1)'}]})});
 assert.doesNotMatch(mail.html,/<script|<img|javascript:|SHOULD NOT APPEAR/);assert.match(mail.html,/&lt;script&gt;/);assert.match(mail.text,/receipt only/);
});
test('production FYI schema probe is SELECT-only and exposes no customer records',async t=>{
 const f=await setup(t),{verifyFyiSchema}=await import('../../scripts/verify_assignment_fyi_d1.mjs');f.DB.queries.length=0;const result=await verifyFyiSchema(f.DB);assert.equal(result.ok,true);assert.ok(f.DB.queries.every(q=>/^SELECT\b/.test(q)));
});
test('a stale provider attempt cannot overwrite a replacement delivery lease',async t=>{
 const f=await setup(t);await assign(f);let release,entered;const ready=new Promise(r=>entered=r),hold=new Promise(r=>release=r),base=f.fetcher;
 globalThis.fetch=async(url,opt)=>{if(String(url).includes('smtp2go')){entered();await hold;}return base(url,opt)};
 const task=dispatchFyi(f.env);await ready;
 f.DB.sql.exec("UPDATE remediation_assignment_notifications SET state='unconfirmed',claim_token='replacement-lease'");release();await task;
 assert.equal(rows(f)[0].state,'unconfirmed');assert.equal(rows(f)[0].provider_id,'');
});
