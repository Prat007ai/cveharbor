import test from 'node:test';
import assert from 'node:assert/strict';
import {DB} from './helpers/d1.mjs';
import {approvedTest,TEST_EXPIRES,TEST_ID} from '../src/monitor-approved-test.js';
const NOW=Date.parse('2026-11-01T23:00:00Z');
function env(){const db=new DB();let batchQueue=Promise.resolve();const batch=db.batch.bind(db);db.batch=statements=>{const next=batchQueue.then(()=>batch(statements));batchQueue=next.catch(()=>{});return next;};db.sql.exec('CREATE TABLE auth_rate_limits(key TEXT PRIMARY KEY,window_start INTEGER,count INTEGER)');return {DB:db,SMTP2GO_API_KEY:'test-only',EMAIL_FROM:'alerts@cveharbor.com'};}
test('approved Worker test sends only two fixed recipients once across overlapping Cron and restart',async()=>{
 const e=env(),sent=[];
 const fetcher=async(url,options)=>{assert.ok(url.endsWith('/email/send'));const body=JSON.parse(options.body);sent.push(body.to[0]);assert.match(body.text_body,/does not activate customer alerts/);return Response.json({data:{succeeded:1,failed:0,email_id:'test-'+sent.length}});};
 await Promise.all([approvedTest(e,NOW,fetcher),approvedTest(e,NOW,fetcher)]);await approvedTest(e,NOW+1,fetcher);
 assert.deepEqual(sent.sort(),['PMahendran@whitecapcanada.com','prat.mahen@gmail.com'].sort());
 // Existing login cleanup must not delete the claim before the hard expiry.
 e.DB.sql.prepare('DELETE FROM auth_rate_limits WHERE window_start<?').run(NOW/1000-3600);
 await approvedTest(e,NOW+2,fetcher);assert.equal(sent.length,2);
 await approvedTest(e,TEST_EXPIRES+1,fetcher);assert.equal(sent.length,2);
});
test('timeout is held without resend; missing credentials or wrong sender causes no writes',async()=>{
 const e=env();let calls=0;await approvedTest(e,NOW,async()=>{calls++;throw Error('timeout')});await approvedTest(e,NOW+60000,async()=>{calls++;throw Error('must not send')});assert.equal(calls,2);
 const f=env();delete f.SMTP2GO_API_KEY;assert.equal((await approvedTest(f,NOW)).inactive,true);assert.equal(f.DB.executions,0);
 f.SMTP2GO_API_KEY='x';f.EMAIL_FROM='other@example.test';assert.equal((await approvedTest(f,NOW)).inactive,true);assert.equal(f.DB.executions,0);
});
test('accepted is distinct from delivery; activity must match provider id, recipient and time',async()=>{
 const e=env();let calls=0;await approvedTest(e,NOW,async()=>Response.json({data:{succeeded:1,failed:0,email_id:'id-'+(++calls)}}));
 const res=await approvedTest(e,NOW+60001,async(url,options)=>{const body=JSON.parse(options.body);return Response.json({data:{events:[{email_id:body.search_email_id,recipient:'other@example.test',date:new Date(NOW+1).toISOString(),event:'delivered'},{email_id:body.search_email_id,recipient:body.search_recipient,date:new Date(NOW+1).toISOString(),event:body.search_recipient.includes('gmail')?'delivered':'hard-bounced'}]}})});
 assert.deepEqual(res.outcomes.map(r=>r.state),['delivered','failed']);assert.equal(res.outcomes[1].event,'hard-bounced');
 assert.equal((await approvedTest(e,NOW+120001,()=>{throw Error('terminal result must not poll')})).outcomes.length,0);
 assert.ok(e.DB.sql.prepare('SELECT key FROM auth_rate_limits WHERE key LIKE ?').all(TEST_ID+':%').every(r=>!r.key.includes('test-only')));
});
test('200 containing provider failure is never recorded as accepted or retried',async()=>{
 const e=env();let sends=0;await approvedTest(e,NOW,async()=>{sends++;return Response.json({data:{succeeded:0,failed:1,failures:['blocked']}})});
 await approvedTest(e,NOW+60001,()=>{throw Error('must not retry')});assert.equal(sends,2);
 const rows=e.DB.sql.prepare("SELECT key FROM auth_rate_limits WHERE key LIKE '%:result:%'").all();assert.ok(rows.every(r=>r.key.includes('submission_unknown')));
});
