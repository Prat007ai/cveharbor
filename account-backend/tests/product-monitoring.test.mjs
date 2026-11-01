import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DB} from './helpers/d1.mjs';
import worker from '../src/index.js';
import {monitoringHandler,dispatchProductMonitoring,dispatchProductMonitorMail} from '../src/monitoring.js';
import {checkSubscribedSources,reminderThreshold,sha,q} from '../src/monitor-engine.js';
import {compareVersions,normalizeVendor,monitorIdentity} from '../src/monitor-sources.js';
import {dispatchMonitorMail,smtp2goWebhook,submitSmtp2go,unsubscribeMonitor} from '../src/monitor-mail.js';
const NOW=Date.parse('2026-11-01T09:00:00Z');
function env(){const DBi=new DB();DBi.sql.exec(fs.readFileSync(new URL('../lifecycle-schema.sql',import.meta.url),'utf8'));DBi.sql.exec(fs.readFileSync(new URL('../migrations/0023_lifecycle_monitoring.sql',import.meta.url),'utf8'));return {DB:DBi,PRODUCT_MONITOR_CHECKS_ENABLED:'true',PRODUCT_MONITOR_DELIVERY_ENABLED:'true',SMTP2GO_API_KEY:'mock-secret',EMAIL_FROM:'alerts@example.test',SMTP2GO_MONITOR_WEBHOOK_TOKEN:'mock-webhook-secret'};}
const user=id=>({id,email:id+'@example.test'});
async function api(e,path='',method='GET',data={},id='a',now=NOW){return monitoringHandler(new Request('https://api.cveharbor.com/v1/monitoring'+path,{method}),e,user(id),'/v1/monitoring'+path,data,now);}
const feed=(version='8.0.11',extra={})=>({'releases-index':[{'channel-version':'8.0','latest-release':version,'latest-release-date':'2026-10-20','support-phase':'active','security':true,'eol-date':'2026-11-10',...extra}]});
async function watch(e,id='a',extra={}){const r=await api(e,'/watches','POST',{product:'.NET',slug:'dotnet',cycle:'8.0',installed_version:'8.0.9',alert_types:['security','maintenance'],...extra},id);const row=await r.json();assert.equal(r.status,201);await api(e,'/preferences','PUT',{email_enabled:true,lead_days:90},id);return row.ids[0];}
const all=(e,table)=>q(e.DB,'SELECT * FROM '+table).all().then(r=>r.results);
test('50 customers share one official source request, one public event and authorized notifications',async()=>{
 const e=env();for(let i=0;i<50;i++){const id='tenant'+i;await q(e.DB,'INSERT INTO users VALUES(?,?)',id,id+'@example.test').run();await watch(e,id);}
 e.DB.executions=0;let calls=0;const result=await checkSubscribedSources(e,async()=>{calls++;return Response.json(feed());},NOW);
 assert.ok(e.DB.executions<=20,'50-recipient source fan-out stays within the free Worker query budget');
 assert.equal(calls,1);assert.equal(result.checked,1);assert.equal((await all(e,'lifecycle_monitor_products')).length,1);assert.equal((await all(e,'lifecycle_monitor_events')).length,1);assert.equal((await all(e,'lifecycle_monitor_notifications')).length,50);
 const global=JSON.stringify(await all(e,'lifecycle_monitor_products'))+JSON.stringify(await all(e,'lifecycle_monitor_state'));assert.doesNotMatch(global,/tenant|example\.test/);
 const state=await all(e,'lifecycle_monitor_state');await checkSubscribedSources(e,()=>Response.json(feed()),NOW+86400001);
 assert.deepEqual(await all(e,'lifecycle_monitor_state'),state,'unchanged state is not rewritten');assert.equal((await all(e,'lifecycle_monitor_notifications')).length,50);
});
test('scheduler runs with no browser, claims a slot once, and remains disabled without approved activation',async()=>{
 const e=env();await watch(e);let calls=0;
 const fetcher=async()=>{calls++;return Response.json(feed());};
 e.PRODUCT_MONITOR_DELIVERY_ENABLED='false';await dispatchProductMonitoring(e,new Date(NOW),fetcher);await dispatchProductMonitoring(e,new Date(NOW),fetcher);
 assert.equal(calls,1);assert.ok((await all(e,'lifecycle_monitor_runs'))[0].completed_at);
 e.PRODUCT_MONITOR_CHECKS_ENABLED='false';assert.equal((await dispatchProductMonitoring(e,new Date(NOW+3600000),fetcher)).disabled,true);assert.equal(calls,1);
});
test('version comparison is numeric, stable and branch-aware; unsupported data is never invented',()=>{
 assert.equal(compareVersions('8.0.9','8.0.10'),-1);assert.equal(compareVersions('8.0.1-preview','8.0.2'),null);
 const p=monitorIdentity({slug:'dotnet',product:'Private alias',cycle:'8.0'});assert.doesNotMatch(p.id,/Private/);
 assert.throws(()=>normalizeVendor('dotnet',feed('9.0.1'),p));
 assert.throws(()=>normalizeVendor('dotnet',feed('8.0.11',{'support-phase':'preview'}),p));
 const wp=normalizeVendor('wordpress',{'6.8.9':'outdated','6.8.10':'latest','6.9.1':'latest'},monitorIdentity({product:'WordPress',slug:'wordpress',cycle:'6.8'}));
 assert.equal(wp.version,'6.8.10');assert.deepEqual(wp.milestones,{});assert.equal(wp.security,false);assert.equal(wp.published,null);
});
test('invalid, unavailable and regressed feeds retain the verified state and create no false alerts',async()=>{
 const e=env();await watch(e);await checkSubscribedSources(e,()=>Response.json(feed()),NOW);const before=await all(e,'lifecycle_monitor_state');
 await checkSubscribedSources(e,()=>Response.json(feed('8.0.1')),NOW+86400001);assert.deepEqual(await all(e,'lifecycle_monitor_state'),before);assert.equal((await all(e,'lifecycle_monitor_events')).length,1);
 await q(e.DB,'UPDATE lifecycle_monitor_sources SET next_due_at=0').run();await checkSubscribedSources(e,()=>new Response('rate limited',{status:429,headers:{'Retry-After':'3600'}}),NOW+86401000);
 assert.deepEqual(await all(e,'lifecycle_monitor_state'),before);assert.ok((await all(e,'lifecycle_monitor_sources'))[0].failures>0);
});
test('late subscription gets only the nearest crossed reminder threshold, then the next threshold',()=>{
 const date='2026-11-21';assert.equal(reminderThreshold(date,[90,30,14,7],NOW),30);assert.equal(reminderThreshold(date,[90,30,14,7],NOW+7*86400000),14);assert.equal(reminderThreshold(date,[90,30,14,7],NOW+30*86400000),0);
});
test('paused, removed, disabled and opted-out users receive no new notifications',async()=>{
 for(const mutation of ['paused','removed','disabled','optout']){
  const e=env(),id=await watch(e);
  if(mutation==='paused')await api(e,'/watches/'+id,'PUT',{status:'paused'});
  if(mutation==='removed')await api(e,'/watches/'+id,'DELETE');
  if(mutation==='disabled')await q(e.DB,'INSERT INTO lifecycle_monitor_accounts VALUES(?,1)','a').run();
  if(mutation==='optout')await api(e,'/preferences','PUT',{email_enabled:false,lead_days:90});
  await checkSubscribedSources(e,()=>Response.json(feed()),NOW);assert.equal((await all(e,'lifecycle_monitor_notifications')).length,0,mutation);
 }
});
test('daily digest, cron replay and verified webhooks preserve submitted versus delivered state',async()=>{
 const e=env();await watch(e);await checkSubscribedSources(e,()=>Response.json(feed()),NOW);
 let sends=0;const send=async(url,options)=>{sends++;const body=JSON.parse(options.body);assert.equal(body.to[0],'a@example.test');assert.ok(body.html_body&&body.text_body);return Response.json({request_id:'request-one',data:{succeeded:1,failed:0,email_id:'provider-one'}});};
 const tomorrow=NOW+86400000;await dispatchMonitorMail(e,send,tomorrow);await dispatchMonitorMail(e,send,tomorrow);assert.equal(sends,1);
 assert.equal((await all(e,'lifecycle_monitor_messages'))[0].state,'submitted');
 const event={id:'webhook-1',event:'delivered',time:new Date(tomorrow+1000).toISOString(),email_id:'provider-one',rcpt:'a@example.test'};
 const req=(data,auth='Bearer mock-webhook-secret')=>new Request('https://api.cveharbor.com/v1/monitoring/webhooks/smtp2go',{method:'POST',headers:{'Authorization':auth,'Content-Type':'application/json'},body:JSON.stringify(data)});
 assert.equal((await smtp2goWebhook(req(event,'Bearer forged'),e,tomorrow+2000)).status,401);
 assert.equal((await smtp2goWebhook(req({...event,rcpt:'b@example.test'}),e,tomorrow+2000)).status,400);
 await smtp2goWebhook(req(event),e,tomorrow+2000);await smtp2goWebhook(req(event),e,tomorrow+2000);
 assert.equal((await all(e,'lifecycle_monitor_delivery_events')).length,1);assert.equal((await all(e,'lifecycle_monitor_messages'))[0].state,'delivered');
 await smtp2goWebhook(req({...event,id:'webhook-2',event:'bounce',bounce:'hard'}),e,tomorrow+2000);
 assert.equal((await all(e,'lifecycle_monitor_suppressions')).length,1);assert.equal((await all(e,'lifecycle_monitor_messages'))[0].state,'suppressed');
});
test('ambiguous provider acceptance is held for reconciliation and never automatically resent',async()=>{
 const e=env();await watch(e);await checkSubscribedSources(e,()=>Response.json(feed()),NOW);let calls=0;
 const send=()=>{calls++;throw Error('Network response lost');};await dispatchMonitorMail(e,send,NOW+86400000);await dispatchMonitorMail(e,send,NOW+2*86400000);
 assert.equal(calls,1);assert.equal((await all(e,'lifecycle_monitor_messages'))[0].state,'submission_unknown');
});
test('SMTP2GO rate limiting retries once safely; 200 with failure is not accepted as delivery',async()=>{
 const e=env();await watch(e);await checkSubscribedSources(e,()=>Response.json(feed()),NOW);let calls=0;
 await dispatchMonitorMail(e,async()=>{calls++;return new Response('{}',{status:429});},NOW+86400000);
 await dispatchMonitorMail(e,async()=>{calls++;return Response.json({data:{succeeded:1,failed:0,email_id:'retry-ok'}});},NOW+86400000+120000);
 assert.equal(calls,2);assert.equal((await all(e,'lifecycle_monitor_messages'))[0].state,'submitted');
 await assert.rejects(submitSmtp2go(e,'a@example.test',{subject:'test',html:'test',text:'test'},()=>Response.json({data:{succeeded:0,failed:1}})),error=>error.unknown===true);
});
test('watch persistence, tenant boundaries, recipient authorization and unsubscribes are enforced',async()=>{
 const e=env(),id=await watch(e);const saved=await (await api(e)).json();assert.equal(saved.watches[0].installed_version,'8.0.9');assert.equal(saved.watches[0].monitoring_label,'Monitoring Not Yet Active');
 assert.deepEqual((await (await api(e,'','GET',{},'b')).json()).watches,[]);
 await assert.rejects(api(e,'/watches/'+id,'PUT',{status:'paused'},'b'),error=>error.status===404);
 await assert.rejects(api(e,'/watches','POST',{product:'.NET',slug:'dotnet',cycle:'8.0',recipient:'stranger@example.test'}),error=>error.status===403);
 await checkSubscribedSources(e,()=>Response.json(feed()),NOW);const n=(await all(e,'lifecycle_monitor_notifications'))[0];
 await unsubscribeMonitor(new Request('https://api.cveharbor.com/unsubscribe',{method:'POST'}),e,n.unsubscribe_token);assert.equal((await q(e.DB,'SELECT email_enabled FROM lifecycle_preferences WHERE user_id=?','a').first()).email_enabled,0);
 assert.equal((await worker.fetch(new Request('https://api.cveharbor.com/v1/monitoring'),e,{})).status,401);
});
test('custom source URLs remain unverified and are never fetched; unknown milestones stay unknown',async()=>{
 const e=env();await api(e,'/watches','POST',{product:'Private custom service',custom_source_url:'https://vendor.example/support',cycle:'1.0'});
 let requests=0;await checkSubscribedSources(e,()=>{requests++;return Response.json({});},NOW);assert.equal(requests,0);
 const state=await (await api(e)).json();assert.equal(state.watches[0].verified,null);
 assert.doesNotMatch(JSON.stringify(await all(e,'lifecycle_monitor_products')),/Private custom service|vendor\.example/);
});
test('one unsupported branch cannot block another customer watching a valid branch',async()=>{
 const e=env();await watch(e);await watch(e,'b',{cycle:'99.0',installed_version:'99.0.1'});
 let calls=0;const result=await checkSubscribedSources(e,()=>{calls++;return Response.json(feed());},NOW);
 assert.equal(calls,1);assert.equal(result.checked,1);assert.equal(result.failed,1);assert.equal((await all(e,'lifecycle_monitor_notifications')).length,1);
 const products=await all(e,'lifecycle_monitor_products');assert.ok(products.find(p=>p.branch==='99.0').verification_error);assert.equal(products.find(p=>p.branch==='8.0').verification_error,'');
});
test('replaced source lease fences stale provider responses before events or verified state can be written',async()=>{
 const e=env();await watch(e);
 await checkSubscribedSources(e,async()=>{await q(e.DB,"UPDATE lifecycle_monitor_sources SET lease_token='replacement' WHERE id='dotnet'").run();return Response.json(feed());},NOW);
 assert.equal((await all(e,'lifecycle_monitor_state')).length,0);assert.equal((await all(e,'lifecycle_monitor_notifications')).length,0);
});
test('schema retry preserves subscriptions, verified history and existing lifecycle preferences',async()=>{
 const e=env();await watch(e);await checkSubscribedSources(e,()=>Response.json(feed()),NOW);const state=await all(e,'lifecycle_monitor_state'),settings=await all(e,'lifecycle_watch_settings');
 e.DB.sql.exec(fs.readFileSync(new URL('../migrations/0023_lifecycle_monitoring.sql',import.meta.url),'utf8'));
 assert.deepEqual(await all(e,'lifecycle_monitor_state'),state);assert.deepEqual(await all(e,'lifecycle_watch_settings'),settings);assert.deepEqual(e.DB.sql.prepare('PRAGMA foreign_key_check').all(),[]);
});
test('a stale submitting job is held, rather than resent after Worker restart',async()=>{
 const e=env();await watch(e);await checkSubscribedSources(e,()=>Response.json(feed()),NOW);
 await q(e.DB,"INSERT INTO lifecycle_monitor_messages(id,user_id,recipient,slot,state,created_at,lease_until) VALUES('crashed','a','a@example.test','digest:old','submitting',?,?)",NOW,NOW+1).run();
 await q(e.DB,"UPDATE lifecycle_monitor_notifications SET state='queued',message_id='crashed'").run();
 let sent=0;await dispatchMonitorMail(e,()=>{sent++;throw Error('Must not send');},NOW+86400000);
 assert.equal(sent,0);assert.equal((await all(e,'lifecycle_monitor_messages'))[0].state,'submission_unknown');
});
test('security events use immediate slots while ordinary updates remain daily',async()=>{
 const e=env();await watch(e,'a',{delivery_mode:'immediate_security'});await checkSubscribedSources(e,()=>Response.json(feed()),NOW);
 let sends=0;const send=()=>{sends++;return Response.json({data:{succeeded:1,failed:0,email_id:'immediate-'+sends}});};
 await dispatchMonitorMail(e,send,NOW);assert.equal(sends,1);
 await q(e.DB,'UPDATE lifecycle_monitor_sources SET next_due_at=0').run();await checkSubscribedSources(e,()=>Response.json(feed('8.0.12')),NOW+3600000);await dispatchMonitorMail(e,send,NOW+3600000);assert.equal(sends,2,'another verified security event is not blocked by an earlier digest');
});
test('daily reminders do not flood past thresholds and unchanged daily runs do not duplicate notification records',async()=>{
 const e=env();await watch(e,'a',{alert_types:['security_support']});
 await q(e.DB,"UPDATE lifecycle_watch_settings SET notice_days='[90,30,14,7]'").run();
 await checkSubscribedSources(e,()=>Response.json(feed()),NOW);const first=await all(e,'lifecycle_monitor_notifications');assert.equal(first.length,1);
 const ev=(await all(e,'lifecycle_monitor_events')).find(ev=>ev.id===first[0].event_id);assert.equal(JSON.parse(ev.record_json).threshold,14);
 await q(e.DB,'UPDATE lifecycle_monitor_sources SET next_due_at=0').run();await checkSubscribedSources(e,()=>Response.json(feed()),NOW+86400000);assert.equal((await all(e,'lifecycle_monitor_notifications')).length,1);
 await q(e.DB,'UPDATE lifecycle_monitor_sources SET next_due_at=0').run();await checkSubscribedSources(e,()=>Response.json(feed()),NOW+3*86400000);assert.equal((await all(e,'lifecycle_monitor_notifications')).length,2,'only the next threshold generates another notification');
});
test('minute delivery simulation runs without a browser, limits writes on idle ticks and claims submission once',async()=>{
 const e=env();await watch(e);await checkSubscribedSources(e,()=>Response.json(feed()),NOW);
 let sends=0;const send=()=>{sends++;return Response.json({data:{succeeded:1,failed:0,email_id:'minute-ok'}});};
 const date=new Date(NOW+86400000);await dispatchProductMonitorMail(e,date,send);await dispatchProductMonitorMail(e,date,send);
 assert.equal(sends,1);const runs=(await all(e,'lifecycle_monitor_runs')).length;
 await dispatchProductMonitorMail(e,new Date(NOW+86460000),send);assert.equal((await all(e,'lifecycle_monitor_runs')).length,runs,'idle minute ticks do not write heartbeat rows');
});
