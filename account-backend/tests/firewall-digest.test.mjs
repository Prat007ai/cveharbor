import fs from 'node:fs';
import {createHash} from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/index.js';
import {dailyEmail,artworkPath} from '../src/firewall-templates.js';
import {DB} from './helpers/d1.mjs';
import {firewallRoute,dispatchFirewallDigest} from '../src/firewall-digest.js';

function bucket(data){
 const raw=JSON.stringify(data), hash=s=>createHash('sha256').update(s).digest('hex'), id=hash(raw);
 const manifest=JSON.stringify({schema:1,files:{'data/threat-ip-history.json':{sha256:id,key:'objects/'+id,bytes:Buffer.byteLength(raw)}}});
 const key='manifests/'+hash(manifest)+'.json';
 const objects=new Map([['current.json',JSON.stringify({schema:1,manifest:key})],[key,manifest],['objects/'+id,raw]]);
 return {get:async k=>objects.has(k)?new Response(objects.get(k)):null};
}
test('confirmed opt-in, full-day additions, repeat dispatch and one-click removal',async t=>{
 const db=new DB();t.after(()=>db.sql.close());
 db.sql.exec(fs.readFileSync(new URL('../../deployment/proposals/firewall-digest/schema.sql',import.meta.url),'utf8'));
 const env={DB:db,EMAIL_FROM:'alerts@example.test',SMTP2GO_API_KEY:'fixture',INTELLIGENCE_SOURCE:'r2',
  INTELLIGENCE_BUCKET:bucket({generated_at:'2026-11-09T01:10:00Z',addresses:{
    '1.2.3.4':{first_indexed:'2026-11-08T10:00:00Z'},'2.3.4.5':{first_indexed:'2026-11-08T21:15:00-05:00'}}})};
 const mails=[],fetcher=globalThis.fetch;
 t.after(()=>{globalThis.fetch=fetcher});
 globalThis.fetch=async(url,options)=>{assert.equal(String(url),'https://api.smtp2go.com/v3/email/send');mails.push(JSON.parse(options.body));return Response.json({data:{succeeded:1,failed:0,email_id:'fixture-receipt'}});};
 const base='https://api.cveharbor.com/v1/firewall-updates', route=req=>firewallRoute(req,env,async()=>true);
 const signup=()=>new Request(base,{method:'POST',headers:{origin:'https://cveharbor.com'},body:new URLSearchParams({email:'subscriber@example.test'})});
 const date=new Date('2026-11-09T08:00:00Z');
 assert.equal((await route(signup())).status,200);
 await route(signup());assert.equal(mails.length,1);
 await dispatchFirewallDigest(env,date);assert.equal(mails.length,1);
 const confirm=mails[0].text_body.match(/https:\/\/\S+$/)[0];assert.ok(confirm.startsWith('https://confirm.cveharbor.com/firewall-updates/confirm/'));
 assert.match(mails[0].html_body,/Confirm my email/);
 assert.match(await (await worker.fetch(new Request(confirm),env,{})).text(),/Receive daily firewall updates/);
 assert.equal(db.sql.prepare('select confirmed_at from firewall_subscribers').get().confirmed_at,null);
 const confirmed=await worker.fetch(new Request(confirm,{method:'POST',headers:{Origin:new URL(confirm).origin}}),env,{});
 assert.match(await confirmed.text(),/Manage email preferences/);
 assert.ok(db.sql.prepare('select confirmed_at from firewall_subscribers').get().confirmed_at);
 db.sql.exec("update firewall_subscribers set confirmed_at=unixepoch('2026-11-07')");
 await Promise.all([dispatchFirewallDigest(env,date),dispatchFirewallDigest(env,date)]);
 assert.equal(mails.length,2);
 assert.match(mails[1].text_body,/1\.2\.3\.4/);assert.doesNotMatch(mails[1].text_body,/2\.3\.4\.5/);
 assert.equal(db.sql.prepare('select provider_id from firewall_digest_deliveries').get().provider_id,'fixture-receipt');
 assert.match(mails[1].html_body,/Newly observed addresses/);assert.match(mails[1].html_body,/1 of 1/);assert.match(mails[1].html_body,/Unsubscribe or manage email preferences/);
 const unsub=mails[1].custom_headers[0].value.slice(1,-1);
 await route(new Request(unsub));assert.equal(db.sql.prepare('select count(*) n from firewall_subscribers').get().n,1);
 await route(new Request(unsub,{method:'POST',body:'List-Unsubscribe=One-Click'}));assert.equal(db.sql.prepare('select count(*) n from firewall_subscribers').get().n,0);
});


test('preferences cover both scopes, preserve unrelated delivery and reject cross-site or unknown selections',async t=>{
 const db=new DB(); t.after(()=>db.sql.close());
 db.sql.exec(fs.readFileSync(new URL('../../deployment/proposals/firewall-digest/schema.sql',import.meta.url),'utf8'));
 db.sql.exec(`CREATE TABLE alert_preferences(user_id TEXT, enabled INTEGER, updated_at TEXT);
 CREATE TABLE alert_optins(user_id TEXT); CREATE TABLE lifecycle_preferences(user_id TEXT,email_enabled INTEGER,updated_at INTEGER);
 CREATE TABLE lifecycle_monitor_notifications(user_id TEXT,state TEXT);
 INSERT INTO alert_preferences VALUES ('a',1,''),('b',1,''); INSERT INTO alert_optins VALUES ('a'),('b');
 INSERT INTO lifecycle_preferences VALUES ('a',1,0),('b',1,0); INSERT INTO lifecycle_monitor_notifications VALUES ('a','queued'),('b','pending');`);
 const origin='https://confirm.cveharbor.com', token='1'.repeat(64);
 const uri=origin+'/firewall-updates/unsubscribe/'+token;
 const add=()=>db.sql.prepare('INSERT INTO firewall_subscribers(id,email,unsubscribe_token,confirmed_at,requested_at) VALUES(?,?,?,?,0)').run('fixture','A@example.test',token,1);
 const send=(url,options={})=>worker.fetch(new Request(url,options),{DB:db},{});
 const post=(body,source=origin)=>send(uri,{method:'POST',body,headers:{Origin:source}});
 add();
 assert.match(await (await send(uri)).text(),/All optional CVEHarbor/);
 assert.equal((await post('scope=all','https://example.test')).status,403);
 assert.equal((await post('scope=unrecognised')).status,400);
 assert.match(await (await post('scope=digest')).text(),/Daily firewall digests have been turned off/);
 assert.equal(db.sql.prepare("SELECT COUNT(*) n FROM alert_optins").get().n,2);
 add();
 assert.match(await (await post('scope=all')).text(),/All optional CVEHarbor email updates have been turned off/);
 assert.equal(db.sql.prepare("SELECT COUNT(*) n FROM firewall_subscribers").get().n,0);
 assert.equal(db.sql.prepare("SELECT user_id FROM alert_optins").get().user_id,'b');
 for(const [table,col] of [['alert_preferences','enabled'],['lifecycle_preferences','email_enabled']]){
  assert.deepEqual(db.sql.prepare('SELECT '+col+' AS enabled FROM '+table+' ORDER BY user_id').all().map(r=>r.enabled),[0,1]);
 }
 assert.deepEqual(db.sql.prepare('SELECT state FROM lifecycle_monitor_notifications ORDER BY user_id').all().map(r=>r.state),['suppressed','pending']);
 assert.equal((await send(origin+'/v1/me')).status,404);
 assert.equal((await send(origin+'/firewall-updates')).status,404);
});
test('the email shows at most ten samples and counts the full list',()=>{
 const ips=Array.from({length:12},(_,i)=>'192.0.2.'+(i+1));
 const email=dailyEmail('2026-11-08',ips,'https://example.test/file','https://example.test/unsubscribe');
 assert.match(email.subject,/12 new IPs/);assert.match(email.html,/10 of 12/);
 for(const ip of ips.slice(0,10))assert.ok(email.text.split('\n').includes(ip));
 assert.ok(!email.text.includes(ips[11]));assert.match(email.text,/Full list: https:\/\/example.test\/file/);
});

test('browser subscription forms retain their origin without sending the private link as referrer; artwork is a public PNG',async t=>{
 const db=new DB();t.after(()=>db.sql.close());
 db.sql.exec(fs.readFileSync(new URL('../../deployment/proposals/firewall-digest/schema.sql',import.meta.url),'utf8'));
 const proof='a'.repeat(64),hash=createHash('sha256').update(proof).digest('hex');
 db.sql.prepare('INSERT INTO firewall_subscribers(id,email,confirmation_hash,requested_at,unsubscribe_token) VALUES(?,?,?,unixepoch(),?)').run('demo','demo@example.test',hash,'b'.repeat(64));
 const origin='https://confirm.cveharbor.com',route=(path,opts)=>worker.fetch(new Request(origin+path,opts),{DB:db},{});
 const confirm='/firewall-updates/confirm/'+proof;
 const form=await route(confirm);assert.equal(form.headers.get('Referrer-Policy'),'strict-origin');
 assert.ok((await form.text()).includes(origin+artworkPath));
 const blocked=await route(confirm,{method:'POST',headers:{Origin:'null'}});assert.equal(blocked.status,403);
 const approved=await route(confirm,{method:'POST',headers:{Origin:origin}});assert.match(await approved.text(),/SUBSCRIPTION CONFIRMED/);
 const img=await route(artworkPath);assert.equal(img.headers.get('Content-Type'),'image/png');
 const bytes=Buffer.from(await img.arrayBuffer());assert.equal(bytes.subarray(0,8).toString('hex'),'89504e470d0a1a0a');
 assert.equal(bytes.readUInt32BE(16),384);assert.equal(bytes.readUInt32BE(20),224);
 assert.equal((await route(artworkPath,{method:'POST'})).status,405);
});
