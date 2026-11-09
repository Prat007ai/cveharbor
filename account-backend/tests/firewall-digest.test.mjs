import fs from 'node:fs';
import {createHash} from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';
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
 const confirm=mails[0].text_body.match(/https:\/\/\S+$/)[0];await route(new Request(confirm));
 assert.equal(db.sql.prepare('select confirmed_at from firewall_subscribers').get().confirmed_at,null);
 await route(new Request(confirm,{method:'POST'}));
 assert.ok(db.sql.prepare('select confirmed_at from firewall_subscribers').get().confirmed_at);
 db.sql.exec("update firewall_subscribers set confirmed_at=unixepoch('2026-11-07')");
 await Promise.all([dispatchFirewallDigest(env,date),dispatchFirewallDigest(env,date)]);
 assert.equal(mails.length,2);
 assert.match(mails[1].text_body,/1\.2\.3\.4/);assert.doesNotMatch(mails[1].text_body,/2\.3\.4\.5/);
 assert.equal(db.sql.prepare('select provider_id from firewall_digest_deliveries').get().provider_id,'fixture-receipt');
 const unsub=mails[1].custom_headers[0].value.slice(1,-1);
 await route(new Request(unsub));assert.equal(db.sql.prepare('select count(*) n from firewall_subscribers').get().n,1);
 await route(new Request(unsub,{method:'POST'}));assert.equal(db.sql.prepare('select count(*) n from firewall_subscribers').get().n,0);
});

