import test from 'node:test';import assert from 'node:assert/strict';
import {FullDB,bucketFixture} from './helpers/full-db.mjs';
import {withStagingTransport,fetch as intercepted} from '../transport.mjs';
import {createFrontend} from '../frontend.mjs';
import {TARGET} from '../target.mjs';
const mail=(subject,attachments=[])=>new Request('https://api.smtp2go.com/v3/email/send',{method:'POST',headers:{'X-Smtp2go-Api-Key':'staging-capture-only'},body:JSON.stringify({to:['synthetic@example.invalid'],subject,text_body:'Synthetic message',attachments})});
test('concurrent capture is isolated; failures and unknown egress never call a real provider',async()=>{
 const a=new FullDB(),b=new FullDB(),native=globalThis.fetch;let calls=0;globalThis.fetch=()=>{calls++;throw Error('Network');};
 try{
  await Promise.all([[a,'A'],[b,'B']].map(([DB,s])=>withStagingTransport({DB,STAGING_MODE:'true',STAGING_EMAIL_CAPTURE_ENABLED:'true'},()=>intercepted(mail(s)))));
  assert.equal(a.sql.prepare('SELECT subject FROM staging_mail').get().subject,'A');assert.equal(b.sql.prepare('SELECT subject FROM staging_mail').get().subject,'B');
  const env={DB:a,STAGING_MODE:'true',STAGING_EMAIL_CAPTURE_ENABLED:'true'};
  assert.equal((await withStagingTransport(env,()=>intercepted(mail('failed')),'mail-failure')).status,503);
  assert.equal(a.sql.prepare('SELECT count(*) n FROM staging_mail').get().n,1);
  await assert.rejects(withStagingTransport(env,()=>intercepted('https://api.cloudflare.com/client/v4/accounts')),/reviewed/);
  await assert.rejects(intercepted(mail('outside')),/disabled/);assert.equal(calls,0);
 }finally{a.close();b.close();globalThis.fetch=native;}
});
test('large report attachment is captured in bounded rows without losing its bytes',async()=>{
 const DB=new FullDB(),blob='JVBERi0'+('A'.repeat(2000001));try{
  await withStagingTransport({DB,STAGING_MODE:'true',STAGING_EMAIL_CAPTURE_ENABLED:'true'},()=>intercepted(mail('Report',[{filename:'synthetic.pdf',mimetype:'application/pdf',fileblob:blob}])));
  const payload=JSON.parse(DB.sql.prepare('SELECT payload_json FROM staging_mail').get().payload_json);assert.equal(payload.attachments[0].base64_length,blob.length);
  const rows=DB.sql.prepare('SELECT body FROM staging_mail_attachment_chunks ORDER BY chunk_index').all();assert.equal(rows.map(r=>r.body).join(''),blob);assert.ok(rows.every(r=>r.body.length<=64000));
 }finally{DB.close();}
});
const verifiedAdmin=async(_t,_i,_a,_reject,onIdentity)=>{onIdentity({email:'admin@example.invalid'});return true;};
test('Access-gated frontend pins one snapshot, preserves old versions and fails visibly on corruption',async()=>{
 const first=await bucketFixture('first'),second=await bucketFixture('second'),front=createFrontend(async()=>true);
 const env={INTELLIGENCE_SOURCE:'r2',INTELLIGENCE_BUCKET:first,ASSETS:{fetch:async()=>new Response('<script src="/data.js"></script>',{headers:{'Content-Type':'text/html'}})}};
 const html=await front.fetch(new Request(TARGET.origin+'/'),env);assert.match(await html.text(),new RegExp('feed_version='+first.version));
 for(const [key,value] of second.data)first.data.set(key,value);
 const prior=await front.fetch(new Request(TARGET.origin+'/data.js?feed_version='+first.version),env);assert.equal(prior.status,200);assert.equal(prior.headers.get('X-CVEHarbor-Feed-Version'),first.version);assert.match(prior.headers.get('Cache-Control'),/private/);
 first.data.set('manifests/'+second.version+'.json',new TextEncoder().encode('{}'));
 assert.equal((await front.fetch(new Request(TARGET.origin+'/data.js'),env)).status,503);
 assert.equal((await front.fetch(new Request(TARGET.origin+'/'),env)).status,200);
 const blocked=createFrontend(async()=>false);assert.equal((await blocked.fetch(new Request(TARGET.origin+'/data.js'),env)).status,403);
});
test('mail administration needs verified allowlisted identity; spoofed headers and cross-site writes fail',async()=>{
 const env={STAGING_ADMIN_EMAILS:'admin@example.invalid',STAGING_API:{fetch:async req=>{assert.equal(req.headers.get('X-CVEHarbor-Staging-Admin'),'admin@example.invalid');return Response.json({ok:true});}}};
 const r=new Request(TARGET.origin+'/__staging/mail',{headers:{'X-CVEHarbor-Staging-Admin':'admin@example.invalid','Cf-Access-Authenticated-User-Email':'admin@example.invalid'}});
 assert.equal((await createFrontend(async()=>true).fetch(r,env)).status,403);
 const front=createFrontend(verifiedAdmin);assert.equal((await front.fetch(r,env)).status,200);
 assert.equal((await front.fetch(new Request(TARGET.origin+'/__staging/jobs',{method:'POST',headers:{Origin:'https://attacker.invalid','Content-Type':'application/json'},body:'{}'}),env)).status,403);
});
test('reviewer cookie survives private service route while Access cookies and spoofed admin header are stripped',async()=>{
 const front=createFrontend(async()=>true),token='a'.repeat(64),env={STAGING_API:{fetch:async req=>{assert.equal(req.headers.get('Cookie'),'__Host-cvh_review='+token);assert.equal(req.headers.get('X-CVEHarbor-Staging-Admin'),null);return new Response('review');}}};
 assert.equal((await front.fetch(new Request(TARGET.origin+'/assignment/'+crypto.randomUUID(),{headers:{Cookie:'CF_Authorization=secret; __Host-cvh_review='+token,'X-CVEHarbor-Staging-Admin':'spoof'}}),env)).status,200);
});
