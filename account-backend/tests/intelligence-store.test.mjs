import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {openIntelligenceSnapshot,intelligenceResponse,pinIntelligenceScripts} from '../src/intelligence-store.js';
import {loadPublicFeed,selectDigest,revisionOf} from '../src/digest.js';
import {loadLifecycleFeed,loadVendorNotes} from '../src/lifecycle.js';
import gate from '../../site-gate/worker.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
function fixture(hours=0){
 const now=new Date(Date.now()-hours*3600000).toISOString();
 const record={id:'CVE-2099-12345',published:now,updated:now,severity:'critical',categories:['PHP'],title:'Synthetic'};
 const values={'data.js':{advisories:[record]},'data/feed-health.json':{mode:'live',last_successful_update:now},
 'lifecycle.js':{checked_at:now,cycles:[{slug:'php',cycle:'8.3',_feed_last_success:now}]},
 'patch-notes.js':{checked_at:now,releases:[{slug:'php',version:'8.3.10',_feed_last_success:now}]},
 'malware-data.js':{value:'</script><script>bad()</script>'}};
 const objects=new Map(),files={};
 for(const [name,value]of Object.entries(values)){const body=Buffer.from(JSON.stringify(value));const sha=hash(body);objects.set('objects/'+sha,body);files[name]={key:'objects/'+sha,sha256:sha,bytes:body.length};}
 const manifest=Buffer.from(JSON.stringify({schema:1,files})),version=hash(manifest);
 objects.set('manifests/'+version+'.json',manifest);objects.set('current.json',Buffer.from(JSON.stringify({schema:1,manifest:'manifests/'+version+'.json'})));
 let calls=[];
 const env={INTELLIGENCE_SOURCE:'r2',INTELLIGENCE_BUCKET:{get:async key=>{calls.push(key);const b=objects.get(key);return b?{size:b.length,arrayBuffer:async()=>b.buffer.slice(b.byteOffset,b.byteOffset+b.byteLength)}:null}}};
 return {env,objects,version,files,record,calls};
}
test('digest reads current data and health in a single version without HTTP',async()=>{
 const f=fixture(),feed=await loadPublicFeed(()=>{throw Error('unexpected HTTP')},f.env);
 assert.equal(feed.records[0].id,f.record.id);assert.equal(f.calls.filter(x=>x==='current.json').length,1);
});
test('eight hour stale and degraded gates remain enforced',async()=>{
 await assert.rejects(loadPublicFeed(null,fixture(9).env),/stale/);
 await assert.rejects(loadPublicFeed(null,fixture(-1).env),/stale/);
});
test('unconfigured R2 fails closed and never silently falls back',async()=>{
 await assert.rejects(loadPublicFeed(()=>{throw Error('legacy fallback')},{INTELLIGENCE_SOURCE:'r2'}),/not configured/);
});
test('corrupt objects and manifest fail closed',async()=>{
 const f=fixture();f.objects.set(f.files['data.js'].key,Buffer.from('corrupt'));
 await assert.rejects(loadPublicFeed(null,f.env),/Corrupt/);
 f.objects.set('manifests/'+f.version+'.json',Buffer.from('{}'));
 await assert.rejects(openIntelligenceSnapshot(f.env),/Corrupt/);
});
test('pinning protects a digest read against concurrent pointer replacement',async()=>{
 const f=fixture(),snap=await openIntelligenceSnapshot(f.env);f.objects.set('current.json',Buffer.from('{}'));
 assert.equal((await snap.json('data.js')).advisories[0].id,f.record.id);
});
test('snapshot restore does not replay already delivered revisions',async()=>{
 const f=fixture(),feed=await loadPublicFeed(null,f.env),sent=new Map([[f.record.id,revisionOf(f.record)]]);
 assert.equal(selectDigest(feed.records,['PHP'],'critical',sent).items.length,0);
 assert.equal(selectDigest(feed.records,['PHP'],'critical',new Map()).items.length,1);
});
test('lifecycle and vendor notes use R2 with three day freshness checks',async()=>{
 const f=fixture();assert.equal((await loadLifecycleFeed(f.env)).cycles.length,1);assert.equal((await loadVendorNotes(f.env)).length,1);
 await assert.rejects(loadLifecycleFeed(fixture(73).env),/too old/);assert.deepEqual(await loadVendorNotes(fixture(73).env),[]);
});
test('script responses serialize only fixed global JSON and do not leak private state',async()=>{
 const f=fixture();const response=await intelligenceResponse(new Request('https://example.invalid/malware-data.js'),f.env);
 assert.equal(response.headers.get('X-CVEHarbor-Feed-Version'),f.version);
 assert.doesNotMatch(await response.text(),/<script|<\/script/);
 assert.equal(await intelligenceResponse(new Request('https://example.invalid/data/threat-ip-history.json'),f.env),null);
 assert.equal(await intelligenceResponse(new Request('https://example.invalid/app.js'),f.env),null);
});
test('HTML pins every data wrapper to the same version',()=>{
 const f=fixture(),html=pinIntelligenceScripts('<script src="/data.js"></script><script src="/lifecycle.js?v=2"></script><script src="/app.js"></script>',f.version);
 assert.equal(html.split('feed_version='+f.version).length,3);assert.match(html,/src="\/app.js"/);
});
test('gate still protects intelligence data and configured missing data returns 503',async()=>{
 const f=fixture();let r=await gate.fetch(new Request('https://cveharbor.com/data.js'),{...f.env,SITE_GATE_ENABLED:'true',SITE_GATE_USERNAME:'x',SITE_GATE_PASSWORD:'fixture-password-long'});assert.equal(r.status,401);
 r=await gate.fetch(new Request('https://cveharbor.com/data.js'),{...f.env,SITE_GATE_ENABLED:'false'});assert.equal(r.status,200);
 f.objects.clear();r=await gate.fetch(new Request('https://cveharbor.com/data.js'),{...f.env,SITE_GATE_ENABLED:'false'});assert.equal(r.status,503);
});

test('fresh lifecycle snapshot excludes individually stale retained rows',async()=>{
 const f=fixture(),old=new Date(Date.now()-4*86400000).toISOString();
 const snapshot={json:async name=>name==='lifecycle.js'?{checked_at:new Date().toISOString(),cycles:[{slug:'php',_feed_last_success:old},{slug:'wordpress',_feed_last_success:new Date().toISOString()}]}:{checked_at:new Date().toISOString(),releases:[{slug:'php',_feed_last_success:old}]}};
 assert.deepEqual((await loadLifecycleFeed(f.env,snapshot)).cycles.map(x=>x.slug),['wordpress']);assert.deepEqual(await loadVendorNotes(f.env,snapshot),[]);
});

test('feed outage does not make existing account or remediation HTML unavailable',async()=>{
 const f=fixture();f.objects.clear();
 for(const html of ['<h1>Sign in</h1>','<h1>Remediation</h1><script src="/data.js"></script>']){
  const env={...f.env,SITE_GATE_ENABLED:'false',ASSETS:{fetch:async()=>new Response(html,{headers:{'Content-Type':'text/html'}})}};
  const response=await gate.fetch(new Request('https://cveharbor.com/remediation/'),env);
  assert.equal(response.status,200);assert.equal(await response.text(),html);
 }
});
