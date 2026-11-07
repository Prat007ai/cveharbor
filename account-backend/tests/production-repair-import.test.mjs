import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {checkRehearsalWrites} from '../../deployment/proposals/production-compatibility/procedure/rehearsal/import-cost.mjs';
import {transferAndImport,transferURL} from '../../deployment/proposals/production-compatibility/procedure/rehearsal/import-once.mjs';
function fixture(){
 const calls=[],saved=new Map();const f={calls,saved,fail:null};
 const bytes=Buffer.from('CREATE TABLE fictional(id INTEGER);');
 f.args={etag:createHash('md5').update(bytes).digest('hex'),bytes,expectedSha256:createHash('sha256').update(bytes).digest('hex'),sleep:async()=>{},checkWindow:()=>{},beforeIngest:async()=>{},
 save:(key,value)=>{assert.ok(!saved.has(key),'existing intent');saved.set(key,value);},
 put:async()=>{calls.push('put');if(f.fail==='put')throw Error('uncertain upload');return {ok:true};},
 api:async(body)=>{calls.push(body);if(f.fail===body.action)throw Error('uncertain response');if(body.action==='init')return {filename:'fictional.sql',upload_url:'https://fictional.r2.cloudflarestorage.com/object?signature=fictional'};if(body.action==='ingest')return {at_bookmark:'same-import'};assert.deepEqual(body,{action:'poll',current_bookmark:'same-import'});return {status:'complete',success:true};}};
 return f;
}
test('missing failed-import billing consumes a reserve, never zero or an invented actual count',()=>{
 assert.deepEqual(checkRehearsalWrites(0),{failed_import_billable_writes:'unknown',failed_import_reserved_writes:500000,failed_claim_billable_writes:'unknown',failed_claim_reserved_writes:10000,accounted_writes:510000,remaining_writes:490000});
 assert.equal(checkRehearsalWrites(193195,30000).remaining_writes,296805);
 assert.equal(checkRehearsalWrites(200000,10000).remaining_writes,290000);
 assert.throws(()=>checkRehearsalWrites(499999,2));assert.throws(()=>checkRehearsalWrites(NaN));
});
test('single upload/ingest, polling only the known import; persisted attempt prevents replay',async()=>{
 const f=fixture();assert.equal((await transferAndImport(f.args)).status,'complete');assert.deepEqual(f.calls.map(x=>typeof x==='string'?x:x.action),['init','put','ingest','poll']);
 const n=f.calls.length;await assert.rejects(()=>transferAndImport(f.args));assert.equal(f.calls.length,n);
});
test('oversized statements, incomplete SQL and changed approval bytes never reach upload initialization',async()=>{
 for(const bytes of [Buffer.from("INSERT INTO t VALUES('"+'é'.repeat(60000)+"');"),Buffer.from('CREATE TABLE incomplete(')]){
  const f=fixture();f.args.bytes=bytes;f.args.expectedSha256=createHash('sha256').update(bytes).digest('hex');f.args.etag=createHash('md5').update(bytes).digest('hex');
  await assert.rejects(()=>transferAndImport(f.args));assert.equal(f.calls.length,0);assert.equal(f.saved.size,0);
 }
 const f=fixture();f.args.expectedSha256='0'.repeat(64);await assert.rejects(()=>transferAndImport(f.args));assert.equal(f.calls.length,0);
});
test('uncertain initialization, upload, ingestion or polling is never retried',async()=>{
 for(const failure of ['init','put','ingest','poll']){const f=fixture();f.fail=failure;await assert.rejects(()=>transferAndImport(f.args));const labels=f.calls.map(x=>typeof x==='string'?x:x.action);assert.equal(labels.filter(x=>x===failure).length,1);assert.equal(labels.at(-1),failure);}
});
test('expiry, unexpected target and untrusted upload destinations stop before ingest',async()=>{
 for(const url of ['http://fictional.r2.cloudflarestorage.com/a','https://cloudflarestorage.com.evil.invalid/a','https://user:secret@fictional.r2.cloudflarestorage.com/a','https://fictional.r2.cloudflarestorage.com:8443/a','https://api.cloudflare.com/a'])assert.throws(()=>transferURL(url));
 const expired=fixture();expired.args.checkWindow=()=>{throw Error('outside window');};await assert.rejects(()=>transferAndImport(expired.args));assert.equal(expired.calls.length,0);
 const drift=fixture();drift.args.beforeIngest=async()=>{throw Error('target no longer empty');};await assert.rejects(()=>transferAndImport(drift.args));assert.ok(!drift.calls.some(x=>x.action==='ingest'));
 const bad=fixture();bad.args.api=async()=>({filename:'test',upload_url:'https://evil.invalid/a'});await assert.rejects(()=>transferAndImport(bad.args));assert.ok(!bad.calls.includes('put'));
});
