import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {baselineDB} from '../../deployment/proposals/production-compatibility/rehearsal.mjs';
import {artifacts,account,cases,names,denied,marker,syntheticCounts,syntheticSQL} from '../../deployment/proposals/production-compatibility/procedure/rehearsal/artifacts.mjs';
import {authorize,run} from '../../deployment/proposals/production-compatibility/procedure/rehearsal/adapter.mjs';
import {target,folder,verifyFiles} from '../../deployment/proposals/production-compatibility/procedure/build.mjs';
import {digest,canonical,schemaSQL} from '../../scripts/production_schema_baseline.mjs';
const install=fs.readFileSync(path.join(folder,'install.sql'),'utf8');
const iso=digest({workers:[],pages:[]});
function fixture(t,scenario='success'){
 const db=baselineDB();db.exec("INSERT INTO users(id,email) VALUES('pr270-fictional','pr270-fictional@example.invalid')");t.after(()=>db.close());
 const time=Math.floor(Date.now()/1000),a=artifacts();
 const resources=Object.fromEntries(cases.map((c,n)=>[c,{name:names[c],uuid:`11111111-1111-4111-8111-${String(n+1).padStart(12,'0')}`,creation_receipt_sha256:'1'.repeat(64),counts_sha256:digest(syntheticCounts()),isolation_sha256:iso,fixture_sql_sha256:a.manifest.synthetic_sql_sha256}]));
 for(const r of Object.values(resources))r.creation_receipt_sha256=digest({account,uuid:r.uuid,name:r.name,created_at:'2026-11-06T00:00:00Z'});
 const p={version:1,approval_id:'22222222-2222-4222-8222-222222222222',source_sha:'a'.repeat(40),account,manifest_sha256:a.sha256,production_manifest_sha256:verifyFiles().sha256,not_before:time-1,expires_at:time+3600,resources,private_storage_verified:true,no_bindings_or_delivery_credentials:true,external_writers_excluded:true,cost_and_quota_checked:true,private_destination:target.private_destination,max_incremental_usd:5,max_total_bytes:1000000000,max_rows_written:1000000,recovery_evidence_sha256:'2'.repeat(64)};
 const env={CLOUDFLARE_ACCOUNT_ID:account,CLOUDFLARE_API_TOKEN:'fictional-token',REHEARSAL_ENABLED:'true',REHEARSAL_SOURCE_SHA:p.source_sha,REHEARSAL_APPROVAL_SHA256:digest(p)};
 const f={db,p,env,events:[],requests:[],claims:new Set(),failure:null};
 f.journal={append:e=>f.events.push(structuredClone(e)),claim:phase=>{assert.ok(!f.claims.has(phase),'local attempt exists');f.claims.add(phase);}};
 f.fetcher=async(url,options)=>{
  f.requests.push({url,options});assert.ok(url.startsWith('https://api.cloudflare.com/client/v4/accounts/'+account+'/'));
  assert.equal(options.redirect,'error');let result;
  if(options.method==='GET'){
   if(url.includes('/workers/scripts?')||url.includes('/pages/projects?'))result=[];
   else result={uuid:resources[scenario].uuid,name:resources[scenario].name,created_at:'2026-11-06T00:00:00Z',file_size:4096};
   if(f.failure==='wrong-name'&&!Array.isArray(result))result.name='cveharbor-accounts-staging';
  }else{
   assert.ok(url.endsWith('/d1/database/'+resources[scenario].uuid+'/query'));
   const {sql,params}=JSON.parse(options.body);
   if(sql===install&&f.failure==='abort')return new Promise((_resolve,reject)=>{if(options.signal.aborted)reject(Error('Fictional disconnect'));else options.signal.addEventListener('abort',()=>reject(Error('Fictional disconnect')),{once:true});});
   if(sql===install&&f.failure==='writer-first')await new Promise(resolve=>setImmediate(resolve));
   try{
    if(sql===install&&f.failure==='partial'){db.exec(sql.slice(0,sql.indexOf('CREATE TABLE IF NOT EXISTS operations_control')));throw Error('Fictional partial commit');}
    if(/^SELECT\b/.test(sql))result=[{success:true,meta:{rows_written:0},results:db.prepare(sql).all(...params)}];
    else{if(params.length)db.prepare(sql).run(...params);else db.exec(sql);result=[{success:true,meta:{rows_written:1},results:[]}];}
   }catch{return new Response(JSON.stringify({success:false,errors:[{message:'fictional-sensitive-record'}]}),{status:400,headers:{'cf-ray':'fictional-ray'}});}
  }
  return new Response(JSON.stringify({success:true,result}),{headers:{'cf-ray':'fictional-ray'}});
 };
 f.call=phase=>run(env,p,scenario,phase,{fetcher:f.fetcher,journal:f.journal});
 f.repin=()=>env.REHEARSAL_APPROVAL_SHA256=digest(p);
 f.writes=()=>f.events.filter(e=>e.kind==='write-intent').length;
 return f;
}
test('isolated artifact pins retain exact reviewed production batch and synthetic baseline',()=>{
 const a=artifacts();assert.equal(a.manifest.production_manifest_sha256,'4dd094b957dc21421a0daf35f6e99b28cfac42ae60b26dee15bf2b6b12e5b42c');
 assert.equal(digest(install),'2932acfd414c14e850d994b5aa31cc098aea6145ced7f32188c8b9edd18e7c46');assert.equal(digest(syntheticSQL()),a.manifest.synthetic_sql_sha256);
 const db=new DatabaseSync(':memory:');try{db.exec(syntheticSQL());assert.equal(digest(canonical(db.prepare(schemaSQL).all())),target.baseline_schema_sha256);assert.equal(db.prepare('SELECT COUNT(*) n FROM users').get().n,1);}finally{db.close();}
});
test('wrong/unapproved targets, duplicate UUIDs, stale approval, missing recovery and disabled runtime reject before network',async t=>{
 for(const mutate of [f=>f.p.account=target.account,...denied.map(id=>f=>f.p.resources.success.uuid=id),f=>f.p.resources.success.name='unknown',f=>f.p.resources.success.uuid=null,f=>f.p.resources.success.uuid=f.p.resources.schema.uuid,f=>{f.p.not_before-=100;f.p.expires_at=f.p.not_before+1;},f=>delete f.p.recovery_evidence_sha256,f=>f.env.REHEARSAL_ENABLED='false',f=>f.p.source_sha='b'.repeat(40),f=>f.p.manifest_sha256='0'.repeat(64)]){
  const f=fixture(t);mutate(f);f.repin();await assert.rejects(()=>f.call('claim'));assert.equal(f.requests.length,0);
 }
 const f=fixture(t);f.env.REHEARSAL_APPROVAL_SHA256='0'.repeat(64);await assert.rejects(()=>f.call('claim'));assert.equal(f.requests.length,0);
});
test('wrong live name, binding/isolation drift and restored snapshot mismatch stop before writes',async t=>{
 for(const kind of ['wrong-name','isolation','counts','creation']){
  const f=fixture(t);if(kind==='wrong-name')f.failure=kind;
  if(kind==='isolation')f.p.resources.success.isolation_sha256='f'.repeat(64);
  if(kind==='counts')f.p.resources.success.counts_sha256='f'.repeat(64);
  if(kind==='creation')f.p.resources.success.creation_receipt_sha256='f'.repeat(64);
  f.repin();await assert.rejects(()=>f.call('claim'));assert.equal(f.writes(),0);
 }
});
test('Worker or Pages bindings and incomplete inventories reject before mutations',async t=>{
 for(const kind of ['worker','pages','incomplete','version']){
  const f=fixture(t),original=f.fetcher,id=f.p.resources.success.uuid;
  f.fetcher=async(url,options)=>{
   let result;
   if(kind==='incomplete'&&url.includes('/workers/scripts?'))result={incomplete:true};
   else if(['worker','version'].includes(kind)&&url.includes('/workers/scripts?'))result=[{id:'fictional-worker'}];
   else if(url.endsWith('/settings'))result={bindings:kind==='version'?[]:[{type:'d1',name:'DB',id}]};
   else if(url.endsWith('/deployments'))result={deployments:kind==='version'?[{versions:[{version_id:'33333333-3333-4333-8333-333333333333'}]}]:[]};
   else if(url.includes('/versions/'))result={id:'33333333-3333-4333-8333-333333333333',resources:{}};
   else if(kind==='pages'&&url.includes('/pages/projects?'))result=[{name:'fictional-pages',deployment_configs:{production:{d1_databases:{DB:{id}}},preview:{}}}];
   else return original(url,options);
   return new Response(JSON.stringify({success:true,result}));
  };
  await assert.rejects(()=>f.call('claim'));assert.equal(f.writes(),0);
 }
});
test('successful batch remains byte-identical, frozen, data preserving and never resumes',async t=>{
 const f=fixture(t);f.p.expires_at=f.p.not_before+600;f.repin();await f.call('claim');
 assert.equal(JSON.parse(f.db.prepare("SELECT payload FROM d1_cveharbor_repair_receipts WHERE id='install-started'").get().payload).expires_at,f.p.expires_at,'DB window cannot outlive owner approval');
 assert.equal((await f.call('install')).status,'acknowledged-reconcile-required');
 const report=await f.call('reconcile');assert.equal(report.installed_schema_match,true);assert.equal(report.baseline_counts_match,true);assert.equal(report.receipt_payloads_match,true);assert.equal(report.leases,0);assert.equal(report.contexts,0);assert.deepEqual(report.control,[{write_hold:1,database_frozen:1,revision:0}]);
 assert.equal(f.requests.filter(r=>r.options.body&&JSON.parse(r.options.body).sql===install).length,1);
 const n=f.writes();await assert.rejects(()=>f.call('install'));assert.equal(f.writes(),n);assert.equal(report.remote_atomicity_established,false);
});
test('post-claim schema and row-count drift reject installation without repair objects or receipt',async t=>{
 for(const scenario of ['schema','count']){
  const f=fixture(t,scenario);await f.call('claim');await f.call('perturb');const schema=f.db.prepare("SELECT sql FROM sqlite_schema ORDER BY name").all();
  await assert.rejects(()=>f.call('install'));assert.deepEqual(f.db.prepare("SELECT sql FROM sqlite_schema ORDER BY name").all(),schema);
  const r=await f.call('reconcile');assert.equal(r.installed_schema_match,false);assert.ok(!r.receipt_ids.includes('installed'));const n=f.writes();await assert.rejects(()=>f.call('install'));assert.equal(f.writes(),n);
 }
});
test('database expiry after claim and deliberately missing start claim produce rejected assertions',async t=>{
 for(const scenario of ['expiry','rejected']){
  const f=fixture(t,scenario);await f.call('claim');
  if(scenario==='expiry'){const future=Math.floor(Date.now()/1000)+100;f.db.function('strftime',(_format,_now)=>String(future));}
  await assert.rejects(()=>f.call('install'));const r=await f.call('reconcile');assert.equal(r.installed_schema_match,false);assert.equal(r.baseline_counts_match,true);assert.ok(!r.receipt_ids.includes('installed'));
 }
});
test('both simulated concurrent orderings stop for reconciliation and retain evidence without retries',async t=>{
 for(const order of [null,'writer-first']){
  const f=fixture(t,'race');await f.call('claim');f.failure=order;await assert.rejects(()=>f.call('install'));
  const r=await f.call('reconcile');assert.equal(r.installed_schema_match,!order);assert.equal(r.baseline_counts_match,!order);assert.ok(f.events.some(e=>e.kind==='concurrent-requests-settled'&&e.ordering_proven===false));
  const n=f.writes();await assert.rejects(()=>f.call('install'));assert.equal(f.writes(),n);
 }
});
test('client cancellation and discarded successful reply are labelled simulations and cannot replay after restart',async t=>{
 for(const scenario of ['interrupt','lost']){
  const f=fixture(t,scenario);await f.call('claim');if(scenario==='interrupt')f.failure='abort';
  await assert.rejects(()=>f.call('install'));const r=await f.call('reconcile');assert.equal(r.installed_schema_match,scenario==='lost');assert.ok(f.events.some(e=>e.simulation===scenario));
  const n=f.writes();f.claims.clear();await assert.rejects(()=>f.call('install'));assert.equal(f.writes(),n,'durable D1 claim blocks fresh local process');
  assert.ok(!JSON.stringify(f.events).includes('fictional-sensitive-record'));assert.ok(!JSON.stringify(f.events).includes('fictional-token'));
 }
});
test('simulated partial provider execution never authorizes retries, reset or production safety claims',async t=>{
 const f=fixture(t);await f.call('claim');f.failure='partial';await assert.rejects(()=>f.call('install'));
 const r=await f.call('reconcile');assert.equal(r.installed_schema_match,false);assert.equal(r.remote_atomicity_established,false);const n=f.writes();f.claims.clear();await assert.rejects(()=>f.call('install'));assert.equal(f.writes(),n);
});
test('lost durable claim acknowledgement and private journal failures stop further mutations',async t=>{
 const f=fixture(t);await f.call('claim');const fetcher=f.fetcher;
 f.fetcher=async(url,options)=>{const result=await fetcher(url,options);if(options.body&&JSON.parse(options.body).sql===`INSERT INTO ${marker}(id,payload) VALUES('install',?)`)throw Error('lost claim reply');return result;};
 await assert.rejects(()=>f.call('install'));assert.ok(!f.requests.some(r=>r.options.body&&JSON.parse(r.options.body).sql===install));
 const n=f.writes();f.claims.clear();await assert.rejects(()=>f.call('install'));assert.equal(f.writes(),n);
 const g=fixture(t);g.journal.claim=()=>{throw Error('disk failure');};await assert.rejects(()=>g.call('claim'));assert.equal(g.writes(),0);
});
test('read-only reconciliation remains available after approval expiry without enabling writes',async t=>{
 const f=fixture(t);await f.call('claim');const later=(f.p.expires_at+3600)*1000;
 authorize(f.env,f.p,'success','reconcile',later);assert.throws(()=>authorize(f.env,f.p,'success','install',later));
 const n=f.writes();await run(f.env,f.p,'success','reconcile',{fetcher:f.fetcher,journal:f.journal,clock:()=>later});assert.equal(f.writes(),n);
});
