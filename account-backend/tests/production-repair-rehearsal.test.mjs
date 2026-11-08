import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {DatabaseSync} from 'node:sqlite';
import {baselineDB} from '../../deployment/proposals/production-compatibility/rehearsal.mjs';
import {artifacts,account,cases,names,denied,marker,markerSQL,syntheticCounts,syntheticSQL,successContinuation,previousPlan,rehearsalJournalObjects,journalCorrectionSQL} from '../../deployment/proposals/production-compatibility/procedure/rehearsal/artifacts.mjs';
import {authorize,run} from '../../deployment/proposals/production-compatibility/procedure/rehearsal/adapter.mjs';
import {target,folder,verifyFiles} from '../../deployment/proposals/production-compatibility/procedure/build.mjs';
import {digest,canonical,schemaSQL} from '../../scripts/production_schema_baseline.mjs';
import {verifyStorage,diskException,custodyException} from '../../deployment/proposals/production-compatibility/procedure/rehearsal/storage-policy.mjs';
import {developmentException} from '../../deployment/proposals/production-compatibility/procedure/rehearsal/development-exception.mjs';
import {privateLog} from '../../deployment/proposals/production-compatibility/procedure/rehearsal/private-log.mjs';
const install=fs.readFileSync(path.join(folder,'install.sql'),'utf8');
const iso=digest({workers:[],pages:[]});
function storageEvidence(){return {version:1,destination:target.private_destination,scope:'pr270-test-data-rehearsal-on-owner-pc',disk_encryption_status:'unverified',disk_encryption_owner_exception:diskException,key_custody_owner_exception:custodyException,key_directory:'D:\\CVEHarbor-Recovery-Keys\\pr270',key_custody:'passphrase-encrypted-online-same-pc',offline_key_custody_verified:false,independent_custody_copy_verified:false,...Object.fromEntries(['owner_only_acl_verified','sync_exclusion_verified','ordinary_sharing_exclusion_verified','trusted_administrative_access_confirmed','capacity_verified','encrypted_packages_required','temporary_plaintext_inventory_required','key_acl_verified','key_sync_and_sharing_exclusion_verified','passphrase_separate_custody_confirmed','recipient_roundtrip_verified'].map(k=>[k,true])),recipient_fingerprint_sha256:'3'.repeat(64),private_evidence_sha256:'4'.repeat(64)};}
function fixture(t,scenario='success'){
 const db=baselineDB();db.exec("INSERT INTO users(id,email) VALUES('pr270-fictional','pr270-fictional@example.invalid')");t.after(()=>db.close());
 const time=Math.floor(Date.now()/1000),a=artifacts();
 const resources=Object.fromEntries(cases.map((c,n)=>[c,{name:names[c],uuid:`11111111-1111-4111-8111-${String(n+1).padStart(12,'0')}`,creation_receipt_sha256:'1'.repeat(64),counts_sha256:digest(syntheticCounts()),isolation_sha256:iso,fixture_sql_sha256:a.manifest.synthetic_sql_sha256}]));
 for(const r of Object.values(resources))r.creation_receipt_sha256=digest({account,uuid:r.uuid,name:r.name,created_at:'2026-11-06T00:00:00Z'});
 const p={version:1,approval_id:'22222222-2222-4222-8222-222222222222',source_sha:'a'.repeat(40),account,manifest_sha256:a.sha256,production_manifest_sha256:verifyFiles().sha256,not_before:time-1,expires_at:time+3600,resources,private_storage_verified:true,no_bindings_or_delivery_credentials:true,external_writers_excluded:true,cost_and_quota_checked:true,private_destination:target.private_destination,max_incremental_usd:5,max_total_bytes:1000000000,max_rows_written:1000000,recovery_evidence_sha256:'2'.repeat(64)};
 p.storage_evidence=storageEvidence();
 const env={CLOUDFLARE_ACCOUNT_ID:account,CLOUDFLARE_API_TOKEN:'fictional-token',REHEARSAL_ENABLED:'true',REHEARSAL_SOURCE_SHA:p.source_sha,REHEARSAL_APPROVAL_SHA256:digest(p)};
 const f={db,p,env,events:[],requests:[],claims:new Set(),failure:null};
 f.journal={append:e=>f.events.push(structuredClone(e)),claim:phase=>{assert.ok(!f.claims.has(phase),'local attempt exists');f.claims.add(phase);}};
 f.fetcher=async(url,options)=>{
  f.requests.push({url,options});assert.ok(url.startsWith('https://api.cloudflare.com/client/v4/accounts/'+account+'/'));
  assert.equal(options.redirect,'error');let result;
  if(options.method==='GET'){
   if(url.includes('/workers/scripts?')||url.includes('/pages/projects'))result=[];
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
  return new Response(JSON.stringify({success:true,result,...(url.includes('/pages/projects')?{result_info:{page:1,per_page:10,count:0,total_count:0,total_pages:0}}:{})}),{headers:{'cf-ray':'fictional-ray'}});
 };
 f.call=phase=>run(env,p,scenario,phase,{fetcher:f.fetcher,journal:f.journal,clock:()=>f.now??Date.now()});
 f.repin=()=>env.REHEARSAL_APPROVAL_SHA256=digest(p);
 f.writes=()=>f.events.filter(e=>e.kind==='write-intent').length;
 return f;
}
// Exact exception identifiers exercised only against fictional in-memory SQLite
// and the mocked fetcher above. No Cloudflare credential or network is used.
function developmentFixture(t,scenario='success'){
 const f=fixture(t,scenario),p=f.p;
 for(const [c,id]of Object.entries(developmentException.resources)){
  p.resources[c].uuid=id;
  p.resources[c].creation_receipt_sha256=digest({account,uuid:id,name:names[c],created_at:'2026-11-06T00:00:00Z'});
 }
 p.not_before=developmentException.not_before;p.expires_at=developmentException.expires_at;
 p.external_writers_excluded=false;
 p.external_writer_exception={id:developmentException.id,accepted_uncertainty:true,inspected_workflows_do_not_target:true,assessment_sha256:'5'.repeat(64)};
 f.now=(p.not_before+60)*1000;
 f.db.function('strftime',(_format,_now)=>String(Math.floor(f.now/1000)));
 f.repin();return f;
}

function continuationFixture(t){
 const f=developmentFixture(t);
 f.db.exec(markerSQL);f.db.prepare(`INSERT INTO ${marker}(id,payload) VALUES('plan',?)`).run(previousPlan());
 f.db.exec(fs.readFileSync(path.join(folder,'rehearsal/previous-bootstrap.sql'),'utf8'));
 f.claims.add('claim'); // Preserve the consumed original claim; never clear it.
 f.p.allowed_scenarios=['success'];f.p.success_continuation=successContinuation;
 const payload={schema_rows:f.db.prepare(schemaSQL).all(),counts:syntheticCounts(),previous_journal_rows:rehearsalJournalObjects(true),previous_plan:previousPlan(),not_before:f.p.not_before,expires_at:f.p.expires_at};
 f.correction=journalCorrectionSQL(payload);f.p.journal_correction_sql_sha256=digest(f.correction);f.repin();return f;
}

function realPrivateJournal(t,f){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'pr270-private-log-'));
 const directory=path.join(root,'run');fs.mkdirSync(directory);
 const realpath=fs.realpathSync;
 t.mock.method(fs,'realpathSync',p=>p===target.private_destination?realpath(root):realpath(p));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 f.journal=privateLog(directory,f.p.approval_id,'success');
 return directory;
}

test('real durable journal supports continuation phases and prevents their replay',async t=>{
 const f=continuationFixture(t),directory=realPrivateJournal(t,f);
 f.journal.claim('claim');
 await f.call('correct-journal');await f.call('continue-claim');await f.call('install');
 const result=await f.call('reconcile');assert.equal(result.installed_schema_match,true);
 assert.deepEqual(result.control,[{write_hold:1,database_frozen:1,revision:0}]);
 for(const phase of ['claim','correct-journal','continue-claim','install']){
  const file=path.join(directory,f.p.approval_id+'-success-'+phase+'.claim');
  const before=fs.readFileSync(file);assert.equal(JSON.parse(before).phase,phase);
  assert.throws(()=>f.journal.claim(phase),{code:'EEXIST'});
  assert.deepEqual(fs.readFileSync(file),before);
 }
 const before=fs.readdirSync(directory).sort();
 for(const phase of ['../install','correct/journal','correct--journal','reconcile','inventory','resume','delete',''])assert.throws(()=>f.journal.claim(phase),/Unknown mutating rehearsal phase/);
 assert.deepEqual(fs.readdirSync(directory).sort(),before);
});

test('real durable correction claim survives a lost response and prevents resubmission',async t=>{
 const f=continuationFixture(t),directory=realPrivateJournal(t,f),fetcher=f.fetcher;let submitted=0;
 f.fetcher=async(url,options)=>{const response=await fetcher(url,options);if(options.body&&JSON.parse(options.body).sql===f.correction){submitted++;throw Error('Fictional lost correction response');}return response;};
 await assert.rejects(()=>f.call('correct-journal'));assert.equal(submitted,1);
 assert.ok(fs.existsSync(path.join(directory,f.p.approval_id+'-success-correct-journal.claim')));
 await assert.rejects(()=>f.call('correct-journal'));assert.equal(submitted,1);
 const result=await f.call('reconcile');assert.deepEqual(result.receipt_ids,[]);assert.deepEqual(result.attempt_ids,['plan']);
});

test('preserved success journal replaces only sequence trigger, then continues claim and installation once',async t=>{
 const f=continuationFixture(t),before=f.db.prepare(`SELECT payload FROM ${marker} WHERE id='plan'`).get().payload;
 await assert.rejects(()=>f.call('claim'));assert.equal(f.requests.length,0);
 await assert.rejects(()=>f.call('continue-claim'));assert.equal(f.writes(),0);
 assert.equal((await f.call('correct-journal')).status,'journal-correction-acknowledged-verification-required');
 assert.equal(f.db.prepare(`SELECT payload FROM ${marker} WHERE id='plan'`).get().payload,before);
 assert.equal(f.db.prepare('SELECT COUNT(*) n FROM d1_cveharbor_repair_receipts').get().n,0);
 await f.call('continue-claim');await f.call('install');
 const r=await f.call('reconcile');assert.equal(r.installed_schema_match,true);assert.equal(r.baseline_counts_match,true);assert.deepEqual(r.control,[{write_hold:1,database_frozen:1,revision:0}]);
 assert.equal(f.writes(),5);assert.ok(f.claims.has('claim'));assert.ok(f.claims.has('continue-claim'));
 const payload=JSON.parse(f.db.prepare("SELECT payload FROM d1_cveharbor_repair_receipts WHERE id='installed'").get().payload);
 assert.equal(payload.source_sha,f.p.source_sha);assert.deepEqual(payload.success_continuation,successContinuation);
 await assert.rejects(()=>f.call('install'));assert.equal(f.writes(),5);
});

test('success continuation rejects stale history, retargeting, missing authorization and changed correction bytes',async t=>{
 for(const alter of [f=>f.p.success_continuation={...successContinuation,previous_source_sha:'b'.repeat(40)},f=>delete f.p.success_continuation,f=>f.p.allowed_scenarios=['success','schema'],f=>f.p.resources.success.uuid=f.p.resources.schema.uuid,f=>f.env.REHEARSAL_ENABLED='false']){
  const f=continuationFixture(t);alter(f);f.repin();await assert.rejects(()=>f.call('correct-journal'));assert.equal(f.requests.length,0);
 }
 const f=continuationFixture(t);f.p.journal_correction_sql_sha256='0'.repeat(64);f.repin();await assert.rejects(()=>f.call('correct-journal'));assert.equal(f.writes(),0);
});

test('uncertain trigger correction preserves claim and reconciles without resubmitting',async t=>{
 const f=continuationFixture(t),fetcher=f.fetcher;
 f.fetcher=async(url,options)=>{const result=await fetcher(url,options);if(options.body&&JSON.parse(options.body).sql===f.correction)throw Error('lost correction reply');return result;};
 await assert.rejects(()=>f.call('correct-journal'));assert.ok(f.claims.has('correct-journal'));assert.equal(f.writes(),1);
 await assert.rejects(()=>f.call('correct-journal'));assert.equal(f.writes(),1);
 const r=await f.call('reconcile');assert.equal(r.baseline_counts_match,true);assert.deepEqual(r.receipt_ids,[]);assert.deepEqual(r.attempt_ids,['plan']);
});

test('development exception records accepted uncertainty and preserves the exact successful batch',async t=>{
 const f=developmentFixture(t);
 await f.call('claim');await f.call('install');
 const r=await f.call('reconcile');assert.equal(r.installed_schema_match,true);assert.equal(r.baseline_counts_match,true);
 assert.deepEqual(r.control,[{write_hold:1,database_frozen:1,revision:0}]);
 assert.equal(f.p.external_writers_excluded,false);
 assert.ok(f.events.some(e=>e.kind==='accepted-external-writer-uncertainty'&&e.external_writers_excluded===false&&e.id===developmentException.id));
 assert.equal(f.requests.filter(r=>r.options.body&&JSON.parse(r.options.body).sql===install).length,1);
});

test('development exception rejects missing acceptance, retargeting, window changes and stale authorization before network',async t=>{
 for(const change of [
  f=>delete f.p.external_writer_exception,
  f=>f.p.external_writers_excluded=true,
  f=>f.p.external_writer_exception.accepted_uncertainty=false,
  f=>f.p.external_writer_exception.inspected_workflows_do_not_target=false,
  f=>f.p.external_writer_exception.id='other-rehearsal',
  f=>delete f.p.external_writer_exception.assessment_sha256,
  f=>f.p.resources.lost.uuid='11111111-1111-4111-8111-111111111111',
  f=>{const r=f.p.resources;[r.schema.uuid,r.count.uuid]=[r.count.uuid,r.schema.uuid];},
  ...denied.map(id=>f=>f.p.resources.success.uuid=id),
  f=>f.p.account=target.account,
  f=>f.p.not_before++,f=>f.p.expires_at--,
  f=>f.now=(f.p.not_before-1)*1000,f=>f.now=(f.p.expires_at+1)*1000,
  f=>f.p.cost_and_quota_checked=false,f=>f.p.max_rows_written++,
  f=>f.env.REHEARSAL_ENABLED='false',f=>delete f.p.recovery_evidence_sha256,
  f=>f.p.no_bindings_or_delivery_credentials=false,f=>f.p.private_storage_verified=false,
  f=>f.p.source_sha='b'.repeat(40),f=>f.p.manifest_sha256='0'.repeat(64)
 ]){
  const f=developmentFixture(t);change(f);f.repin();await assert.rejects(()=>f.call('claim'));assert.equal(f.requests.length,0);
 }
 const f=developmentFixture(t);f.p.external_writer_exception.assessment_sha256='6'.repeat(64);
 await assert.rejects(()=>f.call('claim'));assert.equal(f.requests.length,0,'changed exception invalidates approval pin');
});

test('development exception still stops on live bindings, snapshot changes and ambiguous writes',async t=>{
 for(const kind of ['binding','counts','schema']){
  const f=developmentFixture(t);
  if(kind==='binding'){
   const original=f.fetcher;
   f.fetcher=async(url,options)=>url.includes('/pages/projects')?new Response(JSON.stringify({success:true,result:[{name:'unexpected',deployment_configs:{production:{d1_databases:{DB:{id:f.p.resources.success.uuid}}},preview:{}}}],result_info:{page:1,per_page:10,count:1,total_count:1,total_pages:1}})):original(url,options);
  }else if(kind==='counts')f.db.exec("INSERT INTO users(id,email) VALUES('unexpected','unexpected@example.invalid')");
  else f.db.exec('CREATE TABLE unexpected(id TEXT)');
  await assert.rejects(()=>f.call('claim'));assert.equal(f.writes(),0);
 }
 const f=developmentFixture(t,'lost');await f.call('claim');await assert.rejects(()=>f.call('install'));
 const n=f.writes();f.claims.clear();await assert.rejects(()=>f.call('install'));assert.equal(f.writes(),n);
 f.now=(f.p.expires_at+1)*1000;
 assert.equal((await f.call('reconcile')).installed_schema_match,true,'read-only reconciliation remains available after expiry');
 assert.equal(f.writes(),n);
});
test('isolated artifact pins retain exact reviewed production batch and synthetic baseline',()=>{
 const a=artifacts();assert.equal(a.manifest.production_manifest_sha256,'3e6293f1d8be736a0a95b8cf53636302a034215fabd4ec352210319e42c3b7c3');
 assert.equal(digest(install),'0342629e85f763837f63332e09b98bf448211a00ce06dc0cfe2f292bf604f8ac');assert.equal(digest(syntheticSQL()),a.manifest.synthetic_sql_sha256);
 const db=new DatabaseSync(':memory:');try{db.exec(syntheticSQL());assert.equal(digest(canonical(db.prepare(schemaSQL).all())),target.baseline_schema_sha256);assert.equal(db.prepare('SELECT COUNT(*) n FROM users').get().n,1);}finally{db.close();}
});
test('owner exceptions never assert full disk encryption or independent offline custody',()=>{
 assert.doesNotThrow(()=>verifyStorage(storageEvidence(),target.private_destination));
 for(const [key,value] of [['disk_encryption_status','verified'],['disk_encryption_owner_exception',null],['scope','production'],['key_custody_owner_exception',null],['key_directory','C:\\other'],['offline_key_custody_verified',true],['independent_custody_copy_verified',true]]){
  assert.throws(()=>verifyStorage({...storageEvidence(),[key]:value},target.private_destination));
 }
 for(const [key,value] of Object.entries(storageEvidence()))if(value===true)assert.throws(()=>verifyStorage({...storageEvidence(),[key]:false},target.private_destination));
});
test('missing private storage evidence rejects before any network request',async t=>{
 const f=fixture(t);delete f.p.storage_evidence;f.repin();await assert.rejects(()=>f.call('inventory'));assert.equal(f.requests.length,0);
 const g=fixture(t);g.p.storage_evidence.recipient_roundtrip_verified=false;g.repin();await assert.rejects(()=>g.call('claim'));assert.equal(g.requests.length,0);
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
   else if(kind==='pages'&&url.includes('/pages/projects'))result=[{name:'fictional-pages',deployment_configs:{production:{d1_databases:{DB:{id}}},preview:{}}}];
   else return original(url,options);
   return new Response(JSON.stringify({success:true,result,...(kind==='pages'?{result_info:{page:1,per_page:10,count:1,total_count:1,total_pages:1}}:{})}));
  };
  await assert.rejects(()=>f.call('claim'));assert.equal(f.writes(),0);
 }
});
// The account currently has no Pages projects. Multi-page responses below are
// fictional contract tests, not claims about a remote multi-page observation.
const project=name=>({name,deployment_configs:{production:{},preview:{}}});
function pagesFixture(f,responses){
 const original=f.fetcher,seen=[];
 f.fetcher=async(url,options)=>{
  if(!url.includes('/pages/projects'))return original(url,options);
  seen.push(new URL(url).pathname+new URL(url).search);assert.equal(options.method,'GET');
  assert.equal(new URL(url).search,seen.length===1?'':'?page='+seen.length);
  const response=responses[seen.length-1];assert.ok(response,'Unexpected Pages retry or extra request');
  return new Response(JSON.stringify(response.body??response),{status:response.status??200});
 };
 return seen;
}
const pageBody=(page,results,total=3,size=2)=>({success:true,result:results,result_info:{page,per_page:size,count:results.length,total_count:total,total_pages:Math.ceil(total/size)}});

test('Pages observed 400 rejection is never treated as empty or retried with different parameters',async t=>{
 for(const status of [400,200]){
  const f=fixture(t),seen=pagesFixture(f,[{status,body:{success:false,result:[],errors:[{code:8000024,message:'Invalid list options provided. Review the page or per_page parameter.'}]}}]);
  await assert.rejects(()=>f.call('inventory'),/Provider rejected request/);assert.equal(seen.length,1);assert.equal(f.writes(),0);
 }
 const f=fixture(t);pagesFixture(f,[{status:400,body:pageBody(1,[],0)}]);
 await assert.rejects(()=>f.call('inventory'),/Provider rejected request/);assert.equal(f.writes(),0);
});

test('Pages verified empty inventory accepts provider default metadata without per_page override',async t=>{
 for(const totalPages of [0,1]){
  const f=fixture(t),body=pageBody(1,[],0,10);body.result_info.total_pages=totalPages;
  const seen=pagesFixture(f,[body]);assert.equal((await f.call('inventory')).isolation_sha256,iso);
  assert.equal(seen.length,1);assert.ok(seen[0].endsWith('/pages/projects'));assert.equal(f.writes(),0);
 }
});

test('Pages inventory collects every page using the provider size and includes later projects in its digest',async t=>{
 const f=fixture(t),projects=['alpha','beta','gamma'].map(project);
 const seen=pagesFixture(f,[pageBody(1,projects.slice(0,2)),pageBody(2,projects.slice(2))]);
 assert.equal((await f.call('inventory')).isolation_sha256,digest({workers:[],pages:projects}));
 assert.equal(seen.length,2);assert.ok(seen[1].endsWith('?page=2'));assert.equal(f.writes(),0);
});

test('Pages missing, inconsistent, duplicate or drifting pagination rejects completeness',async t=>{
 const a=project('a'),b=project('b'),c=project('c');
 const cases=[
  [{success:true,result:[]}],
  [{...pageBody(1,[],0),result_info:{page:1,per_page:10}}],
  [{...pageBody(1,[],0),result_info:{page:1,per_page:0,count:0,total_count:0,total_pages:0}}],
  [pageBody(2,[],0)],
  [pageBody(1,[a],3)], // short first page with undisclosed remaining items
  [{...pageBody(1,[a,b]),result_info:{page:1,per_page:2,count:1,total_count:3,total_pages:2}}],
  [pageBody(1,[a,b]),pageBody(2,[])],
  [pageBody(1,[a,b]),pageBody(1,[a,b])],
  [pageBody(1,[a,b]),pageBody(2,[a])], // duplicate replaces unseen project
  [pageBody(1,[a,b]),pageBody(2,[c],4)],
  [pageBody(1,[a,b]),pageBody(2,[],3,3)],
  [{...pageBody(1,[a,b]),result_info:{page:1,per_page:2,count:2,total_count:3,total_pages:1}}],
  [pageBody(1,[a],101,1)],
  [pageBody(1,[{deployment_configs:{production:{},preview:{}}}],1,1)]
 ];
 for(const responses of cases){const f=fixture(t);pagesFixture(f,responses);await assert.rejects(()=>f.call('inventory'));assert.equal(f.writes(),0);}
});

test('Pages error on a later page does not return the earlier partial inventory',async t=>{
 const f=fixture(t),seen=pagesFixture(f,[pageBody(1,[project('a'),project('b')]),{status:400,body:{success:false,errors:[{code:8000024}]}}]);
 await assert.rejects(()=>f.call('inventory'),/Provider rejected request/);assert.equal(seen.length,2);assert.equal(f.writes(),0);
});

test('Pages prohibited binding or missing deployment configuration on a later page prevents writes',async t=>{
 for(const kind of ['production','preview','missing']){
  const f=fixture(t),later=project('later');
  if(kind==='missing')delete later.deployment_configs.preview;
  else later.deployment_configs[kind].d1_databases={DB:{id:f.p.resources.success.uuid}};
  const seen=pagesFixture(f,[pageBody(1,[project('first')],2,1),pageBody(2,[later],2,1)]);
  await assert.rejects(()=>f.call('claim'),kind==='missing'?/Incomplete Pages isolation evidence/:/Pages binding detected/);
  assert.equal(seen.length,2);assert.equal(f.writes(),0);assert.equal(f.claims.size,0);
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
