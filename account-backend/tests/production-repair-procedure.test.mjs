import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {generateKeyPairSync,sign} from 'node:crypto';
import {baselineDB} from '../../deployment/proposals/production-compatibility/rehearsal.mjs';
import {folder,target,receiptTable,verifyFiles,journalObjects,quote} from '../../deployment/proposals/production-compatibility/procedure/build.mjs';
import {execute,inspect,verifyRecovery,authorizeWrite} from '../../deployment/proposals/production-compatibility/procedure/execute.mjs';
import {transport,verifyGitHubGate} from '../../deployment/proposals/production-compatibility/procedure/transport.mjs';
import {digest,canonical} from '../../scripts/production_schema_baseline.mjs';
import {releaseReadiness} from '../src/release-readiness.js';
import {unifiedFixture} from './helpers/unified-db.mjs';
const plain=x=>JSON.parse(JSON.stringify(x)),a=verifyFiles(),now=()=>Math.floor(Date.now()/1000);
const {privateKey,publicKey}=generateKeyPairSync('ed25519');
async function fixture(t){
 const db=baselineDB(),original=await unifiedFixture();
 db.exec('BEGIN; PRAGMA defer_foreign_keys=ON');
 for(const {name} of original.DB.sql.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").all())for(const row of original.DB.sql.prepare('SELECT * FROM '+quote(name)).all()){
  const keys=Object.keys(row);db.prepare('INSERT INTO '+quote(name)+'('+keys.map(quote).join(',')+') VALUES('+keys.map(()=>'?').join(',')+')').run(...keys.map(k=>row[k]));
 }
 db.exec('COMMIT');original.DB.sql.close();t.after(()=>db.close());
 const f={db,writes:[],reports:[],metadata:{account:target.account,database:target.database,worker_version:target.worker_version,deployment:'fictional-deployment',configuration_sha256:'1'.repeat(64),recovery_required:true}};
 const env={GITHUB_REPOSITORY:'Prat007ai/cveharbor',GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_SHA:'a'.repeat(40),GITHUB_RUN_ID:'1234',GITHUB_RUN_ATTEMPT:'1',REPAIR_APPROVED_SOURCE:'a'.repeat(40),REPAIR_MANIFEST_SHA256:a.sha256,CLOUDFLARE_ACCOUNT_ID:target.account,PRODUCTION_COMPATIBILITY_REPAIR_ENABLED:'true',REPAIR_OPERATION:'preflight'};
 f.env=env;f.client={protection:async()=>({owner_review_verified:true}),select:async(sql,params=[])=>plain(db.prepare(sql).all(...params)),observe:async()=>plain(f.metadata),readiness:async()=>{
  const DB={prepare:sql=>({first:async()=>db.prepare(sql).get(),all:async()=>({results:db.prepare(sql).all()})})};
  const response=await releaseReadiness({DB}),r=await response.json();return {http:response.status,ready:r.ready,held:r.held,schema_ready:r.schema_ready};
 },writeOnce:async(sql,params=[])=>{f.writes.push({sql,params});if(params.length)db.prepare(sql).run(...params);else db.exec(sql);return [];} };
 f.run=operation=>execute({...env,REPAIR_OPERATION:operation},{client:f.client,record:r=>f.reports.push(r)});
 f.approve=async(operation='install')=>{
  const s=await inspect(f.client,a),time=now();env.REPAIR_OPERATION=operation;
  if(operation==='resume')env.GITHUB_RUN_ID='1235';
  const e={version:1,account:target.account,database:target.database,worker_version:target.worker_version,schema_sha256:target.baseline_schema_sha256,counts_sha256:digest(s.counts),manifest_sha256:a.sha256,captured_at:time,verified_at:time,ciphertext_sha256:'b'.repeat(64),export_sha256:'c'.repeat(64),bookmark_sha256:'d'.repeat(64),restore_receipt_sha256:'e'.repeat(64),private_destination:target.private_destination,key_custody_verified:true,writer_quiescence_confirmed:true,restore:{account:target.restore_account,name:target.restore_name,database:'11111111-1111-4111-8111-111111111111',schema_sha256:target.baseline_schema_sha256,counts_sha256:digest(s.counts),foreign_key_violations:0,integrity_check:'ok',no_worker_bindings:true,no_delivery_credentials:true}};
  const payload=JSON.stringify(e);env.REPAIR_RECOVERY_EVIDENCE=JSON.stringify({payload,signature:sign(null,Buffer.from(payload),privateKey).toString('base64')});env.REPAIR_RECOVERY_PUBLIC_KEY=publicKey.export({type:'spki',format:'pem'});
  const p={version:1,approval_id:'22222222-2222-4222-8222-222222222222',operation,source_sha:env.GITHUB_SHA,run_id:env.GITHUB_RUN_ID,manifest_sha256:a.sha256,account:target.account,database:target.database,worker_version:target.worker_version,application_commit:target.application_commit,sql_sha256:a.manifest.sql_sha256[operation+'.sql'],baseline_schema_sha256:target.baseline_schema_sha256,preflight_sha256:s.fingerprint,not_before:time-1,expires_at:time+600,recovery_sha256:digest(payload),quiet_window_confirmed:true,independent_writers_excluded:true,no_competing_cloudflare_builds:true,...(operation==='resume'?{expected_revision:0,install_receipt_sha256:s.install_receipt_sha256,verification_sha256:s.fingerprint,resume_scheduled_work_and_eligible_email:true}:{})};
  if(operation==='resume')p.approval_id='33333333-3333-4333-8333-333333333333';
  env.REPAIR_AUTHORIZATION=JSON.stringify(p);return {s,e,p};
 };return f;
}
const blocked=async(f,operation)=>{await assert.rejects(()=>f.run(operation));assert.equal(f.writes.length,0);};
function onDemandInstall(approval) {
 const {not_before, expires_at, ...install} = approval;
 return {...install, version: 2};
}

test('an on-demand install can start after a long review and ends frozen with receipts for the exact run', async t => {
 const f = await fixture(t);
 const {p} = await f.approve();
 const approval = onDemandInstall(p);
 f.env.REPAIR_AUTHORIZATION = JSON.stringify(approval);
 const later = now() + 2 * 3600;
 const report = await execute(f.env, {client: f.client, now: () => later});
 assert.equal(report.status, 'installed-frozen');
 assert.deepEqual(report.control, {write_hold: 1, database_frozen: 1, revision: 0});
 const receipts = f.db.prepare(`SELECT id,payload FROM ${receiptTable} ORDER BY rowid`).all();
 assert.deepEqual(receipts.map(r => r.id), ['install-intent', 'install-started', 'installed']);
 for (const {payload} of receipts) {
   const saved = JSON.parse(payload);
   for (const key of ['run_id', 'source_sha', 'database', 'approval_id']) assert.equal(saved[key], approval[key]);
   assert.equal(saved.authorization_sha256, digest(approval));
   assert.ok(!Object.hasOwn(saved, 'not_before') && !Object.hasOwn(saved, 'expires_at'));
 }
 const writes = f.writes.length;
 await assert.rejects(() => f.run('resume'));
 const {p: resume} = await f.approve('resume');
 f.env.REPAIR_AUTHORIZATION = JSON.stringify({...resume, version: 2});
 await assert.rejects(() => f.run('resume'));
 delete resume.not_before;
 delete resume.expires_at;
 f.env.REPAIR_AUTHORIZATION = JSON.stringify(resume);
 await assert.rejects(() => f.run('resume'));
 assert.equal(f.writes.length, writes);
});

test('on-demand authorization rejects a different run, commit, database, or explicit time bound before writing', async t => {
 const f = await fixture(t);
 const {p} = await f.approve();
 for (const invalid of [{run_id: '5678'}, {source_sha: 'b'.repeat(40)}, {database: '11111111-1111-4111-8111-111111111111'},
                       {not_before: now()}, {expires_at: null}]) {
   f.env.REPAIR_AUTHORIZATION = JSON.stringify({...onDemandInstall(p), ...invalid});
   await blocked(f, 'install');
 }
});
test('pre-write failures report only a fixed code and never submit a write', async t => {
  const privateDetail = 'fictional-private-diagnostic-marker';
  const cases = [
    ['authorization-missing', f => { delete f.env.REPAIR_AUTHORIZATION; }],
    ['authorization-json', f => { f.env.REPAIR_AUTHORIZATION = privateDetail; }],
    ['authorization-run-id', (_f, p) => { p.run_id = privateDetail; }],
    ['authorization-fingerprint', (_f, p) => { p.preflight_sha256 = '0'.repeat(64); }],
    ['authorization-window', (_f, p) => { p.not_before = p.expires_at; }],
    ['recovery-envelope-json', f => { f.env.REPAIR_RECOVERY_EVIDENCE = privateDetail; }],
    ['recovery-public-key', f => { f.env.REPAIR_RECOVERY_PUBLIC_KEY = privateDetail; }],
    ['recovery-signature', f => {
      const envelope = JSON.parse(f.env.REPAIR_RECOVERY_EVIDENCE);
      envelope.signature = Buffer.alloc(64).toString('base64');
      f.env.REPAIR_RECOVERY_EVIDENCE = JSON.stringify(envelope);
    }],
    ['recovery-payload-digest', (_f, p) => { p.recovery_sha256 = '0'.repeat(64); }],
    ['second-inspection', (_f, _p, hooks) => {
      hooks.secondObservation = () => { throw Error(privateDetail); };
    }],
    ['second-fingerprint', (_f, _p, hooks) => {
      hooks.secondObservation = metadata => ({...metadata, deployment: 'other-deployment'});
    }],
    ['pre-write-window', (_f, p, hooks) => {
      hooks.secondObservation = metadata => { hooks.time = p.expires_at + 1; return metadata; };
    }],
    ['final-github-approval', (f) => {
      let reviews = 0;
      const protection = f.client.protection;
      f.client.protection = operation => {
        if (++reviews === 2) throw Error(privateDetail);
        return protection(operation);
      };
    }],
  ];
  for (const [code, fault] of cases) await t.test(code, async t => {
    const f = await fixture(t);
    const {p} = await f.approve();
    const hooks = {time: now(), secondObservation: metadata => metadata};
    // Each inspection observes the Worker both before and after the D1 reads.
    const observe = f.client.observe;
    let observations = 0;
    f.client.observe = async () => {
      const metadata = await observe();
      return ++observations <= 2 ? metadata : hooks.secondObservation(metadata);
    };
    const original = f.env.REPAIR_AUTHORIZATION;
    fault(f, p, hooks);
    if (f.env.REPAIR_AUTHORIZATION === original) f.env.REPAIR_AUTHORIZATION = JSON.stringify(p);
    await assert.rejects(
      execute(f.env, {client: f.client, now: () => hooks.time, record: r => f.reports.push(r)}),
      {message: 'Repair stopped at ' + code + '; use SELECT-only reconciliation. No automatic retry, resume or rollback.'}
    );
    const report = f.reports.at(-1);
    assert.equal(report.failed_stage, code);
    assert.equal(report.status, 'blocked');
    assert.equal(report.write_requests, 0);
    assert.equal(f.writes.length, 0);
    const output = JSON.stringify(f.reports);
    for (const sensitive of [privateDetail, p.approval_id, 'ciphertext_sha256', '"signature":']) {
      assert.ok(!output.includes(sensitive));
    }
  });
});
const sqlFile=name=>fs.readFileSync(path.join(folder,name+'.sql'),'utf8');
test('the database rejects incomplete or mixed on-demand evidence at the first install receipt', async t => {
 const f = await fixture(t), {s, p} = await f.approve();
 f.db.exec(sqlFile('bootstrap'));
 const insert = f.db.prepare(`INSERT INTO ${receiptTable}(id,payload) VALUES('install-intent',?)`);
 for (const patch of [{run_id: undefined}, {run_id: null}, {source_sha: null}, {database: 'other'},
                      {expires_at: null}, {operation: 'resume'}]) {
   const approval = {...onDemandInstall(p), ...patch};
   assert.throws(() => insert.run(JSON.stringify({...approval, authorization_sha256: digest(approval),
     schema_rows: s.schema_rows, counts: s.counts})), /Repair approval expired or database drifted/);
 }
 assert.equal(f.db.prepare(`SELECT COUNT(*) n FROM ${receiptTable}`).get().n, 0);
});
async function claimedInstallation(t){
 const f=await fixture(t),{s,p}=await f.approve();
 f.db.exec(sqlFile('bootstrap'));
 const payload=JSON.stringify({...p,authorization_sha256:digest(p),schema_rows:s.schema_rows,counts:s.counts});
 f.db.prepare(`INSERT INTO ${receiptTable}(id,payload) VALUES('install-intent',?)`).run(payload);
 f.db.exec(sqlFile('install-start'));return {...f,approval:p};
}
test('installation boundary rejects schema and count drift after the durable start claim without repair mutations',async t=>{
 for(const change of [db=>db.exec('CREATE TABLE unexpected_after_claim(id TEXT)'),db=>db.exec("INSERT INTO remediations(user_id,cve_id,status,updated_at) VALUES('a','CVE-2026-999999','Open','2026-11-06')")]){
  const f=await claimedInstallation(t);change(f.db);
  const before=plain(f.db.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name').all());
  assert.throws(()=>f.db.exec(sqlFile('install')));
  assert.deepEqual(plain(f.db.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name').all()),before);
  assert.deepEqual(f.db.prepare(`SELECT id FROM ${receiptTable} ORDER BY id`).all().map(r=>r.id),['install-intent','install-started']);
 }
});
test('database clock rejects approval that expires after claim but before installation, independently of runner clock',async t=>{
 const f=await claimedInstallation(t);f.db.function('strftime',(_format,_value)=>String(f.approval.expires_at+1));
 assert.throws(()=>f.db.exec(sqlFile('install')));
 assert.equal(f.db.prepare("SELECT COUNT(*) n FROM sqlite_schema WHERE name='operations_control'").get().n,0);
 assert.equal(f.db.prepare(`SELECT COUNT(*) n FROM ${receiptTable}`).get().n,2);
});
test('interruption before or after the in-batch assertion leaves the durable claim and never retries',async t=>{
 for(const point of ['before-check','after-check']){
  const f=await fixture(t);await f.approve();const native=f.client.writeOnce;
  f.client.writeOnce=async(sql,params)=>{
   if(sql===sqlFile('install')){
    f.writes.push({sql,params});
    // Fault injection only: the real adapter must never split this batch.
    if(point==='after-check')f.db.exec(sql.split('-- END INSTALLATION PRECONDITION')[0]);
    throw Error('Fictional interruption');
   }
   return native(sql,params);
  };
  await assert.rejects(()=>f.run('install'));
  assert.equal(f.db.prepare("SELECT COUNT(*) n FROM sqlite_schema WHERE name='operations_control'").get().n,0);
  assert.equal((await f.run('reconcile')).state,'uncertain-install');
  await assert.rejects(()=>f.run('install'));assert.equal(f.writes.length,4);
  assert.deepEqual(f.db.prepare(`SELECT id FROM ${receiptTable} ORDER BY id`).all().map(r=>r.id),['install-intent','install-started']);
 }
});
test('executor sends assertion, repair and receipt in one unmodified REST batch and never retries a rejected boundary',async t=>{
 const f=await fixture(t);await f.approve();const native=f.client.writeOnce,calls=[];
 const remote=transport({...f.env,CLOUDFLARE_API_TOKEN:'fictional-only'},{fetcher:async(url,options)=>{
  const body=JSON.parse(options.body);calls.push({url,body});
  assert.equal(body.sql,sqlFile('install'));assert.deepEqual(body.params,[]);
  assert.ok(body.sql.indexOf('AS installation_precondition;')<body.sql.indexOf('CREATE '));
  // The provider-boundary simulation introduces drift AFTER the start claim.
  f.db.exec('CREATE TABLE unexpected_after_claim(id TEXT)');
  assert.throws(()=>f.db.exec(body.sql));
  return new Response(JSON.stringify({success:false,result:[]}),{status:400});
 }});
 f.client.writeOnce=async(sql,params)=>{
  if(sql===sqlFile('install')){f.writes.push({sql,params});return remote.writeOnce(sql,params);}
  return native(sql,params);
 };
 await assert.rejects(()=>f.run('install'));assert.equal(calls.length,1);
 assert.equal(f.db.prepare("SELECT COUNT(*) n FROM sqlite_schema WHERE name='operations_control'").get().n,0);
 assert.equal((await f.run('reconcile')).state,'uncertain-install');
 await assert.rejects(()=>f.run('install'));assert.equal(calls.length,1);assert.equal(f.writes.length,4);
});
test('an absent start claim fails the scalar installation assertion instead of selecting zero rows',async t=>{
 const f=await fixture(t);f.db.exec(sqlFile('bootstrap'));
 assert.throws(()=>f.db.exec(sqlFile('install')));
 assert.equal(f.db.prepare("SELECT COUNT(*) n FROM sqlite_schema WHERE name='operations_control'").get().n,0);
});
test('missing or false environment enable flag rejects writes before provider access',async t=>{
 for(const flag of [undefined,'','false']){
  const f=await fixture(t);await f.approve();f.env.PRODUCTION_COMPATIBILITY_REPAIR_ENABLED=flag;
  f.client.protection=async()=>assert.fail('Runtime authorization must precede provider access');
  await blocked(f,'install');
 }
});
test('procedure files reproduce exact SQL and an independently fingerprinted immutable journal',()=>{
 assert.equal(a.manifest.sql_sha256['install.sql'],digest(fs.readFileSync(path.join(folder,'install.sql'),'utf8')));assert.equal(journalObjects().length,4);
});
test('preflight has zero writes; installation preserves rows and requires separate verify and resume',async t=>{
 const f=await fixture(t),before=await inspect(f.client,a);assert.equal((await f.run('preflight')).state,'baseline');assert.equal(f.writes.length,0);
 await f.approve();assert.equal((await f.run('install')).status,'installed-frozen');assert.equal(f.writes.length,4);
 const after=await inspect(f.client,a,{mode:'verify'});assert.deepEqual(after.counts,before.counts);assert.deepEqual(after.control,{write_hold:1,database_frozen:1,revision:0});
 assert.equal((await f.run('verify')).status,'verified-frozen');assert.equal(f.writes.length,4);
 assert.throws(()=>f.db.exec(`UPDATE ${receiptTable} SET payload='{}'`),/immutable/);assert.throws(()=>f.db.exec(`DELETE FROM ${receiptTable}`),/immutable/);
 await f.approve('resume');f.env.GITHUB_RUN_ID='1235';const p=JSON.parse(f.env.REPAIR_AUTHORIZATION);p.run_id='1235';f.env.REPAIR_AUTHORIZATION=JSON.stringify(p);
 assert.equal((await f.run('resume')).status,'resumed');assert.equal(f.writes.length,7);
 assert.equal((await f.run('reconcile')).state,'resumed');assert.equal(f.writes.length,7);
});
test('wrong repository/account/ref/event/source/manifest/run attempt are rejected before writes',async t=>{
 for(const [key,value] of Object.entries({GITHUB_REPOSITORY:'other/repo',GITHUB_REF:'refs/heads/feature',GITHUB_EVENT_NAME:'push',CLOUDFLARE_ACCOUNT_ID:target.restore_account,GITHUB_SHA:'b'.repeat(40),REPAIR_MANIFEST_SHA256:'0'.repeat(64),GITHUB_RUN_ATTEMPT:'2',PRODUCTION_COMPATIBILITY_REPAIR_ENABLED:'false'})){
  const f=await fixture(t);await f.approve();f.env[key]=value;await blocked(f,'install');
 }
});
test('wrong target, stale approval, wrong SQL, run, recovery hash and unchecked quiet window fail closed',async t=>{
 for(const patch of [{database:'11111111-1111-4111-8111-111111111111'},{worker_version:'bad'},{expires_at:now()-1},{not_before:now()+100},{sql_sha256:'0'.repeat(64)},{run_id:'999'},{preflight_sha256:'0'.repeat(64)},{recovery_sha256:'0'.repeat(64)},{quiet_window_confirmed:false}]){
  const f=await fixture(t);const {p}=await f.approve();f.env.REPAIR_AUTHORIZATION=JSON.stringify({...p,...patch});await blocked(f,'install');
 }
});
test('missing or forged recovery evidence and stale/incorrect restore receipts reject installation',async t=>{
 for(const mutate of [f=>delete f.env.REPAIR_RECOVERY_EVIDENCE,f=>f.env.REPAIR_RECOVERY_PUBLIC_KEY='invalid',f=>{const e=JSON.parse(f.env.REPAIR_RECOVERY_EVIDENCE);e.payload=e.payload.replace('"key_custody_verified":true','"key_custody_verified":false');f.env.REPAIR_RECOVERY_EVIDENCE=JSON.stringify(e); }]){
  const f=await fixture(t);await f.approve();mutate(f);await blocked(f,'install');
 }
 const f=await fixture(t),{s,e,p}=await f.approve();
 for(const patch of [{captured_at:now()-90000},{key_custody_verified:false},{restore:{...e.restore,database:target.database}},{restore:{...e.restore,foreign_key_violations:1}}]){
  const payload=JSON.stringify({...e,...patch}),env={...f.env,REPAIR_RECOVERY_EVIDENCE:JSON.stringify({payload,signature:sign(null,Buffer.from(payload),privateKey).toString('base64')})};
  assert.throws(()=>verifyRecovery(env,{...p,recovery_sha256:digest(payload)},s,now()));
 }
});
test('schema, configuration and row-count drift reject prior preflight approvals',async t=>{
 for(const change of [f=>f.db.exec('CREATE TABLE unexpected(id TEXT)'),f=>f.metadata.worker_version='00000000-0000-4000-8000-000000000000',f=>f.metadata.configuration_sha256='9'.repeat(64),f=>f.db.exec("INSERT INTO remediations(user_id,cve_id,status,updated_at) VALUES('a','CVE-2026-999999','Open','2026-11-06')")]){
  const f=await fixture(t);await f.approve();change(f);await blocked(f,'install');
 }
});
test('database-side receipt guard rejects drift between preflight and intent',async t=>{
 const f=await fixture(t);await f.approve();const native=f.client.writeOnce;
 f.client.writeOnce=async(sql,p)=>{const result=await native(sql,p);if(f.writes.length===1)f.db.exec('CREATE TABLE concurrent_admin_change(id TEXT)');return result;};
 await assert.rejects(()=>f.run('install'));assert.equal(f.writes.length,2);assert.equal(f.db.prepare("SELECT COUNT(*) n FROM sqlite_schema WHERE name='operations_control'").get().n,0);
});
test('partial installation is never repeated by a fresh run or reconciliation',async t=>{
 const f=await fixture(t);await f.approve();const native=f.client.writeOnce;
 f.client.writeOnce=async(sql,p)=>{if(sql.includes('-- Exactly one submission')){f.writes.push({sql});f.db.exec(sql.slice(0,sql.indexOf('CREATE TABLE IF NOT EXISTS operations_control')));throw Error('Fictional disconnect');}return native(sql,p);};
 await assert.rejects(()=>f.run('install'));const n=f.writes.length;
 assert.equal((await f.run('reconcile')).state,'uncertain-install');assert.equal(f.writes.length,n);
 f.env.GITHUB_RUN_ID='9999';await assert.rejects(()=>f.run('install'));assert.equal(f.writes.length,n);
});
test('lost installation response reconciles completed frozen state without another write',async t=>{
 const f=await fixture(t);await f.approve();const native=f.client.writeOnce;
 f.client.writeOnce=async(sql,p)=>{const result=await native(sql,p);if(sql.includes('-- Exactly one submission'))throw Error('Lost reply after commit');return result;};
 await assert.rejects(()=>f.run('install'));assert.equal((await f.run('reconcile')).state,'installed-frozen');assert.equal(f.writes.length,4);
 await assert.rejects(()=>f.run('install'));assert.equal(f.writes.length,4);
});
test('partial journal, mismatched receipt and unsuccessful verification block resume',async t=>{
 for(const kind of ['journal','receipt','readiness','lease','schema']){
  const f=await fixture(t);await f.approve();await f.run('install');const n=f.writes.length;
  if(kind==='journal')f.db.exec(`DROP TRIGGER ${receiptTable}_immutable_update`);
  if(kind==='receipt'){const native=f.client.select;f.client.select=async(sql,p)=>{const rows=await native(sql,p);if(sql.startsWith('SELECT id,payload'))rows.find(r=>r.id==='installed').payload='{}';return rows;};}
  if(kind==='readiness')f.client.readiness=async()=>({http:503,ready:false,held:true,schema_ready:false});
  if(kind==='lease'){const native=f.client.select;f.client.select=async(sql,p)=>sql==='SELECT COUNT(*) n FROM operations_leases'?[{n:1}]:native(sql,p);}
  if(kind==='schema')f.db.exec('DROP TRIGGER validate_finding_write');
  await assert.rejects(()=>f.run('verify'));await assert.rejects(()=>f.run('resume'));assert.equal(f.writes.length,n);assert.equal(f.db.prepare('SELECT write_hold FROM operations_control').get().write_hold,1);
 }
});
test('stale resume revision, omitted effects approval and interrupted resume cannot release again',async t=>{
 const f=await fixture(t);await f.approve();await f.run('install');const {p}=await f.approve('resume');
 for(const patch of [{expected_revision:1},{resume_scheduled_work_and_eligible_email:false},{install_receipt_sha256:'f'.repeat(64)}]){
  f.env.REPAIR_AUTHORIZATION=JSON.stringify({...p,...patch});await assert.rejects(()=>f.run('resume'));assert.equal(f.writes.length,4);
 }
 f.env.REPAIR_AUTHORIZATION=JSON.stringify(p);const native=f.client.writeOnce;
 f.client.writeOnce=async(sql,params)=>{const result=await native(sql,params);if(sql.includes('-- Separate approved'))throw Error('Lost resume response');return result;};
 await assert.rejects(()=>f.run('resume'));assert.equal((await f.run('reconcile')).state,'resumed');await assert.rejects(()=>f.run('resume'));assert.equal(f.writes.length,7);
});
test('two concurrent installations cannot consume the same approval twice',async t=>{
 const f=await fixture(t);await f.approve();const results=await Promise.allSettled([f.run('install'),f.run('install')]);
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(f.db.prepare(`SELECT COUNT(*) n FROM ${receiptTable} WHERE id='installed'`).get().n,1);assert.equal(f.db.prepare('SELECT write_hold FROM operations_control').get().write_hold,1);
});
test('HTTP transport never retries a failed write or leaks provider bodies',async()=>{
 let calls=0;const client=transport({CLOUDFLARE_ACCOUNT_ID:target.account,CLOUDFLARE_API_TOKEN:'fictional-only'},{fetcher:async()=>{calls++;return new Response(JSON.stringify({success:false,errors:[{message:'fictional-sensitive-value'}]}),{status:500});}});
 await assert.rejects(()=>client.writeOnce('CREATE TABLE fictional(id TEXT)'),e=>!e.message.includes('fictional-sensitive-value'));assert.equal(calls,1);
 await assert.rejects(()=>client.select('UPDATE forbidden SET id=1'));assert.equal(calls,1);
});
test('journal bootstrap loss, failed post-install verification and half-resume never trigger repair writes',async t=>{
 for(const kind of ['bootstrap','verification','half-resume']){
  const f=await fixture(t);await f.approve();const native=f.client.writeOnce;
  if(kind==='bootstrap')f.client.writeOnce=async(sql,p)=>{await native(sql.split('CREATE TRIGGER')[0],p);throw Error('Lost bootstrap');};
  if(kind==='verification')f.client.writeOnce=async(sql,p)=>{await native(sql,p);if(sql.includes('-- Exactly one submission'))f.client.readiness=async()=>({http:503,ready:false,held:true,schema_ready:false});};
  if(kind==='half-resume'){
   await f.run('install');await f.approve('resume');f.client.writeOnce=async(sql,p)=>{if(sql.includes('-- Separate approved')){await native(sql.slice(0,sql.indexOf('UPDATE operations_control')),p);throw Error('Interrupted before resume update');}return native(sql,p);};
  }
  await assert.rejects(()=>f.run(kind==='half-resume'?'resume':'install'));const n=f.writes.length;
  await assert.rejects(()=>f.run('reconcile'));await assert.rejects(()=>f.run('install'));assert.equal(f.writes.length,n);
  if(kind!=='bootstrap')assert.equal(f.db.prepare('SELECT write_hold FROM operations_control').get().write_hold,1);
 }
});
test('transport binds active deployment, both DB bindings and required recovery flag',async()=>{
 const bindings=[{name:'DB',type:'d1',id:target.database},{name:'RECOVERY_CONTROL_REQUIRED',type:'plain_text',text:'true'}];
 for(const broken of [null,'database','version','traffic','binding','required']){
  const calls=[];const client=transport({CLOUDFLARE_ACCOUNT_ID:target.account,CLOUDFLARE_API_TOKEN:'fictional-only'},{fetcher:async(url,options)=>{
   calls.push({url,options});assert.equal(options.method,'GET');assert.equal(options.redirect,'error');
   let result;if(url.endsWith('/deployments'))result={deployments:[{id:'fictional',versions:[{version_id:broken==='version'?'wrong':target.worker_version,percentage:broken==='traffic'?50:100}]}]};
   else if(url.endsWith('/versions/'+target.worker_version))result={id:target.worker_version,resources:{bindings}};
   else if(url.endsWith('/settings'))result={bindings:bindings.map(b=>b.name==='DB'&&broken==='binding'?{...b,id:'wrong'}:b.name==='RECOVERY_CONTROL_REQUIRED'&&broken==='required'?{...b,text:'false'}:b)};
   else if(url.endsWith('/schedules'))result={schedules:[]};
   else result={uuid:broken==='database'?'wrong':target.database,name:target.database_name};
   return new Response(JSON.stringify({success:true,result}));
  }});
  if(broken)await assert.rejects(()=>client.observe());else assert.equal((await client.observe()).worker_version,target.worker_version);
  assert.ok(calls.every(c=>c.url.startsWith('https://api.cloudflare.com/client/v4/accounts/'+target.account+'/')));
 }
});
test('live environment gate inspection rejects missing protections, wrong reviewer, stale run and missing approval',async()=>{
 for(const bad of [null,'bypass','reviewer','branch','approval','source','completed','unavailable']){
  const env={REPAIR_GITHUB_TOKEN:'fictional-github-only',GITHUB_RUN_ID:'1234',GITHUB_SHA:'a'.repeat(40)};
  const fetcher=async(url,options)=>{
   assert.equal(options.redirect,'error');assert.equal(options.headers.Authorization,'Bearer fictional-github-only');assert.ok(url.startsWith('https://api.github.com/repos/Prat007ai/cveharbor/'));
   let data;if(url.endsWith('/approvals'))data=bad==='approval'?[]:[{state:'approved',user:{id:349078288},environments:[{id:12}]}];
   else if(url.includes('deployment-branch-policies'))data={total_count:1,branch_policies:[{name:bad==='branch'?'*':'main',type:'branch'}]};
   else if(url.includes('/environments/'))data={id:12,name:'cloudflare-worker-production',can_admins_bypass:bad==='bypass',deployment_branch_policy:{protected_branches:false,custom_branch_policies:true},protection_rules:bad==='reviewer'?[]:[{type:'required_reviewers',reviewers:[{type:'User',reviewer:{id:349078288}}]}]};
   else data={head_sha:bad==='source'?'b'.repeat(40):env.GITHUB_SHA,head_branch:'main',event:'workflow_dispatch',run_attempt:1,status:bad==='completed'?'completed':'in_progress',path:'.github/workflows/production-compatibility-repair.yml'};
   return new Response(JSON.stringify(data),{status:bad==='unavailable'?403:200});
  };
  if(bad)await assert.rejects(()=>verifyGitHubGate(env,'install',fetcher));else assert.equal((await verifyGitHubGate(env,'install',fetcher)).owner_review_verified,true);
 }
});
test('unprotected environment stops before all Cloudflare reads and writes',async t=>{
 const f=await fixture(t);f.client.protection=async()=>{throw Error('Missing required reviewers');};f.client.observe=async()=>assert.fail('No Cloudflare read before environment protection');
 await blocked(f,'preflight');assert.equal(f.reports.at(-1).failed_stage,'environment-protection');
});
