import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {verify as verifySignature,createPublicKey} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {folder,target,receiptTable,quote,originalTables,verifyFiles,journalObjects} from './build.mjs';
import {transport} from './transport.mjs';
import {installed272} from './pr272-transition.mjs';
import {canonical,digest,schemaSQL} from '../../../../scripts/production_schema_baseline.mjs';
import {integrityChecks} from '../../../../account-backend/src/release-integrity-checks.js';
import {backendIdentity} from '../../../../scripts/build_release_identity.mjs';
const hash=x=>assert.match(x||'',/^[a-f0-9]{64}$/,'Missing SHA-256');
const ids=['install-intent','install-started','installed','resume-intent','resume-started'];
export function authorizeContext(env,a){
 assert.equal(env.GITHUB_REPOSITORY,'Prat007ai/cveharbor');assert.equal(env.GITHUB_REF,'refs/heads/main');assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch');
 assert.equal(env.GITHUB_RUN_ATTEMPT,'1','Never rerun a write job; reconcile in a new read-only dispatch');
 assert.match(env.GITHUB_SHA||'',/^[a-f0-9]{40}$/);assert.equal(env.REPAIR_APPROVED_SOURCE,env.GITHUB_SHA);
 assert.match(env.GITHUB_RUN_ID||'',/^\d+$/);assert.equal(env.REPAIR_MANIFEST_SHA256,a.sha256);
 assert.equal(env.CLOUDFLARE_ACCOUNT_ID,target.account);assert.equal(backendIdentity(),target.backend_identity);
 assert.ok(['preflight','install','verify','reconcile','resume'].includes(env.REPAIR_OPERATION));
 if(['install','resume'].includes(env.REPAIR_OPERATION))assert.equal(env.PRODUCTION_COMPATIBILITY_REPAIR_ENABLED,'true');
 return env.REPAIR_OPERATION;
}
function checkApprovalTiming(a, now) {
 // Version 2 is approved for one operation in a single live GitHub run.
 // Reject ambiguous inputs rather than ignoring an explicit time restriction.
 if (a.version === 2) {
   assert.ok(!Object.hasOwn(a, 'not_before') && !Object.hasOwn(a, 'expires_at'));
   return;
 }
 assert.ok(Number.isSafeInteger(a.not_before)&&Number.isSafeInteger(a.expires_at));
 assert.ok(a.not_before<=now&&now<=a.expires_at&&a.expires_at-a.not_before<=1800,'Approval expired, future-dated or overlong');
}
// Only this module constructs these failures, using literal codes. Never forward
// parser, crypto, assertion or provider messages to the operator report.
class CheckFailure extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}
function requireCheck(code, condition) {
  if (!condition) throw new CheckFailure(code);
}
function checked(code, read) {
  try { return read(); } catch { throw new CheckFailure(code); }
}
const sha256Pattern = /^[a-f0-9]{64}$/;
const uuidPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
function matches(pattern, value) {
  return typeof value === 'string' && pattern.test(value);
}

export function verifyRecovery(env, approval, snapshot, now) {
  requireCheck('recovery-envelope-missing', env.REPAIR_RECOVERY_EVIDENCE);
  const envelope = checked('recovery-envelope-json', () => JSON.parse(env.REPAIR_RECOVERY_EVIDENCE));
  requireCheck('recovery-envelope-payload', typeof envelope?.payload === 'string' && envelope.payload.length > 0);
  requireCheck('recovery-envelope-signature', typeof envelope.signature === 'string' && envelope.signature.length > 0);
  requireCheck('recovery-public-key-missing', env.REPAIR_RECOVERY_PUBLIC_KEY);
  const key = checked('recovery-public-key', () => createPublicKey(env.REPAIR_RECOVERY_PUBLIC_KEY));
  requireCheck('recovery-key-type', key.asymmetricKeyType === 'ed25519');
  const valid = checked('recovery-signature', () => verifySignature(null, Buffer.from(envelope.payload), key, Buffer.from(envelope.signature, 'base64')));
  requireCheck('recovery-signature', valid);
  requireCheck('recovery-payload-digest', digest(envelope.payload) === approval.recovery_sha256);

  const e = checked('recovery-payload-json', () => JSON.parse(envelope.payload));
  requireCheck('recovery-version', e?.version === 1);
  requireCheck('recovery-account', e.account === target.account);
  requireCheck('recovery-database', e.database === target.database);
  requireCheck('recovery-worker', e.worker_version === target.worker_version);
  requireCheck('recovery-schema', e.schema_sha256 === target.baseline_schema_sha256);
  requireCheck('recovery-counts', e.counts_sha256 === digest(snapshot.counts));
  requireCheck('recovery-manifest', e.manifest_sha256 === approval.manifest_sha256);
  requireCheck('recovery-capture-time', Number.isSafeInteger(e.captured_at) && e.captured_at <= now && now - e.captured_at <= 86400);
  requireCheck('recovery-verification-time', Number.isSafeInteger(e.verified_at) && e.verified_at >= e.captured_at && e.verified_at <= now);
  requireCheck('recovery-ciphertext-hash', matches(sha256Pattern, e.ciphertext_sha256));
  requireCheck('recovery-export-hash', matches(sha256Pattern, e.export_sha256));
  requireCheck('recovery-bookmark-hash', matches(sha256Pattern, e.bookmark_sha256));
  requireCheck('recovery-receipt-hash', matches(sha256Pattern, e.restore_receipt_sha256));
  requireCheck('recovery-destination', e.private_destination === target.private_destination);
  requireCheck('recovery-key-custody', e.key_custody_verified === true);
  requireCheck('restore-account', e.restore?.account === target.restore_account);
  requireCheck('restore-name', e.restore.name === target.restore_name);
  requireCheck('restore-database-id', matches(uuidPattern, e.restore.database));
  requireCheck('restore-database-isolation', ![target.database, 'fac61562-fc31-426d-8032-550aba63b7f6'].includes(e.restore.database));
  requireCheck('restore-schema', e.restore.schema_sha256 === target.baseline_schema_sha256);
  requireCheck('restore-counts', e.restore.counts_sha256 === e.counts_sha256);
  requireCheck('restore-foreign-keys', Object.is(e.restore.foreign_key_violations, 0));
  requireCheck('restore-integrity', e.restore.integrity_check === 'ok');
  requireCheck('restore-worker-bindings', e.restore.no_worker_bindings === true);
  requireCheck('restore-delivery-credentials', e.restore.no_delivery_credentials === true);
  requireCheck('recovery-writer-quiescence', e.writer_quiescence_confirmed === true);
  return e;
}

export function authorizeWrite(env, a, s, now) {
  requireCheck('authorization-missing', env.REPAIR_AUTHORIZATION);
  const p = checked('authorization-json', () => JSON.parse(env.REPAIR_AUTHORIZATION));
  requireCheck('authorization-version', p?.version === 1 || p?.version === 2);
  requireCheck('authorization-id', matches(uuidPattern, p.approval_id));
  requireCheck('authorization-operation', p.operation === env.REPAIR_OPERATION);
  requireCheck('authorization-source', p.source_sha === env.GITHUB_SHA);
  requireCheck('authorization-run-id', p.run_id === env.GITHUB_RUN_ID);
  requireCheck('authorization-manifest', p.manifest_sha256 === a.sha256);
  requireCheck('authorization-account', p.account === target.account);
  requireCheck('authorization-database', p.database === target.database);
  requireCheck('authorization-worker', p.worker_version === target.worker_version);
  requireCheck('authorization-application', p.application_commit === target.application_commit);
  requireCheck('authorization-sql', p.sql_sha256 === a.manifest.sql_sha256[p.operation + '.sql']);
  requireCheck('authorization-schema', p.baseline_schema_sha256 === target.baseline_schema_sha256);
  requireCheck('authorization-fingerprint', p.preflight_sha256 === s.fingerprint);
  checked('authorization-window', () => checkApprovalTiming(p, now));
  requireCheck('authorization-recovery-hash', matches(sha256Pattern, p.recovery_sha256));
  requireCheck('authorization-quiet-window', p.quiet_window_confirmed === true);
  requireCheck('authorization-independent-writers', p.independent_writers_excluded === true);
  requireCheck('authorization-competing-builds', p.no_competing_cloudflare_builds === true);
  if (p.operation === 'resume') {
    requireCheck('resume-journal-upgrade-required', !s.requires_trigger_upgrade);
    requireCheck('resume-state', s.state === 'installed-frozen');
    requireCheck('resume-install-receipt', p.install_receipt_sha256 === s.install_receipt_sha256);
    requireCheck('resume-revision', Object.is(p.expected_revision, s.control.revision));
    requireCheck('resume-scheduled-work', p.resume_scheduled_work_and_eligible_email === true);
    requireCheck('resume-verification', p.verification_sha256 === s.fingerprint);
    requireCheck('resume-separate-run', p.run_id !== s.install_run_id);
    requireCheck('resume-separate-approval', p.approval_id !== s.install_approval_id);
  }
  verifyRecovery(env, p, s, now);
  return p;
}
async function counts(client){const result={};for(const table of originalTables()){const rows=await client.select('SELECT COUNT(*) n FROM '+quote(table));assert.equal(rows.length,1);result[table]=Number(rows[0].n);assert.ok(Number.isSafeInteger(result[table])&&result[table]>=0);}return result;}
async function integrity(client){const result={};for(const [name,sql] of Object.entries(integrityChecks))result[name]=Number((await client.select(sql))[0].n);result.foreign_keys=Number((await client.select('SELECT COUNT(*) n FROM pragma_foreign_key_check'))[0].n);assert.ok(Object.values(result).every(n=>n===0),'Integrity verification unsuccessful');return result;}
// Only aggregates; refresh at verification/resume, never read recipients or content.
export async function queueSnapshot(client){
 const queries={
  status_mail:"SELECT state,COUNT(*) n FROM remediation_status_notifications GROUP BY state ORDER BY state",
  fyi_mail:"SELECT state,COUNT(*) n FROM remediation_assignment_notifications GROUP BY state ORDER BY state",
  progress_mail:"SELECT state,COUNT(*) n FROM remediation_review_notifications GROUP BY state ORDER BY state",
  due_disclosures:"SELECT COUNT(*) n FROM cvie_disclosure_queue WHERE next_attempt_at<=unixepoch()*1000 AND lease_until<=unixepoch()*1000",
  due_shared_scopes:"SELECT COUNT(*) n FROM cvie_shared_scopes WHERE next_attempt_at<=unixepoch()*1000 AND lease_until<=unixepoch()*1000",
  due_sources:"SELECT COUNT(*) n FROM cvie_sources WHERE next_attempt_at<=unixepoch()*1000 AND lease_until<=unixepoch()*1000",
  due_reminders:"SELECT COUNT(*) n FROM remediation_review_access p JOIN remediation_assignment_requests a ON a.id=p.assignment_id JOIN remediations r ON r.user_id=a.user_id AND r.cve_id=a.cve_id WHERE p.interval_seconds IS NOT NULL AND p.last_progress_at+p.interval_seconds<=unixepoch() AND p.expires_at>unixepoch() AND a.delivery_status='sent' AND a.revoked_at IS NULL AND r.status IN ('Open','Investigating') AND NOT EXISTS(SELECT 1 FROM remediation_review_notifications n WHERE n.event_key='reminder:'||a.id||':'||p.progress_version)"
 };
 const out={};for(const [name,sql] of Object.entries(queries))out[name]=await client.select(sql);return out;
}
function receiptSequence(rows,a){
 assert.ok(rows.length>=1&&rows.length<=5,'Empty/unknown receipt journal requires investigation');
 const ordered=ids.slice(0,rows.length).map(id=>rows.find(r=>r.id===id));assert.ok(ordered.every(Boolean),'Partial receipt sequence');
 const payloads=ordered.map(r=>JSON.parse(r.payload));
 for(const [index,p] of payloads.entries()){
  if(index<3 && p.manifest_sha256===installed272.manifest){
   assert.equal(digest(ordered[index].payload),installed272.receipt,'Historical installation receipt changed');
   assert.equal(p.source_sha,installed272.source);assert.equal(p.run_id,installed272.run);
  }else assert.equal(p.manifest_sha256,a.sha256);
  for(const k of ['account','database','worker_version','application_commit'])assert.equal(p[k],target[k]);hash(p.authorization_sha256);hash(p.recovery_sha256);hash(p.preflight_sha256);assert.match(p.source_sha,/^[a-f0-9]{40}$/);
 }
 for(let i=1;i<Math.min(3,ordered.length);i++)assert.equal(ordered[i].payload,ordered[0].payload,'Installation receipt mismatch');
 if(ordered.length>=4)assert.equal(payloads[3].install_receipt_sha256,digest(ordered[2].payload),'Resume receipt not bound to installation');
 if(ordered.length===5)assert.equal(ordered[4].payload,ordered[3].payload,'Resume receipt mismatch');
 return {ordered,payloads};
}
export async function inspect(client,a,{mode='preflight'}={}){
 const metadata=await client.observe();for(const k of ['account','database','worker_version'])assert.equal(metadata[k],target[k]);assert.equal(metadata.recovery_required,true);
 const schema_rows=await client.select(schemaSQL),schema_sha256=digest(canonical(schema_rows));
 const journal=await client.select("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name GLOB 'd1_*' AND sql IS NOT NULL ORDER BY type,name");
 const dataCounts=await counts(client),checks=await integrity(client),queues=await queueSnapshot(client);
 let resumeObservation;
 let state='baseline',receipts=[],control=null,install_receipt_sha256=null,install_run_id=null,install_approval_id=null;
 const journal_schema_sha256=digest(canonical(journal));
 const requires_trigger_upgrade=journal_schema_sha256===installed272.journal;
 if(journal.length){
  if(!requires_trigger_upgrade)assert.deepEqual(canonical(journal),journalObjects(),'Unknown/partial operational journal');
  receipts=await client.select('SELECT id,payload FROM '+receiptTable+' ORDER BY id');const {ordered,payloads}=receiptSequence(receipts,a);
  install_run_id=payloads[0].run_id;install_approval_id=payloads[0].approval_id;
  if(requires_trigger_upgrade){
   assert.equal(ordered.length,3,'Unexpected receipt sequence for original production trigger');
   assert.equal(digest(ordered[2].payload),installed272.receipt,'Unexpected installed receipt for original production trigger');
  }
  if(receipts.length<3)state='uncertain-install';
  else{
   assert.equal(schema_sha256,target.installed_schema_sha256,'Installed schema drift/partial execution');
   control=(await client.select('SELECT write_hold,database_frozen,revision FROM operations_control WHERE id=1'))[0];assert.ok(control);
   install_receipt_sha256=digest(ordered[2].payload);
   if(receipts.length===3){assert.deepEqual(control,{write_hold:1,database_frozen:1,revision:0});state='installed-frozen';}
   if(receipts.length>=4){
    const p=payloads[3];assert.equal(p.operation,'resume');assert.equal(p.expected_revision,0);
    // A start receipt precedes the control UPDATE. Its presence proves a claim, not a release.
    // The new control table starts at revision 0 with no events; its UPDATE trigger records
    // the entire new control state in the same statement. A second event is contradictory.
    const events=await client.select(`SELECT e.write_hold,e.database_frozen,e.revision,e.reason,
     (e.reason=c.reason AND e.changed_at=c.changed_at) AS matches_control
     FROM operations_events e JOIN operations_control c ON c.id=1 LIMIT 2`);
    if(control.revision===0){
     assert.deepEqual(control,{write_hold:1,database_frozen:1,revision:0},'Incomplete resume/control mismatch');
     assert.equal(events.length,0,'Unexpected control event at frozen revision');
     state='uncertain-resume';
    }else{
     assert.equal(receipts.length,5,'Resume start receipt missing');
     assert.deepEqual(control,{write_hold:0,database_frozen:0,revision:1},'Resume receipt/control mismatch');
     assert.deepEqual(events,[{...control,reason:'PR270 resume '+p.approval_id,matches_control:1}],'Resume control event mismatch');
     state='resumed';
    }
    resumeObservation={receipt_ids:ordered.map(r=>r.id),control_event:events.length?'matched':'not-observed'};
   }
   if(state!=='resumed'){
    assert.deepEqual(dataCounts,payloads[0].counts,'Existing row counts changed');
    assert.equal(Number((await client.select('SELECT COUNT(*) n FROM operations_leases'))[0].n),0,'Active or stale leases block verification');
    assert.equal(Number((await client.select('SELECT COUNT(*) n FROM remediation_finding_write_context'))[0].n),0,'Unfinished finding writes');
   }
  }
 }else assert.equal(schema_sha256,target.baseline_schema_sha256,'Baseline schema drift');
 const readiness=await client.readiness();
 if(state==='baseline')assert.deepEqual(readiness,{http:503,ready:false,held:true,schema_ready:false});
 if(state==='installed-frozen'||state==='uncertain-resume')assert.deepEqual(readiness,{http:503,ready:false,held:true,schema_ready:true},'Frozen readiness verification failed');
 if(state==='resumed')assert.deepEqual(readiness,{http:200,ready:true,held:false,schema_ready:true},'Resumed readiness verification failed');
 const after=await client.observe();assert.deepEqual(after,metadata,'Worker configuration drifted during inspection');
 if(mode==='verify')assert.equal(state,'installed-frozen','Verification requires a completed frozen installation');
 const report={state,metadata,schema_sha256,counts:dataCounts,integrity:checks,queues,control,install_receipt_sha256,install_run_id,install_approval_id,receipts_sha256:digest(receipts),readiness,...(resumeObservation?{resume_observation:resumeObservation}:{}),...(journal.length?{journal_schema_sha256,requires_trigger_upgrade}:{})};
 return {...report,fingerprint:digest(report),schema_rows};
}
export async function execute(env,{client,artifact,now=()=>Math.floor(Date.now()/1000),record=()=>{}}={}){
 const a=artifact||verifyFiles(),operation=authorizeContext(env,a);client??=transport(env);
 const report={operation,status:'stopped',write_requests:0,automatic_retry:false,automatic_resume:false,automatic_rollback:false};
 const persist=()=>record(structuredClone(report));let stage='preflight';
 const capture=s=>Object.assign(report,{state:s.state,fingerprint:s.fingerprint,install_receipt_sha256:s.install_receipt_sha256,queues:s.queues,checked_at:new Date(now()*1000).toISOString(),metadata:s.metadata,schema_sha256:s.schema_sha256,counts_sha256:digest(s.counts),control:s.control,journal_schema_sha256:s.journal_schema_sha256,requires_trigger_upgrade:s.requires_trigger_upgrade,...(s.resume_observation?{resume_observation:s.resume_observation,readiness:s.readiness}:{})});
 // Any failure, including report persistence, halts. Never submit another write
 // to record a failure: a write response might have been lost after commit.
 const write=async(sql,params=[])=>{report.status='write-outcome-unknown';report.write_requests++;persist();return client.writeOnce(sql,params);};
 try{
  stage='environment-protection';report.protection=await client.protection(operation);
  stage='preflight';
  const before=await inspect(client,a,{mode:operation==='verify'?'verify':'preflight'});
  capture(before);
  if(['preflight','verify','reconcile'].includes(operation)){
   report.status=before.state.startsWith('uncertain')?'reconciliation-required':operation==='verify'?'verified-frozen':'observed';persist();return report;
  }
  stage='authorization';
  const approval=authorizeWrite(env,a,before,now());
  stage='initial-write-state';
  assert.equal(before.state,operation==='install'?'baseline':'installed-frozen');
  stage='prepare-receipt';
  const payload={...approval,authorization_sha256:digest(approval),schema_rows:before.schema_rows,counts:before.counts};
  const params=[JSON.stringify(payload)];
  // Repeat all observations immediately before the first write. SQL receipt
  // triggers additionally compare raw schema, counts, integrity and expiry in D1.
  stage='second-inspection';
  const second=await inspect(client,a);
  stage='second-fingerprint';
  assert.equal(second.fingerprint,before.fingerprint,'State changed before execution');
  stage='pre-write-window';
  checkApprovalTiming(approval,now());
  stage='final-github-approval';
  await client.protection(operation);
  if(operation==='install'){
   stage='journal-create';await write(fs.readFileSync(path.join(folder,'bootstrap.sql'),'utf8'));
   stage='install-intent';await write(`INSERT INTO ${receiptTable}(id,payload) VALUES('install-intent',?)`,params);
   // Persisted intent must match before submitting schema SQL exactly once.
   const rows=await client.select(`SELECT payload FROM ${receiptTable} WHERE id='install-intent'`);assert.equal(rows.length,1);assert.equal(rows[0].payload,params[0]);
   assert.deepEqual(await client.observe(),before.metadata);checkApprovalTiming(approval,now());
   stage='install-start';await write(fs.readFileSync(path.join(folder,'install-start.sql'),'utf8'));
   const claimed=await client.select(`SELECT payload FROM ${receiptTable} WHERE id='install-started'`);assert.equal(claimed.length,1);assert.equal(claimed[0].payload,params[0]);
   checkApprovalTiming(approval,now());
   // The start claim is durable intent, not authorization for later drift.
   // Submit the generated DB assertion AND DDL in one request, never split,
   // pre-execute the assertion, or retry even if the provider reports failure.
   stage='schema-install';await write(fs.readFileSync(path.join(folder,'install.sql'),'utf8'));
   stage='installation-verification';const after=await inspect(client,a,{mode:'verify'});assert.deepEqual(after.counts,before.counts);
   report.status='installed-frozen';capture(after);
  }else{
   stage='resume-recovery-freshness';verifyRecovery(env,approval,second,now());
   stage='resume-intent';await write(`INSERT INTO ${receiptTable}(id,payload) VALUES('resume-intent',?)`,params);
   assert.deepEqual(await client.observe(),before.metadata);checkApprovalTiming(approval,now());
   stage='resume-start';await write(fs.readFileSync(path.join(folder,'resume-start.sql'),'utf8'));
   const claimed=await client.select(`SELECT payload FROM ${receiptTable} WHERE id='resume-started'`);assert.equal(claimed.length,1);assert.equal(claimed[0].payload,params[0]);
   checkApprovalTiming(approval,now());
   stage='resume-recovery-freshness';verifyRecovery(env,approval,second,now());
   stage='resume';await write(fs.readFileSync(path.join(folder,'resume.sql'),'utf8'),params);
   stage='resume-verification';const after=await inspect(client,a);assert.equal(after.state,'resumed');report.status='resumed';capture(after);
  }
  persist();return report;
 }catch(error){
  if(stage==='authorization' && error instanceof CheckFailure)stage=error.code;
  report.status=report.write_requests?'reconciliation-required':'blocked';report.failed_stage=stage;persist();
  throw Error('Repair stopped at '+stage+'; use SELECT-only reconciliation. No automatic retry, resume or rollback.');
 }
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const record=r=>console.log(JSON.stringify(r));
 try{await execute(process.env,{record});}catch(error){console.error(error.message);process.exitCode=1;}
}
