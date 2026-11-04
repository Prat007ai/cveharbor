// One explicitly approved adoption batch, then STOP. No deploy, retry or resume.
import fs from 'node:fs';
import path from 'node:path';
import { root } from './configure.mjs';
import { TARGET } from '../target.mjs';
import { hash, guardSQL, loadMigrationPlan, STAGING_DATABASE_ID } from './migrate.mjs';
import { diagnoseSchema, loadDiagnosticReference, REFERENCE_SHA256 } from './schema-diagnostic.mjs';
import { inspectSchemaState } from './schema-state.mjs';
import { failure, safeFailure } from './errors.mjs';

export const ADOPTION_SHA256 = '7ed30868dae48623caaccd9f1bead405333785b7b8c888f0308fb0b11ffe3eea';
export function loadAdoption(env, repository = path.resolve(root, '..')) {
  const bytes = fs.readFileSync(path.join(repository, 'staging/adoption.v1.json'));
  if (hash(bytes) !== ADOPTION_SHA256 || env.CF_STAGING_ADOPTION_SHA256 !== ADOPTION_SHA256)
    throw failure('adoption.plan', 'checksum');
  const adoption = JSON.parse(bytes), plan = loadMigrationPlan(env, repository);
  const reference = loadDiagnosticReference({ ...env, CF_STAGING_SCHEMA_DIAGNOSTIC_SHA256: REFERENCE_SHA256 }, repository);
  const statements = [...plan.files[0].statements, plan.files[1].statements.at(-1)];
  const sql = fs.readFileSync(path.join(repository, adoption.sql_path), 'utf8');
  if (adoption.account !== TARGET.account || adoption.database_id !== STAGING_DATABASE_ID || adoption.reference_sha256 !== REFERENCE_SHA256 ||
      adoption.execution_plan_sha256 !== env.CF_STAGING_SCHEMA_PLAN_SHA256 || adoption.original_checkpoint !== 29 || adoption.target_checkpoint !== 37 ||
      adoption.original_schema_sha256 !== reference.checkpoints[29].schema_sha256 || plan.files[1].end !== 37 || statements.length !== 8 ||
      hash(sql) !== adoption.sql_sha256 || sql !== statements.join('\n') + '\n') throw failure('adoption.plan', 'mismatch');
  return { adoption, plan, reference, statements };
}

// This is an administrator attestation, not a claim that the executor downloaded
// or restore-tested the private export. Raw bookmark/location never enter logs.
export function recoveryEvidence(env, adoption, now = Date.now()) {
  let proof;
  try { proof = JSON.parse(env.CF_STAGING_RECOVERY_EVIDENCE || ''); } catch { throw failure('adoption.recovery', 'missing'); }
  const age = now - Date.parse(proof.captured_at);
  if (proof.account !== TARGET.account || proof.database_id !== STAGING_DATABASE_ID || proof.source_sha !== env.GITHUB_SHA ||
      proof.start_schema_sha256 !== adoption.original_schema_sha256 || proof.adoption_sha256 !== ADOPTION_SHA256 ||
      proof.writers_quiesced !== true || proof.export_validated !== true || proof.restore_available !== true ||
      !Number.isFinite(age) || age < 0 || age > 3600000 || !/^[a-f0-9]{64}$/.test(proof.export_sha256 || '') ||
      typeof proof.bookmark !== 'string' || proof.bookmark.length < 6 || proof.bookmark.length > 512 ||
      typeof proof.private_export_reference !== 'string' || !proof.private_export_reference.trim() || proof.private_export_reference.length > 1000)
    throw failure('adoption.recovery', 'invalid_or_stale');
  return { evidence_sha256: hash(env.CF_STAGING_RECOVERY_EVIDENCE), export_sha256: proof.export_sha256,
    captured_at: proof.captured_at, bookmark_sha256: hash(proof.bookmark), administrator_attested: true };
}

export async function adoptSchema(env, { transport = fetch, record = () => {}, now = Date.now } = {}) {
  const report = { action: 'adopt-schema', status: 'stopped', account: TARGET.account, database_id: STAGING_DATABASE_ID,
    source_sha: env.GITHUB_SHA, adoption_sha256: ADOPTION_SHA256, started_at: new Date(now()).toISOString(),
    mutation_requests: 0, automatic_retries: 0, worker_mutations: 0, production_requests: 0,
    usage: { rows_read: 0, rows_written: 0, complete: true }, requests: [] };
  const persist = () => record('adoption', structuredClone(report));
  let loaded, identified = false, reconciling = false;
  const base = `https://api.cloudflare.com/client/v4/accounts/${TARGET.account}/d1/database/${STAGING_DATABASE_ID}`;
  function budget() {
    if ((!report.usage.complete && !reconciling) || report.usage.rows_read > 100000 || report.usage.rows_written > 100 ||
        report.requests.length > 500 || (report.peak_storage_bytes || 0) > 100000000) throw failure('adoption.usage', 'limit_or_missing_metrics');
  }
  async function request(sql, operation, expected = 1, write = false) {
    budget();
    const receipt = { operation, write, expected_results: expected }; report.requests.push(receipt); persist();
    let response, body;
    try {
      response = await transport(base + '/query', { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(45000),
        headers: { Authorization: 'Bearer ' + env.CF_STAGING_API_TOKEN, 'Content-Type': 'application/json' }, body: JSON.stringify({ sql }) });
      receipt.http_status = response.status; body = await response.json();
    } catch { report.usage.complete = false; throw failure(operation, 'ambiguous_response'); }
    const results = body?.result;
    if (!response.ok || body?.success !== true || body?.errors?.length || !Array.isArray(results) || results.length !== expected ||
        results.some(r => r.success !== true || r.error || r.errors?.length || !Array.isArray(r.results))) {
      report.usage.complete = false; throw failure(operation, 'd1_failure');
    }
    for (const result of results) {
      const meta = result.meta || {};
      for (const key of ['rows_read', 'rows_written']) {
        if (!Number.isSafeInteger(meta[key]) || meta[key] < 0) { report.usage.complete = false; throw failure(operation, 'missing_metrics'); }
        report.usage[key] += meta[key];
      }
      if (!write && meta.rows_written !== 0) throw failure(operation, 'unexpected_writes');
      if (!Number.isSafeInteger(meta.size_after) || meta.size_after < 0) throw failure(operation, 'missing_storage');
      report.peak_storage_bytes = Math.max(report.peak_storage_bytes || 0, meta.size_after);
    }
    receipt.complete = true; persist(); budget(); return results;
  }
  const query = async (sql, operation) => (await request(sql, operation))[0].results;
  async function inspectCurrent(label) {
    report.verified_target_checkpoint = null;
    return inspectSchemaState(loaded.plan, query, state => { report.actual_state = state; persist(); }, label);
  }
  try {
    if (env.STAGING_CHANGE_APPROVED !== 'PR243-STAGING-ONLY' || env.CF_STAGING_PROVISION_ACTION !== 'adopt-schema' ||
        env.CF_STAGING_ACCOUNT_ID !== TARGET.account || env.CF_STAGING_D1_DATABASE_ID !== STAGING_DATABASE_ID || !env.CF_STAGING_API_TOKEN ||
        !/^[a-f0-9]{40}$/.test(env.GITHUB_SHA || '') || env.GITHUB_SHA !== env.CF_STAGING_APPROVED_COMMIT || env.CF_STAGING_SCHEMA_RESUME_STEP)
      throw failure('adoption.authorize', 'configuration');
    loaded = loadAdoption(env);
    report.recovery = recoveryEvidence(env, loaded.adoption, now());
    report.original_evidence = loaded.adoption.evidence;
    report.sql_sha256 = loaded.adoption.sql_sha256;
    report.execution_plan_sha256 = loaded.adoption.execution_plan_sha256;
    const diagnostic = await diagnoseSchema({ ...env, CF_STAGING_PROVISION_ACTION: 'diagnose-schema', CF_STAGING_SCHEMA_DIAGNOSTIC_SHA256: REFERENCE_SHA256 },
      { transport, record: (name, value) => record('adoption-' + name, value) });
    if (!diagnostic.first_29_verified || diagnostic.usage.rows_written !== 0 || diagnostic.storage_delta_bytes !== 0)
      throw failure('adoption.start', 'original_checkpoint_not_verified');
    identified = true;
    report.original_checkpoint_verified = true;
    report.usage.rows_read += diagnostic.usage.rows_read;
    report.usage.rows_written += diagnostic.usage.rows_written;
    report.storage_before_bytes = diagnostic.storage_before_bytes;
    report.peak_storage_bytes = diagnostic.storage_before_bytes;
    // Revalidate freshness after the bounded read sequence, immediately before write.
    recoveryEvidence(env, loaded.adoption, now());
    const guards = guardSQL(loaded.reference, 29, []);
    const sql = [...guards.map(g => g.sql), ...loaded.statements].join('\n');
    report.guarded_batch_sha256 = hash(sql);
    if (Buffer.byteLength(sql) > 95000) throw failure('adoption.batch', 'statement_limit');
    budget();
    report.actual_state = { complete: false, matching_steps: [], status: 'invalidated_by_write' };
    report.mutation_requests = 1; report.guard_count = guards.length; report.adoption_statements = 8; persist();
    // D1 REST transactional multi-statement query. All assertions and eight
    // adoption statements share ONE request. No manual BEGIN/COMMIT or retries.
    await request(sql, 'adoption.apply', guards.length + 8, true);
    const after = await inspectCurrent('after-adoption');
    if (!after.actual.matching_steps.includes(37)) throw failure('adoption.verify', 'target_checkpoint_mismatch');
    const fk = await query('PRAGMA foreign_key_check', 'adoption.foreign_keys');
    const quick = await query('PRAGMA quick_check', 'adoption.quick_check');
    if (fk.length || quick.length !== 1 || Object.values(quick[0])[0] !== 'ok') throw failure('adoption.verify', 'integrity');
    report.verified_target_checkpoint = 37; report.status = 'complete';
    report.next = 'STOP. Separately review and approve remaining migrations; no resume cursor was configured.';
  } catch (error) {
    report.failure = safeFailure(error); report.verified_target_checkpoint = null;
    if (report.actual_state) report.actual_state = { ...report.actual_state, complete: false, matching_steps: [] };
    // Exactly one read-only reconciliation, never a write retry. Missing usage
    // metrics may block even reconciliation; its failure is explicit.
    if (identified) try { reconciling = true; await inspectCurrent('stopped-adoption'); } catch (e) { report.reconciliation_failure = safeFailure(e); }
    report.next = 'STOP. Review original/current checkpoint evidence. Do not replay adoption or guess a cursor.';
    throw error;
  } finally { report.completed_at = new Date(now()).toISOString(); persist(); }
  return report;
}
