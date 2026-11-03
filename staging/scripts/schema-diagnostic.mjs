// Closed read-only operation for the ORIGINAL run #15 bootstrap reference.
// No imports from migration/deployment executors and no generic SQL entrypoint.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { TARGET } from '../target.mjs';
import { root } from './configure.mjs';
import { failure, safeFailure } from './errors.mjs';
import { inspectSchemaState, quoteIdentifier } from './schema-state.mjs';
export const DIAGNOSTIC_DATABASE_ID = 'fac61562-fc31-426d-8032-550aba63b7f6';
export const REFERENCE_SHA256 = 'd2a9af7136414eabe7dc5c74814addbdbb113e43d7edc0c85d8fbaadc1e9248e';
export const DIAGNOSTIC_LIMITS = Object.freeze({ rows_read: 100000, rows_written: 0, requests: 1000, storage_bytes: 100000000 });
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const canonical = x => Array.isArray(x) ? x.map(canonical) : x && typeof x === 'object' ? Object.fromEntries(Object.keys(x).sort().map(k => [k, canonical(x[k])])) : x;
const same = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
export function loadDiagnosticReference(env, repository = path.resolve(root, '..')) {
  const bytes = fs.readFileSync(path.join(repository, 'staging/schema-diagnostic.v1.json'));
  if (digest(bytes) !== REFERENCE_SHA256 || env.CF_STAGING_SCHEMA_DIAGNOSTIC_SHA256 !== REFERENCE_SHA256)
    throw failure('schema.diagnostic.reference', 'checksum');
  const plan = JSON.parse(bytes);
  if (plan.account !== TARGET.account || plan.database_id !== DIAGNOSTIC_DATABASE_ID || plan.expected_step !== 29 || plan.checkpoints.length !== 30 ||
      digest(fs.readFileSync(path.join(repository, plan.source_sql))) !== plan.source_sql_sha256) throw failure('schema.diagnostic.source', 'checksum');
  return plan;
}
export function diagnosticReadAllowed(sql, plan) {
  if (sql === plan.schema_sql || ['PRAGMA quick_check', 'PRAGMA foreign_key_check'].includes(sql)) return true;
  // Identifier quoting is part of the grammar; no trailing SQL or parameters.
  if (/^SELECT count\(\*\) AS n FROM "(?:[^"]|"")+"$/.test(sql)) return true;
  if (/^PRAGMA (?:table_info|index_list|index_info)\("(?:[^"]|"")+"\)$/.test(sql)) return true;
  return Object.values(plan.schemas).some(s => s.tables.some(t => sql === t.row_sql + ' LIMIT 1001'));
}
export async function diagnoseSchema(env, { transport = fetch, record = () => {}, plan } = {}) {
  const report = { action: 'diagnose-schema', status: 'stopped', account: TARGET.account, database_id: DIAGNOSTIC_DATABASE_ID,
    source_sha: env.GITHUB_SHA, reference_sha256: REFERENCE_SHA256, expected_step: 29, first_29_verified: null,
    requests: [], usage: { rows_read: 0, rows_written: 0, complete: true }, storage: [],
    limits: DIAGNOSTIC_LIMITS, mutation_requests: 0, automatic_retries: 0, production_requests: 0, started_at: new Date().toISOString() };
  const persist = () => record('schema-diagnostic', report);
  const base = `https://api.cloudflare.com/client/v4/accounts/${TARGET.account}`;
  const dbRoute = '/d1/database/' + DIAGNOSTIC_DATABASE_ID;
  async function request(route, operation, sql) {
    if (!(route === '' || route === dbRoute || route === dbRoute + '/query' && typeof sql === 'string' && diagnosticReadAllowed(sql, plan)))
      throw failure(operation, 'read_only_boundary');
    if (report.requests.length >= DIAGNOSTIC_LIMITS.requests || report.usage.rows_read > DIAGNOSTIC_LIMITS.rows_read ||
        report.storage.some(s => s.bytes > DIAGNOSTIC_LIMITS.storage_bytes)) throw failure(operation, 'inspection_limit');
    const receipt = { operation, method: sql ? 'POST' : 'GET' }; report.requests.push(receipt); persist();
    let response, body;
    try {
      response = await transport(base + route, { method: receipt.method, redirect: 'error', signal: AbortSignal.timeout(30000),
        headers: { Authorization: 'Bearer ' + env.CF_STAGING_API_TOKEN, 'Content-Type': 'application/json' }, ...(sql ? { body: JSON.stringify({ sql }) } : {}) });
      receipt.http_status = response.status;
    } catch { report.usage.complete = false; throw failure(operation, 'network'); }
    try { body = await response.json(); } catch { report.usage.complete = false; throw failure(operation, 'invalid_json'); }
    const result = body?.result;
    if (!response.ok || body?.success !== true || Array.isArray(body?.errors) && body.errors.length ||
        sql && (!Array.isArray(result) || result.length !== 1 || result[0]?.success !== true || result[0]?.error)) {
      report.usage.complete = false;
      // Recognize locally, export only a fixed category, never the provider text.
      const text = JSON.stringify(body?.errors || []);
      throw failure(operation, /too many terms in compound select/i.test(text) ? 'compound_select_limit' : 'cloudflare_api',
        { http_status: response.status, api_codes: (Array.isArray(body?.errors) ? body.errors : []).map(e => e?.code).filter(Number.isInteger).slice(0, 8) });
    }
    if (sql) {
      const meta = result[0].meta || {};
      receipt.metrics = Object.fromEntries(['rows_read', 'rows_written', 'size_after', 'duration'].map(k => [k, Number.isFinite(meta[k]) && meta[k] >= 0 ? meta[k] : null]));
      for (const key of ['rows_read', 'rows_written']) {
        if (!Number.isSafeInteger(receipt.metrics[key])) { report.usage.complete = false; persist(); throw failure(operation, 'metadata_unavailable'); }
        report.usage[key] += receipt.metrics[key];
      }
      if (Number.isSafeInteger(meta.size_after)) report.storage.push({ operation, bytes: meta.size_after, source: 'query_meta' });
      if (meta.rows_written !== 0) throw failure(operation, 'unexpected_writes');
      if (report.usage.rows_read > DIAGNOSTIC_LIMITS.rows_read || report.storage.some(s => s.bytes > DIAGNOSTIC_LIMITS.storage_bytes))
        throw failure(operation, 'inspection_limit');
      if (!Array.isArray(result[0].results)) throw failure(operation, 'result_shape');
    }
    receipt.completed = true; persist(); return result;
  }
  const query = async (sql, op) => (await request(dbRoute + '/query', 'schema.diagnostic.' + op, sql))[0].results;
  async function metadata(label) {
    const db = await request(dbRoute, 'schema.diagnostic.database.' + label);
    if (db?.uuid !== DIAGNOSTIC_DATABASE_ID || db?.name !== TARGET.database || !Number.isSafeInteger(db?.file_size) || db.file_size < 0)
      throw failure('schema.diagnostic.database', 'target');
    report.storage.push({ operation: label, bytes: db.file_size, source: 'database_metadata' }); persist(); return db.file_size;
  }
  try {
    if (env.CF_STAGING_PROVISION_ACTION !== 'diagnose-schema' || env.CF_STAGING_ACCOUNT_ID !== TARGET.account ||
        env.CF_STAGING_D1_DATABASE_ID !== DIAGNOSTIC_DATABASE_ID || !env.CF_STAGING_API_TOKEN) throw failure('schema.diagnostic.authorize', 'configuration');
    plan ??= loadDiagnosticReference(env);
    if ((await request('', 'schema.diagnostic.account'))?.id !== TARGET.account) throw failure('schema.diagnostic.account', 'target');
    report.storage_before_bytes = await metadata('before');
    const state = await inspectSchemaState(plan, query, actual => { report.actual_state = actual; persist(); }, 'read-only-original-run15');
    report.original_source = { commit: plan.source_commit, sql_sha256: plan.source_sql_sha256, expected_step: plan.expected_step };
    report.introspection = []; report.index_details = [];
    for (const [i, [name]] of state.actual.counts.entries()) {
      const columns = await query('PRAGMA table_info(' + quoteIdentifier(name) + ')', 'columns.' + i);
      const indexes = await query('PRAGMA index_list(' + quoteIdentifier(name) + ')', 'indexes.' + i);
      // Default values/SQL definitions are hashed, never exported from unknown schema.
      const expected = plan.introspection[name];
      const matches = !!expected && same(columns, expected.columns) && same(indexes, expected.indexes);
      report.introspection.push({ table: name, columns_sha256: digest(JSON.stringify(columns)), indexes, matches_reference: matches }); persist();
      for (const [j, index] of indexes.entries()) {
        if (typeof index?.name !== 'string') throw failure('schema.diagnostic.indexes', 'result_shape');
        const detail = await query('PRAGMA index_info(' + quoteIdentifier(index.name) + ')', 'index_info.' + i + '.' + j);
        report.index_details.push({ name: index.name, columns: detail, matches_reference: same(detail, plan.introspection_indexes[index.name]) }); persist();
      }
    }
    const fk = await query('PRAGMA foreign_key_check', 'foreign_keys');
    const quick = await query('PRAGMA quick_check', 'quick_check');
    report.integrity = { foreign_keys_passed: fk.length === 0, quick_check_passed: quick.length === 1 && Object.values(quick[0])[0] === 'ok' };
    // A second full observation prevents a failed end verification from retaining
    // a successful beginning observation as the current database checkpoint.
    const end = await inspectSchemaState(plan, query, actual => { report.actual_state = actual; persist(); }, 'read-only-final');
    report.storage_after_bytes = await metadata('after');
    report.storage_delta_bytes = report.storage_after_bytes - report.storage_before_bytes;
    report.first_29_verified = end.actual.matching_steps.includes(29) && state.actual.schema_sha256 === end.actual.schema_sha256 &&
      same(state.actual.counts, end.actual.counts) && report.introspection.every(x => x.matches_reference) && report.index_details.every(x => x.matches_reference) &&
      report.integrity.foreign_keys_passed && report.integrity.quick_check_passed;
    report.status = 'complete';
  } catch (error) {
    report.first_29_verified = null; report.failure = safeFailure(error);
    if (report.actual_state?.complete) {
      report.historical_observation = report.actual_state;
      report.actual_state = { ...report.actual_state, status: 'failed', complete: false, matching_steps: [], rows_verified: false, invalidated_by: 'diagnostic_failure' };
    }
    persist(); throw error;
  } finally { report.completed_at = new Date().toISOString(); persist(); }
  return report;
}
