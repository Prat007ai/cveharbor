// Exact-target schema executor. Never called by default; protected approval is mandatory.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { TARGET } from '../target.mjs';
import { root } from './configure.mjs';
import { diagnose } from './diagnose.mjs';
import { probeAccess } from './probe-access.mjs';
import { failure, safeFailure } from './errors.mjs';
import { inspectSchemaState, countSQL } from './schema-state.mjs';

export const STAGING_DATABASE_ID = 'fac61562-fc31-426d-8032-550aba63b7f6';
export const hash = value => createHash('sha256').update(value).digest('hex');
const encoded = value => JSON.stringify(value);
const identifier = value => '"' + value.replaceAll('"', '""') + '"';
const literal = value => "'" + value.replaceAll("'", "''") + "'";
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const same = (a, b) => encoded(canonical(a)) === encoded(canonical(b));
const validNumber = n => Number.isSafeInteger(n) && n >= 0;
export const LIMITS = Object.freeze({ rows_read: 1000000, rows_written: 100000, storage_bytes: 100000000 });

export function loadMigrationPlan(env, repository = path.resolve(root, '..')) {
  const manifestBytes=fs.readFileSync(path.join(repository,'staging/migrations.v1.json'));
  const approved=JSON.parse(manifestBytes);
  const expected=JSON.parse(fs.readFileSync(path.join(repository,'staging/bootstrap-approval.v1.json')));
  const payload=fs.readFileSync(path.join(repository,'staging/.build/schema/execution-plan.json'));
  const plan=JSON.parse(payload);
  if(hash(payload)!==expected.execution_plan_sha256||env.CF_STAGING_SCHEMA_PLAN_SHA256!==expected.execution_plan_sha256||plan.format!==1||plan.approved_manifest_sha256!==hash(manifestBytes)||plan.files.length!==approved.entries.length+1||expected.database_id!==STAGING_DATABASE_ID||expected.account!==TARGET.account)throw failure('migration.plan','checksum');
  for(let i=0;i<approved.entries.length;i++){
    const e=approved.entries[i],f=plan.files[i];
    if(f.file!==e.path||f.sha256!==e.sha256||hash(fs.readFileSync(path.join(repository,e.path)))!==e.sha256)throw failure('migration.sql','checksum',{file_index:i});
  }
  const guard=plan.files.at(-1);if(guard.file!=='staging/.build/schema/recovery-guards.sql'||guard.sha256!==hash(fs.readFileSync(path.join(repository,guard.file))))throw failure('migration.guards','checksum');
  return plan;
}

// Overflow is intentional: a failed condition aborts the D1 batch before its SQL.
// This rechecks schema + all row counts and built-in seed values inside the write batch.
export function guardSQL(plan, step, observedRows) {
  const state = plan.checkpoints[step], schema = plan.schemas[state.schema_sha256];
  const conditions = [`(SELECT count(*) FROM (${plan.schema_sql}))=${schema.objects.length}`];
  for (const [type, name, table, sql] of schema.objects) conditions.push(`EXISTS(SELECT 1 FROM sqlite_schema WHERE type=${literal(type)} AND name=${literal(name)} AND tbl_name=${literal(table)} AND sql IS ${sql === null ? 'NULL' : literal(sql)})`);
  for (const [name, count] of state.counts) conditions.push(`(SELECT count(*) FROM ${identifier(name)})=${count}`);
  for (const table of schema.tables) {
    const values = observedRows.filter(row => row[0] === table.name).map(row => row[1]);
    if (values.length) conditions.push(`(SELECT json_group_array(value) FROM (${table.row_sql}))=${literal(encoded(values))}`);
  }
  // Keep individual SQL under D1's 100 KB statement limit. Each guard is first in
  // the same batch; failure of any guard prevents all mutation statements.
  const guards = [];
  for (let i = 0; i < conditions.length; i += 20) guards.push({ sql: 'SELECT CASE WHEN ' + conditions.slice(i, i + 20).join(' AND ') + ' THEN 1 ELSE abs(-9223372036854775808) END AS staging_schema_guard;' });
  if (guards.some(g => Buffer.byteLength(g.sql) > 95000)) throw failure('migration.guard', 'statement_limit');
  return guards;
}

export async function migrate(env, { plan, transport = fetch, inventory = diagnose, probe = probeAccess, record = () => {}, requestIntervalMs = 350, beforeWrite = () => {} } = {}) {
  const report = { status: 'stopped', action: env.CF_STAGING_PROVISION_ACTION, account: TARGET.account, database_id: STAGING_DATABASE_ID,
    source_sha: env.GITHUB_SHA, plan_sha256: env.CF_STAGING_SCHEMA_PLAN_SHA256, started_at: new Date().toISOString(),
    requests: [], batches: [], storage: [], usage: { migration: { rows_read: 0, rows_written: 0 }, verification: { rows_read: 0, rows_written: 0 }, complete: true },
    limits: LIMITS, request_interval_ms: requestIntervalMs, automatic_retries: 0, production_requests: 0, worker_or_access_mutations: 0 };
  const persist = () => record('migration', report);
  let identified = false, before, lastRequestAt = 0;
  const base = `https://api.cloudflare.com/client/v4/accounts/${TARGET.account}`;
  const dbRoute = `/d1/database/${STAGING_DATABASE_ID}`;
  function budget() {
    const read = report.usage.migration.rows_read + report.usage.verification.rows_read;
    const written = report.usage.migration.rows_written + report.usage.verification.rows_written;
    if (read > LIMITS.rows_read || written > LIMITS.rows_written || report.storage.some(s => s.bytes > LIMITS.storage_bytes)) throw failure('migration.budget', 'usage_limit');
  }
  async function request(route, operation, body, group = 'verification') {
    // The only permitted POST is the exact staging D1 query endpoint. No SDK retry.
    if ((!route.startsWith('/') && route !== '') || route.includes('..') || route.includes('://') || body && route !== dbRoute + '/query') throw failure(operation, 'route');
    const gap = lastRequestAt + requestIntervalMs - Date.now();
    if (gap > 0) await new Promise(resolve => setTimeout(resolve, gap));
    lastRequestAt = Date.now();
    const receipt = { operation, method: body ? 'POST' : 'GET', started_at: new Date().toISOString() };
    report.requests.push(receipt); persist();
    let response, payload;
    try {
      response = await transport(base + route, { method: receipt.method, redirect: 'error', signal: AbortSignal.timeout(45000),
        headers: { Authorization: 'Bearer ' + env.CF_STAGING_API_TOKEN, 'Content-Type': 'application/json' }, ...(body ? { body: encoded(body) } : {}) });
      receipt.http_status = response.status;
      try { payload = await response.json(); } catch { throw failure(operation, 'invalid_json'); }
    } catch (error) {
      report.usage.complete = false; receipt.outcome = 'ambiguous'; persist();
      throw failure(operation, 'network', {}, error);
    }
    const results = Array.isArray(payload?.result) ? payload.result : [];
    if (body) {
      receipt.group = group; receipt.metrics = [];
      for (const result of results) {
        const meta = result?.meta || {};
        const metrics = Object.fromEntries(['rows_read', 'rows_written', 'size_after', 'duration'].map(k => [k, Number.isFinite(meta[k]) && meta[k] >= 0 ? meta[k] : null]));
        receipt.metrics.push(metrics);
        for (const key of ['rows_read', 'rows_written']) {
          if (!validNumber(metrics[key])) report.usage.complete = false;
          else report.usage[group][key] += metrics[key];
        }
        if (validNumber(metrics.size_after)) report.storage.push({ operation, bytes: metrics.size_after, source: 'query_meta' });
      }
      if (!results.length) report.usage.complete = false;
    }
    const bad = !response.ok || payload?.success !== true || (Array.isArray(payload.errors) && payload.errors.length) ||
      body && (!results.length || results.some(r => r?.success !== true || r?.error || (Array.isArray(r?.errors) && r.errors.length)));
    receipt.outcome = bad ? 'failed' : 'success'; receipt.completed_at = new Date().toISOString(); persist();
    if (bad) {
      if (body) report.usage.complete = false;
      const failed = results.findIndex(r => r?.success !== true || r?.error || (Array.isArray(r?.errors) && r.errors.length));
      throw failure(operation, response.status === 401 || response.status === 403 ? 'authorization' : response.status === 429 ? 'rate_limit' : /too many terms in compound select/i.test(JSON.stringify(payload?.errors || [])) ? 'compound_select_limit' : body ? 'd1_statement_or_batch' : 'cloudflare_api',
        { http_status: response.status, ...(failed >= 0 ? { result_index: failed } : {}), api_codes: (Array.isArray(payload?.errors) ? payload.errors : []).map(e => e?.code).filter(Number.isInteger).slice(0, 8) });
    }
    if (body && results.length !== (body.batch?.length || 1)) { report.usage.complete = false; throw failure(operation, 'result_count'); }
    return payload.result;
  }
  async function query(sql, operation) {
    const result = await request(dbRoute + '/query', operation, { sql });
    if (!Array.isArray(result[0]?.results)) throw failure(operation, 'result_shape');
    return result[0].results;
  }
  async function storage(label) {
    const db = await request(dbRoute, 'migration.database.' + label);
    if (db?.uuid !== STAGING_DATABASE_ID || db?.name !== TARGET.database) throw failure('migration.database.identity', 'target');
    if (!validNumber(db.file_size)) throw failure('migration.storage', 'metadata_unavailable');
    report.storage.push({ operation: label, bytes: db.file_size, source: 'database_metadata' }); persist();
    return db.file_size;
  }
  async function immutableState() {
    const state = {};
    for (const name of [TARGET.api, TARGET.site]) for (const suffix of ['settings', 'deployments', 'subdomain', 'schedules'])
      state[name + '/' + suffix] = await request(`/workers/scripts/${name}/${suffix}`, 'migration.invariants.' + name + '.' + suffix);
    const apps = await request('/access/apps?per_page=100', 'migration.invariants.access');
    if (!Array.isArray(apps) || apps.length >= 100) throw failure('migration.invariants.access', 'validation');
    const matches = apps.filter(a => a.domain === new URL(TARGET.origin).hostname && a.aud === env.CF_STAGING_ACCESS_AUD);
    if (matches.length !== 1 || !/^[a-f0-9-]+$/i.test(matches[0].id)) throw failure('migration.invariants.access', 'validation');
    state.access = matches[0];
    state.policies = await request(`/access/apps/${matches[0].id}/policies`, 'migration.invariants.policies');
    return hash(encoded(canonical(state)));
  }
  async function inspect(label) {
    if (report.last_verified_step !== undefined && report.last_verified_step !== null)
      report.historical_verified_step = report.last_verified_step;
    report.last_verified_step = null;
    return inspectSchemaState(plan, (sql, suffix) => query(sql, 'migration.state.' + label + '.' + suffix),
      state => { report.actual_state = state; persist(); }, label, { countBatch: async (names, suffix) => {
        if (!names.length || names.length > 5) throw failure('migration.counts', 'inspection_limit');
        const results = await request(dbRoute + '/query', 'migration.state.' + label + '.' + suffix, { batch: names.map(name => ({ sql: countSQL(name) })) });
        return results.map(r => r.results?.length === 1 ? r.results[0]?.n : null);
      } });
  }

  try {
    if (!validNumber(requestIntervalMs)) throw failure('migration.pacing', 'configuration');
    if (env.STAGING_CHANGE_APPROVED !== 'PR243-STAGING-ONLY' || env.CF_STAGING_PROVISION_ACTION !== 'migrate' ||
        env.CF_STAGING_ACCOUNT_ID !== TARGET.account || env.CF_STAGING_D1_DATABASE_ID !== STAGING_DATABASE_ID || !env.CF_STAGING_API_TOKEN ||
        !/^(0|[1-9]\d*)$/.test(env.CF_STAGING_SCHEMA_RESUME_STEP || '')) throw failure('migration.authorize', 'configuration');
    plan ??= loadMigrationPlan(env);
    const start = Number(env.CF_STAGING_SCHEMA_RESUME_STEP);
    if (!Number.isSafeInteger(start) || start >= plan.checkpoints.length) throw failure('migration.resume', 'configuration');
    report.approved_start_step = start; report.total_statements = plan.checkpoints.length - 1; persist();
    if ((await request('', 'migration.account'))?.id !== TARGET.account) throw failure('migration.account', 'target');
    report.storage_before_bytes = await storage('before'); identified = true;
    const inventoryReport = await inventory(env, transport);
    record('migration-inventory', inventoryReport);
    if (!inventoryReport.verified) throw failure('migration.inventory', 'validation');
    before = await immutableState(); report.invariants_before_sha256 = before;
    const access = await probe(env, transport); record('migration-access-before', access);
    if (!access.passed) throw failure('migration.access.before', 'validation');
    let state = await inspect('before');
    if (!state.actual.matching_steps.includes(start)) throw failure('migration.resume', 'state_mismatch');
    if (!report.usage.complete) throw failure('migration.metrics', 'metadata_unavailable');
    budget();
    for (const file of plan.files.filter(f => f.end > start)) {
      const from = Math.max(start, file.start);
      if (!state.actual.matching_steps.includes(from)) throw failure('migration.checkpoint', 'state_mismatch');
      const guards = guardSQL(plan, from, state.rows);
      const sql = file.statements.slice(from - file.start).map(sql => ({ sql }));
      const batch = { file: file.file, phase: file.phase, sql_sha256: file.sha256, from_step: from, to_step: file.end, guard_count: guards.length, outcome: 'pending' };
      report.batches.push(batch); persist();
      budget();
      beforeWrite();
      report.actual_state = { status: 'invalidated_by_write', complete: false, matching_steps: [], counts: [], rows_verified: false };
      report.historical_verified_step = report.last_verified_step ?? null; report.last_verified_step = null; persist();
      await request(dbRoute + '/query', 'migration.apply.' + file.phase + '.' + file.start, { batch: [...guards, ...sql] }, 'migration');
      batch.outcome = 'response_success'; persist();
      state = await inspect('after-' + file.end);
      if (!state.actual.matching_steps.includes(file.end)) throw failure('migration.verify.' + file.end, 'state_mismatch');
      const fk = await query('PRAGMA foreign_key_check', 'migration.foreign_keys.' + file.end);
      if (fk.length) throw failure('migration.foreign_keys.' + file.end, 'integrity');
      await storage('after-' + file.end);
      batch.outcome = 'verified'; report.last_verified_step = file.end; persist();
      if (!report.usage.complete) throw failure('migration.metrics', 'metadata_unavailable');
      budget();
    }
    const integrity = await query('PRAGMA quick_check', 'migration.integrity');
    if (integrity.length !== 1 || Object.values(integrity[0])[0] !== 'ok') throw failure('migration.integrity', 'integrity');
    report.invariants_after_sha256 = await immutableState();
    report.invariants_unchanged = report.invariants_after_sha256 === before;
    if (!report.invariants_unchanged) throw failure('migration.invariants', 'changed');
    const accessAfter = await probe(env, transport); record('migration-access-after', accessAfter);
    if (!accessAfter.passed) throw failure('migration.access.after', 'validation');
    report.storage_after_bytes = await storage('after');
    report.storage_delta_bytes = report.storage_after_bytes - report.storage_before_bytes;
    if (!report.usage.complete) throw failure('migration.metrics', 'metadata_unavailable');
    budget(); report.status = 'complete';
  } catch (error) {
    report.failure = safeFailure(error);
    const unfinished = report.batches.at(-1);
    if (unfinished && unfinished.outcome !== 'verified') unfinished.outcome = 'stopped_unverified';
    // Exactly one read-only reconciliation pass, never a replay of write SQL.
    if (identified) {
      try { await inspect('stopped'); report.state_inspected_after_stop = true; } catch (e) { report.state_inspection_failure = safeFailure(e); }
      try { report.storage_after_bytes = await storage('stopped'); report.storage_delta_bytes = report.storage_after_bytes - report.storage_before_bytes; } catch (e) { report.storage_inspection_failure = safeFailure(e); }
      if (before) try { report.invariants_after_sha256 = await immutableState(); report.invariants_unchanged = before === report.invariants_after_sha256; } catch (e) { report.invariants_inspection_failure = safeFailure(e); }
    }
    report.next = 'Review actual state and usage; separately approve an exact resume step or a forward repair. Never rerun blindly.';
    persist(); throw error;
  } finally {
    report.peak_observed_storage_bytes = report.storage.length ? Math.max(...report.storage.map(s => s.bytes)) : null;
    report.completed_at = new Date().toISOString(); persist();
  }
  return report;
}


export {migrationState,verifySchema,applyManifest} from './manifest-state.mjs';
