import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { root } from '../scripts/configure.mjs';
import { TARGET } from '../target.mjs';
import { inspectSchemaState, countSQL } from '../scripts/schema-state.mjs';
import { diagnoseSchema, diagnosticReadAllowed, loadDiagnosticReference, REFERENCE_SHA256, DIAGNOSTIC_DATABASE_ID } from '../scripts/schema-diagnostic.mjs';
import { authorize, executeRelease } from '../scripts/release.mjs';
const sha = 'a'.repeat(40);
const env = { GITHUB_REPOSITORY: 'Prat007ai/cveharbor', GITHUB_REF: 'refs/heads/codex/cvie-core-phase012', GITHUB_SHA: sha,
  CF_STAGING_APPROVED_COMMIT: sha, GITHUB_EVENT_NAME: 'push', GITHUB_RUN_ATTEMPT: '2',
  CF_STAGING_PROVISION_ACTION: 'diagnose-schema', CF_STAGING_SCHEMA_DIAGNOSTIC_SHA256: REFERENCE_SHA256,
  CF_STAGING_ACCOUNT_ID: TARGET.account, CF_STAGING_D1_DATABASE_ID: DIAGNOSTIC_DATABASE_ID, CF_STAGING_API_TOKEN: 'synthetic-secret' };
const event = { head_commit: { id: sha, message: 'read-only schema checks [staging-release]' } };
const plan = loadDiagnosticReference(env);
const sql = fs.readFileSync(path.join(root, '../account-backend/schema.sql'), 'utf8');
async function harness(t, setup = sql, hook = async () => undefined) {
  const child = spawn('python', ['-u', path.join(root, 'tests/sqlite-diagnostic.py')], { stdio: ['pipe', 'pipe', 'inherit'] });
  t.after(() => { child.stdin.end(); child.kill(); });
  const waiting = [];
  createInterface({ input: child.stdout }).on('line', line => waiting.shift()(JSON.parse(line)));
  const execute = body => new Promise(resolve => { waiting.push(resolve); child.stdin.write(JSON.stringify(body) + '\n'); });
  assert.equal((await execute({ setup })).success, true);
  const calls = []; let latest;
  const transport = async (url, init) => {
    const base = `https://api.cloudflare.com/client/v4/accounts/${TARGET.account}`;
    assert.ok(url === base || url.startsWith(base + '/d1/database/' + DIAGNOSTIC_DATABASE_ID));
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ url, method: init.method, sql: body?.sql });
    const intercepted = await hook({ url, init, body, execute, calls });
    if (intercepted) return intercepted;
    if (body) {
      assert.equal(init.method, 'POST'); assert.deepEqual(Object.keys(body), ['sql']);
      assert.equal(diagnosticReadAllowed(body.sql, plan), true);
      const result = await execute(body);
      return Response.json(result, { status: result.success ? 200 : 400 });
    }
    assert.equal(init.method, 'GET');
    if (url === base) return Response.json({ success: true, result: { id: TARGET.account } });
    const size = (await execute({ sql: 'PRAGMA page_count' })).result[0].meta.size_after;
    return Response.json({ success: true, result: { uuid: DIAGNOSTIC_DATABASE_ID, name: TARGET.database, file_size: size } });
  };
  return { execute, calls, final: () => latest, deps: { plan, transport, record: (_n, r) => { latest = structuredClone(r); } } };
}

test('D1 five-term compound limit reproduces the legacy 18-table query failure; individual counts pass', async t => {
  const h = await harness(t);
  const legacy = plan.checkpoints[29].counts.map(([name]) => `SELECT '${name}' AS name,count(*) AS n FROM "${name}"`).join(' UNION ALL ') + ' ORDER BY name';
  assert.equal((await h.execute({ sql: legacy })).success, false);
  for (const [name] of plan.checkpoints[29].counts) assert.equal((await h.execute({ sql: countSQL(name) })).success, true);
});
test('full original checkpoint 29 is verified with read-only SQLite authorization and complete schema/index evidence', async t => {
  const h = await harness(t);
  const report = await diagnoseSchema(env, h.deps);
  assert.equal(report.status, 'complete'); assert.equal(report.first_29_verified, true);
  assert.deepEqual(report.actual_state.matching_steps, [29]); assert.equal(report.actual_state.counts.length, 18);
  assert.equal(report.introspection.length, 18); assert.ok(report.index_details.length > 0);
  assert.equal(report.actual_state.objects.length, plan.schemas[plan.checkpoints[29].schema_sha256].objects.length);
  assert.ok(report.actual_state.objects.some(x => x.type === 'index'));
  assert.ok(report.introspection.every(x => x.matches_reference));
  assert.equal(report.usage.rows_written, 0); assert.equal(report.usage.complete, true);
  assert.equal(report.storage_delta_bytes, 0); assert.equal(report.mutation_requests, 0);
  assert.ok(h.calls.every(c => !/workers|access|r2|bookmark/.test(c.url)));
  assert.doesNotMatch(JSON.stringify(report), /synthetic-secret|synthetic-error/);
});
test('count errors preserve fresh schema and partial counts, never the old checkpoint', async t => {
  let counts = 0;
  const h = await harness(t, sql, async ({ body }) => {
    if (body?.sql.startsWith('SELECT count(*)') && ++counts === 3) return Response.json({ success: false, errors: [{ code: 7500, message: 'synthetic-secret' }] }, { status: 400 });
  });
  await assert.rejects(diagnoseSchema(env, h.deps));
  const report = h.final();
  assert.equal(report.first_29_verified, null); assert.equal(report.actual_state.complete, false);
  assert.equal(report.actual_state.status, 'failed'); assert.equal(report.actual_state.schema_sha256, plan.checkpoints[29].schema_sha256);
  assert.equal(report.actual_state.counts.length, 2); assert.ok(report.actual_state.objects.length > 0);
  assert.deepEqual(report.actual_state.matching_steps, []); assert.equal(report.automatic_retries, 0);
  assert.doesNotMatch(JSON.stringify(report), /synthetic-secret/);
});
test('a failed final observation invalidates earlier diagnostic success', async t => {
  let schemaReads = 0;
  const h = await harness(t, sql, async ({ body }) => {
    if (body?.sql === plan.schema_sql && ++schemaReads === 3) return Response.json({ success: false, errors: [] }, { status: 400 });
  });
  await assert.rejects(diagnoseSchema(env, h.deps));
  assert.equal(h.final().actual_state.schema_sha256, null);
  assert.equal(h.final().actual_state.complete, false); assert.deepEqual(h.final().actual_state.matching_steps, []);
  assert.equal(h.final().first_29_verified, null);
});
test('partial prefix, unknown objects and unexpected customer rows cannot confirm checkpoint 29', async t => {
  for (const setup of ['CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);',
    sql + '\nCREATE TABLE unexpected(id TEXT);', sql + "\nINSERT INTO users(id,email) VALUES('private','private@example.test');"]) {
    const h = await harness(t, setup); const report = await diagnoseSchema(env, h.deps);
    assert.equal(report.first_29_verified, false);
    assert.ok(!report.actual_state.matching_steps.includes(29));
    assert.doesNotMatch(JSON.stringify(report), /private@example|"private"/);
    assert.ok(h.calls.every(c => !c.sql?.startsWith('SELECT quote')));
  }
});
test('closed SQL grammar and SQLite authorizer reject writes, multiple statements, parameters and arbitrary selects', async t => {
  const h = await harness(t);
  for (const bad of ['DELETE FROM users', 'CREATE TABLE x(id)', 'PRAGMA foreign_keys=OFF', 'SELECT count(*) AS n FROM "users"; DELETE FROM users', 'SELECT * FROM users', 'SELECT load_extension(1)'])
    assert.equal(diagnosticReadAllowed(bad, plan), false);
  assert.equal((await h.execute({ sql: 'DELETE FROM users' })).success, false);
  assert.equal(diagnosticReadAllowed(countSQL('a";DELETE FROM users;--'), plan), true); // one quoted identifier, not executable SQL
});
test('exact approval/target/reference gates reject wrong scope before any network or migration/deployment client', async () => {
  assert.equal(authorize(env, event, sha), 'diagnose-schema');
  for (const patch of [{ GITHUB_SHA: 'b'.repeat(40) }, { CF_STAGING_D1_DATABASE_ID: TARGET.productionDatabase },
    { CF_STAGING_ACCOUNT_ID: 'other' }, { CF_STAGING_SCHEMA_DIAGNOSTIC_SHA256: '' }, { GITHUB_RUN_ATTEMPT: '1' }])
    assert.throws(() => authorize({ ...env, ...patch }, event, sha));
  await assert.rejects(diagnoseSchema({ ...env, CF_STAGING_D1_DATABASE_ID: TARGET.productionDatabase }, { transport: async () => assert.fail('No network') }));
  await executeRelease(env, event, sha, { schemaDiagnostic: async () => ({ action: 'diagnose-schema' }),
    get: () => assert.fail('No release clients'), DB: {}, preflight: () => assert.fail('No release preflight'),
    migrate: () => assert.fail('No migration'), runner: () => assert.fail('No deploy') });
});
test('missing counters, unexpected writes, budget excess, lost response and bad database identity stop without retries', async t => {
  for (const mode of ['metrics', 'writes', 'budget', 'network', 'identity']) {
    let queries = 0;
    const h = await harness(t, sql, async ({ url, body, execute }) => {
      if (mode === 'identity' && !body && url.includes('/d1/database/')) return Response.json({ success: true, result: { uuid: TARGET.productionDatabase, name: TARGET.database, file_size: 0 } });
      if (!body) return;
      queries++;
      if (mode === 'network') throw Error('synthetic-secret');
      const result = await execute(body);
      if (mode === 'metrics') delete result.result[0].meta.rows_read;
      if (mode === 'writes') result.result[0].meta.rows_written = 1;
      if (mode === 'budget') result.result[0].meta.rows_read = 100001;
      return Response.json(result);
    });
    await assert.rejects(diagnoseSchema(env, h.deps));
    assert.equal(queries, mode === 'identity' ? 0 : 1); assert.equal(h.final().automatic_retries, 0);
    assert.equal(h.final().first_29_verified, null); assert.doesNotMatch(JSON.stringify(h.final()), /synthetic-secret/);
  }
});

test('API object key order does not change column/index verification', async t => {
  const h = await harness(t, sql, async ({ body, execute }) => {
    if (!body) return;
    const result = await execute(body);
    for (const r of result.result || []) r.results = r.results.map(row => Object.fromEntries(Object.entries(row).reverse()));
    return Response.json(result);
  });
  assert.equal((await diagnoseSchema(env, h.deps)).first_29_verified, true);
});
