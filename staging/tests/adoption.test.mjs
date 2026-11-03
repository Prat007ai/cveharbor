import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { root } from '../scripts/configure.mjs';
import { TARGET } from '../target.mjs';
import { adoptSchema, loadAdoption, ADOPTION_SHA256 } from '../scripts/adopt-schema.mjs';
import { migrate, STAGING_DATABASE_ID } from '../scripts/migrate.mjs';
import { executeRelease, authorize } from '../scripts/release.mjs';

const build = spawnSync('python', ['staging/scripts/migration-plan.py'], { cwd: path.resolve(root, '..'), encoding: 'utf8' });
assert.equal(build.status, 0, build.stderr);
const pinned = JSON.parse(fs.readFileSync(path.join(root, 'adoption.v1.json')));
const sha = 'a'.repeat(40);
function environment(patch = {}) {
  const e = { GITHUB_SHA: sha, CF_STAGING_APPROVED_COMMIT: sha, GITHUB_REPOSITORY: 'Prat007ai/cveharbor',
    GITHUB_REF: 'refs/heads/codex/cvie-core-phase012', GITHUB_EVENT_NAME: 'workflow_dispatch',
    STAGING_CHANGE_APPROVED: 'PR243-STAGING-ONLY', CF_STAGING_PROVISION_ACTION: 'adopt-schema',
    CF_STAGING_ADOPTION_SHA256: ADOPTION_SHA256, CF_STAGING_SCHEMA_PLAN_SHA256: pinned.execution_plan_sha256,
    CF_STAGING_ACCOUNT_ID: TARGET.account, CF_STAGING_D1_DATABASE_ID: STAGING_DATABASE_ID,
    CF_STAGING_API_TOKEN: 'synthetic-private-token', CF_STAGING_ACCESS_AUD: 'b'.repeat(64), ...patch };
  e.CF_STAGING_RECOVERY_EVIDENCE = JSON.stringify({ account: TARGET.account, database_id: STAGING_DATABASE_ID,
    source_sha: sha, start_schema_sha256: pinned.original_schema_sha256, adoption_sha256: ADOPTION_SHA256,
    writers_quiesced: true, export_validated: true, restore_available: true, captured_at: new Date().toISOString(),
    bookmark: 'synthetic-private-bookmark', export_sha256: 'c'.repeat(64), private_export_reference: 'synthetic-private-storage' });
  return e;
}
const { plan, reference } = loadAdoption(environment());
const original = fs.readFileSync(path.join(root, '../account-backend/schema.sql'), 'utf8');
async function harness(t, hook = async () => undefined) {
  const child = spawn('python', ['-u', path.join(root, 'tests/sqlite-d1.py')], { stdio: ['pipe', 'pipe', 'inherit'] });
  t.after(() => { child.stdin.end(); child.kill(); });
  const pending = [];
  createInterface({ input: child.stdout }).on('line', line => pending.shift()(JSON.parse(line)));
  const execute = body => new Promise(resolve => { pending.push(resolve); child.stdin.write(JSON.stringify(body) + '\n'); });
  assert.equal((await execute({ sql: original })).success, true);
  const calls = [], reports = {};
  const transport = async (url, init) => {
    const base = 'https://api.cloudflare.com/client/v4/accounts/' + TARGET.account;
    assert.ok(url === base || url.startsWith(base + '/')); assert.equal(init.redirect, 'error');
    const route = url.slice(base.length), body = init.body ? JSON.parse(init.body) : null;
    calls.push({ route, method: init.method, body });
    const override = await hook({ route, body, execute });
    if (override) return override;
    if (body) {
      assert.equal(route, '/d1/database/' + STAGING_DATABASE_ID + '/query');
      const response = await execute(body);
      return Response.json(response, { status: response.success ? 200 : 400 });
    }
    if (route === '') return Response.json({ success: true, result: { id: TARGET.account } });
    if (route === '/d1/database/' + STAGING_DATABASE_ID) {
      const r = await execute({ sql: 'PRAGMA page_count' });
      return Response.json({ success: true, result: { uuid: STAGING_DATABASE_ID, name: TARGET.database, file_size: r.result[0].meta.size_after } });
    }
    if (route.startsWith('/access/apps/')) return Response.json({ success: true, result: [{ id: 'policy', decision: 'allow' }] });
    if (route.startsWith('/access/apps')) return Response.json({ success: true, result: [{ id: 'abc-def', domain: new URL(TARGET.origin).hostname, aud: 'b'.repeat(64) }] });
    assert.match(route, /^\/workers\/scripts\/cveharbor-(accounts|site)-staging\/(settings|deployments|subdomain|schedules)$/);
    return Response.json({ success: true, result: { unchanged: true } });
  };
  return { execute, calls, reports, deps: { transport, record: (name, report) => { reports[name] = structuredClone(report); } } };
}
const writing = body => body?.sql?.includes('CREATE TABLE staging_schema_history');
const originalObjects = async h => (await h.execute({ sql: "SELECT type,name,rootpage,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name" })).result[0].results;

test('eight-statement adoption preserves original objects and stops at current checkpoint 37; separately approved continuation reaches full schema', async t => {
  const h = await harness(t), before = await originalObjects(h), e = environment();
  const r = await adoptSchema(e, h.deps);
  assert.equal(r.status, 'complete'); assert.equal(r.verified_target_checkpoint, 37);
  assert.equal(r.mutation_requests, 1); assert.equal(r.adoption_statements, 8);
  assert.equal(r.actual_state.counts.length, 22); assert.equal(r.actual_state.counts.find(x => x[0] === 'staging_schema_history')[1], 2);
  assert.ok(h.calls.every(c => c.route === '' || c.route.startsWith('/d1/database/' + STAGING_DATABASE_ID)));
  assert.equal(h.calls.filter(c => writing(c.body)).length, 1);
  assert.equal(e.CF_STAGING_SCHEMA_RESUME_STEP, undefined);
  const after = await originalObjects(h);
  assert.deepEqual(after.filter(o => before.some(x => x.name === o.name)), before);
  assert.doesNotMatch(JSON.stringify(h.reports), /synthetic-private-token|synthetic-private-bookmark|synthetic-private-storage/);
  const result = await migrate({ ...e, CF_STAGING_PROVISION_ACTION: 'migrate', CF_STAGING_SCHEMA_RESUME_STEP: '37' }, {
    plan, transport: h.deps.transport, inventory: async () => ({ verified: true }), probe: async () => ({ passed: true }) });
  assert.equal(result.status, 'complete'); assert.equal(result.last_verified_step, 740);
  assert.equal(result.batches[0].file, 'account-backend/totp-schema.sql');
  assert.equal(result.total_statements - result.approved_start_step, 703);
  assert.equal(result.actual_state.counts.length, 102);
  assert.equal(result.actual_state.counts.find(x => x[0] === 'staging_schema_history')[1], 35);
  assert.deepEqual((await originalObjects(h)).filter(o => before.some(x => x.name === o.name)), before);
});

test('wrong target/source/action/digest/cursor and missing or stale recovery evidence stop before network', async () => {
  const reject = async e => assert.rejects(adoptSchema(e, { transport: () => assert.fail('No network') }));
  for (const delta of [{ CF_STAGING_D1_DATABASE_ID: TARGET.productionDatabase }, { CF_STAGING_ACCOUNT_ID: 'production' },
    { GITHUB_SHA: 'b'.repeat(40) }, { CF_STAGING_PROVISION_ACTION: 'migrate' }, { CF_STAGING_SCHEMA_RESUME_STEP: '37' },
    { CF_STAGING_ADOPTION_SHA256: 'd'.repeat(64) }, { CF_STAGING_SCHEMA_PLAN_SHA256: 'd'.repeat(64) }]) await reject(environment(delta));
  for (const delta of [{ writers_quiesced: false }, { export_validated: false }, { restore_available: false },
    { database_id: TARGET.productionDatabase }, { source_sha: 'b'.repeat(40) }, { start_schema_sha256: 'd'.repeat(64) },
    { captured_at: new Date(Date.now() - 3600001).toISOString() }, { captured_at: new Date(Date.now() + 60000).toISOString() }, { bookmark: '' }]) {
    const e = environment(); e.CF_STAGING_RECOVERY_EVIDENCE = JSON.stringify({ ...JSON.parse(e.CF_STAGING_RECOVERY_EVIDENCE), ...delta }); await reject(e);
  }
  await reject({ ...environment(), CF_STAGING_RECOVERY_EVIDENCE: '' });
});

test('adoption release dispatch cannot enter migration, Worker, Access or publication paths', async () => {
  const e = environment(), event = { inputs: { operation: 'adopt-schema' } };
  assert.equal(authorize(e, event, sha), 'adopt-schema');
  for (const delta of [{ GITHUB_REF: 'refs/heads/main' }, { GITHUB_EVENT_NAME: 'pull_request' }, { CF_STAGING_SCHEMA_RESUME_STEP: '0' }])
    assert.throws(() => authorize({ ...e, ...delta }, event, sha));
  const result = await executeRelease(e, event, sha, { adoptSchema: async () => ({ action: 'adopt-schema' }),
    get: () => assert.fail('No release clients'), preflight: () => assert.fail('No deployment preflight'),
    migrate: () => assert.fail('No continuation'), runner: () => assert.fail('No processes') });
  assert.equal(result.action, 'adopt-schema');
});

test('unknown objects, new customer rows and an already adopted database cannot be adopted', async t => {
  for (const sql of ['CREATE TABLE unknown(id TEXT)', "INSERT INTO users(id,email) VALUES('synthetic','test@example.invalid')", null]) {
    const h = await harness(t);
    if (sql) assert.equal((await h.execute({ sql })).success, true);
    else await adoptSchema(environment(), h.deps);
    const before = h.calls.filter(c => writing(c.body)).length;
    await assert.rejects(adoptSchema(environment(), h.deps));
    assert.equal(h.calls.filter(c => writing(c.body)).length, before);
  }
});

test('transactional guards reject concurrent rows or schema changes before any bridge statement', async t => {
  for (const sql of ["INSERT INTO users(id,email) VALUES('synthetic','test@example.invalid')", 'CREATE TABLE raced(id TEXT)']) {
    const h = await harness(t, async ({ body, execute }) => { if (writing(body)) await execute({ sql }); });
    await assert.rejects(adoptSchema(environment(), h.deps));
    assert.equal((await originalObjects(h)).some(o => o.name === 'staging_schema_history'), false);
    assert.equal(h.calls.filter(c => writing(c.body)).length, 1);
  }
});

test('mid-batch failure rolls back all staging DDL and receipts', async t => {
  const h = await harness(t, async ({ body, execute }) => {
    if (!writing(body)) return;
    const sql = body.sql.replace('CREATE TABLE staging_mail (', 'SELECT abs(-9223372036854775808);\nCREATE TABLE staging_mail (');
    const result = await execute({ sql }); assert.equal(result.success, false);
    return Response.json(result, { status: 400 });
  });
  const before = await originalObjects(h);
  await assert.rejects(adoptSchema(environment(), h.deps));
  assert.deepEqual(await originalObjects(h), before);
  assert.equal(h.reports.adoption.actual_state.schema_sha256, reference.checkpoints[29].schema_sha256);
  assert.equal(h.reports.adoption.verified_target_checkpoint, null);
});

test('committed but lost response is read back as checkpoint 37 without a retry or continuation', async t => {
  const h = await harness(t, async ({ body, execute }) => {
    if (writing(body)) { assert.equal((await execute(body)).success, true); throw Error('synthetic-private-token'); }
  });
  await assert.rejects(adoptSchema(environment(), h.deps));
  assert.equal(h.reports.adoption.status, 'stopped'); assert.equal(h.reports.adoption.usage.complete, false);
  assert.deepEqual(h.reports.adoption.actual_state.matching_steps, [37]);
  assert.equal(h.reports.adoption.verified_target_checkpoint, null);
  assert.equal(h.calls.filter(c => writing(c.body)).length, 1);
  assert.doesNotMatch(JSON.stringify(h.reports), /synthetic-private-token/);
});

test('failed post-write inspections do not leave a successful current checkpoint', async t => {
  let written = false;
  const h = await harness(t, async ({ body }) => {
    if (writing(body)) written = true;
    else if (written && body?.sql === plan.schema_sql) return Response.json({ success: false }, { status: 500 });
  });
  await assert.rejects(adoptSchema(environment(), h.deps));
  assert.equal(h.reports.adoption.actual_state.complete, false);
  assert.deepEqual(h.reports.adoption.actual_state.matching_steps, []);
  assert.equal(h.reports.adoption.verified_target_checkpoint, null);
});

test('recovery freshness is checked again immediately before the guarded write', async t => {
  const h = await harness(t), e = environment(); let calls = 0; const stamp = Date.parse(JSON.parse(e.CF_STAGING_RECOVERY_EVIDENCE).captured_at);
  await assert.rejects(adoptSchema(e, { ...h.deps, now: () => stamp + (++calls > 2 ? 3600001 : 0) }));
  assert.equal(h.reports.adoption.original_checkpoint_verified, true);
  assert.equal(h.calls.filter(c => writing(c.body)).length, 0);
});

test('missing write metrics stop after one batch and cannot report a successful adoption', async t => {
  const h = await harness(t, async ({ body, execute }) => {
    if (!writing(body)) return;
    const r = await execute(body); delete r.result.at(-1).meta.rows_written;
    return Response.json(r);
  });
  await assert.rejects(adoptSchema(environment(), h.deps));
  assert.equal(h.reports.adoption.status, 'stopped'); assert.equal(h.reports.adoption.usage.complete, false);
  assert.deepEqual(h.reports.adoption.actual_state.matching_steps, [37]);
  assert.equal(h.reports.adoption.verified_target_checkpoint, null);
  assert.equal(h.calls.filter(c => writing(c.body)).length, 1);
});
