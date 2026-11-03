import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn, spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { migrate, loadMigrationPlan, STAGING_DATABASE_ID, hash } from '../scripts/migrate.mjs';
import { authorize, provision } from '../scripts/provision.mjs';
import { TARGET } from '../target.mjs';
import { root } from '../scripts/configure.mjs';

const build = spawnSync('python', ['staging/scripts/migration-plan.py'], { cwd: path.resolve(root, '..'), encoding: 'utf8' });
assert.equal(build.status, 0, build.stderr);
const planBytes = fs.readFileSync(path.join(root, '.build/schema/execution-plan.json'));
const plan = JSON.parse(planBytes);
const sha = 'a'.repeat(40);
const env = { STAGING_CHANGE_APPROVED: 'PR243-STAGING-ONLY', CF_STAGING_PROVISION_ACTION: 'migrate-schema',
  CF_STAGING_ACCOUNT_ID: TARGET.account, CF_STAGING_D1_DATABASE_ID: STAGING_DATABASE_ID, CF_STAGING_API_TOKEN: 'synthetic-secret',
  CF_STAGING_ACCESS_AUD: 'b'.repeat(64), CF_STAGING_SCHEMA_PLAN_SHA256: hash(planBytes), CF_STAGING_SCHEMA_RESUME_STEP: '0',
  GITHUB_SHA: sha, CF_STAGING_APPROVED_COMMIT: sha, GITHUB_REPOSITORY: 'Prat007ai/cveharbor',
  GITHUB_REF: 'refs/heads/codex/cvie-core-phase012', GITHUB_EVENT_NAME: 'push', GITHUB_RUN_ATTEMPT: '2' };
const event = { head_commit: { id: sha, message: 'schema preparation [staging-provision]' } };
function harness(t, hook = async () => undefined) {
  const child = spawn('python', ['-u', path.join(root, 'tests/sqlite-d1.py')], { stdio: ['pipe', 'pipe', 'inherit'] });
  t.after(() => { child.stdin.end(); child.kill(); });
  const lines = createInterface({ input: child.stdout });
  const waiters = [];
  lines.on('line', line => waiters.shift()(JSON.parse(line)));
  const execute = body => new Promise(resolve => { waiters.push(resolve); child.stdin.write(JSON.stringify(body) + '\n'); });
  let latest; const calls = [];
  let size = 0;
  const transport = async (url, init) => {
    assert.equal(new URL(url).origin, 'https://api.cloudflare.com');
    assert.ok(new URL(url).pathname.startsWith('/client/v4/accounts/' + TARGET.account));
    assert.equal(init.redirect, 'error');
    const route = new URL(url).pathname.split(TARGET.account)[1];
    calls.push({ route, method: init.method });
    if (init.method === 'POST') {
      assert.equal(route, `/d1/database/${STAGING_DATABASE_ID}/query`);
      const body = JSON.parse(init.body);
      const intercepted = await hook({ body, execute, calls });
      if (intercepted) return intercepted;
      const response = await execute(body);
      for (const result of response.result || []) size = result.meta?.size_after ?? size;
      return Response.json(response);
    }
    assert.equal(init.method, 'GET');
    if (route === '') return Response.json({ success: true, result: { id: TARGET.account } });
    if (route === `/d1/database/${STAGING_DATABASE_ID}`) {
      const stats = await execute({ sql: 'PRAGMA page_count' });
      size = stats.result[0].meta.size_after;
      return Response.json({ success: true, result: { uuid: STAGING_DATABASE_ID, name: TARGET.database, file_size: size } });
    }
    if (route.startsWith('/access/apps/')) return Response.json({ success: true, result: [{ id: 'policy', decision: 'allow' }] });
    if (route.startsWith('/access/apps')) return Response.json({ success: true, result: [{ id: 'abc-def', domain: new URL(TARGET.origin).hostname, aud: env.CF_STAGING_ACCESS_AUD }] });
    assert.match(route, /^\/workers\/scripts\/cveharbor-(accounts|site)-staging\/(settings|deployments|subdomain|schedules)$/);
    return Response.json({ success: true, result: { unchanged: true } });
  };
  const deps = { plan, transport, inventory: async () => ({ verified: true }), probe: async () => ({ passed: true }),
    record: (name, data) => { if (name === 'migration') latest = structuredClone(data); } };
  return { deps, calls, execute, final: () => latest };
}

test('migration source and explicit operation gates reject production, wrong UUID/digest/step and initial push', async () => {
  assert.equal(authorize(env, event, sha).action, 'migrate-schema');
  assert.equal(loadMigrationPlan(env).checkpoints.length, 371);
  for (const patch of [{ CF_STAGING_D1_DATABASE_ID: TARGET.productionDatabase }, { CF_STAGING_D1_DATABASE_ID: '11111111-2222-4333-8444-555555555555' },
    { CF_STAGING_ACCOUNT_ID: 'production' }, { CF_STAGING_SCHEMA_PLAN_SHA256: '' }, { CF_STAGING_SCHEMA_RESUME_STEP: '' },
    { CF_STAGING_SCHEMA_RESUME_STEP: '-1' }, { GITHUB_RUN_ATTEMPT: '1' }, { GITHUB_REF: 'refs/heads/main' }, { CF_STAGING_APPROVED_COMMIT: 'c'.repeat(40) }]) assert.throws(() => authorize({ ...env, ...patch }, event, sha));
  assert.throws(() => loadMigrationPlan({ ...env, CF_STAGING_SCHEMA_PLAN_SHA256: 'f'.repeat(64) }));
  let called = false;
  await assert.rejects(migrate({ ...env, CF_STAGING_D1_DATABASE_ID: TARGET.productionDatabase }, { plan, transport: async () => { called = true; } }));
  assert.equal(called, false);
});

test('all 370 real SQL statements and guards pass local SQLite, with no extra tables and separated usage', async t => {
  const h = harness(t);
  const report = await migrate(env, h.deps);
  assert.equal(report.status, 'complete'); assert.equal(report.last_verified_step, 370);
  assert.equal(report.batches.length, 29); assert.ok(report.batches.every(b => b.outcome === 'verified'));
  assert.equal(report.actual_state.counts.length, 89);
  assert.equal(report.usage.complete, true); assert.ok(report.usage.migration.rows_written > 100); assert.ok(report.usage.verification.rows_read > 0);
  assert.equal(report.usage.verification.rows_written, 0); assert.ok(report.storage_after_bytes > report.storage_before_bytes);
  assert.equal(report.invariants_before_sha256, report.invariants_after_sha256);
  assert.doesNotMatch(JSON.stringify(report), /synthetic-secret|sqlite_sequence|Authorization/);
  assert.equal(h.calls.filter(c => c.method !== 'POST' && c.method !== 'GET').length, 0);
  assert.equal(report.worker_or_access_mutations, 0);
});

test('a partial migration stops, reports actual prefix and resumes only at a separately approved matching step', async t => {
  let failed = false, writeBatches = 0;
  const target = plan.files.at(-1);
  const h = harness(t, async ({ body, execute }) => {
    if (!body.batch) return;
    writeBatches++;
    if (!failed && body.batch.some(q => q.sql.includes('CREATE TABLE cvie_identities'))) {
      failed = true;
      // Deliberately emulate a partially applied provider response, stronger than
      // the usual transactional batch failure contract.
      const guardCount = body.batch.length - target.statements.length;
      for (const query of body.batch.slice(0, guardCount + 5)) await execute(query);
      return Response.json({ success: false, errors: [{ code: 7500, message: 'synthetic-secret' }], result: [] });
    }
  });
  await assert.rejects(migrate(env, h.deps));
  const stopped = h.final();
  assert.equal(stopped.status, 'stopped'); assert.equal(stopped.automatic_retries, 0);
  const step = target.start + 5;
  assert.ok(stopped.actual_state.matching_steps.includes(step)); assert.equal(stopped.state_inspected_after_stop, true);
  assert.equal(stopped.usage.complete, false); assert.equal(writeBatches, 29);
  assert.doesNotMatch(JSON.stringify(stopped), /synthetic-secret/);
  await assert.rejects(migrate(env, h.deps)); // zero cursor cannot replay existing objects
  assert.equal(writeBatches, 29);
  const resumed = await migrate({ ...env, CF_STAGING_SCHEMA_RESUME_STEP: String(step) }, h.deps);
  assert.equal(resumed.status, 'complete'); assert.equal(resumed.batches.length, 1);
  assert.equal(resumed.batches[0].from_step, step); assert.equal(writeBatches, 30);
});

test('a lost success response stops without retry and reports the committed checkpoint', async t => {
  let lost = false, batches = 0;
  const first = plan.files[0];
  const h = harness(t, async ({ body, execute }) => {
    if (!body.batch) return;
    batches++;
    if (!lost) { lost = true; await execute(body); throw Error('synthetic-secret'); }
  });
  await assert.rejects(migrate(env, h.deps));
  const report = h.final();
  assert.equal(batches, 1); assert.ok(report.actual_state.matching_steps.includes(first.end));
  assert.ok(report.storage_after_bytes > report.storage_before_bytes);
  assert.equal(report.failure.category, 'network'); assert.equal(report.usage.complete, false);
  assert.equal(report.invariants_unchanged, true); assert.doesNotMatch(JSON.stringify(report), /synthetic-secret/);
});

test('in-batch guard blocks a concurrent customer row and reports the unexpected state without reading its contents', async t => {
  let injected = false, batches = 0;
  const h = harness(t, async ({ body, execute }) => {
    if (!body.batch) return;
    batches++;
    if (batches === 2 && !injected) {
      injected = true;
      await execute({ sql: "INSERT INTO users(id,email) VALUES('private-user','private@example.test')" });
    }
  });
  await assert.rejects(migrate(env, h.deps));
  const report = h.final();
  assert.equal(batches, 2); assert.deepEqual(report.actual_state.matching_steps, []);
  assert.equal(report.actual_state.rows_verified, false);
  assert.ok(report.actual_state.counts.some(([name, count]) => name === 'users' && count === 1));
  assert.doesNotMatch(JSON.stringify(report), /private-user|private@example/);
});

test('missing metrics and explicit statement errors stop before the next migration batch', async t => {
  for (const mode of ['metrics', 'statement', 'http', 'budget']) {
    let batches = 0;
    const h = harness(t, async ({ body, execute }) => {
      if (!body.batch) return;
      batches++;
      const result = await execute(body);
      if (mode === 'metrics') delete result.result[0].meta.rows_read;
      if (mode === 'statement') result.result[0].success = false;
      if (mode === 'budget') result.result[0].meta.rows_written = 100001;
      return mode === 'http' ? Response.json({ success: false, result: [], errors: [] }, { status: 429 }) : Response.json(result);
    });
    await assert.rejects(migrate(env, h.deps));
    assert.equal(batches, 1); assert.equal(h.final().status, 'stopped');
    assert.equal(h.final().state_inspected_after_stop, true);
    assert.equal(h.final().failure.category, mode === 'metrics' ? 'metadata_unavailable' : mode === 'budget' ? 'usage_limit' : mode === 'http' ? 'rate_limit' : 'd1_statement_or_batch');
  }
});

test('protected provisioning selects migration only, and never reaches Worker upload', async () => {
  const calls = [];
  const preflight = { account: TARGET.account, blockers: [], read_only_checks_passed: true, checks: [
    { name: 'token_permission_grants', status: 'unverified', metadata_available: false, http_status: 403 },
    { name: 'token_staging_only_scope', status: 'unverified', metadata_available: false },
    { name: 'service_token_matches_policy_and_client', status: 'pass' }] };
  await provision(env, event, sha, { migrationPlan: () => plan,
    check: async (_env, _f, options) => { assert.deepEqual(options, { existingDatabase: true, workerState: 'deployed' }); return preflight; },
    migration: async (e, deps) => { calls.push('migration'); assert.equal(e.STAGING_CHANGE_APPROVED, env.STAGING_CHANGE_APPROVED); assert.equal(deps.plan, plan); },
    cloud: async () => assert.fail('No Worker deployment or creation'), probe: async () => assert.fail('Migration owns its read-only probes') });
  assert.deepEqual(calls, ['migration']);
});

test('missing/changed database identity, failed Access checks and unexpected inventory prevent every migration write', async t => {
  for (const mode of ['identity', 'access', 'inventory']) {
    let batches = 0;
    const h = harness(t, async ({ body }) => { if (body.batch) batches++; });
    if (mode === 'access') h.deps.probe = async () => ({ passed: false });
    if (mode === 'inventory') h.deps.inventory = async () => ({ verified: false });
    if (mode === 'identity') {
      const original = h.deps.transport;
      h.deps.transport = async (url, init) => url.endsWith('/d1/database/' + STAGING_DATABASE_ID)
        ? Response.json({ success: true, result: { uuid: TARGET.productionDatabase, name: TARGET.database, file_size: 0 } }) : original(url, init);
    }
    await assert.rejects(migrate(env, h.deps));
    assert.equal(batches, 0); assert.equal(h.final().status, 'stopped');
  }
});

test('a Worker or Access invariant change is reported, without attempting to repair or redeploy anything', async t => {
  const h = harness(t);
  const original = h.deps.transport;
  let reads = 0;
  h.deps.transport = async (url, init) => {
    if (url.endsWith('/workers/scripts/' + TARGET.api + '/deployments')) {
      reads++;
      if (reads > 1) return Response.json({ success: true, result: { externally_changed: true } });
    }
    return original(url, init);
  };
  await assert.rejects(migrate(env, h.deps));
  assert.equal(h.final().failure.category, 'changed'); assert.equal(h.final().invariants_unchanged, false);
  assert.equal(h.final().worker_or_access_mutations, 0);
});

test('SQL input changes are rejected even when the generated plan is unchanged', () => {
  const repository = path.resolve(root, '..');
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'cvie-schema-checksum-'));
  try {
    for (const file of [...plan.files.map(f => f.file), 'docs/cvie-evidence/staging-schema-plan-manifest.json',
      'docs/cvie-evidence/staging-schema-executor-approval.json', 'staging/.build/schema/execution-plan.json']) {
      const destination = path.join(temporary, file);
      fs.mkdirSync(path.dirname(destination), { recursive: true }); fs.copyFileSync(path.join(repository, file), destination);
    }
    fs.appendFileSync(path.join(temporary, 'account-backend/schema.sql'), '\n-- tampered input\n');
    assert.throws(() => loadMigrationPlan(env, temporary));
  } finally { fs.rmSync(temporary, { recursive: true, force: true }); }
});
