import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { authorize, acceptPreflight, provision } from '../scripts/provision.mjs';
import { probeAccess } from '../scripts/probe-access.mjs';
import { TARGET } from '../target.mjs';
const sha = 'c'.repeat(40), uuid = '11111111-2222-4333-8444-555555555555';
const env = { GITHUB_REPOSITORY: 'Prat007ai/cveharbor', GITHUB_REF: 'refs/heads/codex/cvie-core-phase012', GITHUB_SHA: sha, GITHUB_RUN_ATTEMPT: '2', GITHUB_EVENT_NAME: 'push', CF_STAGING_APPROVED_COMMIT: sha, CF_STAGING_PROVISION_ACTION: 'create-database', CF_STAGING_ACCOUNT_ID: TARGET.account };
const event = { head_commit: { id: sha, message: 'Reviewed staging preparation [staging-provision]' } };
const attestation = JSON.parse(fs.readFileSync(new URL('../../docs/cvie-evidence/staging-owner-attestation.json', import.meta.url)));
const report = () => ({ account: TARGET.account, blockers: [], read_only_checks_passed: true, checks: [
  { name: 'token_permission_grants', status: 'unverified', metadata_available: false, http_status: 403 },
  { name: 'token_staging_only_scope', status: 'unverified', metadata_available: false },
  { name: 'service_token_matches_policy_and_client', status: 'pass' },
] });

test('exact SHA/checkout, account, branch, operation and explicit rerun are mandatory', () => {
  assert.equal(authorize(env, event, sha).action, 'create-database');
  for (const patch of [
    { CF_STAGING_APPROVED_COMMIT: '' }, { CF_STAGING_APPROVED_COMMIT: 'd'.repeat(40) }, { GITHUB_SHA: 'e'.repeat(40) },
    { CF_STAGING_ACCOUNT_ID: 'production' }, { GITHUB_REF: 'refs/heads/main' }, { GITHUB_REPOSITORY: 'fork/cveharbor' },
    { CF_STAGING_PROVISION_ACTION: '' }, { CF_STAGING_PROVISION_ACTION: 'migrate' }, { GITHUB_RUN_ATTEMPT: '1' },
    { GITHUB_EVENT_NAME: 'pull_request' }, { GITHUB_EVENT_NAME: 'schedule' }, { CF_STAGING_D1_DATABASE_ID: uuid },
  ]) assert.throws(() => authorize({ ...env, ...patch }, event, sha));
  assert.throws(() => authorize(env, event, 'f'.repeat(40)));
  assert.throws(() => authorize(env, { head_commit: { id: sha, message: '[staging-preflight]' } }, sha));
  assert.throws(() => authorize(env, { head_commit: { ...event.head_commit, id: 'd'.repeat(40) } }, sha));
});
test('dispatch must name the matching operation; deploy requires a nonproduction UUID', () => {
  const dispatch = { ...env, GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_RUN_ATTEMPT: '1' };
  assert.equal(authorize(dispatch, { inputs: { provision_action: 'create-database', check_credentials: 'false' } }, sha).action, 'create-database');
  for (const inputs of [{}, { provision_action: 'none' }, { provision_action: 'deploy-workers' }, { provision_action: 'create-database', check_credentials: 'true' }]) assert.throws(() => authorize(dispatch, { inputs }, sha));
  for (const id of ['', TARGET.productionDatabase, 'not-a-uuid']) assert.throws(() => authorize({ ...env, CF_STAGING_PROVISION_ACTION: 'deploy-workers', CF_STAGING_D1_DATABASE_ID: id }, event, sha));
  assert.equal(authorize({ ...env, CF_STAGING_PROVISION_ACTION: 'deploy-workers', CF_STAGING_D1_DATABASE_ID: uuid }, event, sha).action, 'deploy-workers');
});
test('owner attestation accepts only the known 403 gap, never conflicting metadata or failed linkage', () => {
  acceptPreflight(report(), attestation);
  for (const mutate of [
    r => r.blockers.push('access'), r => { r.account = 'production'; }, r => { r.read_only_checks_passed = false; },
    r => { r.checks[0].http_status = 500; }, r => { r.checks[0].metadata_available = true; },
    r => { r.checks[1].metadata_available = true; }, r => { r.checks[2].status = 'unverified'; },
  ]) { const r = report(); mutate(r); assert.throws(() => acceptPreflight(r, attestation)); }
  assert.throws(() => acceptPreflight(report(), { ...attestation, permissions_confirmed: [] }));
});
test('create entrypoint executes exactly one action and never deploys, probes application or migrates', async () => {
  const calls = [], artifacts = [];
  const deps = { check: async (_env, _transport, options) => { assert.equal(options.existingDatabase, false); return report(); },
    cloud: async (action, e) => { calls.push(action); assert.equal(e.STAGING_CHANGE_APPROVED, 'PR243-STAGING-ONLY'); return { database_id: uuid }; },
    probe: async () => assert.fail('Creation must stop before application probes'), record: (name, data) => artifacts.push({ name, data }) };
  await provision(env, event, sha, deps);
  assert.deepEqual(calls, ['create-database']); assert.deepEqual(artifacts.map(a => a.name), ['preflight', 'provision']);
  await assert.rejects(provision({ ...env, GITHUB_RUN_ATTEMPT: '1' }, event, sha, { check: async () => assert.fail('No network before gates') }));
  await assert.rejects(provision(env, event, sha, { ...deps, check: async () => ({ ...report(), blockers: ['bad policy'] }), cloud: async () => assert.fail('No mutation after failed preflight') }));
});
test('deploy mode verifies existing DB preflight and records failing Access before stopping', async () => {
  const artifacts = [];
  await assert.rejects(provision({ ...env, CF_STAGING_PROVISION_ACTION: 'deploy-workers', CF_STAGING_D1_DATABASE_ID: uuid }, event, sha, {
    check: async (_e, _f, options) => { assert.equal(options.existingDatabase, true); return report(); },
    cloud: async action => { assert.equal(action, 'deploy'); return {}; }, probe: async () => ({ passed: false }), record: name => artifacts.push(name),
  }), /Access check failed/);
  assert.deepEqual(artifacts, ['preflight', 'provision', 'access']);
});
test('Access probe uses four fixed-host GETs, no redirects/sessions, and keeps secrets out of evidence', async () => {
  const authEnv = { CF_STAGING_ACCESS_ISSUER: 'https://synthetic-stage.cloudflareaccess.com', CF_STAGING_ACCESS_AUD: 'a'.repeat(64), CF_STAGING_ACCESS_CLIENT_ID: 'secret-client', CF_STAGING_ACCESS_CLIENT_SECRET: 'secret-value' };
  let count = 0;
  const transport = async (url, init) => {
    count++; assert.equal(new URL(url).origin, TARGET.origin); assert.equal(init.method, 'GET'); assert.equal(init.redirect, 'manual'); assert.equal(init.headers.Cookie, undefined);
    if (!init.headers['CF-Access-Client-Secret']) return new Response('', { status: 403 });
    const headers = { 'X-Robots-Tag': 'noindex, nofollow, noarchive' };
    return url.endsWith('/v1/me') ? Response.json({ authenticated: false }, { status: 401, headers }) : new Response('<html>CVEHarbor</html>', { headers: { ...headers, 'Content-Type': 'text/html' } });
  };
  const result = await probeAccess(authEnv, transport); assert.equal(result.passed, true); assert.equal(count, 4);
  assert.doesNotMatch(JSON.stringify(result), /secret-client|secret-value/);
  assert.equal((await probeAccess(authEnv, async () => new Response('public', { status: 200 }))).passed, false);
  assert.equal((await probeAccess(authEnv, async () => Response.redirect('https://attacker.test', 302))).passed, false);
});
