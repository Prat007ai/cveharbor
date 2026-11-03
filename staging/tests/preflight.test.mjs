import test from 'node:test';
import assert from 'node:assert/strict';
import { preflight } from '../scripts/preflight.mjs';
import { TARGET } from '../target.mjs';
const env = { CF_STAGING_ACCOUNT_ID: TARGET.account, CF_STAGING_API_TOKEN: 'private-management-token', CF_STAGING_ACCESS_ISSUER: 'https://synthetic-stage.cloudflareaccess.com', CF_STAGING_ACCESS_AUD: 'a'.repeat(64), CF_STAGING_ACCESS_CLIENT_ID: 'private-service-client', CF_STAGING_ACCESS_CLIENT_SECRET: 'private-service-secret' };
const sid = '11111111-2222-4333-8444-555555555555';
function fixture({ metadataDenied = false, bypass = false } = {}) {
  return async (url, init) => {
    assert.equal(init.method, 'GET'); assert.equal(init.redirect, 'manual');
    const u = new URL(url); let result;
    if (u.origin === TARGET.origin) { assert.equal(init.headers['CF-Access-Client-Secret'], env.CF_STAGING_ACCESS_CLIENT_SECRET); return new Response('', { status: 404 }); }
    if (u.origin === env.CF_STAGING_ACCESS_ISSUER) { assert.equal(init.headers.Authorization, undefined); return Response.json({ keys: [{ kty: 'RSA', kid: 'fixture' }] }); }
    assert.equal(u.origin, 'https://api.cloudflare.com');
    const base = '/client/v4/accounts/' + TARGET.account;
    assert.ok(u.pathname === base || u.pathname.startsWith(base + '/'));
    const route = u.pathname.slice(base.length);
    if (route === '') result = { id: TARGET.account, name: 'CVEHarbor Staging' };
    else if (route === '/tokens/verify') result = { id: 'f'.repeat(32), status: 'active' };
    else if (route === '/tokens/' + 'f'.repeat(32)) {
      if (metadataDenied) return Response.json({ success: false }, { status: 403 });
      result = { policies: [{ effect: 'allow', resources: { ['com.cloudflare.api.account.' + TARGET.account]: '*' }, permission_groups: ['Workers Scripts Write','D1 Write','Account Settings Read','Access: Apps and Policies Read'].map(name => ({ name })) }] };
    } else if (route === '/workers/subdomain') result = { subdomain: 'cveharbor-staging' };
    else if (route === '/workers/scripts' || route === '/d1/database') result = [];
    else if (route === '/access/apps') result = [{ id: sid, domain: new URL(TARGET.origin).hostname, aud: env.CF_STAGING_ACCESS_AUD, type: 'self_hosted', name: 'CVEHarbor Staging' }];
    else if (route.endsWith('/policies')) result = [
      { name: 'CVEHarbor staging reviewers', decision: bypass ? 'bypass' : 'allow', include: [{ email: { email: 'private-reviewer@example.test' } }] },
      { name: 'CVEHarbor staging automated tests', decision: 'non_identity', include: [{ service_token: { token_id: sid } }] },
    ];
    else if (route === '/access/service_tokens') result = [{ id: sid, name: 'cvie-staging-validation', client_id: env.CF_STAGING_ACCESS_CLIENT_ID, enabled: true }];
    else assert.fail('Unexpected route');
    return Response.json({ success: true, result });
  };
}
test('preflight is GET-only, reports safe evidence, and does not infer a valid service secret from 404', async () => {
  const result = await preflight(env, fixture());
  assert.equal(result.read_only_checks_passed, true); assert.equal(result.ready_for_creation, true);
  assert.equal(result.mutation_requests, 0); assert.equal(result.production_requests, 0);
  assert.equal(result.checks.find(c => c.name === 'service_secret_end_to_end').status, 'unverified');
  assert.doesNotMatch(JSON.stringify(result), /private-management-token|private-service-client|private-service-secret|private-reviewer/);
});
test('unreadable token metadata is not called a confirmed write grant or isolation proof', async () => {
  const result = await preflight(env, fixture({ metadataDenied: true }));
  assert.equal(result.read_only_checks_passed, true); assert.equal(result.ready_for_creation, false);
  assert.ok(result.limitations.includes('token_permission_grants'));
});
test('wrong account, missing secret and Access bypass fail closed', async () => {
  const noNetwork = async () => assert.fail('No request allowed');
  assert.equal((await preflight({ ...env, CF_STAGING_ACCOUNT_ID: 'another' }, noNetwork)).ready_for_creation, false);
  assert.equal((await preflight({ ...env, CF_STAGING_ACCESS_CLIENT_SECRET: '' }, noNetwork)).ready_for_creation, false);
  const result = await preflight(env, fixture({ bypass: true }));
  assert.equal(result.ready_for_creation, false); assert.ok(result.blockers.includes('no_access_bypass_or_additional_allow'));
});
