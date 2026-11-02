import test from 'node:test';
import assert from 'node:assert/strict';
import { configs, validate } from '../scripts/configure.mjs';
import { TARGET } from '../target.mjs';
import { createAccessVerifier } from '../access.mjs';
import { createFrontend } from '../frontend.mjs';
import { createStagingAPI } from '../api-wrapper.mjs';
import { fetch as blockedFetch } from '../blocked-fetch.mjs';
const env = { CF_STAGING_ACCOUNT_ID: TARGET.account, CF_STAGING_D1_DATABASE_ID: '11111111-2222-4333-8444-555555555555', CF_STAGING_ACCESS_ISSUER: 'https://synthetic-staging.cloudflareaccess.com', CF_STAGING_ACCESS_AUD: 'a'.repeat(64) };

test('configuration requires the approved account, a new D1 UUID and Access values', () => {
  configs(env);
  for (const change of [{ CF_STAGING_ACCOUNT_ID: 'another-account' }, { CF_STAGING_D1_DATABASE_ID: TARGET.productionDatabase }, { CF_STAGING_D1_DATABASE_ID: '' }, { CF_STAGING_ACCESS_AUD: '' }, { CF_STAGING_ACCESS_ISSUER: 'https://attacker.test' }]) assert.throws(() => configs({ ...env, ...change }));
});
test('configuration rejects API public access, production services, schedules and asset bypass', () => {
  for (const mutate of [
    c => { c.api.workers_dev = true; }, c => { c.api.triggers.crons = ['* * * * *']; },
    c => { c.api.d1_databases[0].database_id = TARGET.productionDatabase; },
    c => { c.site.services[0].service = 'cveharbor-accounts'; }, c => { c.site.assets.run_worker_first = false; },
    c => { c.api.vars.ALERT_DELIVERY_ENABLED = 'true'; }, c => { c.api.kv_namespaces = [{}]; },
  ]) { const c = configs(env); mutate(c); assert.throws(() => validate(c.api, c.site)); }
});

const b64 = v => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
test('Access validates signatures, issuer, audience and time, and fails closed on key/network errors', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, true, ['sign','verify']);
  const key = { ...await crypto.subtle.exportKey('jwk', pair.publicKey), kid: 'staging-key' };
  let calls = 0;
  const clock = () => 1700000000000;
  const verify = createAccessVerifier(async url => { calls++; assert.equal(url, env.CF_STAGING_ACCESS_ISSUER + '/cdn-cgi/access/certs'); return Response.json({ keys: [key] }); }, clock);
  const claims = { iss: env.CF_STAGING_ACCESS_ISSUER, aud: [env.CF_STAGING_ACCESS_AUD], iat: clock()/1000-10, exp: clock()/1000+300 };
  const sign = async (c = claims, h = { alg: 'RS256', kid: key.kid }) => {
    const data = b64(h) + '.' + b64(c);
    return data + '.' + Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, new TextEncoder().encode(data))).toString('base64url');
  };
  const check = t => verify(t, env.CF_STAGING_ACCESS_ISSUER, env.CF_STAGING_ACCESS_AUD);
  assert.equal(await check(await sign()), true);
  assert.equal(await check(await sign()), true);
  assert.equal(calls, 1);
  for (const c of [{ ...claims, iss: 'https://wrong.cloudflareaccess.com' }, { ...claims, aud: ['b'.repeat(64)] }, { ...claims, exp: clock()/1000 }, { ...claims, iat: clock()/1000+90 }, { ...claims, nbf: clock()/1000+90 }]) assert.equal(await check(await sign(c)), false);
  assert.equal(await check(await sign(claims, { alg: 'none', kid: key.kid })), false);
  assert.equal(await check(await sign(claims, { alg: 'RS256', kid: 'unknown' })), false);
  const valid = await sign();
  assert.equal(await check(valid.slice(0, -5) + 'AAAAA'), false);
  assert.equal(await check(null), false);
  assert.equal(await createAccessVerifier(async () => { throw Error('offline'); }, clock)(valid, env.CF_STAGING_ACCESS_ISSUER, env.CF_STAGING_ACCESS_AUD), false);
});
test('frontend denies every unauthenticated path before invoking assets or API', async () => {
  const front = createFrontend(async () => false);
  const fail = { fetch() { assert.fail('Access bypass'); } };
  for (const path of ['/', '/v1/health', '/v1/technology-catalogue', '/__staging/control', '/data.js']) {
    const r = await front.fetch(new Request(TARGET.origin + path), { ASSETS: fail, STAGING_API: fail });
    assert.equal(r.status, 403);
  }
});
test('frontend forwards application cookie only, strips Access credentials and enforces same-origin routing', async () => {
  const token = 'a'.repeat(64);
  const front = createFrontend(async () => true);
  const binding = { async fetch(r) {
    assert.equal(r.url, TARGET.origin + '/v1/technology-catalogue'); assert.equal(r.method, 'PUT');
    assert.equal(await r.text(), '{"products":[]}');
    assert.equal(r.headers.get('Cookie'), 'cvh_session=' + token);
    for (const h of ['Authorization','Cf-Access-Jwt-Assertion','Cf-Access-Client-Secret','Cf-Access-Client-Id','Cf-Access-Authenticated-User-Email']) assert.equal(r.headers.get(h), null);
    return Response.json({ saved: true }, { headers: { 'Set-Cookie': 'cvh_session=' + token + '; Secure; HttpOnly; SameSite=Strict' } });
  } };
  const request = new Request(TARGET.origin + '/v1/technology-catalogue', { method: 'PUT', body: '{"products":[]}', headers: {
    Origin: TARGET.origin, Cookie: 'CF_Authorization=secret; cvh_session=' + token, Authorization: 'Basic secret',
    'Cf-Access-Client-Secret': 'secret', 'Cf-Access-Client-Id': 'client', 'Cf-Access-Jwt-Assertion': 'token', 'Cf-Access-Authenticated-User-Email': 'private@example.test',
  } });
  const r = await front.fetch(request, { STAGING_API: binding });
  assert.equal(r.status, 200); assert.match(r.headers.get('Set-Cookie'), /HttpOnly/); assert.match(r.headers.get('Content-Security-Policy'), /connect-src 'self'/);
  assert.equal((await front.fetch(new Request('https://cveharbor.com/v1/health'), {})).status, 403);
  assert.equal((await front.fetch(new Request(TARGET.origin + '/v1/health', { headers: { Origin: 'https://cveharbor.com' } }), {})).status, 403);
  assert.equal((await front.fetch(new Request(TARGET.origin + '/'), { ASSETS: { fetch: async () => Response.redirect('https://api.cveharbor.com', 302) } })).status, 502);
});
test('API wrapper removes credentials, forces all deliveries off and never executes scheduled work', async () => {
  let called = 0;
  const wrapped = createStagingAPI({ async fetch(r, e) {
    called++; assert.equal(e.SMTP2GO_API_KEY, undefined); assert.equal(e.NVD_API_KEY, undefined); assert.equal(e.CLOUDFLARE_API_TOKEN, undefined);
    assert.equal(e.ALERT_DELIVERY_ENABLED, 'false'); assert.equal(e.ASSIGNMENT_EMAIL_ENABLED, 'false'); assert.equal(e.REMEDIATION_WORKFLOW_ENABLED, 'true');
    return new Response('ok');
  }, scheduled() { assert.fail('Scheduled work executed'); } });
  await wrapped.scheduled({}, { SCHEDULED_JOBS_ENABLED: 'true' });
  assert.equal((await wrapped.fetch(new Request(TARGET.origin + '/v1/health'), { STAGING_MODE: 'true', SMTP2GO_API_KEY: 'wrong', NVD_API_KEY: 'wrong', CLOUDFLARE_API_TOKEN: 'wrong', ALERT_DELIVERY_ENABLED: 'true' }, {})).status, 200);
  assert.equal(called, 1);
  assert.equal((await wrapped.fetch(new Request('https://api.cveharbor.com/v1/health'), { STAGING_MODE: 'true' }, {})).status, 403);
  await assert.rejects(blockedFetch('https://api.smtp2go.com/v3/email/send'), /disabled/);
});
