import test from 'node:test';
import assert from 'node:assert/strict';
import { createAccessVerifier } from '../access.mjs';
import { createFrontend } from '../frontend.mjs';
import { TARGET } from '../target.mjs';

const issuer = 'https://synthetic-staging.cloudflareaccess.com', audience = 'a'.repeat(64);
const now = 1700000000000;
async function fixture() {
  const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const jwk = { ...await crypto.subtle.exportKey('jwk', pair.publicKey), kid: 'synthetic-key' };
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const claims = { type: 'app', iss: issuer, aud: [audience], exp: now / 1000 + 300, iat: now / 1000 - 10 };
  const sign = async (patch = {}, header = {}) => {
    const input = encode({ alg: 'RS256', kid: jwk.kid, ...header }) + '.' + encode({ ...claims, ...patch });
    return input + '.' + Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, new TextEncoder().encode(input))).toString('base64url');
  };
  const check = createAccessVerifier(async (url, init) => { assert.equal(init.redirect, 'manual'); assert.equal(url, issuer + '/cdn-cgi/access/certs'); return Response.json({ keys: [jwk] }); }, () => now);
  return { sign, front: createFrontend(check) };
}
test('human and Service Auth application assertions both pass cryptographic origin validation without an Access response cookie', async () => {
  const { sign, front } = await fixture();
  for (const identity of [{ sub: 'synthetic-human', email: 'reviewer@example.test' }, { sub: '', common_name: 'synthetic-client.access' }]) {
    const assertion = await sign(identity);
    const headers = { 'Cf-Access-Jwt-Assertion': assertion };
    if (identity.common_name) Object.assign(headers, { 'CF-Access-Client-Id': 'synthetic-client.access', 'CF-Access-Client-Secret': 'synthetic-secret' });
    else headers.Cookie = 'CF_Authorization=' + assertion;
    let assets = 0, api = 0;
    const env = { ACCESS_ISSUER: issuer, ACCESS_AUD: audience,
      ASSETS: { fetch: async request => {
        assets++; assert.equal(request.headers.get('Cookie'), null);
        for (const name of ['Cf-Access-Jwt-Assertion', 'CF-Access-Client-Id', 'CF-Access-Client-Secret']) assert.equal(request.headers.get(name), null);
        return new Response('protected asset');
      } },
      STAGING_API: { fetch: async request => {
        api++; assert.equal(request.headers.get('Cookie'), null); // Access identity is not an application session
        for (const name of ['Cf-Access-Jwt-Assertion', 'CF-Access-Client-Id', 'CF-Access-Client-Secret']) assert.equal(request.headers.get(name), null);
        return Response.json({ authenticated: false }, { status: 401 });
      } },
    };
    assert.equal((await front.fetch(new Request(TARGET.origin + '/styles.css', { headers }), env)).status, 200);
    assert.equal((await front.fetch(new Request(TARGET.origin + '/v1/me', { headers }), env)).status, 401);
    assert.equal((await front.fetch(new Request(TARGET.origin + '/styles.css', { headers: { ...headers, Origin: 'https://other.example' } }), env)).status, 403);
    assert.equal(assets, 1); assert.equal(api, 1);
  }
});
test('raw service headers, identity headers and cookies cannot replace a verified assertion', async () => {
  const { sign, front } = await fixture();
  const human = await sign({ sub: 'human', email: 'reviewer@example.test' });
  for (const headers of [
    {}, { 'CF-Access-Client-Id': 'synthetic-client.access', 'CF-Access-Client-Secret': 'synthetic-secret' },
    { 'Cf-Access-Authenticated-User-Email': 'reviewer@example.test' }, { Cookie: 'CF_Authorization=' + human },
    { 'Cf-Access-Jwt-Assertion': 'forged.jwt.signature', Cookie: 'CF_Authorization=' + human },
  ]) {
    const noFetch = { fetch: () => assert.fail('Unverified request must not reach an asset or API') };
    const env = { ACCESS_ISSUER: issuer, ACCESS_AUD: audience, ASSETS: noFetch, STAGING_API: noFetch };
    for (const route of ['/', '/v1/me']) assert.equal((await front.fetch(new Request(TARGET.origin + route, { headers }), env)).status, 403);
  }
});
test('human and service assertions reject wrong account/application, expired or future claims and forged signatures', async () => {
  const { sign, front } = await fixture();
  const forbidden = { fetch: () => assert.fail('Rejected identity must not reach a binding') };
  const env = { ACCESS_ISSUER: issuer, ACCESS_AUD: audience, ASSETS: forbidden, STAGING_API: forbidden };
  for (const identity of [{ sub: 'human', email: 'reviewer@example.test' }, { sub: '', common_name: 'synthetic-client.access' }]) {
    for (const patch of [{ iss: 'https://other-account.cloudflareaccess.com' }, { aud: ['b'.repeat(64)] }, { exp: now / 1000 - 1 }, { iat: now / 1000 + 90 }, { nbf: now / 1000 + 90 }]) {
      const assertion = await sign({ ...identity, ...patch });
      assert.equal((await front.fetch(new Request(TARGET.origin + '/', { headers: { 'Cf-Access-Jwt-Assertion': assertion } }), env)).status, 403);
    }
    const valid = await sign(identity);
    const forged = valid.slice(0, -10) + 'AAAAAAAAAA';
    assert.equal((await front.fetch(new Request(TARGET.origin + '/', { headers: { 'Cf-Access-Jwt-Assertion': forged } }), env)).status, 403);
  }
});
