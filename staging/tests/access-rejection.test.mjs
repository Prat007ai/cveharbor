import test from 'node:test';
import assert from 'node:assert/strict';
import { createAccessVerifier, ACCESS_FAILURE_CATEGORIES } from '../access.mjs';
import { createFrontend } from '../frontend.mjs';
import { TARGET } from '../target.mjs';
const issuer = 'https://synthetic-staging.cloudflareaccess.com', aud = 'a'.repeat(64);
test('rejection diagnostics preserve real signature/claim checks without exporting JWTs, claims or key IDs', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, true, ['sign','verify']);
  const key = { ...await crypto.subtle.exportKey('jwk', pair.publicKey), kid: 'private-key-id' };
  const b64 = x => Buffer.from(JSON.stringify(x)).toString('base64url');
  const sign = async claims => { const input = b64({ alg: 'RS256', kid: key.kid }) + '.' + b64(claims); return input + '.' + Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, new TextEncoder().encode(input))).toString('base64url'); };
  const claims = { iss: issuer, aud: [aud], iat: 1699999990, exp: 1700000300, email: 'private@example.test' };
  const verifier = createAccessVerifier(async () => Response.json({ keys: [key] }), () => 1700000000000);
  for (const [token, category] of [[null, 'token_missing'], ['invalid.jwt.parts', 'token_parse'], [await sign({ ...claims, aud: ['b'.repeat(64)] }), 'audience'], [await sign({ ...claims, exp: 1600000000 }), 'time'], [await sign({ ...claims, iss: 'https://wrong.cloudflareaccess.com' }), 'issuer']]) {
    const observed = []; assert.equal(await verifier(token, issuer, aud, c => observed.push(c)), false);
    assert.deepEqual(observed, [category]); assert.doesNotMatch(JSON.stringify(observed), /private|@|eyJ/);
  }
  const valid = await sign(claims);
  assert.equal(await verifier(valid, issuer, aud), true);
  const unavailable = createAccessVerifier(async () => { throw Error('secret-provider-error'); }, () => 1700000000000);
  const observed = []; assert.equal(await unavailable(valid, issuer, aud, c => observed.push(c)), false);
  assert.deepEqual(observed, ['jwks_fetch']);
});
test('frontend denial exposes only allowlisted failure categories and still blocks assets and API', async () => {
  for (const category of [...ACCESS_FAILURE_CATEGORIES, 'secret-credential']) {
    const front = createFrontend(async (_token, _issuer, _aud, report) => { report(category); return false; });
    for (const route of ['/', '/styles.css', '/v1/me']) {
      const r = await front.fetch(new Request(TARGET.origin + route), { ASSETS: { fetch: () => assert.fail('Asset bypass') }, STAGING_API: { fetch: () => assert.fail('API bypass') } });
      assert.equal(r.status, 403); assert.equal(r.headers.get('X-Staging-Access-Error'), category === 'secret-credential' ? 'unknown' : category);
      assert.equal(await r.text(), 'Cloudflare Access authentication required'); assert.equal(r.headers.get('Cache-Control'), 'private, no-store');
    }
  }
});
