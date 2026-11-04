import test from 'node:test';
import assert from 'node:assert/strict';
import { createAccessVerifier } from '../access.mjs';
const issuer = 'https://synthetic-staging.cloudflareaccess.com', audience = 'a'.repeat(64), now = 1700000000000;
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
// These structurally valid claims intentionally reach key retrieval. The redirect
// must be rejected before any key can be imported or signature accepted.
const token = encode({ alg: 'RS256', kid: 'synthetic-key' }) + '.' + encode({ iss: issuer, aud: [audience], iat: now / 1000 - 1, exp: now / 1000 + 60 }) + '.AAAA';
test('JWKS uses Workers-supported manual mode and rejects every redirect without trusting its body', async () => {
  for (const status of [300, 301, 302, 303, 304, 307, 308, 399]) {
    let calls = 0; const reasons = [];
    const verify = createAccessVerifier(async (url, init) => {
      calls++; assert.equal(url, issuer + '/cdn-cgi/access/certs'); assert.equal(init.redirect, 'manual');
      return new Response(null, { status, headers: { Location: 'https://untrusted.example/keys' } });
    }, () => now);
    assert.equal(await verify(token, issuer, audience, c => reasons.push(c)), false);
    assert.equal(calls, 1); assert.deepEqual(reasons, ['jwks_redirect']);
  }
});
test('JWKS network and HTTP failures still fail closed and expose only fixed categories', async () => {
  for (const [transport, category] of [
    [async () => { throw Error('secret-network-details'); }, 'jwks_fetch'],
    [async () => new Response('secret-provider-body', { status: 403 }), 'jwks_http'],
  ]) {
    const reasons = []; const verify = createAccessVerifier(transport, () => now);
    assert.equal(await verify(token, issuer, audience, c => reasons.push(c)), false);
    assert.deepEqual(reasons, [category]); assert.doesNotMatch(JSON.stringify(reasons), /secret/);
  }
});
