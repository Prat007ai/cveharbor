// Local workerd only, synthetic assertions/keys, no network service or credentials.
// Node accepts redirect:'error'; Workers rejects it before outbound I/O. Keep a
// failing legacy control beside the real verifier to catch this runtime mismatch.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { root } from './configure.mjs';
const { build } = await import('esbuild');
const output = path.join(root, '.build/access-runtime');
fs.mkdirSync(output, { recursive: true });
const issuer = 'https://synthetic-staging.cloudflareaccess.com', audience = 'a'.repeat(64);
const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
const jwk = { ...await crypto.subtle.exportKey('jwk', pair.publicKey), kid: 'synthetic-runtime-key' };
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
async function token(identity, team = issuer) {
  const input = encode({ alg: 'RS256', kid: jwk.kid }) + '.' + encode({ type: 'app', iss: team, aud: [audience], iat: Math.floor(Date.now() / 1000) - 10, exp: Math.floor(Date.now() / 1000) + 600, ...identity });
  return input + '.' + Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, new TextEncoder().encode(input))).toString('base64url');
}
const human = await token({ sub: 'synthetic-human', email: 'human@example.test' });
const service = await token({ sub: '', common_name: 'synthetic-client.access' });
const redirectIssuer = 'https://redirect-staging.cloudflareaccess.com';
const redirected = await token({ sub: '', common_name: 'synthetic-client.access' }, redirectIssuer);
const source = fs.readFileSync(path.join(root, 'access.mjs'), 'utf8');
assert.ok(source.includes("redirect: 'manual'"));
fs.writeFileSync(path.join(output, 'legacy.mjs'), source.replace("redirect: 'manual'", "redirect: 'error'"));
const entry = `
import { createAccessVerifier } from ${JSON.stringify(path.join(root, 'access.mjs'))};
import { createAccessVerifier as legacy } from './legacy.mjs';
import {withStagingTransport,fetch as fixtureFetch} from ${JSON.stringify(path.join(root, 'transport.mjs'))};
export default { async fetch() {
  const result = {};
  const captured=[];
  const db={prepare(sql){return {bind(...params){return {sql,params};}};},async batch(rows){captured.push(...rows);return [];}};
  await withStagingTransport({STAGING_MODE:'true',STAGING_EMAIL_CAPTURE_ENABLED:'true',DB:db},async()=>{
    await fixtureFetch('https://api.smtp2go.com/v3/email/send',{method:'POST',headers:{'X-Smtp2go-Api-Key':'staging-capture-only'},body:JSON.stringify({to:['test@example.invalid'],subject:'Native staging capture',text_body:'Synthetic only'})});
    result.syntheticProvider=(await fixtureFetch('https://raw.githubusercontent.com/dotnet/core/main/release-notes/releases-index.json',{redirect:'error'})).status;
  });
  result.captured=captured.length;
  try{await fixtureFetch('https://example.org/');result.outsideContextDenied=false;}catch{result.outsideContextDenied=true;}

  const check = async (factory, assertion, issuer) => {
    const categories = [];
    const valid = await factory()(assertion, issuer, ${JSON.stringify(audience)}, category => categories.push(category));
    return { valid, categories };
  };
  try { new Request(${JSON.stringify(issuer)}, { redirect: 'error' }); result.legacyRequestRejected = false; }
  catch (error) { result.legacyRequestRejected = error instanceof TypeError; }
  result.legacy = await check(legacy, ${JSON.stringify(service)}, ${JSON.stringify(issuer)});
  result.human = await check(createAccessVerifier, ${JSON.stringify(human)}, ${JSON.stringify(issuer)});
  result.service = await check(createAccessVerifier, ${JSON.stringify(service)}, ${JSON.stringify(issuer)});
  result.redirect = await check(createAccessVerifier, ${JSON.stringify(redirected)}, ${JSON.stringify(redirectIssuer)});
  result.outbound = await (await fetch(${JSON.stringify(issuer + '/count')}, { redirect: 'manual' })).json();
  return Response.json(result);
} };`;
fs.writeFileSync(path.join(output, 'entry.mjs'), entry);
await build({ entryPoints: [path.join(output, 'entry.mjs')], outfile: path.join(output, 'worker.mjs'), bundle: true, format: 'esm', platform: 'browser',external:['node:async_hooks'] });
fs.writeFileSync(path.join(output, 'jwks.mjs'), `let requests = [];
export default { async fetch(request) {
  const url = new URL(request.url);
  if (url.pathname === '/count') return Response.json(requests);
  requests.push({ host: url.hostname, path: url.pathname });
  if (url.origin === ${JSON.stringify(redirectIssuer)}) return new Response(null, { status: 302, headers: { Location: 'https://untrusted.example/keys' } });
  if (url.origin !== ${JSON.stringify(issuer)} || url.pathname !== '/cdn-cgi/access/certs') return new Response('Unexpected synthetic destination', { status: 500 });
  return Response.json({ keys: [${JSON.stringify(jwk)}] });
} };`);
fs.writeFileSync(path.join(output, 'config.capnp'), `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [
    (name = "main", worker = (compatibilityDate = "2026-10-23", compatibilityFlags = ["nodejs_compat"], modules = [(name = "worker.mjs", esModule = embed "worker.mjs")], globalOutbound = "jwks")),
    (name = "jwks", worker = (compatibilityDate = "2026-10-23", modules = [(name = "jwks.mjs", esModule = embed "jwks.mjs")], globalOutbound = "jwks"))
  ],
  sockets = [(name = "local", address = "127.0.0.1:18743", http = (), service = "main")]
);`);
const env = { PATH: process.env.PATH, CI: 'true', WRANGLER_SEND_METRICS: 'false',
  ...(process.env.HTTPS_PROXY ? { HTTPS_PROXY: process.env.HTTPS_PROXY } : {}), ...(process.env.HTTP_PROXY ? { HTTP_PROXY: process.env.HTTP_PROXY } : {}),
  ...(process.env.NODE_EXTRA_CA_CERTS ? { NODE_EXTRA_CA_CERTS: process.env.NODE_EXTRA_CA_CERTS } : {}) };
let diagnostics = '';
const child = spawn('npx', ['--yes', 'workerd@1.20261023.1', 'serve', path.join(output, 'config.capnp')], { cwd: output, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
child.stdout.on('data', chunk => { diagnostics += chunk; }); child.stderr.on('data', chunk => { diagnostics += chunk; });
let startError;
child.on('error', error => { startError = error; });
try {
  let response;
  for (let attempt = 0; attempt < 240; attempt++) {
    if (startError || child.exitCode !== null) throw Error('Local workerd did not start: ' + diagnostics.slice(-4000));
    try { response = await fetch('http://127.0.0.1:18743/', { signal: AbortSignal.timeout(2000) }); break; } catch {}
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  assert.ok(response, 'Local workerd startup timed out');
  const result = await response.json();
  assert.equal(result.captured,1);assert.equal(result.syntheticProvider,200);assert.equal(result.outsideContextDenied,true);
  assert.equal(result.legacyRequestRejected, true);
  assert.deepEqual(result.legacy, { valid: false, categories: ['jwks_fetch'] });
  assert.deepEqual(result.human, { valid: true, categories: [] });
  assert.deepEqual(result.service, { valid: true, categories: [] });
  assert.deepEqual(result.redirect, { valid: false, categories: ['jwks_redirect'] });
  assert.equal(result.outbound.length, 3);
  assert.ok(result.outbound.every(r => r.path === '/cdn-cgi/access/certs' && [new URL(issuer).hostname, new URL(redirectIssuer).hostname].includes(r.host)));
  fs.mkdirSync(path.join(root, 'artifacts'), { recursive: true });
  fs.writeFileSync(path.join(root, 'artifacts/access-runtime.json'), JSON.stringify({ local_only: true, transport_async_context_verified:true, email_capture_verified:true, external_network_services: 0, legacy_reproduced: true, human_jwt_verified: true, service_jwt_verified: true, redirects_rejected: true }, null, 2) + '\n');
  console.log('Local workerd reproduced legacy redirect error; fixed human/service JWTs verify; redirects fail closed. No external network service configured.');
} finally { try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill('SIGTERM'); } }

