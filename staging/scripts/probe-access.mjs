import { TARGET, accessSettings } from '../target.mjs';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { root } from './configure.mjs';

// GET-only negative/positive boundary checks. Never follow redirects or use an
// application session. Only /v1/me without a cookie reaches the application.
export async function probeAccess(env, transport = fetch) {
  const { ACCESS_ISSUER } = accessSettings(env.CF_STAGING_ACCESS_ISSUER, env.CF_STAGING_ACCESS_AUD);
  if (!env.CF_STAGING_ACCESS_CLIENT_ID || !env.CF_STAGING_ACCESS_CLIENT_SECRET) throw Error('Staging service credentials required');
  const checks = []; let requests = 0;
  async function get(route, headers = {}) {
    requests++;
    try { return await transport(TARGET.origin + route, { method: 'GET', headers, redirect: 'manual', signal: AbortSignal.timeout(20000) }); }
    catch { return new Response('', { status: 599 }); }
  }
  function denied(response) {
    if ([401, 403].includes(response.status)) return true;
    try { const url = new URL(response.headers.get('Location')); return [302, 303, 307, 308].includes(response.status) && url.origin === ACCESS_ISSUER && url.pathname.startsWith('/cdn-cgi/access/login'); } catch { return false; }
  }
  const auth = { 'CF-Access-Client-Id': env.CF_STAGING_ACCESS_CLIENT_ID, 'CF-Access-Client-Secret': env.CF_STAGING_ACCESS_CLIENT_SECRET };
  const guarded = response => response.headers.get('X-Robots-Tag') === 'noindex, nofollow, noarchive' && response.headers.get('Cache-Control') === 'private, no-store';
  const assets = [['/', /text\/html/], ['/styles.css', /text\/css/], ['/app.js', /(?:java|ecma)script/], ['/data.js', /(?:java|ecma)script/], ['/assets/workspace-harbor.svg', /image\/svg\+xml/], ['/workspace/', /text\/html/]];
  for (const [route, type] of assets) {
    for (const [name, headers] of [['anonymous', {}], ['forged_jwt', { 'Cf-Access-Jwt-Assertion': 'invalid.signature.token' }]]) {
      const r = await get(route, headers); checks.push({ name, route, passed: denied(r), status: r.status });
    }
    const page = await get(route, auth);
    const text = await page.text();
    checks.push({ name: 'service_static_asset', route, passed: page.status === 200 && type.test(page.headers.get('Content-Type') || '') && guarded(page) && (route !== '/' || text.includes('CVEHarbor')), status: page.status,
      response_category: page.status === 599 ? 'network' : text === 'Cloudflare Access authentication required' ? 'worker_access_jwt_missing_or_invalid' : page.status === 403 ? 'access_denied' : 'other' });
    // Positive service auth plus a forbidden Origin must reach our Worker before
    // every sampled asset. A denial by Access alone is not accepted as proof.
    const cross = await get(route, { ...auth, Origin: 'https://invalid.example' });
    checks.push({ name: 'worker_runs_before_asset', route, passed: cross.status === 403 && guarded(cross) && await cross.text() === 'Forbidden origin', status: cross.status });
  }
  for (const [name, headers] of [['anonymous_api', {}], ['forged_jwt_api', { 'Cf-Access-Jwt-Assertion': 'invalid.signature.token' }]]) {
    const r = await get('/v1/me', headers); checks.push({ name, route: '/v1/me', passed: denied(r), status: r.status });
  }
  const me = await get('/v1/me', auth);
  let payload; try { payload = await me.json(); } catch {}
  checks.push({ name: 'application_session_required', passed: me.status === 401 && payload?.authenticated === false && guarded(me), status: me.status });
  requests++;
  let direct;
  try { direct = await transport('https://cveharbor-accounts-staging.cveharbor-staging.workers.dev/v1/me', { method: 'GET', headers: {}, redirect: 'manual', signal: AbortSignal.timeout(20000) }); }
  catch { direct = new Response('', { status: 599 }); }
  checks.push({ name: 'private_api_has_no_public_origin', passed: direct.status === 404, status: direct.status });
  const report = { checks, passed: checks.every(c => c.passed), method: 'GET', requests, application_sessions_used: false, sampled_assets: assets.length, universal_routing_requires_active_version_metadata: true };
  // Return failure evidence; caller records it before failing the job.
  return report;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  let report;
  try { report = await probeAccess(process.env); if (!report.passed) process.exitCode = 1; }
  catch { report = { passed: false, category: 'probe_setup_or_transport', application_sessions_used: false }; process.exitCode = 1; }
  fs.mkdirSync(path.join(root, 'artifacts'), { recursive: true });
  fs.writeFileSync(path.join(root, 'artifacts/access.json'), JSON.stringify(report, null, 2) + '\n');
  console.log('Sanitized GET-only access probe evidence recorded.');
}

