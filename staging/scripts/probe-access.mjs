import { TARGET, accessSettings } from '../target.mjs';

// Read-only smoke checks. No application sessions, login requests, SQL or redirects.
export async function probeAccess(env, transport = fetch) {
  const { ACCESS_ISSUER } = accessSettings(env.CF_STAGING_ACCESS_ISSUER, env.CF_STAGING_ACCESS_AUD);
  if (!env.CF_STAGING_ACCESS_CLIENT_ID || !env.CF_STAGING_ACCESS_CLIENT_SECRET) throw Error('Staging service credentials required');
  const checks = [];
  async function get(route, headers = {}) {
    return transport(TARGET.origin + route, { method: 'GET', headers, redirect: 'manual', signal: AbortSignal.timeout(20000) });
  }
  function denied(response) {
    if ([401, 403].includes(response.status)) return true;
    try { const url = new URL(response.headers.get('Location')); return [302, 303, 307, 308].includes(response.status) && url.origin === ACCESS_ISSUER && url.pathname.startsWith('/cdn-cgi/access/login'); } catch { return false; }
  }
  for (const [name, headers] of [['anonymous', {}], ['forged_jwt', { 'Cf-Access-Jwt-Assertion': 'invalid.signature.token' }]]) {
    const r = await get('/', headers); checks.push({ name, passed: denied(r), status: r.status });
  }
  const auth = { 'CF-Access-Client-Id': env.CF_STAGING_ACCESS_CLIENT_ID, 'CF-Access-Client-Secret': env.CF_STAGING_ACCESS_CLIENT_SECRET };
  const page = await get('/', auth);
  checks.push({ name: 'service_static_page', passed: page.status === 200 && /text\/html/i.test(page.headers.get('Content-Type') || '') && page.headers.get('X-Robots-Tag') === 'noindex, nofollow, noarchive' && (await page.text()).includes('CVEHarbor'), status: page.status });
  const me = await get('/v1/me', auth);
  let payload; try { payload = await me.json(); } catch {}
  checks.push({ name: 'application_session_required', passed: me.status === 401 && payload?.authenticated === false && me.headers.get('X-Robots-Tag') === 'noindex, nofollow, noarchive', status: me.status });
  const report = { checks, passed: checks.every(c => c.passed), method: 'GET', requests: checks.length, application_sessions_used: false };
  // Return failure evidence; caller records it before failing the job.
  return report;
}
