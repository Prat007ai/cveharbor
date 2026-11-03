import { TARGET } from './target.mjs';
import { createAccessVerifier, ACCESS_FAILURE_CATEGORIES } from './access.mjs';
const verify = createAccessVerifier();
const securityHeaders = {
  'Cache-Control': 'private, no-store',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
};
const deny = (text, status) => new Response(text, { status, headers: securityHeaders });
export function createFrontend(check = verify) {
  return { async fetch(request, env) {
    const url = new URL(request.url);
    if (url.origin !== TARGET.origin) return deny('Unknown staging host', 403);
    let rejection = 'unknown';
    if (!await check(request.headers.get('Cf-Access-Jwt-Assertion'), env.ACCESS_ISSUER, env.ACCESS_AUD, category => { if (ACCESS_FAILURE_CATEGORIES.includes(category)) rejection = category; })) {
      const response = deny('Cloudflare Access authentication required', 403);
      response.headers.set('X-Staging-Access-Error', rejection);
      return response;
    }
    const origin = request.headers.get('Origin');
    if (origin && origin !== TARGET.origin) return deny('Forbidden origin', 403);
    const headers = new Headers(request.headers);
    for (const name of ['Authorization', 'Proxy-Authorization', 'Cf-Access-Jwt-Assertion', 'Cf-Access-Client-Id', 'Cf-Access-Client-Secret', 'Cf-Access-Authenticated-User-Email']) headers.delete(name);
    // Only the application session may cross the service binding; Access cookies stay at the frontend.
    const session = (headers.get('Cookie') || '').split(';').map(v => v.trim()).filter(v => /^cvh_session=[a-f0-9]{64}$/.test(v));
    headers.delete('Cookie');
    if (session.length === 1) headers.set('Cookie', session[0]);
    const forwarded = new Request(request, { headers });
    let response;
    if (url.pathname.startsWith('/v1/')) {
      if (!env.STAGING_API?.fetch) return deny('Staging API unavailable', 503);
      response = await env.STAGING_API.fetch(forwarded);
    } else {
      if (url.pathname.startsWith('/__staging')) return deny('Not found', 404);
      if (!['GET', 'HEAD'].includes(request.method)) return deny('Method not allowed', 405);
      if (!env.ASSETS?.fetch) return deny('Staging assets unavailable', 503);
      headers.delete('Cookie');
      response = await env.ASSETS.fetch(new Request(request, { headers }));
    }
    const outgoing = new Headers(response.headers);
    for (const [key, value] of Object.entries(securityHeaders)) outgoing.set(key, value);
    const location = outgoing.get('Location');
    if (location && new URL(location, url).origin !== TARGET.origin) return deny('External redirect blocked', 502);
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers: outgoing });
  } };
}
export default createFrontend();

