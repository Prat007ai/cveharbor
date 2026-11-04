import {intelligenceResponse,openIntelligenceSnapshot,pinIntelligenceScripts,useIntelligenceStore} from '../account-backend/src/intelligence-store.js';
import {ADMIN_HTML} from './admin-page.mjs';
import { TARGET, LEGACY_ORIGIN } from './target.mjs';
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
    if (url.origin !== TARGET.origin && !(url.origin === LEGACY_ORIGIN && url.pathname === '/v1/staging-readiness' && request.method === 'GET')) return deny('Unknown staging host', 403);
    let rejection = 'unknown', identity=null;
    if (!await check(request.headers.get('Cf-Access-Jwt-Assertion'), env.ACCESS_ISSUER, env.ACCESS_AUD, category => { if (ACCESS_FAILURE_CATEGORIES.includes(category)) rejection = category; }, verified => {identity=verified;})) {
      const response = deny('Cloudflare Access authentication required', 403);
      response.headers.set('X-Staging-Access-Error', rejection);
      return response;
    }
    const origin = request.headers.get('Origin');
    if (origin && origin !== TARGET.origin) return deny('Forbidden origin', 403);
    const adminPath=url.pathname.startsWith('/__staging');
    const adminEmail=String(identity?.email||'').toLowerCase();
    const isAdmin=!!adminEmail&&String(env.STAGING_ADMIN_EMAILS||'').split(',').map(s=>s.trim().toLowerCase()).includes(adminEmail);
    if(adminPath&&!isAdmin)return deny('Staging administrator required',403);
    if(adminPath&&!['GET','HEAD'].includes(request.method)&&(request.method!=='POST'||origin!==TARGET.origin||request.headers.get('Content-Type')!=='application/json'))return deny('Forbidden administration request',403);
    const headers = new Headers(request.headers);
    headers.delete('X-CVEHarbor-Staging-Admin');
    if(adminPath&&isAdmin)headers.set('X-CVEHarbor-Staging-Admin',adminEmail);
    for (const name of ['Authorization', 'Proxy-Authorization', 'Cf-Access-Jwt-Assertion', 'Cf-Access-Client-Id', 'Cf-Access-Client-Secret', 'Cf-Access-Authenticated-User-Email']) headers.delete(name);
    // Only the application session may cross the service binding; Access cookies stay at the frontend.
    const session = (headers.get('Cookie') || '').split(';').map(v => v.trim()).filter(v => /^(?:cvh_session|__Host-cvh_review)=[a-f0-9]{64}$/.test(v));
    headers.delete('Cookie');
    if(new Set(session.map(s=>s.split('=')[0])).size===session.length&&session.length)headers.set('Cookie',session.join('; '));
    const forwarded = new Request(request, { headers });
    let response;
    if(adminPath&&(url.pathname==='/__staging'||url.pathname==='/__staging/')&&request.method==='GET'){
      response=new Response(ADMIN_HTML,{headers:{'Content-Type':'text/html; charset=utf-8'}});
    } else if (url.pathname.startsWith('/v1/')||url.pathname.startsWith('/assignment/')||url.pathname.startsWith('/acknowledge/')||adminPath) {
      if (!env.STAGING_API?.fetch) return deny('Staging API unavailable', 503);
      response = await env.STAGING_API.fetch(forwarded);
    } else {

      if (!['GET', 'HEAD'].includes(request.method)) return deny('Method not allowed', 405);
      if (!env.ASSETS?.fetch) return deny('Staging assets unavailable', 503);
      headers.delete('Cookie');
      try{response=await intelligenceResponse(request,env);}catch{return deny('Staging intelligence unavailable',503);}
      if(!response)response = await env.ASSETS.fetch(new Request(request, { headers }));
      if(request.method==='GET'&&response.ok&&(response.headers.get('Content-Type')||'').includes('text/html')){
        let html=await response.text();
        try{if(useIntelligenceStore(env))html=pinIntelligenceScripts(html,(await openIntelligenceSnapshot(env)).version);}catch{}
        const h=new Headers(response.headers);h.delete('Content-Length');h.delete('ETag');
        response=new Response(html,{status:response.status,headers:h});
      }
    }
    const outgoing = new Headers(response.headers);
    for (const [key, value] of Object.entries(securityHeaders)) outgoing.set(key, value);
    const location = outgoing.get('Location');
    if (location && new URL(location, url).origin !== TARGET.origin) return deny('External redirect blocked', 502);
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers: outgoing });
  } };
}
export default createFrontend();


