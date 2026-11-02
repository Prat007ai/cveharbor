// Verify Access at the origin as well as at Cloudflare's edge. Never trust an email header.
export function createAccessVerifier(fetchKeys = fetch, clock = () => Date.now()) {
  let cached = null;
  let pending = null;
  const decode = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  async function keys(issuer) {
    const now = clock();
    if (cached?.issuer === issuer && cached.until > now) return cached.keys;
    if (!pending) pending = (async () => {
      const r = await fetchKeys(issuer + '/cdn-cgi/access/certs', { redirect: 'error', signal: AbortSignal.timeout(5000) });
      if (!r.ok) throw Error('Access keys unavailable');
      const text = await r.text();
      if (text.length > 65536) throw Error('Access keys too large');
      const data = JSON.parse(text);
      if (!Array.isArray(data.keys) || data.keys.length > 20) throw Error('Invalid Access keys');
      cached = { issuer, keys: data.keys, until: clock() + 60000 };
      return cached.keys;
    })().finally(() => { pending = null; });
    return pending;
  }
  return async (token, issuer, audience) => {
    try {
      if (!/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(issuer || '') || !/^[a-f0-9]{64}$/i.test(audience || '')) return false;
      if (typeof token !== 'string' || token.length > 16384) return false;
      const parts = token.split('.');
      if (parts.length !== 3 || parts.some(p => !/^[a-zA-Z0-9_-]+$/.test(p))) return false;
      const header = JSON.parse(new TextDecoder().decode(decode(parts[0])));
      const claims = JSON.parse(new TextDecoder().decode(decode(parts[1])));
      const now = clock() / 1000;
      if (header.alg !== 'RS256' || typeof header.kid !== 'string' || header.crit) return false;
      if (claims.iss !== issuer || !(Array.isArray(claims.aud) ? claims.aud : [claims.aud]).includes(audience)) return false;
      if (!Number.isFinite(claims.exp) || claims.exp <= now || !Number.isFinite(claims.iat) || claims.iat > now + 30) return false;
      if (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || claims.nbf > now + 30)) return false;
      const jwk = (await keys(issuer)).find(k => k.kid === header.kid && k.kty === 'RSA' && (!k.alg || k.alg === 'RS256') && (!k.use || k.use === 'sig'));
      if (!jwk) return false; // Fail closed until the short cache expires on rotation.
      const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
      return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, decode(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1]));
    } catch { return false; }
  };
}
