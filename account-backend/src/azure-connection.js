// Deployment-only access check. No prompts, customer input, or inference calls.
import {azureConfiguration, azureAccessToken, verifyAzureAccess, AzureConnectionError} from './azure-client.js';

export const probePath = '/v1/ops/azure-connection';
const encoder = new TextEncoder();
const hex = value => /^[a-f0-9]{64}$/.test(value || '');
const bytes = value => Uint8Array.from(value.match(/../g), part => parseInt(part, 16));
const reply = (data, status) => new Response(JSON.stringify(data), {status, headers: {
  'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
}});
export const probeMessage = (timestamp, nonce, release) => ['POST', probePath, timestamp, nonce, release].join('\n');

export async function azureConnectionProbe(req, env, release, {fetcher = fetch, now = Date.now()} = {}) {
  const unavailable = () => reply({error: 'Connection check unavailable'}, 404);
  const url = new URL(req.url);
  if (url.hostname !== 'api.cveharbor.com' || url.pathname !== probePath || url.search ||
      req.method !== 'POST') return unavailable();
  let proof;
  try { proof = JSON.parse(env.CVEHARBOR_AZURE_CONNECTION_PROBE); } catch { return unavailable(); }
  const seconds = Math.floor(now / 1000);
  const stamp = req.headers.get('X-CVH-Timestamp');
  const nonce = req.headers.get('X-CVH-Nonce');
  const signature = req.headers.get('X-CVH-Signature');
  if (!hex(proof?.key) || !hex(release) || proof.release !== release ||
      !Number.isSafeInteger(proof.created) || !Number.isSafeInteger(proof.expires) ||
      proof.expires - proof.created !== 900 || seconds < proof.created || seconds >= proof.expires ||
      !/^\d{10}$/.test(stamp || '') || Math.abs(seconds - Number(stamp)) > 60 ||
      !hex(nonce) || !hex(signature)) return unavailable();
  const key = await crypto.subtle.importKey('raw', bytes(proof.key), {name: 'HMAC', hash: 'SHA-256'}, false, ['verify']);
  if (!await crypto.subtle.verify('HMAC', key, bytes(signature), encoder.encode(probeMessage(stamp, nonce, release)))) return unavailable();

  // Workers exposes a stream even for an empty HTTP POST. Admit only a stream
  // that is already at EOF; never accept prompt bytes or buffer a request body.
  if (req.body !== null) {
    const reader = req.body.getReader();
    try {
      const {done} = await reader.read();
      if (!done) { await reader.cancel(); return unavailable(); }
    } catch { return unavailable(); }
    finally { reader.releaseLock(); }
  }

  const result = {release, authentication_verified: false, resource_access_verified: false,
    inference_attempted: false, customer_ai_enabled: false};
  try {
    const config = azureConfiguration(env);
    // Only the owner's reviewed Azure resource and application are valid for this rollout.
    if (config.endpoint !== 'https://cvie-prod.openai.azure.com' || config.deployment !== 'gpt-5.4-mini' ||
        config.tenant !== 'f95d3766-898f-4e4d-a0ad-9b5efa394592' ||
        config.client !== 'dec0de99-1e60-461f-bfb2-aa518b40036a') throw new AzureConnectionError('invalid_configuration');
    const token = await azureAccessToken(config, fetcher);
    result.authentication_verified = true;
    await verifyAzureAccess(config, token, fetcher);
    result.resource_access_verified = true;
    return reply({...result, status: 'passed'}, 200);
  } catch (error) {
    return reply({...result, status: 'failed', error: error instanceof AzureConnectionError ? error.code : 'verification_failed'}, 503);
  }
}
