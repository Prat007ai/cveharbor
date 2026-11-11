// Uses Web APIs supported by Cloudflare Workers and Node's verification runner.
export class AzureConnectionError extends Error {
  constructor(code, status = null) {
    super(code);
    this.name = 'AzureConnectionError';
    this.code = code;
    this.status = status;
  }
}

const fail = (code, status) => { throw new AzureConnectionError(code, status); };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function azureConfiguration(env) {
  let endpoint;
  try { endpoint = new URL(env.CVEHARBOR_AZURE_OPENAI_ENDPOINT); }
  catch { fail('invalid_configuration'); }
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password ||
      endpoint.port || endpoint.pathname !== '/' || endpoint.search || endpoint.hash ||
      !/^[a-z0-9-]+\.openai\.azure\.com$/.test(endpoint.hostname)) {
    fail('invalid_configuration');
  }
  const tenant = env.CVEHARBOR_AZURE_OPENAI_TENANT_ID;
  const client = env.CVEHARBOR_AZURE_OPENAI_CLIENT_ID;
  const secret = env.CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET;
  const deployment = env.CVEHARBOR_AZURE_OPENAI_DEPLOYMENT;
  if (!uuid.test(tenant || '') || !uuid.test(client || '') ||
      typeof secret !== 'string' || !secret.trim() || secret.length > 8192 ||
      /[\r\n]/.test(secret) || !/^[a-zA-Z0-9._-]{1,100}$/.test(deployment || '')) {
    fail('invalid_configuration');
  }
  return { endpoint: endpoint.origin, tenant, client, secret, deployment };
}

async function jsonRequest(fetcher, url, options, stage) {
  try {
    const response = await fetcher(url, {
      ...options,
      // Workers supports manual/follow, not error. Never follow a redirect:
      // the non-2xx check below rejects it before credentials can be forwarded.
      redirect: 'manual',
      signal: AbortSignal.timeout(45000),
    });
    if (!response.ok) fail(stage + '_http_error', response.status);
    // Bound provider payloads and never propagate provider error bodies or URLs.
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let bytes = 0;
    let text = '';
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > 262144) {
        await reader.cancel();
        fail(stage + '_invalid_response');
      }
      text += decoder.decode(value, { stream: true });
    }
    return JSON.parse(text + decoder.decode());
  } catch (error) {
    if (error instanceof AzureConnectionError) throw error;
    fail(stage + '_request_failed');
  }
}

export async function azureAccessToken(config, fetcher = fetch) {
  const data = await jsonRequest(fetcher,
    'https://login.microsoftonline.com/' + config.tenant + '/oauth2/v2.0/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: config.client,
        client_secret: config.secret,
        grant_type: 'client_credentials',
        scope: 'https://cognitiveservices.azure.com/.default',
      }).toString(),
    }, 'authentication');
  if (typeof data.access_token !== 'string' || !data.access_token ||
      /[\r\n]/.test(data.access_token) || data.token_type?.toLowerCase() !== 'bearer' ||
      !Number.isFinite(data.expires_in) || data.expires_in <= 60) {
    fail('authentication_invalid_response');
  }
  return data.access_token;
}

export async function verifyAzureAccess(config, token, fetcher = fetch) {
  const data = await jsonRequest(fetcher, config.endpoint + '/openai/v1/models', {
    method: 'GET', headers: { Authorization: 'Bearer ' + token },
  }, 'resource_access');
  if (!Array.isArray(data.data)) fail('resource_access_invalid_response');
  return { resource_access_verified: true };
}

export function completionUsage(data) {
  const usage = data?.usage;
  const input = usage?.prompt_tokens;
  const output = usage?.completion_tokens;
  const cached = usage?.prompt_tokens_details?.cached_tokens ?? 0;
  const reasoning = usage?.completion_tokens_details?.reasoning_tokens ?? 0;
  const counts = [input, output, cached, reasoning, usage?.total_tokens];
  if (!counts.every(value => Number.isSafeInteger(value) && value >= 0) ||
      input + output !== usage.total_tokens || cached > input || reasoning > output) {
    fail('inference_usage_unavailable');
  }
  return { input_tokens: input, output_tokens: output, cached_input_tokens: cached,
    reasoning_tokens: reasoning, total_tokens: input + output };
}

export async function azureCompletion(config, token, messages, fetcher = fetch) {
  const data = await jsonRequest(fetcher, config.endpoint + '/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
    body: JSON.stringify({ model: config.deployment, messages,
      max_completion_tokens: 1024, reasoning_effort: 'low', stream: false, store: false }),
  }, 'inference');
  const usage = completionUsage(data);
  const choice = data.choices?.[0];
  if (typeof data.model !== 'string' || typeof choice?.message?.content !== 'string') {
    fail('inference_invalid_response');
  }
  return { text: choice.message.content, model: data.model, usage,
    finish_reason: choice.finish_reason };
}
