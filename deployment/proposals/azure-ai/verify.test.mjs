import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { azureConfiguration, azureAccessToken, completionUsage, AzureConnectionError } from './client.mjs';
import { runVerification, estimateUsdNano, fictionalPrompt } from './verify.mjs';

const env = {
  AZURE_AI_VERIFY_MODE: 'access',
  CVEHARBOR_AZURE_OPENAI_ENDPOINT: 'https://cvie-prod.openai.azure.com/',
  CVEHARBOR_AZURE_OPENAI_TENANT_ID: '11111111-1111-4111-8111-111111111111',
  CVEHARBOR_AZURE_OPENAI_CLIENT_ID: '22222222-2222-4222-8222-222222222222',
  CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET: 'fictional-secret+&=percent%',
  CVEHARBOR_AZURE_OPENAI_DEPLOYMENT: 'gpt-5.4-mini',
};
const token = 'fictional-access-token';
const modelReply = () => ({
  model: 'gpt-5.4-mini-2026-03-17',
  choices: [{ finish_reason: 'stop', message: { content: 'Check the exact package and its repository.' } }],
  usage: { prompt_tokens: 88, completion_tokens: 172, total_tokens: 260,
    prompt_tokens_details: { cached_tokens: 0 }, completion_tokens_details: { reasoning_tokens: 40 } },
});
function transport(overrides = {}) {
  const calls = [];
  const fetcher = async (url, options) => {
    calls.push({ url, options });
    assert.equal(options.redirect, 'manual');
    assert.ok(options.signal instanceof AbortSignal);
    if (url.endsWith('/token')) {
      const body = new URLSearchParams(options.body);
      assert.equal(body.get('client_secret'), env.CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET);
      assert.equal(body.get('scope'), 'https://cognitiveservices.azure.com/.default');
      assert.equal(body.get('grant_type'), 'client_credentials');
      return overrides.auth?.() ?? Response.json({ access_token: token, token_type: 'Bearer', expires_in: 3600 });
    }
    assert.equal(options.headers.Authorization, 'Bearer ' + token);
    assert.ok(!JSON.stringify(options).includes(env.CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET));
    if (url.endsWith('/models')) return overrides.models?.() ?? Response.json({ data: [] });
    assert.equal(url, env.CVEHARBOR_AZURE_OPENAI_ENDPOINT + 'openai/v1/chat/completions');
    return overrides.inference?.() ?? Response.json(modelReply());
  };
  return { calls, fetcher };
}

test('redirects at authentication and resource access are rejected without following or exposing destinations', async () => {
  for (const status of [301,302,303,307,308]) {
    for (const stage of ['auth','models']) {
      const {calls,fetcher}=transport({[stage]:()=>new Response(null,{status,headers:{Location:'https://untrusted.example/private'}})});
      const result=await runVerification(env,fetcher);
      assert.equal(result.status,'failed');
      assert.equal(result.error,stage==='auth'?'authentication_http_error':'resource_access_http_error');
      assert.equal(calls.length,stage==='auth'?1:2);
      assert.equal(result.inference_attempted,false);
      assert.ok(!JSON.stringify(result).includes('untrusted.example'));
    }
  }
});

test('access mode authenticates and checks resource permissions without inference', async () => {
  const { calls, fetcher } = transport();
  const result = await runVerification(env, fetcher);
  assert.equal(result.status, 'passed');
  assert.equal(result.authentication_verified, true);
  assert.equal(result.resource_access_verified, true);
  assert.equal(result.inference_attempted, false);
  assert.equal(result.organization_id, null);
  assert.equal(result.user_id, null);
  assert.equal(result.usage_category, 'platform_verification');
  assert.equal(result.usage, null);
  assert.equal(calls.length, 2);
});

test('explicit inference makes one bounded fictional request and records cost once', async () => {
  const { calls, fetcher } = transport();
  const result = await runVerification({ ...env, AZURE_AI_VERIFY_MODE: 'inference' }, fetcher);
  assert.equal(result.status, 'passed');
  assert.equal(calls.length, 3);
  const request = JSON.parse(calls[2].options.body);
  assert.equal(request.messages[1].content, fictionalPrompt);
  assert.equal(request.max_completion_tokens, 1024);
  assert.equal(request.reasoning_effort, 'low');
  assert.equal(request.store, false);
  assert.equal(request.stream, false);
  assert.equal(result.usage.total_tokens, 260);
  assert.equal(result.usage.reasoning_tokens, 40);
  assert.equal(result.estimated_cost_usd, 0.000924);
  const report = JSON.stringify(result);
  for (const privateValue of [token, env.CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET, fictionalPrompt, modelReply().choices[0].message.content]) {
    assert.ok(!report.includes(privateValue));
  }
});

test('cached input uses its own rate and reasoning is included in output exactly once', () => {
  const reply = modelReply();
  reply.usage.prompt_tokens_details.cached_tokens = 50;
  const usage = completionUsage(reply);
  assert.equal(estimateUsdNano(usage), 886875);
  assert.equal(usage.output_tokens, 172);
});

test('invalid configuration never sends a request', async () => {
  const mutations = [
    { CVEHARBOR_AZURE_OPENAI_ENDPOINT: 'http://cvie-prod.openai.azure.com/' },
    { CVEHARBOR_AZURE_OPENAI_ENDPOINT: 'https://cvie-prod.openai.azure.com.evil.test/' },
    { CVEHARBOR_AZURE_OPENAI_ENDPOINT: 'https://login:password@cvie-prod.openai.azure.com/' },
    { CVEHARBOR_AZURE_OPENAI_ENDPOINT: 'https://cvie-prod.openai.azure.com/?secret=x' },
    { CVEHARBOR_AZURE_OPENAI_ENDPOINT: 'https://cvie-prod.openai.azure.com/openai/v1/' },
    { CVEHARBOR_AZURE_OPENAI_ENDPOINT: 'https://other.openai.azure.com/' },
    { CVEHARBOR_AZURE_OPENAI_TENANT_ID: '../../common' },
    { CVEHARBOR_AZURE_OPENAI_CLIENT_ID: '' },
    { CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET: '' },
    { CVEHARBOR_AZURE_OPENAI_DEPLOYMENT: 'expensive-model' },
    { AZURE_AI_VERIFY_MODE: 'anything' },
  ];
  for (const mutation of mutations) {
    let calls = 0;
    const report = await runVerification({ ...env, ...mutation }, async () => { calls++; });
    assert.equal(report.status, 'failed');
    assert.equal(calls, 0);
  }
});

test('authentication errors are sanitized and never retried', async () => {
  const { calls, fetcher } = transport({ auth: () => new Response(env.CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET, { status: 401 }) });
  const report = await runVerification(env, fetcher);
  assert.equal(report.error, 'authentication_http_error');
  assert.equal(report.http_status, 401);
  assert.equal(report.authentication_verified, false);
  assert.equal(calls.length, 1);
  assert.ok(!JSON.stringify(report).includes(env.CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET));
});

test('resource access rejection prevents model usage', async () => {
  const { calls, fetcher } = transport({ models: () => new Response(token, { status: 403 }) });
  const report = await runVerification({ ...env, AZURE_AI_VERIFY_MODE: 'inference' }, fetcher);
  assert.equal(report.authentication_verified, true);
  assert.equal(report.error, 'resource_access_http_error');
  assert.equal(report.inference_attempted, false);
  assert.equal(calls.length, 2);
  assert.ok(!JSON.stringify(report).includes(token));
});

test('invalid, expired and header-injecting tokens fail closed', async () => {
  for (const value of [
    {}, { access_token: token, token_type: 'Bearer', expires_in: 0 },
    { access_token: token + '\r\nInjected: yes', token_type: 'Bearer', expires_in: 3600 },
    { access_token: token, token_type: 'Other', expires_in: 3600 },
  ]) {
    await assert.rejects(azureAccessToken(azureConfiguration(env), async () => Response.json(value)),
      error => error instanceof AzureConnectionError && error.code === 'authentication_invalid_response');
  }
});

test('timeouts and network failures retain uncertain cost and do not retry inference', async () => {
  const { calls, fetcher } = transport({ inference: () => { throw new Error('Timeout ' + token); } });
  const report = await runVerification({ ...env, AZURE_AI_VERIFY_MODE: 'inference' }, fetcher);
  assert.equal(report.error, 'inference_request_failed');
  assert.equal(report.cost_status, 'unknown_pending_reconciliation');
  assert.equal(report.estimated_cost_usd, null);
  assert.equal(calls.length, 3);
  assert.ok(!JSON.stringify(report).includes(token));
});

test('provider rate limits and server failures are sanitized without automatic retries', async () => {
  for (const status of [400, 429, 500, 503]) {
    const { calls, fetcher } = transport({ inference: () => new Response(token, { status }) });
    const report = await runVerification({ ...env, AZURE_AI_VERIFY_MODE: 'inference' }, fetcher);
    assert.equal(report.http_status, status);
    assert.equal(report.status, 'failed');
    assert.equal(report.estimated_cost_usd, null);
    assert.equal(calls.length, 3);
  }
});

test('missing or contradictory usage is never treated as free', async () => {
  for (const usage of [null, {}, { prompt_tokens: -1, completion_tokens: 2, total_tokens: 1 },
    { prompt_tokens: 1, completion_tokens: 2, total_tokens: 4 },
    { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3, prompt_tokens_details: { cached_tokens: 5 } },
    { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3, completion_tokens_details: { reasoning_tokens: 3 } },
  ]) {
    const { fetcher } = transport({ inference: () => Response.json({ ...modelReply(), usage }) });
    const report = await runVerification({ ...env, AZURE_AI_VERIFY_MODE: 'inference' }, fetcher);
    assert.equal(report.error, 'inference_usage_unavailable');
    assert.equal(report.cost_status, 'unknown_pending_reconciliation');
    assert.equal(report.estimated_cost_usd, null);
  }
});

test('truncation, refusal and changed model preserve usage and flag verification failure', async () => {
  for (const kind of ['length', 'content_filter', 'empty', 'changed_model']) {
    const data = modelReply();
    if (kind === 'changed_model') data.model = 'unreviewed-model';
    else if (kind === 'empty') data.choices[0].message.content = '';
    else data.choices[0].finish_reason = kind;
    const { fetcher } = transport({ inference: () => Response.json(data) });
    const report = await runVerification({ ...env, AZURE_AI_VERIFY_MODE: 'inference' }, fetcher);
    assert.equal(report.status, 'failed');
    assert.equal(report.usage.total_tokens, 260);
    assert.equal(report.estimated_cost_usd, kind === 'changed_model' ? null : 0.000924);
  }
});

test('oversized or malformed provider payloads are bounded and sanitized', async () => {
  for (const body of ['{"broken":', 'x'.repeat(262145)]) {
    const { fetcher } = transport({ auth: () => new Response(body) });
    const report = await runVerification(env, fetcher);
    assert.equal(report.status, 'failed');
    assert.equal(report.authentication_verified, false);
    assert.ok(JSON.stringify(report).length < 2000);
  }
});

test('workflow keeps secrets in the protected manual main-only job', () => {
  const workflow = readFileSync(new URL('../../../.github/workflows/verify-azure-ai.yml', import.meta.url), 'utf8');
  const [testJob, secretJob] = workflow.split('\n  verify:\n');
  assert.ok(!testJob.includes('${{ secrets.'));
  assert.ok(secretJob.includes("github.event_name == 'workflow_dispatch'"));
  assert.ok(secretJob.includes("github.ref == 'refs/heads/main'"));
  assert.ok(secretJob.includes('inputs.reviewed_commit == github.sha'));
  assert.ok(secretJob.includes('environment: cloudflare-worker-production'));
  assert.ok(workflow.includes('default: access'));
  assert.ok(!workflow.includes('\n  push:'));
});
