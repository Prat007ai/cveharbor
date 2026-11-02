import test from 'node:test';
import assert from 'node:assert/strict';
import { runCloud } from '../scripts/cloud.mjs';
import { TARGET } from '../target.mjs';
const fixtureEnv = { CF_STAGING_ACCOUNT_ID: TARGET.account, CF_STAGING_API_TOKEN: 'synthetic-not-a-credential', CF_STAGING_ACCESS_ISSUER: 'https://synthetic-staging.cloudflareaccess.com', CF_STAGING_ACCESS_AUD: 'a'.repeat(64) };
const mock = (bypass = false) => async (url, options) => {
  assert.ok(url.startsWith(`https://api.cloudflare.com/client/v4/accounts/${TARGET.account}/`));
  assert.equal(options.method, 'GET');
  let result;
  if (url.endsWith('/workers/subdomain')) result = { subdomain: 'cveharbor-staging' };
  else if (url.endsWith('/access/apps?per_page=100')) result = [{ id: 'aabbcc', domain: new URL(TARGET.origin).hostname, aud: 'a'.repeat(64), type: 'self_hosted' }];
  else if (url.endsWith('/access/apps/aabbcc/policies')) result = [{ decision: bypass ? 'bypass' : 'allow', include: [{ email: { email: 'synthetic@example.test' } }] }];
  else if (url.endsWith('/d1/database?per_page=100')) result = [];
  else assert.fail('Unexpected endpoint');
  return Response.json({ success: true, result });
};
test('cloud preflight is staging-only and read-only; bypass policy fails closed', async () => {
  const logs = [];
  await runCloud('check', fixtureEnv, mock(), text => logs.push(text));
  assert.match(logs.join(''), /no resources changed/);
  await assert.rejects(runCloud('check', fixtureEnv, mock(true)), /no bypass/);
  assert.doesNotMatch(logs.join(''), /synthetic-not-a-credential|synthetic@example/);
});
test('cloud create/deploy refuse before explicit approval or with another account', async () => {
  const forbidden = async () => assert.fail('Network must not be called');
  for (const action of ['create-database', 'deploy']) await assert.rejects(runCloud(action, fixtureEnv, forbidden), /Resource changes are gated/);
  await assert.rejects(runCloud('check', { ...fixtureEnv, CF_STAGING_ACCOUNT_ID: 'production' }, forbidden), /Dedicated staging account/);
});
