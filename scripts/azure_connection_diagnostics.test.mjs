import test from 'node:test';
import assert from 'node:assert/strict';
import {diagnosticFetch} from './azure_connection_diagnostics.mjs';

test('credential failures retain only a fixed operation and HTTP status', async () => {
  const report = {}; let stage;
  const response = new Response('private provider body', {status:403});
  const check = diagnosticFetch(report, value => {stage=value;}, async () => response);
  assert.equal(await check('https://api.cloudflare.com/client/v4/accounts/private/d1/database/11111111-1111-1111-1111-111111111111?private=value',
    {headers:{Authorization:'Bearer private-secret'}}), response);
  assert.equal(stage, 'cloudflare_database_identity');
  assert.deepEqual(report, {last_http_status:403});
  assert.ok(!JSON.stringify(report).includes('private'));
});

test('network failure clears a stale status without copying the error', async () => {
  const report = {last_http_status:200}; let stage;
  const check = diagnosticFetch(report, value => {stage=value;}, async () => {throw Error('private provider details');});
  await assert.rejects(check('https://api.cloudflare.com/client/v4/accounts/private/workers/scripts/test/settings'));
  assert.equal(stage, 'cloudflare_worker_settings');
  assert.deepEqual(report, {});
});
