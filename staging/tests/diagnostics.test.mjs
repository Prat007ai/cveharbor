import test from 'node:test';
import assert from 'node:assert/strict';
import { diagnose } from '../scripts/diagnose.mjs';
import { runCloud } from '../scripts/cloud.mjs';
import { safeFailure, wranglerCategory } from '../scripts/errors.mjs';
import { TARGET } from '../target.mjs';
const id = '11111111-2222-4333-8444-555555555555';
const env = { CF_STAGING_ACCOUNT_ID: TARGET.account, CF_STAGING_D1_DATABASE_ID: id, CF_STAGING_API_TOKEN: 'secret-token', CF_STAGING_ACCESS_ISSUER: 'https://synthetic-stage.cloudflareaccess.com', CF_STAGING_ACCESS_AUD: 'a'.repeat(64) };
test('diagnostics inspect absent/partial Workers with GET only and redact unrelated metadata', async () => {
  for (const partial of [false, true]) {
    const calls = [], records = [];
    const transport = async (url, init) => {
      assert.equal(init.method, 'GET'); assert.equal(init.redirect, 'error');
      const prefix = `https://api.cloudflare.com/client/v4/accounts/${TARGET.account}`;
      assert.ok(url.startsWith(prefix)); const route = url.slice(prefix.length); calls.push(route);
      let result;
      if (!route) result = { id: TARGET.account };
      else if (route === '/d1/database?per_page=100') result = [{ name: TARGET.database, uuid: id }];
      else if (route === `/d1/database/${id}`) result = { name: TARGET.database, uuid: id, num_tables: 0, file_size: 12288 };
      else if (route === '/workers/scripts') result = partial ? [{ id: TARGET.api }, { id: 'unrelated-private-name' }] : [];
      else if (route.endsWith('/settings')) result = { bindings: [{ name: 'SMTP2GO_API_KEY', type: 'secret_text', text: 'secret-value' }] };
      else if (route.endsWith('/subdomain')) result = { enabled: false, previews_enabled: false };
      else if (route.endsWith('/schedules')) result = { schedules: [] };
      else if (route.endsWith('/deployments')) result = { deployments: [{}] };
      else assert.fail(route);
      return Response.json({ success: true, result });
    };
    const report = await diagnose(env, transport, r => records.push(JSON.stringify(r)));
    assert.equal(report.database.present, true); assert.equal(report.database.metadata_identity_matches, true);
    assert.equal(report.workers[0].present, partial); assert.equal(report.workers[1].present, false);
    if (partial) { assert.equal(report.workers[0].unexpected_binding_count, 1); assert.equal(report.workers[0].d1_binding_matches, false); }
    assert.doesNotMatch(records.join(''), /secret-token|secret-value|SMTP2GO|unrelated-private-name/);
    assert.ok(!calls.some(p => /query|export|import|migrat/.test(p)));
  }
});
test('diagnostics reject another account before requests and retain sanitized authorization failure', async () => {
  await assert.rejects(diagnose({ ...env, CF_STAGING_ACCOUNT_ID: 'other' }, async () => assert.fail('No requests')));
  const records = [];
  await assert.rejects(diagnose(env, async () => Response.json({ errors: [{ message: 'secret-token' }] }, { status: 403 }), r => records.push(JSON.stringify(r))));
  assert.match(records.at(-1), /authorization/); assert.doesNotMatch(records.join(''), /secret-token/);
});
test('management failures preserve operation/status/category without raw response text', async () => {
  for (const [transport, category] of [
    [async () => Response.json({ success: false, errors: [{ code: 10000, message: 'secret-token' }] }, { status: 403 }), 'authorization'],
    [async () => new Response('secret-token'), 'invalid_json'],
    [async () => { throw Error('secret-token'); }, 'network'],
  ]) {
    try { await runCloud('check', env, transport); assert.fail('Must fail'); }
    catch (error) { const report = safeFailure(error); assert.equal(report.category, category); assert.equal(report.operation, 'management.GET./account'); assert.doesNotMatch(JSON.stringify(report), /secret-token/); }
  }
});
test('untrusted errors and Wrangler output export only fixed categories', () => {
  assert.deepEqual(safeFailure(Object.assign(Error('secret-token'), { operation: 'secret-token', category: 'secret-token' })), { operation: 'provisioning', category: 'unknown' });
  assert.equal(wranglerCategory({ stderr: 'secret-token Authentication error [code: 10000]' }), 'authorization');
  assert.equal(wranglerCategory({ stderr: 'secret-token Build failed' }), 'build');
  assert.equal(wranglerCategory({ error: { code: 'ETIMEDOUT', message: 'secret-token' } }), 'subprocess_timeout');
  assert.equal(wranglerCategory({ stderr: 'secret-token arbitrary error' }), 'wrangler_exit');
});
