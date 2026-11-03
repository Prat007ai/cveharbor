import test from 'node:test';
import assert from 'node:assert/strict';
import { runCloud } from '../scripts/cloud.mjs';
import { TARGET } from '../target.mjs';
const fixtureEnv = { CF_STAGING_ACCOUNT_ID: TARGET.account, CF_STAGING_API_TOKEN: 'synthetic-not-a-credential', CF_STAGING_ACCESS_ISSUER: 'https://synthetic-staging.cloudflareaccess.com', CF_STAGING_ACCESS_AUD: 'a'.repeat(64) };
const mock = (bypass = false) => async (url, options) => {
  assert.ok(url === `https://api.cloudflare.com/client/v4/accounts/${TARGET.account}` || url.startsWith(`https://api.cloudflare.com/client/v4/accounts/${TARGET.account}/`));
  assert.equal(options.method, 'GET');
  let result;
  if (url.endsWith('/accounts/' + TARGET.account)) result = { id: TARGET.account };
  else if (url.endsWith('/workers/subdomain')) result = { subdomain: 'cveharbor-staging' };
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
  await assert.rejects(runCloud('check', fixtureEnv, mock(true)), /Staging operation stopped/);
  assert.doesNotMatch(logs.join(''), /synthetic-not-a-credential|synthetic@example/);
});
test('cloud create/deploy refuse before explicit approval or with another account', async () => {
  const forbidden = async () => assert.fail('Network must not be called');
  for (const action of ['create-database', 'deploy']) await assert.rejects(runCloud(action, fixtureEnv, forbidden), /Resource changes are gated/);
  await assert.rejects(runCloud('check', { ...fixtureEnv, CF_STAGING_ACCOUNT_ID: 'production' }, forbidden), /Dedicated staging account/);
});

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { root } from '../scripts/configure.mjs';
const uuid = '11111111-2222-4333-8444-555555555555', sha = 'c'.repeat(40);
function management({ deploy = false, badDB = false, unexpectedWorker = false, failure = '', calls = [] } = {}) {
  let uploads = 0;
  const apiVars = JSON.parse(fs.readFileSync(path.join(root, 'wrangler.api.json'))).vars;
  const plain = vars => Object.entries(vars).map(([name, text]) => ({ type: 'plain_text', name, text }));
  return { uploaded: () => uploads++, transport: async (url, init) => {
    const prefix = `https://api.cloudflare.com/client/v4/accounts/${TARGET.account}`;
    assert.ok(url.startsWith(prefix)); const route = url.slice(prefix.length); calls.push(init.method + ' ' + route);
    let result;
    if (route === '') result = { id: TARGET.account };
    else if (route === '/workers/subdomain') result = { subdomain: 'cveharbor-staging' };
    else if (route === '/access/apps?per_page=100') result = [{ id: 'aabbcc', domain: new URL(TARGET.origin).hostname, aud: 'a'.repeat(64), type: 'self_hosted' }];
    else if (route.endsWith('/policies')) result = [{ decision: 'allow', include: [{ email: { email: 'synthetic@example.test' } }] }];
    else if (route === '/d1/database?per_page=100') result = deploy ? [{ name: TARGET.database, uuid }] : [];
    else if (route === '/workers/scripts') result = unexpectedWorker ? [{ id: 'unexpected' }] : uploads === 2 ? [{ id: TARGET.api }, { id: TARGET.site }] : [];
    else if (route === '/d1/database') { assert.equal(init.method, 'POST'); assert.deepEqual(JSON.parse(init.body), { name: TARGET.database }); result = { name: TARGET.database, uuid }; }
    else if (route === `/workers/scripts/${TARGET.api}/settings`) result = { bindings: [
      { type: 'd1', name: 'DB', id: badDB ? TARGET.productionDatabase : uuid },
      { type: 'ratelimit', name: 'ASSIGNMENT_ACK_RATE_LIMITER', namespace_id: '24302', simple: { limit: 60, period: 60 } }, ...plain(apiVars),
      ...(failure === 'secret' ? [{ type: 'secret_text', name: 'SMTP2GO_API_KEY' }] : []),
    ] };
    else if (route === `/workers/scripts/${TARGET.site}/settings`) result = { bindings: [{ type: 'service', name: 'STAGING_API', service: TARGET.api }, { type: 'assets', name: 'ASSETS' }, ...plain({ ACCESS_ISSUER: fixtureEnv.CF_STAGING_ACCESS_ISSUER, ACCESS_AUD: fixtureEnv.CF_STAGING_ACCESS_AUD })], assets: { config: { run_worker_first: true } } };
    else if (route.endsWith('/deployments')) result = { deployments: [{ id: uuid, versions: [{ version_id: uuid, percentage: 100 }] }] };
    else if (route.endsWith('/subdomain')) result = { enabled: route.includes(TARGET.site) || failure === 'public-api', previews_enabled: false };
    else if (route.endsWith('/schedules')) result = { schedules: failure === 'cron' ? [{}] : [] };
    else assert.fail('Unapproved route ' + route);
    if (route !== '/d1/database') assert.equal(init.method, 'GET');
    return Response.json({ success: true, result });
  } };
}
async function withBundle(fn) {
  const files = ['api.mjs', 'manifest.json', 'api.json', 'site.json'];
  const previous = files.map(name => { try { return fs.readFileSync(path.join(root, '.build', name)); } catch { return null; } });
  fs.mkdirSync(path.join(root, '.build'), { recursive: true });
  const bundle = 'export default {}';
  fs.writeFileSync(path.join(root, '.build/api.mjs'), bundle);
  fs.writeFileSync(path.join(root, '.build/manifest.json'), JSON.stringify({ account: TARGET.account, commit: sha, providers: 'blocked', api_sha256: createHash('sha256').update(bundle).digest('hex') }));
  try { await fn(); } finally { files.forEach((name, i) => { const p = path.join(root, '.build', name); if (previous[i]) fs.writeFileSync(p, previous[i]); else fs.rmSync(p, { force: true }); }); }
}
test('database creation has exactly one fixed-account POST and returns only sanitized evidence', async () => {
  const calls = [], fixture = management({ calls });
  const result = await runCloud('create-database', { ...fixtureEnv, STAGING_CHANGE_APPROVED: 'PR243-STAGING-ONLY' }, fixture.transport, () => {});
  assert.equal(result.database_id, uuid);
  assert.deepEqual(calls.filter(x => !x.startsWith('GET')), ['POST /d1/database']);
  assert.doesNotMatch(JSON.stringify(result), /synthetic-not-a-credential|synthetic@example/);
  await assert.rejects(runCloud('create-database', { ...fixtureEnv, STAGING_CHANGE_APPROVED: 'PR243-STAGING-ONLY' }, management({ deploy: true }).transport), /Staging operation stopped/);
  await assert.rejects(runCloud('create-database', { ...fixtureEnv, STAGING_CHANGE_APPROVED: 'PR243-STAGING-ONLY' }, management({ unexpectedWorker: true }).transport), /Staging operation stopped/);
});
test('both dry runs precede upload, API verification gates frontend, and child credentials are isolated', async () => {
  await withBundle(async () => {
    for (const failure of ['', 'bad-db', 'secret', 'public-api', 'cron', 'dry-run']) {
      const calls = [], commands = [], fixture = management({ deploy: true, badDB: failure === 'bad-db', failure, calls });
      const runner = (_command, args, options) => {
        assert.equal(args[1], 'wrangler@4.156.0');
        const name = path.basename(args[4], '.json'), dry = args.includes('--dry-run');
        commands.push(name + (dry ? '-dry' : '-upload'));
        assert.equal(options.env.CLOUDFLARE_ACCOUNT_ID, TARGET.account);
        assert.equal(options.env.PRODUCTION_SECRET, undefined); assert.equal(options.env.CLOUDFLARE_API_TOKEN, fixtureEnv.CF_STAGING_API_TOKEN);
        if (!dry) { fixture.uploaded(); if (name === 'site') assert.ok(calls.includes(`GET /workers/scripts/${TARGET.api}/schedules`)); }
        return { status: failure === 'dry-run' ? 1 : 0 };
      };
      const promise = runCloud('deploy', { ...fixtureEnv, STAGING_CHANGE_APPROVED: 'PR243-STAGING-ONLY', CF_STAGING_D1_DATABASE_ID: uuid, GITHUB_SHA: sha, PRODUCTION_SECRET: 'never-forward' }, fixture.transport, () => {}, runner);
      if (failure) { await assert.rejects(promise); assert.ok(!commands.includes('site-upload')); }
      else { const result = await promise; assert.equal(result.bindings_verified, true); assert.deepEqual(commands, ['api-dry', 'site-dry', 'api-upload', 'site-upload']); }
    }
  });
});

