// No default mutation. This tool has no production-account selection option.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { TARGET, accessSettings, databaseId } from '../target.mjs';
import { root, writeConfigs } from './configure.mjs';
import { failure, wranglerCategory } from './errors.mjs';

export async function runCloud(action = 'check', env = process.env, fetcher = fetch, log = console.log, runner = spawnSync) {
  if (!['check', 'create-database', 'deploy'].includes(action)) throw Error('Use check, create-database or deploy. No SQL execution is exposed.');
  if (env.CF_STAGING_ACCOUNT_ID !== TARGET.account || !env.CF_STAGING_API_TOKEN) throw Error('Dedicated staging account/token required');
  accessSettings(env.CF_STAGING_ACCESS_ISSUER, env.CF_STAGING_ACCESS_AUD);
  if (action !== 'check' && env.STAGING_CHANGE_APPROVED !== 'PR243-STAGING-ONLY') throw Error('Resource changes are gated until credentials and execution are approved.');
  let operation = 'management.account';
  try {
  const apiBase = `https://api.cloudflare.com/client/v4/accounts/${TARGET.account}`;
  async function cf(route, method = 'GET', body) {
    // Only fixed account-relative paths constructed below are accepted.
    if ((route !== '' && !route.startsWith('/')) || route.includes('..') || route.includes('://')) throw Error('Invalid staging management path');
    operation = `management.${method}.${route.split('?')[0] || '/account'}`;
    let response;
    try { response = await fetcher(apiBase + route, { method, redirect: 'error', signal: AbortSignal.timeout(30000),
      headers: { Authorization: 'Bearer ' + env.CF_STAGING_API_TOKEN, 'Content-Type': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}) });
    } catch { throw failure(operation, 'network'); }
    let result;
    try { result = await response.json(); } catch { throw failure(operation, 'invalid_json', { http_status: response.status }); }
    // Never print API response bodies, tokens, policy members or provider errors.
    if (!response.ok || result?.success !== true) throw failure(operation, response.status === 401 || response.status === 403 ? 'authorization' : response.status === 429 ? 'rate_limit' : 'cloudflare_api', { http_status: response.status, api_codes: Array.isArray(result?.errors) ? result.errors.map(e => e?.code).filter(Number.isInteger).slice(0, 8) : [] });
    return result.result;
  }
  const identity = await cf('');
  if (identity?.id !== TARGET.account) throw Error('Account identity mismatch');
  const subdomain = await cf('/workers/subdomain');
  if (subdomain.subdomain !== 'cveharbor-staging') throw Error('Workers subdomain mismatch');
  const applications = await cf('/access/apps?per_page=100');
  if (!Array.isArray(applications) || applications.length >= 100) throw Error('Access application listing requires explicit review');
  const hostname = new URL(TARGET.origin).hostname;
  const application = applications.find(a => a.domain === hostname && a.aud === env.CF_STAGING_ACCESS_AUD && a.type === 'self_hosted');
  if (!application || !/^[a-f0-9-]+$/i.test(application.id)) throw Error('Create the exact staging Access application and supply its AUD first');
  const policies = await cf(`/access/apps/${application.id}/policies`);
  if (!Array.isArray(policies) || !policies.some(p => p.decision === 'allow') || policies.some(p => p.decision === 'bypass' || (p.include || []).some(i => Object.hasOwn(i, 'everyone'))))
    throw Error('Access must have an explicit allow policy and no bypass/everyone rule');
  const databases = await cf('/d1/database?per_page=100');
  if (!Array.isArray(databases) || databases.length >= 100) throw Error('Unexpected staging database inventory');
  const existing = databases.find(d => d.name === TARGET.database);
  if (action !== 'check') {
    const workers = await cf('/workers/scripts');
    if (!Array.isArray(workers) || workers.length) throw Error('Initial provisioning requires an empty Worker inventory; inspect partial deployments before retrying');
    if (databases.some(d => d.name !== TARGET.database || d.uuid === TARGET.productionDatabase)) throw Error('Unexpected staging database inventory');
  }
  if (action === 'create-database') {
    if (env.CF_STAGING_D1_DATABASE_ID) throw Error('Creation requires unset database UUID');
    if (existing) throw Error('Staging database already exists; record its UUID rather than creating/replacing it');
    const created = await cf('/d1/database', 'POST', { name: TARGET.database });
    databaseId(created.uuid);
    if (created.name !== TARGET.database) throw Error('Created database name mismatch; inspect inventory before retrying');
    const evidence = { account: TARGET.account, database: TARGET.database, database_id: created.uuid, next: 'Set CF_STAGING_D1_DATABASE_ID in the protected GitHub environment. No migration or deployment was run.' };
    log(JSON.stringify(evidence));
    return evidence;
  } else {
    if (env.CF_STAGING_D1_DATABASE_ID) {
      databaseId(env.CF_STAGING_D1_DATABASE_ID);
      if (!existing || existing.uuid !== env.CF_STAGING_D1_DATABASE_ID) throw Error('Staging database name/UUID ownership mismatch');
    } else if (action === 'deploy') throw Error('Staging D1 UUID is required for deployment');
    if (action === 'deploy') {
      if (!env.CF_STAGING_D1_DATABASE_ID) throw Error('D1 UUID required');
      operation = 'bundle.verify';
      const manifest = JSON.parse(fs.readFileSync(path.join(root, '.build/manifest.json'), 'utf8'));
      const hash = createHash('sha256').update(fs.readFileSync(path.join(root, '.build/api.mjs'))).digest('hex');
      if (manifest.account !== TARGET.account || manifest.api_sha256 !== hash || manifest.providers !== 'blocked' || manifest.commit !== env.GITHUB_SHA) throw Error('Rebuild the reviewed staging bundle');
      operation = 'configuration.validate';
      const configs = writeConfigs(env);
      // Do not inherit generic Cloudflare credentials, shell profiles or local Wrangler env files.
      const childEnv = { PATH: env.PATH, XDG_CONFIG_HOME: path.join(root, '.build/runner-config'), CI: 'true',
        CLOUDFLARE_ACCOUNT_ID: TARGET.account, CLOUDFLARE_API_TOKEN: env.CF_STAGING_API_TOKEN,
        CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV: 'false', WRANGLER_SEND_METRICS: 'false',
        ...(env.HTTPS_PROXY ? { HTTPS_PROXY: env.HTTPS_PROXY } : {}), ...(env.HTTP_PROXY ? { HTTP_PROXY: env.HTTP_PROXY } : {}),
        ...(env.NODE_EXTRA_CA_CERTS ? { NODE_EXTRA_CA_CERTS: env.NODE_EXTRA_CA_CERTS } : {}) };
      fs.mkdirSync(childEnv.XDG_CONFIG_HOME, { recursive: true });
      function wrangler(name, dryRun) {
        operation = `wrangler.${name}.${dryRun ? 'dry_run' : 'deploy'}`;
        const result = runner('npx', ['--yes', 'wrangler@4.156.0', 'deploy', '--config', path.join(root, '.build', name + '.json'), ...(dryRun ? ['--dry-run'] : [])], { cwd: path.join(root, '.build'), env: childEnv, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, timeout: 180000 });
        // Wrangler output can contain provider details. Do not export raw subprocess output.
        if (result.error || result.status !== 0) throw failure(operation, wranglerCategory(result), { exit_code: Number.isInteger(result.status) ? result.status : null });
      }
      async function exposure(name, publicExpected) {
        const actual = await cf(`/workers/scripts/${name}/subdomain`);
        const scheduled = await cf(`/workers/scripts/${name}/schedules`);
        const schedules = Array.isArray(scheduled) ? scheduled : scheduled?.schedules;
        if (actual.enabled !== publicExpected || actual.previews_enabled !== false || !Array.isArray(schedules) || schedules.length) throw Error('Unexpected Worker exposure or schedules');
      }
      function varsMatch(bindings, vars) {
        const plain = bindings.filter(b => b.type === 'plain_text');
        if (plain.length !== Object.keys(vars).length || plain.some(b => vars[b.name] !== b.text)) throw Error('Deployed staging flags/configuration mismatch');
      }
      // Both packages must dry-run before the first upload.
      wrangler('api', true); wrangler('site', true);
      wrangler('api', false);
      const settings = await cf(`/workers/scripts/${TARGET.api}/settings`);
      const bindings = settings.bindings || [];
      const d1 = bindings.filter(b => b.type === 'd1');
      if (d1.length !== 1 || d1[0].name !== 'DB' || d1[0].id !== env.CF_STAGING_D1_DATABASE_ID) throw Error('Deployed API D1 binding mismatch');
      if (bindings.some(b => !['d1', 'ratelimit', 'plain_text'].includes(b.type))) throw Error('Unexpected staging API binding or secret');
      varsMatch(bindings, configs.api.vars);
      const limits = bindings.filter(b => b.type === 'ratelimit');
      if (limits.length !== 1 || limits[0].name !== 'ASSIGNMENT_ACK_RATE_LIMITER' || String(limits[0].namespace_id) !== '24302' || limits[0].simple?.limit !== 60 || limits[0].simple?.period !== 60) throw Error('Rate limiter binding mismatch');
      await exposure(TARGET.api, false);
      // No frontend upload is possible before all API readback checks pass.
      wrangler('site', false);
      const siteSettings = await cf(`/workers/scripts/${TARGET.site}/settings`);
      const siteBindings = siteSettings.bindings || [];
      const services = siteBindings.filter(b => b.type === 'service');
      if (services.length !== 1 || services[0].name !== 'STAGING_API' || services[0].service !== TARGET.api || services[0].environment && services[0].environment !== 'production' || siteBindings.some(b => !['service', 'assets', 'plain_text'].includes(b.type))) throw Error('Frontend service binding mismatch');
      if (siteBindings.filter(b => b.type === 'assets' && b.name === 'ASSETS').length !== 1 || siteSettings.assets?.config?.run_worker_first !== true) throw Error('Frontend assets must pass through Access gate');
      varsMatch(siteBindings, configs.site.vars);
      await exposure(TARGET.site, true);
      const inventory = await cf('/workers/scripts');
      if (!Array.isArray(inventory) || inventory.length !== 2 || ![TARGET.api, TARGET.site].every(name => inventory.some(w => w.id === name))) throw Error('Unexpected post-deployment Worker inventory');
      const deployed = [];
      for (const name of [TARGET.api, TARGET.site]) {
        const latest = (await cf(`/workers/scripts/${name}/deployments`))?.deployments?.[0];
        if (!/^[a-f0-9-]{36}$/i.test(latest?.id || '') || !Array.isArray(latest.versions) || latest.versions.length !== 1 || !/^[a-f0-9-]{36}$/i.test(latest.versions[0].version_id || '') || latest.versions[0].percentage !== 100) throw Error('Unexpected initial Worker deployment metadata');
        deployed.push({ worker: name, deployment_id: latest.id, version_id: latest.versions[0].version_id });
      }
      log('Staging deployment checked. No migrations, fixtures, cron or email delivery were enabled.');
      return { account: TARGET.account, database_id: env.CF_STAGING_D1_DATABASE_ID, workers: deployed, api_sha256: hash, source_sha: manifest.commit, bindings_verified: true, migrations_executed: false, schedules_enabled: false, email_enabled: false };
    } else log('Staging-only credential, subdomain and Access checks passed; no resources changed.');
  }
  } catch (error) { throw failure(operation, 'validation', {}, error); }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) await runCloud(process.argv[2] || 'check');

