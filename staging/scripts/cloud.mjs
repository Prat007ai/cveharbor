// No default mutation. This tool has no production-account selection option.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { TARGET, accessSettings, databaseId } from '../target.mjs';
import { root, writeConfigs } from './configure.mjs';

export async function runCloud(action = 'check', env = process.env, fetcher = fetch, log = console.log) {
  if (!['check', 'create-database', 'deploy'].includes(action)) throw Error('Use check, create-database or deploy. No SQL execution is exposed.');
  if (env.CF_STAGING_ACCOUNT_ID !== TARGET.account || !env.CF_STAGING_API_TOKEN) throw Error('Dedicated staging account/token required');
  accessSettings(env.CF_STAGING_ACCESS_ISSUER, env.CF_STAGING_ACCESS_AUD);
  if (action !== 'check' && env.STAGING_CHANGE_APPROVED !== 'PR243-STAGING-ONLY') throw Error('Resource changes are gated until credentials and execution are approved.');
  const apiBase = `https://api.cloudflare.com/client/v4/accounts/${TARGET.account}`;
  async function cf(route, method = 'GET', body) {
    // Only fixed account-relative paths constructed below are accepted.
    if (!route.startsWith('/') || route.includes('..') || route.includes('://')) throw Error('Invalid staging management path');
    const response = await fetcher(apiBase + route, { method, redirect: 'error', signal: AbortSignal.timeout(30000),
      headers: { Authorization: 'Bearer ' + env.CF_STAGING_API_TOKEN, 'Content-Type': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}) });
    const result = await response.json();
    // Never print API response bodies, tokens, policy members or provider errors.
    if (!response.ok || result.success !== true) throw Error(`Staging management ${method} failed (${response.status}); inspect permissions securely.`);
    return result.result;
  }
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
  if (action === 'create-database') {
    if (existing) throw Error('Staging database already exists; record its UUID rather than creating/replacing it');
    const created = await cf('/d1/database', 'POST', { name: TARGET.database });
    databaseId(created.uuid);
    log(JSON.stringify({ account: TARGET.account, database: TARGET.database, database_id: created.uuid, next: 'Set CF_STAGING_D1_DATABASE_ID in the protected GitHub environment. No migration or deployment was run.' }));
  } else {
    if (env.CF_STAGING_D1_DATABASE_ID) {
      databaseId(env.CF_STAGING_D1_DATABASE_ID);
      if (!existing || existing.uuid !== env.CF_STAGING_D1_DATABASE_ID) throw Error('Staging database name/UUID ownership mismatch');
    } else if (action === 'deploy') throw Error('Staging D1 UUID is required for deployment');
    if (action === 'deploy') {
      if (!env.CF_STAGING_D1_DATABASE_ID) throw Error('D1 UUID required');
      const manifest = JSON.parse(fs.readFileSync(path.join(root, '.build/manifest.json'), 'utf8'));
      const hash = createHash('sha256').update(fs.readFileSync(path.join(root, '.build/api.mjs'))).digest('hex');
      if (manifest.account !== TARGET.account || manifest.api_sha256 !== hash || manifest.providers !== 'blocked') throw Error('Rebuild the reviewed staging bundle');
      writeConfigs(env);
      // Do not inherit generic Cloudflare credentials, shell profiles or local Wrangler env files.
      const childEnv = { PATH: env.PATH, XDG_CONFIG_HOME: path.join(root, '.build/runner-config'), CI: 'true',
        CLOUDFLARE_ACCOUNT_ID: TARGET.account, CLOUDFLARE_API_TOKEN: env.CF_STAGING_API_TOKEN,
        CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV: 'false', WRANGLER_SEND_METRICS: 'false',
        ...(env.HTTPS_PROXY ? { HTTPS_PROXY: env.HTTPS_PROXY } : {}), ...(env.HTTP_PROXY ? { HTTP_PROXY: env.HTTP_PROXY } : {}),
        ...(env.NODE_EXTRA_CA_CERTS ? { NODE_EXTRA_CA_CERTS: env.NODE_EXTRA_CA_CERTS } : {}) };
      fs.mkdirSync(childEnv.XDG_CONFIG_HOME, { recursive: true });
      for (const name of ['api', 'site']) {
        const result = spawnSync('npx', ['--yes', 'wrangler@4.156.0', 'deploy', '--config', path.join(root, '.build', name + '.json')], { cwd: path.join(root, '.build'), env: childEnv, stdio: 'inherit' });
        if (result.error || result.status !== 0) throw Error(`Staging ${name} deployment failed; stop before proceeding`);
      }
      const settings = await cf(`/workers/scripts/${TARGET.api}/settings`);
      const bindings = settings.bindings || [];
      const d1 = bindings.filter(b => b.type === 'd1');
      if (d1.length !== 1 || d1[0].name !== 'DB' || d1[0].id !== env.CF_STAGING_D1_DATABASE_ID) throw Error('Deployed API D1 binding mismatch');
      if (bindings.some(b => b.type === 'secret_text' && b.name !== 'TOTP_ENCRYPTION_KEY')) throw Error('Unexpected staging API runtime secret');
      const apiExposure = await cf(`/workers/scripts/${TARGET.api}/subdomain`);
      const schedules = await cf(`/workers/scripts/${TARGET.api}/schedules`);
      if (apiExposure.enabled || apiExposure.previews_enabled || (schedules.schedules || schedules || []).length) throw Error('Unexpected staging API public exposure or schedule');
      const siteSettings = await cf(`/workers/scripts/${TARGET.site}/settings`);
      const services = (siteSettings.bindings || []).filter(b => b.type === 'service');
      if (services.length !== 1 || services[0].name !== 'STAGING_API' || services[0].service !== TARGET.api || (siteSettings.bindings || []).some(b => b.type === 'd1')) throw Error('Frontend service binding mismatch');
      log('Staging deployment checked. No migrations, fixtures, cron or email delivery were enabled.');
    } else log('Staging-only credential, subdomain and Access checks passed; no resources changed.');
  }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) await runCloud(process.argv[2] || 'check');
