// Credential-free packaging validation only. This entrypoint cannot upload.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { TARGET } from '../target.mjs';
import { root, writeConfigs } from './configure.mjs';
import { failure, safeFailure, wranglerCategory } from './errors.mjs';

export function dryRun(env = process.env, runner = spawnSync) {
  writeConfigs({ CF_STAGING_ACCOUNT_ID: TARGET.account, CF_STAGING_D1_DATABASE_ID: 'fac61562-fc31-426d-8032-550aba63b7f6',
    CF_STAGING_APPLICATION_PROFILE:fs.existsSync(path.join(root,'.build/manifest.json'))&&JSON.parse(fs.readFileSync(path.join(root,'.build/manifest.json'))).application_profile==='production-baseline'?'production-baseline':undefined,
    CF_STAGING_ACCESS_ISSUER: 'https://synthetic-staging.cloudflareaccess.com', CF_STAGING_ACCESS_AUD: 'a'.repeat(64) });
  // Same isolated subprocess setup as provisioning, but without any token.
  const childEnv = { PATH: env.PATH, XDG_CONFIG_HOME: path.join(root, '.build/dry-run-config'), CI: 'true',
    CLOUDFLARE_ACCOUNT_ID: TARGET.account, CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV: 'false', WRANGLER_SEND_METRICS: 'false',
    ...(env.HTTPS_PROXY ? { HTTPS_PROXY: env.HTTPS_PROXY } : {}), ...(env.HTTP_PROXY ? { HTTP_PROXY: env.HTTP_PROXY } : {}),
    ...(env.NODE_EXTRA_CA_CERTS ? { NODE_EXTRA_CA_CERTS: env.NODE_EXTRA_CA_CERTS } : {}) };
  fs.mkdirSync(childEnv.XDG_CONFIG_HOME, { recursive: true });
  const report = { account: TARGET.account, credential_free: true, uploads: 0, packages: [] };
  for (const name of ['api', 'site']) {
    const operation = `wrangler.${name}.dry_run`;
    const result = runner('npx', ['--yes', 'wrangler@4.156.0', 'deploy', '--config', path.join(root, '.build', name + '.json'), '--dry-run'],
      { cwd: path.join(root, '.build'), env: childEnv, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, timeout: 180000 });
    if (result.error || result.status !== 0) throw failure(operation, wranglerCategory(result), { exit_code: Number.isInteger(result.status) ? result.status : null });
    report.packages.push({ worker: name, passed: true });
  }
  return report;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  let report;
  try { report = dryRun(); console.log('Both credential-free Wrangler dry runs passed; no uploads.'); }
  catch (error) { report = { passed: false, credential_free: true, uploads: 0, ...safeFailure(error) }; console.error(JSON.stringify(report)); process.exitCode = 1; }
  fs.mkdirSync(path.join(root, 'artifacts'), { recursive: true });
  fs.writeFileSync(path.join(root, 'artifacts/dry-run.json'), JSON.stringify(report, null, 2) + '\n');
}

