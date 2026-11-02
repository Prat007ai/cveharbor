import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TARGET, databaseId, accessSettings } from '../target.mjs';
export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = name => JSON.parse(fs.readFileSync(path.join(root, name), 'utf8'));
export function configs(env) {
  if (env.CF_STAGING_ACCOUNT_ID !== TARGET.account) throw Error('Staging account mismatch');
  const api = read('wrangler.api.json'), site = read('wrangler.site.json');
  api.d1_databases[0].database_id = databaseId(env.CF_STAGING_D1_DATABASE_ID);
  site.vars = accessSettings(env.CF_STAGING_ACCESS_ISSUER, env.CF_STAGING_ACCESS_AUD);
  api.main = path.join(root, '.build/api.mjs');
  api.d1_databases[0].migrations_dir = path.resolve(root, '../account-backend/migrations');
  site.main = path.join(root, 'frontend.mjs');
  site.assets.directory = path.join(root, '.build/public');
  validate(api, site);
  return { api, site };
}
export function validate(api, site) {
  const commonKeys = ['$schema', 'name', 'account_id', 'main', 'compatibility_date', 'workers_dev', 'preview_urls', 'keep_vars', 'routes', 'triggers', 'vars'];
  if (Object.keys(api).some(k => ![...commonKeys, 'd1_databases', 'ratelimits'].includes(k)) || Object.keys(site).some(k => ![...commonKeys, 'assets', 'services'].includes(k))) throw Error('Unreviewed configuration keys or bindings');
  for (const [config, name] of [[api, TARGET.api], [site, TARGET.site]]) {
    if (config.name !== name || config.account_id !== TARGET.account || config.compatibility_date !== TARGET.compatibility || config.keep_vars !== false || config.preview_urls !== false)
      throw Error('Unexpected staging deployment identity or defaults');
    if (config.routes?.length || config.triggers?.crons?.length || config.env || config.queues || config.kv_namespaces || config.durable_objects || config.r2_buckets || config.hyperdrive || config.workflows || config.send_email)
      throw Error('Unexpected staging routes, schedules or infrastructure');
  }
  if (api.workers_dev !== false || site.workers_dev !== true || api.services || site.d1_databases) throw Error('Invalid staging exposure or bindings');
  if (api.main !== path.join(root, '.build/api.mjs') || site.main !== path.join(root, 'frontend.mjs') || site.assets.directory !== path.join(root, '.build/public')) throw Error('Invalid build path');
  if (api.d1_databases?.length !== 1 || api.d1_databases[0].binding !== 'DB' || api.d1_databases[0].database_name !== TARGET.database) throw Error('Unexpected D1 binding');
  databaseId(api.d1_databases[0].database_id);
  if (JSON.stringify(site.services) !== JSON.stringify([{ binding: 'STAGING_API', service: TARGET.api }]) || site.assets.binding !== 'ASSETS' || site.assets.run_worker_first !== true) throw Error('Access gate can be bypassed');
  accessSettings(site.vars.ACCESS_ISSUER, site.vars.ACCESS_AUD);
  if (Object.keys(site.vars).some(k => !['ACCESS_ISSUER', 'ACCESS_AUD'].includes(k))) throw Error('Unreviewed frontend variables');
  const expected = read('wrangler.api.json').vars;
  if (JSON.stringify(api.vars) !== JSON.stringify(expected)) throw Error('Initial staging flags must match the reviewed disabled configuration');
  if (JSON.stringify(api.ratelimits) !== JSON.stringify(read('wrangler.api.json').ratelimits)) throw Error('Unexpected rate limit binding');
}
export function writeConfigs(env) {
  const output = configs(env);
  fs.mkdirSync(path.join(root, '.build'), { recursive: true });
  for (const [name, config] of Object.entries(output)) fs.writeFileSync(path.join(root, '.build', name + '.json'), JSON.stringify(config, null, 2) + '\n');
  return output;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  writeConfigs(process.env);
  console.log('Validated staging-only configuration written; no cloud requests made.');
}
