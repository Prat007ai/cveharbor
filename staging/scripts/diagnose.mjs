// Protected, GET-only inventory. No SQL, Wrangler, resource writes or retries.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TARGET, databaseId } from '../target.mjs';
import { root, configs } from './configure.mjs';
import { failure, safeFailure } from './errors.mjs';
import { readAssetGate } from './asset-gate.mjs';

export async function diagnose(env, transport = fetch, record = () => {}) {
  if (env.CF_STAGING_ACCOUNT_ID !== TARGET.account || !env.CF_STAGING_API_TOKEN) throw failure('diagnostics.authorize', 'configuration');
  const id = databaseId(env.CF_STAGING_D1_DATABASE_ID);
  const expected = configs(env);
  const report = { account: TARGET.account, checked_at: new Date().toISOString(), mutation_requests: 0, production_requests: 0, requests: [], workers: [] };
  record(report);
  async function get(route) {
    const operation = `diagnostics.GET.${route}`;
    let response;
    try { response = await transport(`https://api.cloudflare.com/client/v4/accounts/${TARGET.account}${route}`, {
      method: 'GET', redirect: 'error', signal: AbortSignal.timeout(30000), headers: { Authorization: 'Bearer ' + env.CF_STAGING_API_TOKEN },
    }); } catch { throw failure(operation, 'network'); }
    report.requests.push({ operation, http_status: response.status }); record(report);
    let body;
    try { body = await response.json(); } catch { throw failure(operation, 'invalid_json', { http_status: response.status }); }
    if (!response.ok || body?.success !== true) throw failure(operation, response.status === 403 || response.status === 401 ? 'authorization' : 'cloudflare_api', { http_status: response.status });
    return body.result;
  }
  try {
    if ((await get(''))?.id !== TARGET.account) throw failure('diagnostics.identity', 'validation');
    const dbs = await get('/d1/database?per_page=100');
    if (!Array.isArray(dbs) || dbs.length >= 100) throw failure('diagnostics.database_inventory', 'validation');
    report.database = { name: TARGET.database, id, present: dbs.some(d => d.name === TARGET.database && d.uuid === id), unexpected_count: dbs.filter(d => d.name !== TARGET.database || d.uuid !== id).length };
    if (report.database.present) {
      const db = await get(`/d1/database/${id}`);
      report.database.metadata_identity_matches = db?.uuid === id && db?.name === TARGET.database;
      report.database.num_tables = Number.isInteger(db?.num_tables) ? db.num_tables : null;
      report.database.file_size = Number.isFinite(db?.file_size) ? db.file_size : null;
    }
    const rows = await get('/workers/scripts');
    if (!Array.isArray(rows)) throw failure('diagnostics.worker_inventory', 'validation');
    report.unexpected_worker_count = rows.filter(w => ![TARGET.api, TARGET.site].includes(w.id)).length;
    for (const [name, config] of [[TARGET.api, expected.api], [TARGET.site, expected.site]]) {
      const worker = { name, present: rows.some(w => w.id === name) }; report.workers.push(worker); record(report);
      if (!worker.present) continue;
      const settings = await get(`/workers/scripts/${name}/settings`);
      const bindings = settings?.bindings || [];
      if (!Array.isArray(bindings)) throw failure('diagnostics.bindings', 'validation');
      const plain = bindings.filter(b => b.type === 'plain_text');
      worker.variables_match = plain.length === Object.keys(config.vars).length && plain.every(b => config.vars[b.name] === b.text);
      worker.unexpected_binding_count = bindings.filter(b => !(name === TARGET.api ? ['d1', 'ratelimit', 'plain_text'] : ['service', 'assets', 'plain_text']).includes(b.type)).length;
      if (name === TARGET.api) {
        const db = bindings.filter(b => b.type === 'd1'), limits = bindings.filter(b => b.type === 'ratelimit');
        worker.d1_binding_matches = db.length === 1 && db[0].name === 'DB' && db[0].id === id;
        worker.rate_limit_matches = limits.length === 1 && limits[0].name === 'ASSIGNMENT_ACK_RATE_LIMITER' && String(limits[0].namespace_id) === '24302' && limits[0].simple?.limit === 60 && limits[0].simple?.period === 60;
      } else {
        const services = bindings.filter(b => b.type === 'service');
        worker.service_binding_matches = services.length === 1 && services[0].name === 'STAGING_API' && services[0].service === TARGET.api && (!services[0].environment || services[0].environment === 'production');
        Object.assign(worker, await readAssetGate(settings, get));
      }
      const exposure = await get(`/workers/scripts/${name}/subdomain`);
      worker.exposure_matches = exposure?.enabled === (name === TARGET.site) && exposure?.previews_enabled === false;
      const scheduled = await get(`/workers/scripts/${name}/schedules`);
      const schedules = Array.isArray(scheduled) ? scheduled : scheduled?.schedules;
      worker.schedules_disabled = Array.isArray(schedules) && schedules.length === 0;
      const deployments = await get(`/workers/scripts/${name}/deployments`);
      worker.deployment_present = Array.isArray(deployments?.deployments) && deployments.deployments.length > 0;
    }
    report.completed = true;
    report.verified = report.database.present && report.database.metadata_identity_matches && report.database.unexpected_count === 0 && report.unexpected_worker_count === 0 && report.workers.every(w => w.present && w.variables_match && w.unexpected_binding_count === 0 && w.exposure_matches && w.schedules_disabled && w.deployment_present && (w.name === TARGET.api ? w.d1_binding_matches && w.rate_limit_matches : w.service_binding_matches && w.assets_gate_matches === true));
    record(report); return report;
  } catch (error) { report.failure = safeFailure(error); record(report); throw error; }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const record = report => { fs.mkdirSync(path.join(root, 'artifacts'), { recursive: true }); fs.writeFileSync(path.join(root, 'artifacts/diagnostics.json'), JSON.stringify(report, null, 2) + '\n'); };
  try { const report = await diagnose(process.env, fetch, record); console.log('GET-only staging inventory recorded; no SQL or resource changes.'); if (!report.verified) process.exitCode = 1; }
  catch (error) { console.error(JSON.stringify(safeFailure(error))); process.exitCode = 1; }
}
