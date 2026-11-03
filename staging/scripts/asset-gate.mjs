// /scripts/:name/settings exposes bindings, but does not contractually expose
// assets.config. Read assets from the currently serving Version instead:
// https://developers.cloudflare.com/api/resources/workers/subresources/beta/subresources/workers/subresources/versions/methods/get/
import { TARGET } from '../target.mjs';
import { safeFailure } from './errors.mjs';
const uuid = value => /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value || '');
export function routingEvidence(config) {
  const value = config?.run_worker_first;
  const kind = value === undefined ? 'missing' : Array.isArray(value) ? 'route_array' : typeof value;
  const global = value === true || (Array.isArray(value) && value.length > 0 && value.every(v => v === '/*'));
  const explicit = typeof value === 'boolean' || (Array.isArray(value) && value.every(v => typeof v === 'string'));
  return { shape: kind, global_worker_first: explicit ? global : null,
    rule_count: Array.isArray(value) ? value.length : null, has_exclusions: Array.isArray(value) && value.some(v => typeof v === 'string' && v.startsWith('!')) };
}
export async function readAssetGate(settings, get, name = TARGET.site) {
  if (name !== TARGET.site) throw Error('Only the fixed staging frontend may be inspected');
  const bindings = Array.isArray(settings?.bindings) ? settings.bindings : [];
  const binding = bindings.filter(b => b.type === 'assets');
  const report = { assets_binding_matches: binding.length === 1 && binding[0].name === 'ASSETS',
    settings_assets_config_present: !!settings?.assets?.config, assets_gate_status: 'unverified', assets_gate_matches: null };
  try {
    const latest = (await get(`/workers/scripts/${name}/deployments`))?.deployments?.[0];
    if (!uuid(latest?.id) || latest.versions?.length !== 1 || !uuid(latest.versions[0]?.version_id) || latest.versions[0].percentage !== 100) {
      return { ...report, reason: 'active_deployment_not_single_full_version' };
    }
    const id = latest.versions[0].version_id;
    // Worker identifier can be name; modules are omitted so code/secrets aren't exported.
    const version = await get(`/workers/workers/${name}/versions/${id}`);
    if (version?.id !== id) return { ...report, reason: 'active_version_identity_mismatch' };
    report.asset_routing = routingEvidence(version?.assets?.config);
    report.active_deployment_id = latest.id; report.active_version_id = id;
    if (report.asset_routing.global_worker_first === null) return { ...report, reason: 'active_version_asset_routing_unavailable' };
    report.assets_gate_matches = report.assets_binding_matches && report.asset_routing.global_worker_first;
    report.assets_gate_status = report.assets_gate_matches ? 'pass' : 'fail';
    return report;
  } catch (error) { return { ...report, reason: 'active_version_metadata_read_failed', failure: safeFailure(error) }; }
}
