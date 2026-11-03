import test from 'node:test';
import assert from 'node:assert/strict';
import { readAssetGate, routingEvidence } from '../scripts/asset-gate.mjs';
import { TARGET } from '../target.mjs';
const id = '11111111-2222-4333-8444-555555555555';
const settings = { bindings: [{ type: 'assets', name: 'ASSETS' }] }; // real /settings contract has no assets.config
const get = (value, patch = {}) => async route => {
  if (route === `/workers/scripts/${TARGET.site}/deployments`) return { deployments: [{ id, versions: [{ version_id: id, percentage: 100 }] }] };
  assert.equal(route, `/workers/workers/${TARGET.site}/versions/${id}`);
  return { id, assets: { config: { run_worker_first: value } }, ...patch };
};
test('asset routing comes from the serving version, not the upload metadata assumed on /settings', async () => {
  for (const value of [true, ['/*']]) {
    const report = await readAssetGate(settings, get(value));
    assert.equal(report.assets_gate_matches, true); assert.equal(report.assets_gate_status, 'pass');
    assert.equal(report.settings_assets_config_present, false);
  }
  const contradicted = await readAssetGate({ ...settings, assets: { config: { run_worker_first: true } } }, get(false));
  assert.equal(contradicted.assets_gate_status, 'fail');
});
test('partial routes, exclusions, missing metadata and wrong bindings never validate all assets', async () => {
  for (const value of [false, [], ['/v1/*'], ['/*', '!/assets/*'], ['/*', '!/styles.css']]) {
    const report = await readAssetGate(settings, get(value)); assert.equal(report.assets_gate_status, 'fail');
  }
  for (const value of [undefined, null, 'true', { arbitrary: true }]) assert.equal(routingEvidence({ run_worker_first: value }).global_worker_first, null);
  const missing = await readAssetGate(settings, get(undefined)); assert.equal(missing.assets_gate_status, 'unverified'); assert.equal(missing.assets_gate_matches, null);
  assert.equal((await readAssetGate({ bindings: [] }, get(true))).assets_gate_status, 'fail');
  assert.equal((await readAssetGate(settings, get(true, { id: 'other' }))).assets_gate_status, 'unverified');
});
test('only an identified single 100% serving version is accepted; provider errors stay redacted', async () => {
  for (const latest of [{}, { id, versions: [{ version_id: id, percentage: 50 }] }, { id, versions: [{ version_id: 'bad', percentage: 100 }] }]) {
    assert.equal((await readAssetGate(settings, async () => ({ deployments: [latest] }))).assets_gate_status, 'unverified');
  }
  const error = await readAssetGate(settings, async () => { throw Error('secret-token raw provider body'); });
  assert.equal(error.assets_gate_status, 'unverified'); assert.doesNotMatch(JSON.stringify(error), /secret-token|provider body/);
});
