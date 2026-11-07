import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {backendIdentity} from './build_release_identity.mjs';

export async function verifyService({fetcher = fetch, expectedRelease, recovery = false, readinessOnly = false} = {}) {
  const get = path => fetcher('https://api.cveharbor.com/v1/' + path, {
    headers: {'Cache-Control': 'no-cache'}, redirect: 'error', signal: AbortSignal.timeout(15000)
  });
  const response = await get('release-readiness');
  const state = await response.json();
  assert.ok(state.schema_ready === true, 'Production schema/readiness query failed. Check D1 compatibility.');
  if (expectedRelease) assert.ok(state.release === expectedRelease, 'Production is serving a different Worker build');
  if (recovery) {
    assert.ok(response.status === 503 && state.held === true && state.ready === false, 'Expected a verified maintenance hold');
    return;
  }
  assert.ok(state.held === false, 'Production reports an active maintenance hold with a ready schema');
  assert.ok(response.status === 200 && state.ready === true, 'Production readiness failed');
  if (readinessOnly) return;
  const health = await get('health');
  assert.ok(health.status === 200 && (await health.json()).accounts === 'configured', 'Production account health failed');
  assert.equal((await get('me')).status, 401, 'Anonymous account endpoint must return 401');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const monitoring = process.argv.includes('--monitor');
  try {
    await verifyService({readinessOnly: monitoring, expectedRelease: monitoring ? undefined : backendIdentity(),
      recovery: !monitoring && process.env.RECOVERY_RELEASE === 'true'});
    console.log('Production service checks passed.');
  } catch (error) {
    console.error(error instanceof assert.AssertionError ? error.message : 'Production readiness response unavailable');
    process.exitCode = 1;
  }
}
