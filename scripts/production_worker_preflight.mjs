// Run from the repository root immediately before Wrangler uploads the accounts Worker.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {d1Client} from './cloudflare_d1.mjs';
import {forwardMigrations} from './release_migrations.mjs';
import {verifyNativeHistory} from '../staging/scripts/simple-release.mjs';
import {integrityGuards, releaseReadiness} from '../account-backend/src/release-readiness.js';

const target = JSON.parse(fs.readFileSync(new URL('../deployment/proposals/production-compatibility/procedure/target.json', import.meta.url)));

export function verifyTarget(account, config) {
  assert.ok(account === target.account && (config.account_id ?? account) === account, 'Wrong production account');
  assert.ok(config.name === target.worker, 'Wrong production Worker');
  assert.ok(config.vars?.RECOVERY_CONTROL_REQUIRED === 'true', 'Worker must require recovery controls');
  const bindings = config.d1_databases;
  assert.ok(bindings?.length === 1 && bindings[0].binding === 'DB' &&
    bindings[0].database_id === target.database && bindings[0].database_name === target.database_name,
    'Candidate DB binding must point to the production accounts database');
}

export async function verifySchema(DB, {recovery = false, migrations = forwardMigrations()} = {}) {
  const {results} = await DB.prepare("SELECT type,name FROM sqlite_schema WHERE type IN ('table','trigger')").all();
  const objects = new Set(results.map(({type, name}) => type + ':' + name));
  for (const name of ['operations_control', 'operations_leases', 'operations_events', 'remediation_finding_write_context']) {
    assert.ok(objects.has('table:' + name), 'Missing required production table: ' + name);
  }
  for (const name of ['operations_control_history', ...integrityGuards]) {
    assert.ok(objects.has('trigger:' + name), 'Missing required production trigger: ' + name);
  }
  const controls = await DB.prepare('SELECT write_hold,database_frozen,revision FROM operations_control WHERE id=1').first();
  const flag = recovery ? 1 : 0;
  assert.ok(controls && controls.write_hold === flag && controls.database_frozen === flag &&
    Number.isSafeInteger(controls.revision) && controls.revision >= 0, 'Recovery control row missing, held or inconsistent with the release mode');
  if (recovery) {
    assert.equal((await DB.prepare('SELECT COUNT(*) n FROM operations_leases').first()).n, 0, 'Recovery release requires drained leases');
  }
  const pending = await verifyNativeHistory(DB, migrations);
  if (pending.length) assert.fail('Required production migration receipt missing: ' + pending[0].name);

  // Execute the candidate's actual runtime reads and integrity/guard coverage logic on live D1.
  const response = await releaseReadiness({DB, RECOVERY_CONTROL_REQUIRED: 'true'});
  const state = await response.json();
  assert.ok(response.status === (recovery ? 503 : 200) && state.schema_ready === true &&
    state.held === recovery && state.ready === !recovery, 'Candidate readiness failed on production D1: check recovery guards, integrity and runtime queries');
}

export async function preflight(env, config, fetcher = fetch) {
  verifyTarget(env.CLOUDFLARE_ACCOUNT_ID, config);
  const DB = d1Client({database: target.database, readOnly: true, env, fetcher});
  const meta = await DB.metadata();
  assert.ok(meta?.uuid === target.database && meta.name === target.database_name, 'Live D1 identity mismatch');
  const response = await fetcher('https://api.cloudflare.com/client/v4/accounts/' + target.account +
    '/workers/scripts/' + target.worker + '/settings', {
    headers: {Authorization: 'Bearer ' + env.CLOUDFLARE_API_TOKEN}, redirect: 'error', signal: AbortSignal.timeout(15000)
  });
  assert.ok(response.ok, 'Could not verify live Worker settings');
  const settings = await response.json();
  const bindings = settings.result?.bindings?.filter(b => b.type === 'd1');
  assert.ok(settings.success && bindings?.length === 1 && bindings[0].name === 'DB' && bindings[0].id === target.database,
    'Live Worker DB binding mismatch');
  await verifySchema(DB, {recovery: env.RECOVERY_RELEASE === 'true'});
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const config = JSON.parse(execFileSync('python3', ['-c',
      'import json,tomllib; print(json.dumps(tomllib.load(open("account-backend/wrangler.toml","rb"))))',
    ], {encoding: 'utf8'}));
    await preflight(process.env, config);
    console.log('Production account Worker passed the read-only D1 compatibility check.');
  } catch (error) {
    console.error('Production upload blocked:', error instanceof assert.AssertionError ? error.message : 'Compatibility evidence unavailable');
    process.exitCode = 1;
  }
}
