import assert from 'node:assert/strict';
import fs from 'node:fs';
import {d1Client} from './cloudflare_d1.mjs';
import {PRODUCTION_DB} from './production_schema_baseline.mjs';
import {holdStatus} from './recovery_control.mjs';
import {verifyIntegrity, integrityChecks} from './verify_remediation_integrity_d1.mjs';

const prior = fs.readFileSync('release/customer-investigation/backend-identity.txt','utf8').trim();
const response = await fetch('https://api.cveharbor.com/v1/release-readiness', {cache:'no-store',redirect:'error', signal:AbortSignal.timeout(15000)});
const state = await response.json();
assert.equal(state.release,prior);
assert.equal(state.held,false);
assert.equal(state.schema,'phase1-integrity-recovery-v1');
assert.equal(process.env.CLOUDFLARE_ACCOUNT_ID,'aa99b9b15e0492302e4f6484b8d27bc2');
const db = d1Client({database:PRODUCTION_DB,readOnly:true});
assert.equal((await db.metadata()).uuid,PRODUCTION_DB);
const hold = await holdStatus(db);
assert.equal(hold.guards_complete,true);
assert.equal(hold.write_hold,0);
assert.equal(hold.database_frozen,0);
const checks = await verifyIntegrity(db);
console.log(JSON.stringify(checks));
assert.equal(checks.ok,true);
assert.equal((await db.prepare('SELECT count(*) n FROM pragma_foreign_key_check').first()).n,0);
if (response.status === 503) {
  // Only the legacy classification of valid, customer-owned records may differ.
  assert.equal(state.ready,false);
  assert.equal(state.schema_ready,false);
  assert.ok(Object.hasOwn(checks.counts,'invalid_remediation_customer_scopes'));
  const legacy = (await db.prepare(integrityChecks.detached_asset_records).first()).n;
  assert.ok(legacy > 0,'The legacy readiness failure has a different cause');
  console.log('Confirmed the legacy check classified valid scoped assignments as detached:',legacy);
} else {
  assert.equal(response.status,200);
  assert.equal(state.schema_ready,true);
  assert.equal(state.ready,true);
}
