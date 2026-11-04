import test from 'node:test';
import assert from 'node:assert/strict';
import {checkStagingBoundary} from './check_phase1_staging_boundary.mjs';
const valid = {STAGING_ACCOUNT_ID:'a'.repeat(32), PRODUCTION_ACCOUNT_ID:'b'.repeat(32), STAGING_DATABASE_ID:'11111111-1111-4111-8111-111111111111', STAGING_DATABASE_NAME:'cveharbor-phase1-staging', STAGING_DISPOSABLE:'true'};
test('accepts only a distinct explicitly disposable target', () => assert.doesNotThrow(() => checkStagingBoundary(valid)));
for (const [name, patch] of Object.entries({same_account:{STAGING_ACCOUNT_ID:valid.PRODUCTION_ACCOUNT_ID}, missing_production_identity:{PRODUCTION_ACCOUNT_ID:''}, malformed_account:{STAGING_ACCOUNT_ID:'invalid'}, production_database:{STAGING_DATABASE_ID:'46710e51-7ca4-4571-b89c-921b9969de0b'}, wrong_name:{STAGING_DATABASE_NAME:'cveharbor-accounts'}, not_disposable:{STAGING_DISPOSABLE:'false'}})) {
  test('rejects ' + name, () => assert.throws(() => checkStagingBoundary({...valid, ...patch})));
}
