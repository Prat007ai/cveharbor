import test from 'node:test';
import assert from 'node:assert/strict';
import { dryRun } from '../scripts/dry-run.mjs';
import { safeFailure } from '../scripts/errors.mjs';
import { TARGET } from '../target.mjs';
test('packaging always dry-runs both packages and forwards no cloud or application credential', () => {
  const calls = [];
  const result = dryRun({ PATH: '/synthetic', CLOUDFLARE_API_TOKEN: 'production-secret', CF_STAGING_API_TOKEN: 'staging-secret', NODE_OPTIONS: '--require attacker.js' }, (command, args, options) => {
    calls.push(args); assert.equal(command, 'npx'); assert.ok(args.includes('--dry-run'));
    assert.equal(options.env.CLOUDFLARE_ACCOUNT_ID, TARGET.account);
    assert.equal(options.env.CLOUDFLARE_API_TOKEN, undefined); assert.equal(options.env.CF_STAGING_API_TOKEN, undefined); assert.equal(options.env.NODE_OPTIONS, undefined);
    return { status: 0 };
  });
  assert.equal(calls.length, 2); assert.equal(result.uploads, 0); assert.equal(result.credential_free, true);
});
test('failed dry-run stops before second command and exports only a sanitized operation/category', () => {
  let calls = 0;
  assert.throws(() => dryRun({}, () => { calls++; return { status: 1, stderr: 'Build failed secret-token' }; }), error => {
    const report = safeFailure(error); assert.equal(report.operation, 'wrangler.api.dry_run'); assert.equal(report.category, 'build'); assert.doesNotMatch(JSON.stringify(report), /secret-token/); return true;
  });
  assert.equal(calls, 1);
});
