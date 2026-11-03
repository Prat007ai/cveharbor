import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';

// Configuration check only: no network, credentials or customer data are logged.
// A separate account-scoped token remains mandatory; IDs alone cannot limit a token.
export function checkStagingBoundary(env) {
  const account = env.STAGING_ACCOUNT_ID;
  const production = env.PRODUCTION_ACCOUNT_ID;
  assert.match(account || '', /^[a-f0-9]{32}$/, 'A staging account ID is required');
  assert.match(production || '', /^[a-f0-9]{32}$/, 'Configure the verified production account ID');
  assert.notEqual(account, production, 'Staging must use a separate Cloudflare account');
  assert.match(env.STAGING_DATABASE_ID || '', /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  assert.notEqual(env.STAGING_DATABASE_ID, '46710e51-7ca4-4571-b89c-921b9969de0b', 'Production database is forbidden');
  assert.match(env.STAGING_DATABASE_NAME || '', /^cveharbor-phase1-staging(?:-[a-z0-9-]+)?$/);
  assert.equal(env.STAGING_DISPOSABLE, 'true', 'Explicit disposable staging opt-in required');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { checkStagingBoundary(process.env); console.log('Separate-account staging configuration verified; token scope must be verified by an administrator.'); }
  catch { console.error('Staging configuration rejected. Verify separate account, disposable database UUID/name and opt-in; no Cloudflare request was made.'); process.exitCode = 1; }
}
