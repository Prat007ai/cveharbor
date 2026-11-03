import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { root } from './configure.mjs';
import {FullDB} from '../tests/helpers/full-db.mjs';
import { TARGET } from '../target.mjs';
const nativeFetch = globalThis.fetch;
let outbound = 0, scheduledWrites = 0;
globalThis.fetch = async () => { outbound++; throw Error('Unexpected network request'); };
try {
  const { default: api } = await import(pathToFileURL(path.join(root, '.build/api.mjs')));
  const db = { prepare() { scheduledWrites++; throw Error('No query expected'); } };
  const env = { STAGING_MODE: 'true', DB: db, SMTP2GO_API_KEY: 'must-not-be-used', EMAIL_FROM: 'fixture@example.test', ALERT_DELIVERY_ENABLED: 'true' };
  await api.scheduled({ cron: '* * * * *' }, env, { waitUntil() { assert.fail('Scheduled work queued'); } });
  assert.equal(scheduledWrites, 0);
  const login = await api.fetch(new Request(TARGET.origin + '/v1/auth/request', { method: 'POST', headers: { Origin: TARGET.origin, 'Content-Type': 'application/json' }, body: '{"email":"fixture@example.test"}' }), env, {});
  assert.equal(login.status, 503);
  // Public CVE lookup normally fetches external data; the built code must fail without global fetch.
  await api.fetch(new Request(TARGET.origin + '/v1/cve/CVE-2099-99999'), env, { waitUntil() {} });
  assert.equal(outbound, 0);
  const invalid = await api.fetch(new Request('https://api.cveharbor.com/v1/health'), env, {});
  assert.equal(invalid.status, 403);
  const full=new FullDB();try{
   const unauthorized = await api.fetch(new Request(TARGET.origin + '/v1/me'), {...env,DB:full}, {});
   assert.equal(unauthorized.status, 401);
  }finally{full.close();}
} finally { globalThis.fetch = nativeFetch; }
const files = fs.readdirSync(path.join(root, '.build/public'), { recursive: true }).filter(n => /\.(?:js|json|html)$/.test(n));
for (const name of files) {
  const text = fs.readFileSync(path.join(root, '.build/public', name), 'utf8');
  assert.doesNotMatch(text, /https:\/\/(?:api\.|confirm\.|www\.)?cveharbor\.com/, name);
}
console.log('Built Worker: no outbound calls, mail unavailable, scheduled work disabled, account authentication retained. Synthetic frontend has no production origins.');

