import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import {verifyService} from './production_service_health.mjs';
const target=JSON.parse(fs.readFileSync('deployment/proposals/production-compatibility/procedure/target.json'));
const changes=execFileSync('git',['diff','--name-only',target.application_commit,'HEAD','--',
 'account-backend/src','account-backend/migrations','account-backend/wrangler.toml','account-backend/*.sql','release/migrations'],{encoding:'utf8'}).trim().split(/\r?\n/);
assert.deepEqual(changes,['account-backend/src/cvie-records.js','account-backend/src/recovery-control.js']);
assert.equal(process.env.CLOUDFLARE_ACCOUNT_ID,target.account);
const api='https://api.cloudflare.com/client/v4/accounts/'+target.account+'/workers/scripts/'+target.worker;
const r=await fetch(api+'/deployments',{headers:{Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN},redirect:'error'});
assert.ok(r.ok,'Could not verify production Worker version');
const state=await r.json();assert.ok(state.success);
assert.deepEqual(state.result.deployments[0].versions,[{version_id:target.worker_version,percentage:100}]);
await verifyService({expectedRelease:target.backend_identity,readinessOnly:true});
console.log('Verified production predecessor and two code-only changes.');
