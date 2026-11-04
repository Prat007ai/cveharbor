// Runs only inside the existing approved production deployment job, after the staging gate.
import fs from 'node:fs';import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';
import {forwardMigrations,migrationConfig} from './release_migrations.mjs';import {d1Client} from './cloudflare_d1.mjs';
import {verifyNativeHistory,recordNativeChecksums} from '../staging/scripts/simple-release.mjs';
import {holdStatus,installGuards} from './recovery_control.mjs';
const baseline=JSON.parse(fs.readFileSync('release/baseline.json'));
assert.equal(baseline.status,'verified');assert.equal(process.env.GITHUB_REF,'refs/heads/main');assert.equal(process.env.SIMPLE_RELEASE_ENABLED,'true');
const config=migrationConfig({production:true,account:process.env.CLOUDFLARE_ACCOUNT_ID});
assert.equal(baseline.production_database_id,config.d1_databases[0].database_id);
const files=forwardMigrations(),DB=d1Client({readOnly:false});
const pending=await verifyNativeHistory(DB,files);
if(pending.length){
 // Routine forward files are additive only. Respect any existing recovery hold.
 const hold=await holdStatus(DB);assert.equal(hold.write_hold,0,'Production recovery hold blocks routine migrations');assert.equal(hold.database_frozen,0);
 const meta=await DB.metadata();assert.equal(meta.uuid,baseline.production_database_id);
 const recovery=await fetch('https://api.cloudflare.com/client/v4/accounts/'+process.env.CLOUDFLARE_ACCOUNT_ID+'/d1/database/'+baseline.production_database_id+'/time_travel/bookmark',{headers:{Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN},redirect:'error',signal:AbortSignal.timeout(20000)});const point=await recovery.json();assert.ok(recovery.ok&&point.success&&point.result?.bookmark,'Production recovery point unavailable');
 fs.mkdirSync('release/.build',{recursive:true});fs.writeFileSync('release/.build/production-migrations.json',JSON.stringify(config));
 const r=spawnSync('npx',['--yes','wrangler@4.156.0','d1','migrations','apply','cveharbor-accounts','--remote','--config','release/.build/production-migrations.json'],{stdio:'inherit'});assert.equal(r.status,0);
 await installGuards(DB);await recordNativeChecksums(DB,files);console.log('Additive forward migrations applied; production recovery controls preserved.');
}else console.log('No pending native forward migrations.');
