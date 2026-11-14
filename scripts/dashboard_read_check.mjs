// Read-only release verification; no inference, record changes or secret output.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {d1Client} from './cloudflare_d1.mjs';
import {PRODUCTION_DB,digest} from './production_schema_baseline.mjs';
import {holdStatus} from './recovery_control.mjs';
import {verifyService} from './production_service_health.mjs';
import {verifyAfterDeployment} from './organization_ai_health.mjs';
const after=process.argv[2]==='after';assert.ok(after||process.argv[2]==='before');
const predecessor='1d687be8ff23a3785b466f41151a065f5dc4aa34aabaafb0b50b832b7021d50f';
const expected=after?fs.readFileSync('release/dashboard-read-capacity-backend.txt','utf8').trim():predecessor;
if(after)await verifyAfterDeployment({expectedRelease:expected,predecessor});else await verifyService({expectedRelease:expected});
const account='aa99b9b15e0492302e4f6484b8d27bc2';assert.equal(process.env.CLOUDFLARE_ACCOUNT_ID,account);
const db=d1Client({database:PRODUCTION_DB,readOnly:true}),metadata=await db.metadata();
assert.equal(metadata.uuid,PRODUCTION_DB);assert.equal(metadata.name,'cveharbor-accounts');
assert.equal(metadata.read_replication?.mode,'auto','Capacity release requires verified read replicas');
const control=await holdStatus(db);assert.equal(control.guards_complete,true);assert.equal(control.write_hold,0);assert.equal(control.database_frozen,0);
assert.equal((await db.prepare('SELECT version FROM inventory_capacity_schema').first()).version,1);
assert.equal((await db.prepare('SELECT COUNT(*) n FROM users u LEFT JOIN inventory_capacity_revisions r ON r.user_id=u.id LEFT JOIN (SELECT user_id,COUNT(*) n FROM inventory_assets GROUP BY user_id) a ON a.user_id=u.id WHERE COALESCE(r.software_count,0)!=COALESCE(a.n,0)').first()).n,0);
const activation={};
for(const [kind,sql]of Object.entries({organization:'SELECT org,enabled FROM ai_organizations ORDER BY org',personal:'SELECT org,enabled FROM ai_personal_accounts ORDER BY org'}))activation[kind]=digest((await db.prepare(sql).all()).results);
const cf=async suffix=>{const r=await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/workers/scripts/cveharbor-accounts${suffix}`,{headers:{Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN},redirect:'error',signal:AbortSignal.timeout(15000)});assert.ok(r.ok,'Cannot verify Worker settings/recovery');const data=await r.json();assert.equal(data.success,true);return data.result;};
const settings=await cf('/settings'),deployment=(await cf('/deployments')).deployments[0];
assert.equal(deployment.versions.length,1);assert.equal(deployment.versions[0].percentage,100);
const version=deployment.versions[0].version_id;await cf('/versions/'+version);
const stable=v=>Array.isArray(v)?v.map(stable):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v;
const bindings=digest(stable(settings.bindings.toSorted((a,b)=>a.name.localeCompare(b.name))));
const receipt='dashboard-read-capacity-backend-recovery.json';
if(!after)fs.writeFileSync(receipt,JSON.stringify({commit:process.env.GITHUB_SHA,previous_version:version,previous_deployment:deployment.id,bindings_sha256:bindings,activation_sha256:activation,status:'predecessor_verified'},null,2)+'\n');
else{
 const prior=JSON.parse(fs.readFileSync(receipt,'utf8'));assert.equal(prior.commit,process.env.GITHUB_SHA);assert.equal(prior.bindings_sha256,bindings,'Worker bindings changed');assert.deepEqual(prior.activation_sha256,activation,'AI activation changed');assert.notEqual(version,prior.previous_version);await cf('/versions/'+prior.previous_version);
 for(const route of ['/v1/me','/v1/workspace/summary','/v1/workspace/items','/v1/cvie','/v1/cvie/advisories','/v1/inventory/page','/v1/inventory/status','/v1/team/organizations','/v1/ai/capabilities'])assert.equal((await fetch('https://api.cveharbor.com'+route,{redirect:'error',signal:AbortSignal.timeout(15000)})).status,401);
 fs.writeFileSync(receipt,JSON.stringify({...prior,status:'verified',deployed_version:version,deployed_deployment:deployment.id,release:expected,activation_preserved:true},null,2)+'\n');
}
console.log('Verified capacity storage, counts, serving build, unchanged bindings and AI activation, recovery version and authentication boundaries.');
