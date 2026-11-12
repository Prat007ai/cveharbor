// Read-only release verification. No AI requests, configuration writes or customer-record output.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {d1Client} from './cloudflare_d1.mjs';
import {PRODUCTION_DB} from './production_schema_baseline.mjs';
import {verifyService} from './production_service_health.mjs';
import {verifyAfterDeployment} from './organization_ai_health.mjs';
const after=process.argv[2]==='after';assert.ok(after||process.argv[2]==='before');
const mapping=process.env.TEAM_STATE==='dotnet-mapping',release=mapping?'dotnet-mapping':'windows-inventory';
const predecessor=mapping?'0caf38d9c1ea4ed9bbc8c91f71cd8074b69559ae66cb33919d74d607b7519927':'ce561b7756d14c874d353470c84b8c9228626e400df8d776dcb83ee03eadeb2a';
const expected=after?fs.readFileSync('release/'+release+'-backend.txt','utf8').trim():predecessor;
if(after)await verifyAfterDeployment({expectedRelease:expected,predecessor});else await verifyService({expectedRelease:expected});
const account='aa99b9b15e0492302e4f6484b8d27bc2';assert.equal(process.env.CLOUDFLARE_ACCOUNT_ID,account);
const db=d1Client({database:PRODUCTION_DB,readOnly:true});assert.equal((await db.metadata()).name,'cveharbor-accounts');
assert.equal((await db.prepare('SELECT count(*) n FROM ai_organizations WHERE enabled=1').first()).n,0,'AI must remain paused for all organizations');
const cf=async suffix=>{const r=await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/workers/scripts/cveharbor-accounts${suffix}`,{headers:{Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN},redirect:'error',signal:AbortSignal.timeout(15000)});assert.ok(r.ok,'Cannot verify Worker settings/recovery');const data=await r.json();assert.equal(data.success,true);return data.result;};
const settings=await cf('/settings'),deployment=(await cf('/deployments')).deployments[0];
assert.equal(deployment.versions.length,1);assert.equal(deployment.versions[0].percentage,100);
const version=deployment.versions[0].version_id;await cf('/versions/'+version);
const stable=v=>Array.isArray(v)?v.map(stable):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v;
const bindings=createHash('sha256').update(JSON.stringify(stable(settings.bindings.toSorted((a,b)=>a.name.localeCompare(b.name))))).digest('hex');
for(const name of ['CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET','CVEHARBOR_AZURE_CONNECTION_PROBE'])assert.equal(settings.bindings.find(b=>b.name===name)?.type,'secret_text');
const receipt=release+'-backend-recovery.json';
if(!after)fs.writeFileSync(receipt,JSON.stringify({commit:process.env.GITHUB_SHA,previous_version:version,previous_deployment:deployment.id,bindings_sha256:bindings,status:'predecessor_verified'},null,2)+'\n');
else{
 const prior=JSON.parse(fs.readFileSync(receipt,'utf8'));assert.equal(prior.commit,process.env.GITHUB_SHA);assert.equal(prior.bindings_sha256,bindings,'Worker bindings changed');assert.notEqual(version,prior.previous_version);await cf('/versions/'+prior.previous_version);
 for(const route of ['/v1/team/organizations','/v1/ai/capabilities','/v1/ai/admin/usage'])assert.equal((await fetch('https://api.cveharbor.com'+route,{redirect:'error'})).status,401);
 fs.writeFileSync(receipt,JSON.stringify({...prior,status:'verified',deployed_version:version,deployed_deployment:deployment.id,release:expected,ai_paused:true},null,2)+'\n');
}
console.log('Verified inventory release, unchanged Worker bindings, recovery version, authentication boundaries and all organization AI paused.');
