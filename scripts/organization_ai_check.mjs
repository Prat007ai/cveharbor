// Read-only production checks; never print secret values or private usage records.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
import {createHash} from 'node:crypto';
import {d1Client} from './cloudflare_d1.mjs';
import {PRODUCTION_DB,canonical,schemaSQL,digest} from './production_schema_baseline.mjs';
import {verifyService} from './production_service_health.mjs';
import {verifyAfterDeployment} from './organization_ai_health.mjs';
const after=process.argv[2]==='after';assert.ok(after||process.argv[2]==='before');
const account='aa99b9b15e0492302e4f6484b8d27bc2';assert.equal(process.env.CLOUDFLARE_ACCOUNT_ID,account);
const predecessor='b27e7dfae44a4de59daf6e9e903a74a3bf34132be06bb8de622746d1b1cc625a';
const expected=after?fs.readFileSync('release/organization-ai-backend.txt','utf8').trim():predecessor;
if(after)await verifyAfterDeployment({expectedRelease:expected,predecessor});
else await verifyService({expectedRelease:expected});
const db=d1Client({database:PRODUCTION_DB,readOnly:true}),metadata=await db.metadata();
assert.equal(metadata.uuid,PRODUCTION_DB);assert.equal(metadata.name,'cveharbor-accounts');
const ddl=fs.readFileSync('deployment/proposals/organization-ai/schema.sql','utf8').replaceAll('\r\n','\n');
assert.equal(digest(ddl),fs.readFileSync('release/organization-ai-schema.txt','utf8').trim());
const local=new DatabaseSync(':memory:');local.exec(ddl);const objects=local.prepare(schemaSQL).all();local.close();
const names=new Set(objects.map(o=>o.name));
assert.deepEqual(canonical((await db.prepare(schemaSQL).all()).results.filter(o=>names.has(o.name))),canonical(objects),'Installed AI schema differs from reviewed SQL');
for(const email of ['prat@mahendran.tech','prat.mahen@gmail.com']){
 const owner=await db.prepare('SELECT count(*) n FROM users u JOIN user_totp t ON t.user_id=u.id AND t.enabled=1 WHERE lower(u.email)=?').bind(email).first();
 assert.equal(owner.n,1,'Each reviewed platform owner must have exactly one existing MFA-enabled account');
}
const cf=async suffix=>{
 const r=await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/workers/scripts/cveharbor-accounts${suffix}`,{headers:{Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN},redirect:'error',signal:AbortSignal.timeout(15000)});
 assert.ok(r.ok,'Cannot verify production Worker settings or recovery version');const data=await r.json();assert.equal(data.success,true);return data.result;
};
const settings=await cf('/settings'),deploy=(await cf('/deployments')).deployments[0];
assert.equal(deploy.versions.length,1);assert.equal(deploy.versions[0].percentage,100);
const version=deploy.versions[0].version_id;await cf('/versions/'+version);
const additions={CVEHARBOR_AI_PLATFORM_BACKUP_OWNER_EMAIL:'prat.mahen@gmail.com'};
for(const [name,text] of Object.entries({CVEHARBOR_AI_ACCOUNTING_ENABLED:'true',CVEHARBOR_AI_ENABLED:'true',CVEHARBOR_AI_PLATFORM_OWNER_EMAIL:'prat@mahendran.tech'})){
 const binding=settings.bindings.find(b=>b.name===name);assert.equal(binding?.type,'plain_text');assert.equal(binding.text,text);
}
const stable=v=>Array.isArray(v)?v.map(stable):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v;
const bindingHash=createHash('sha256').update(JSON.stringify(stable(settings.bindings.filter(b=>!Object.hasOwn(additions,b.name)).sort((a,b)=>a.name.localeCompare(b.name))))).digest('hex');
for(const [name,text] of Object.entries(additions)){const binding=settings.bindings.find(b=>b.name===name);if(after){assert.equal(binding?.type,'plain_text');assert.equal(binding.text,text);}else assert.equal(binding,undefined,'AI settings already exist; reconcile rather than overwrite');}
for(const name of ['CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET','CVEHARBOR_AZURE_CONNECTION_PROBE'])assert.equal(settings.bindings.find(b=>b.name===name)?.type,'secret_text');
const receipt='organization-ai-backend-recovery.json';
assert.equal((await db.prepare('SELECT count(*) n FROM ai_organizations WHERE enabled=1').first()).n,0,'Release must leave every organization paused');
if(!after){
 fs.writeFileSync(receipt,JSON.stringify({commit:process.env.GITHUB_SHA,previous_version:version,previous_deployment:deploy.id,bindings_sha256:bindingHash,status:'predecessor_verified'},null,2)+'\n');
}else{
 const prior=JSON.parse(fs.readFileSync(receipt,'utf8'));assert.equal(prior.commit,process.env.GITHUB_SHA);assert.equal(prior.bindings_sha256,bindingHash,'Unrelated bindings changed');assert.notEqual(version,prior.previous_version);await cf('/versions/'+prior.previous_version);
 for(const route of ['/v1/ai/admin/usage','/v1/ai/capabilities'])assert.equal((await fetch('https://api.cveharbor.com'+route,{redirect:'error'})).status,401);
 fs.writeFileSync(receipt,JSON.stringify({...prior,status:'verified',deployed_version:version,deployed_deployment:deploy.id,release:expected},null,2)+'\n');
}
console.log('AI schema, reviewed owner, backend identity, preserved credentials and release boundaries verified.');
