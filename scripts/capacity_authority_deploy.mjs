// Proposed isolated-test infrastructure. Requires explicit coordinator mode in the existing protected job.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
export const coordinatorName='cveharbor-capacity-authority';
const account='9706b4d98ad72884e67fd1eb875c8a61',database='b4a226d7-35e8-469f-abfe-2a2eee0a96de',marker='retained-fictional-v1';
export function coordinatorConfig(env){
 assert.equal(env.CLOUDFLARE_ACCOUNT_ID,account);
 assert.equal(env.GITHUB_WORKFLOW_REF,'Prat007ai/cveharbor/.github/workflows/inventory-capacity-cloud.yml@refs/heads/main');
 assert.equal(env.GITHUB_REF,'refs/heads/main');assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch');assert.equal(env.GITHUB_RUN_ATTEMPT,'1');
 assert.equal(env.GITHUB_REPOSITORY,'Prat007ai/cveharbor');assert.match(env.GITHUB_SHA||'',/^[a-f0-9]{40}$/);assert.equal(env.CAPACITY_REVIEWED_COMMIT,env.GITHUB_SHA);
 assert.equal(env.CAPACITY_AUTHORITY_COORDINATOR,'true');
 return {name:coordinatorName,account_id:account,main:path.resolve('scripts/capacity_authority_coordinator.mjs'),compatibility_date:'2026-10-28',
  workers_dev:false,preview_urls:false,routes:[],vars:{CAPACITY_AUTHORITY_MARKER:marker},
  d1_databases:[{binding:'DB',database_name:'cveharbor-capacity-43438175247',database_id:database}],
  durable_objects:{bindings:[{name:'AUTHORITY',class_name:'CapacityAuthorityCoordinator'}]},
  migrations:[{tag:'capacity-authority-v1',new_sqlite_classes:['CapacityAuthorityCoordinator']}]};
}
function verifySettings(settings){
 const bindings=settings.bindings||[];
 assert.equal(bindings.length,3);
 assert.ok(bindings.some(b=>b.name==='DB'&&b.type==='d1'&&b.id===database));
 assert.ok(bindings.some(b=>b.name==='CAPACITY_AUTHORITY_MARKER'&&b.type==='plain_text'&&b.text===marker));
 assert.ok(bindings.some(b=>b.name==='AUTHORITY'&&b.type==='durable_object_namespace'&&b.class_name==='CapacityAuthorityCoordinator'));
}
export async function deployCapacityCoordinator(env,root,childEnv,api){
 const config=coordinatorConfig(env),scripts=await api('/workers/scripts');
 if(scripts.some(s=>s.id===coordinatorName))verifySettings(await api('/workers/scripts/'+coordinatorName+'/settings'));
 const file=path.join(root,'authority-wrangler.json');fs.writeFileSync(file,JSON.stringify(config));
 try{execFileSync('npx',['--yes','wrangler@4.156.0','deploy','--config',file],{env:childEnv,stdio:'pipe',timeout:120000,maxBuffer:2097152});}
 catch{throw Error('Private test coordinator deployment failed; inspect the retained resource before retrying');}
 verifySettings(await api('/workers/scripts/'+coordinatorName+'/settings'));
 const exposure=await api('/workers/scripts/'+coordinatorName+'/subdomain');
 assert.equal(exposure.enabled,false);assert.equal(exposure.previews_enabled,false);
 return {worker:coordinatorName,database,public_endpoints:false,retained:true};
}
