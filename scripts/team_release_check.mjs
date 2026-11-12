import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {d1Client} from './cloudflare_d1.mjs';
import {PRODUCTION_DB} from './production_schema_baseline.mjs';
import {verifyService} from './production_service_health.mjs';

const state=process.env.TEAM_STATE;
if(['windows-inventory','dotnet-mapping'].includes(state)){await import('./windows_inventory_check.mjs');process.exit(0);}
if(state==='organization-ai'){await import('./organization_ai_check.mjs');process.exit(0);}
let completedRecoveryReceipt=null;
assert.ok(['disabled','enabled','cvie-refresh','workspace-history'].includes(state));
const after=process.argv[2]==='after';
assert.ok(after||process.argv[2]==='before');
const account='aa99b9b15e0492302e4f6484b8d27bc2';
assert.equal(process.env.CLOUDFLARE_ACCOUNT_ID,account);
const prior=state==='disabled'?'firewall-backend-identity':'team-backend-disabled';
const file=state==='workspace-history'?(after?'workspace-history-backend':'azure-worker-backend'):state==='cvie-refresh'?(after?'cvie-refresh-backend':'team-backend-enabled'):(after?'team-backend-'+state:prior);
await verifyService({expectedRelease:fs.readFileSync('release/'+file+'.txt','utf8').trim()});
const db=d1Client({database:PRODUCTION_DB,readOnly:true});
const md=await db.metadata();
assert.equal(md.uuid,PRODUCTION_DB);
assert.equal(md.name,'cveharbor-accounts');
for(const name of ['team_members','team_audit','team_organizations','team_last_login','team_visible_customers','team_scoped_records']){
  await db.prepare('SELECT * FROM '+name+' LIMIT 0').all();
}
const url='https://api.cloudflare.com/client/v4/accounts/'+account+'/workers/scripts/cveharbor-accounts/settings';
const res=await fetch(url,{headers:{Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN},redirect:'error',signal:AbortSignal.timeout(15000)});
assert.ok(res.ok,'Cannot confirm live Worker bindings');
const settings=await res.json();
assert.equal(settings.success,true);
if(state==='workspace-history'){
 const provider=async suffix=>{const r=await fetch(url.replace('/settings',suffix),{headers:{Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN},redirect:'error',signal:AbortSignal.timeout(15000)});assert.ok(r.ok,'Worker recovery evidence unavailable');const data=await r.json();assert.equal(data.success,true);return data.result;};
 const stable=value=>Array.isArray(value)?value.map(stable):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(k=>[k,stable(value[k])])):value;
 const bindings=settings.result.bindings.filter(b=>b.name!=='WORKSPACE_HISTORY_ENABLED').sort((a,b)=>a.name.localeCompare(b.name));
 const bindingsHash=createHash('sha256').update(JSON.stringify(stable(bindings))).digest('hex');
 const current=(await provider('/deployments')).deployments[0];
 assert.equal(current.versions.length,1);assert.equal(current.versions[0].percentage,100);
 const version=current.versions[0].version_id;await provider('/versions/'+version);
 const receipt='workspace-history-backend-recovery.json';
 if(!after){fs.writeFileSync(receipt,JSON.stringify({commit:process.env.GITHUB_SHA,previous_version:version,previous_deployment:current.id,bindings_sha256:bindingsHash,status:'predecessor_preserved'},null,2)+'\n');}
 else {const before=JSON.parse(fs.readFileSync(receipt,'utf8'));assert.equal(before.commit,process.env.GITHUB_SHA);assert.equal(before.bindings_sha256,bindingsHash,'Unrelated Worker bindings changed');assert.notEqual(version,before.previous_version);await provider('/versions/'+before.previous_version);completedRecoveryReceipt={...before,deployed_version:version,deployed_deployment:current.id,status:'verified'};}
 const azure={CVEHARBOR_AZURE_OPENAI_ENDPOINT:'https://cvie-prod.openai.azure.com/',CVEHARBOR_AZURE_OPENAI_DEPLOYMENT:'gpt-5.4-mini',CVEHARBOR_AZURE_OPENAI_TENANT_ID:'f95d3766-898f-4e4d-a0ad-9b5efa394592',CVEHARBOR_AZURE_OPENAI_CLIENT_ID:'dec0de99-1e60-461f-bfb2-aa518b40036a'};
 for(const [name,value]of Object.entries(azure)){const binding=settings.result.bindings.find(b=>b.name===name);assert.equal(binding?.type,'plain_text');assert.equal(binding.text,value,'Azure configuration must be preserved');}
 for(const name of ['CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET','CVEHARBOR_AZURE_CONNECTION_PROBE'])assert.equal(settings.result.bindings.find(b=>b.name===name)?.type,'secret_text','Existing Azure secret binding must remain present');
 await db.prepare('SELECT day,captured_at,metric_version,needs_review,in_progress,fixed,accepted_risk,not_applicable,inventory_records FROM workspace_finding_daily_snapshots LIMIT 0').all();
 const history=settings.result.bindings.find(b=>b.name==='WORKSPACE_HISTORY_ENABLED');
 if(after){assert.equal(history?.type,'plain_text');assert.equal(history.text,'true');}
 else assert.ok(!history||history.type==='plain_text'&&history.text==='false');
 const boundary=await fetch('https://api.cveharbor.com/v1/workspace/trend',{redirect:'error',signal:AbortSignal.timeout(15000)});assert.equal(boundary.status,401);
}
const flag=settings.result.bindings.find(b=>b.name==='TEAM_ACCESS_ENABLED');
if(after||state==='enabled'||state==='cvie-refresh'||state==='workspace-history'){
  assert.equal(flag?.type,'plain_text');
  assert.equal(flag.text,(state==='workspace-history'||state==='cvie-refresh'||after&&state==='enabled')?'true':'false');
}else assert.ok(!flag||flag.type==='plain_text'&&flag.text==='false');
const api=await fetch('https://api.cveharbor.com/v1/team/organizations',{redirect:'error',signal:AbortSignal.timeout(15000)});
assert.equal(api.status,401);
console.log('Confirmed production build, accounts storage, Team & Access setting and anonymous access boundary.');
if(completedRecoveryReceipt)fs.writeFileSync('workspace-history-backend-recovery.json',JSON.stringify(completedRecoveryReceipt,null,2)+'\n');
