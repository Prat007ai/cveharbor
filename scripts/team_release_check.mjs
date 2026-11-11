import assert from 'node:assert/strict';
import fs from 'node:fs';
import {d1Client} from './cloudflare_d1.mjs';
import {PRODUCTION_DB} from './production_schema_baseline.mjs';
import {verifyService} from './production_service_health.mjs';

const state=process.env.TEAM_STATE;
assert.ok(['disabled','enabled','cvie-refresh','workspace-history'].includes(state));
const after=process.argv[2]==='after';
assert.ok(after||process.argv[2]==='before');
const account='aa99b9b15e0492302e4f6484b8d27bc2';
assert.equal(process.env.CLOUDFLARE_ACCOUNT_ID,account);
const prior=state==='disabled'?'firewall-backend-identity':'team-backend-disabled';
const file=state==='workspace-history'?(after?'workspace-history-backend':'cvie-refresh-backend'):state==='cvie-refresh'?(after?'cvie-refresh-backend':'team-backend-enabled'):(after?'team-backend-'+state:prior);
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
