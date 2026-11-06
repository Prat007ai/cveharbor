// Fixed account/endpoints only. No SDK, retry loop, deploy, export, restore or resource API.
import assert from 'node:assert/strict';
import {target} from './build.mjs';
import {digest,runtimeFlags} from '../../../../scripts/production_schema_baseline.mjs';
export async function verifyGitHubGate(env,operation,fetcher=fetch){
 const name=['install','resume'].includes(operation)?'cloudflare-worker-production':'cloudflare-production-audit';
 assert.ok(env.REPAIR_GITHUB_TOKEN,'Environment protection read credential unavailable');
 assert.match(env.GITHUB_RUN_ID||'',/^\d+$/);
 async function get(route){
  let response,data;try{response=await fetcher('https://api.github.com/repos/Prat007ai/cveharbor/'+route,{redirect:'error',signal:AbortSignal.timeout(20000),headers:{Authorization:'Bearer '+env.REPAIR_GITHUB_TOKEN,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}});data=await response.json();}catch{throw Error('GitHub protection evidence unavailable');}
  assert.ok(response.ok,'GitHub protection evidence unavailable');return data;
 }
 const run=await get('actions/runs/'+env.GITHUB_RUN_ID);
 assert.equal(run.head_sha,env.GITHUB_SHA);assert.equal(run.head_branch,'main');assert.equal(run.event,'workflow_dispatch');assert.equal(run.run_attempt,1);assert.equal(run.status,'in_progress');
 assert.equal(String(run.path).split('@')[0],'.github/workflows/production-compatibility-repair.yml','Wrong approved workflow');
 const e=await get('environments/'+name);assert.equal(e.name,name);assert.equal(e.can_admins_bypass,false,'Environment bypass must be disabled');
 assert.deepEqual(e.deployment_branch_policy,{protected_branches:false,custom_branch_policies:true},'Explicit main-only environment policy required');
 const required=e.protection_rules?.find(r=>r.type==='required_reviewers');assert.equal(required?.reviewers?.length,1,'Owner environment reviewer required');
 assert.equal(required.reviewers[0].type,'User');assert.equal(required.reviewers[0].reviewer.id,349078288);
 const branches=await get('environments/'+name+'/deployment-branch-policies?per_page=100');
 assert.equal(branches.total_count,1);assert.equal(branches.branch_policies.length,1);assert.equal(branches.branch_policies[0].name,'main');assert.equal(branches.branch_policies[0].type,'branch');
 const reviews=await get('actions/runs/'+env.GITHUB_RUN_ID+'/approvals');assert.ok(Array.isArray(reviews));
 const relevant=reviews.filter(r=>r.environments?.some(x=>x.id===e.id));assert.ok(relevant.length>0,'No environment approval for this run');
 assert.ok(relevant.some(r=>r.state==='approved'&&r.user?.id===349078288)&&!relevant.some(r=>r.state==='rejected'),'Owner approval for this run is missing/rejected');
 return {environment:name,owner_review_verified:true,main_only:true,bypass:false};
}
export function transport(env,{fetcher=fetch}={}){
 assert.equal(env.CLOUDFLARE_ACCOUNT_ID,target.account,'Wrong credential account');
 assert.ok(env.CLOUDFLARE_API_TOKEN,'Protected credentials unavailable');
 const base=`https://api.cloudflare.com/client/v4/accounts/${target.account}`;
 const db=`/d1/database/${target.database}`,worker=`/workers/scripts/${target.worker}`;
 const routes=new Set([db,worker+'/deployments',worker+'/versions/'+target.worker_version,worker+'/settings',worker+'/schedules']);
 async function request(route,sql,params=[]){
  assert.ok(sql?route===db+'/query':routes.has(route),'Unapproved endpoint');
  let response,body;
  try{
   response=await fetcher(base+route,{method:sql?'POST':'GET',redirect:'error',signal:AbortSignal.timeout(60000),headers:{Authorization:'Bearer '+env.CLOUDFLARE_API_TOKEN,...(sql?{'Content-Type':'application/json'}:{})},...(sql?{body:JSON.stringify({sql,params})}:{})});
   body=await response.json();
  }catch{throw Error('Provider outcome unavailable; reconcile read-only, never retry a write');}
  assert.ok(response.ok&&body.success,'Provider operation failed; raw response withheld');
  if(sql)assert.ok(Array.isArray(body.result)&&body.result.length>0&&body.result.every(r=>r.success),'Incomplete D1 result; reconcile read-only');
  return body.result;
 }
 async function select(sql,params=[]){
  assert.ok(/^SELECT\b/.test(sql)&&!sql.includes(';'),'SELECT-only inspection');
  const result=await request(db+'/query',sql,params);
  assert.equal(result.length,1);assert.equal(result[0].meta?.rows_written,0,'Read-only audit wrote rows');
  assert.ok(Array.isArray(result[0].results));return result[0].results;
 }
 async function observe(){
  const database=await request(db),active=(await request(worker+'/deployments'))?.deployments?.[0];
  assert.equal(database.uuid,target.database);assert.equal(database.name,target.database_name);
  assert.deepEqual(active?.versions,[{version_id:target.worker_version,percentage:100}],'Active Worker version/traffic drift');
  const version=await request(worker+'/versions/'+target.worker_version),settings=await request(worker+'/settings'),schedules=await request(worker+'/schedules');
  assert.equal(version.id,target.worker_version);
  for(const bindings of [version.resources?.bindings,settings.bindings]){
   assert.ok(Array.isArray(bindings),'Binding metadata unavailable');
   const databases=bindings.filter(b=>b.type==='d1');assert.equal(databases.length,1);
   assert.equal(databases[0].name,'DB');assert.equal(databases[0].id,target.database);
   const flag=bindings.filter(b=>b.name==='RECOVERY_CONTROL_REQUIRED');assert.equal(flag.length,1);assert.equal(flag[0].type,'plain_text');assert.equal(flag[0].text,'true');
  }
  const again=(await request(worker+'/deployments'))?.deployments?.[0];assert.deepEqual(again,active,'Deployment changed during inspection');
  const flags=runtimeFlags({resources:{bindings:settings.bindings}});assert.equal(flags.available,true);assert.ok(!Object.values(flags.values).includes('unverified'),'Unverified runtime feature flag');
  assert.ok(Array.isArray(schedules.schedules)&&schedules.schedules.every(s=>typeof s.cron==='string'),'Schedule metadata unavailable');
  return {account:target.account,database:database.uuid,worker_version:version.id,deployment:active.id,configuration_sha256:digest({settings,schedules}),runtime_flags:flags.values,cron:schedules.schedules.map(s=>s.cron),recovery_required:true};
 }
 async function readiness(){
  let response,body;try{response=await fetcher(target.readiness_url,{redirect:'error',signal:AbortSignal.timeout(20000),headers:{'Cache-Control':'no-cache'}});body=await response.json();}catch{throw Error('Readiness unavailable');}
  assert.ok([200,503].includes(response.status));assert.equal(body.release,target.backend_identity);assert.equal(body.schema,'phase1-integrity-recovery-v1');
  return {http:response.status,ready:body.ready,held:body.held,schema_ready:body.schema_ready};
 }
 return {select,observe,readiness,protection:operation=>verifyGitHubGate(env,operation,fetcher),writeOnce:(sql,params=[])=>request(db+'/query',sql,params)};
}
