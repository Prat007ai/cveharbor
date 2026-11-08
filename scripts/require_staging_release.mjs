// Verify provenance through GitHub, never accept a user-supplied success JSON.
import assert from 'node:assert/strict';import fs from 'node:fs';import {spawnSync} from 'node:child_process';import {fileURLToPath} from 'node:url';import {createHash} from 'node:crypto';
import {backendIdentity} from './build_release_identity.mjs';
export function verifyReceipt(run,job,receipt,sha,identity){
 assert.equal(run.head_sha,sha);assert.equal(run.head_branch,'main');assert.ok(['push','workflow_dispatch'].includes(run.event));
 assert.equal(run.path,'.github/workflows/cvie-staging.yml');assert.equal(run.status,'completed');assert.equal(run.conclusion,'success');
 if(job.name==='customer-candidate'){
  assert.equal(run.event,'workflow_dispatch');assert.equal(run.run_attempt,1);assert.equal(job.conclusion,'success');
  assert.equal(receipt.scope,'query-fix-287');assert.equal(receipt.operation,'deploy');assert.equal(receipt.commit,sha);
  assert.equal(receipt.backend_uploaded,true);assert.equal(receipt.frontend_uploaded,false);assert.equal(receipt.database_changed,false);
  assert.equal(receipt.completed,true);assert.equal(receipt.backend_identity,identity);assert.equal(receipt.production_mutations,0);
  assert.equal(receipt.account,'9706b4d98ad72884e67fd1eb875c8a61');assert.equal(receipt.database_id,'fac61562-fc31-426d-8032-550aba63b7f6');
  for(const name of ['access_and_inventory','backend_verified','backend_runtime','staging_catalogue_query_verified'])assert.ok(receipt.steps.some(step=>step.name===name));
  return receipt;
 }
 assert.equal(job.name,'automatic-staging');assert.equal(job.conclusion,'success');
 assert.equal(receipt.status,'passed');assert.equal(receipt.operation,'release');assert.equal(receipt.source_sha,sha);
 assert.equal(receipt.account,'9706b4d98ad72884e67fd1eb875c8a61');assert.equal(receipt.database_id,'fac61562-fc31-426d-8032-550aba63b7f6');
 assert.equal(receipt.production_mutations,0);assert.equal(receipt.backend_identity,identity);return receipt;
}
export async function requireStaging(env,{transport=fetch,sleep=ms=>new Promise(r=>setTimeout(r,ms)),attempts=120}={}){
 assert.equal(env.SIMPLE_RELEASE_ENABLED,'true','Staging-first promotion has not been activated');assert.equal(env.GITHUB_REF,'refs/heads/main');assert.equal(env.GITHUB_REPOSITORY,'Prat007ai/cveharbor');assert.match(env.GITHUB_SHA||'',/^[a-f0-9]{40}$/);assert.ok(env.GH_TOKEN);
 const base='https://api.github.com/repos/Prat007ai/cveharbor';
 async function get(route){const r=await transport(base+route,{headers:{Authorization:'Bearer '+env.GH_TOKEN,Accept:'application/vnd.github+json'},redirect:'error',signal:AbortSignal.timeout(20000)});assert.ok(r.ok,'GitHub staging evidence unavailable');return r.json();}
 for(let i=0;i<attempts;i++){
  const runs=await get('/actions/workflows/cvie-staging.yml/runs?branch=main&head_sha='+env.GITHUB_SHA+'&per_page=30');
  const run=runs.workflow_runs?.filter(r=>r.head_sha===env.GITHUB_SHA&&['push','workflow_dispatch'].includes(r.event)).sort((a,b)=>b.id-a.id)[0];
  if(run?.status==='completed'){
   assert.equal(run.conclusion,'success','Staging failed; promotion blocked');
   const jobs=await get('/actions/runs/'+run.id+'/jobs?per_page=100');const candidate=jobs.jobs.find(j=>j.name==='customer-candidate'&&j.conclusion==='success');
   let name='staging-tested-'+env.GITHUB_SHA+'-'+run.run_attempt,filename='staging-release.json';
   if(candidate){
    assert.equal(env.GITHUB_WORKFLOW_REF,'Prat007ai/cveharbor/.github/workflows/deploy-worker-code.yml@refs/heads/main');
    assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch');
    const inputs=JSON.parse(fs.readFileSync(env.GITHUB_EVENT_PATH)).inputs;
    assert.equal(inputs.release_mode,'code-only');assert.equal(String(inputs.query_fix_287),'true');
    const merge=await get('/git/commits/'+env.GITHUB_SHA);
    assert.equal(merge.parents.length,2);assert.equal(merge.parents[0].sha,'8808eca65768860a1b138d2fe7f9158d27566164');
    assert.match(merge.message,/^Merge PR #287: Reduce CVIE catalogue query cost/);
    assert.equal(backendIdentity(),'738b07a3eee67dc5a3d872dfb4ccbbe5ba2aab628b8c964e820b7b69aea63ce8');
    name='customer-candidate-execution';filename='customer-candidate-execution.json';
   }
   const job=candidate||jobs.jobs.find(j=>j.name==='automatic-staging');assert.ok(job,'Exact staging job missing');
   const artifacts=await get('/actions/runs/'+run.id+'/artifacts?per_page=100');const artifact=artifacts.artifacts.find(a=>a.name===name);assert.ok(artifact&&!artifact.expired,'Staging receipt unavailable');
   // Auth is sent only to GitHub. The signed archive redirect is fetched separately.
   assert.ok(artifact.size_in_bytes<1000000,'Oversized staging evidence');
   const response=await transport(base+'/actions/artifacts/'+artifact.id+'/zip',{headers:{Authorization:'Bearer '+env.GH_TOKEN},redirect:'manual',signal:AbortSignal.timeout(20000)});
   assert.equal(response.status,302);const location=new URL(response.headers.get('location'));assert.equal(location.protocol,'https:');assert.ok(/(?:^|\.)(?:blob\.core\.windows\.net|githubusercontent\.com|github\.com)$/.test(location.hostname),'Unexpected artifact host');
   const archive=await transport(location,{redirect:'error',signal:AbortSignal.timeout(20000)});assert.ok(archive.ok);const bytes=Buffer.from(await archive.arrayBuffer());assert.ok(bytes.length<1000000);
   assert.equal('sha256:'+createHash('sha256').update(bytes).digest('hex'),artifact.digest,'Artifact checksum mismatch');
   const decoded=spawnSync('python',['-c',"import io,json,sys,zipfile;z=zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read()));names=z.namelist();assert names==[sys.argv[1]];i=z.getinfo(names[0]);assert i.file_size<100000;print(z.read(i).decode())",filename],{input:bytes,maxBuffer:200000});assert.equal(decoded.status,0,'Invalid staging receipt archive');
   const receipt=verifyReceipt(run,job,JSON.parse(decoded.stdout.toString()),env.GITHUB_SHA,backendIdentity());
   return {staging_run_id:run.id,source_sha:env.GITHUB_SHA,status:'passed',backend_identity:receipt.backend_identity};
  }
  if(i+1<attempts)await sleep(15000);
 }
 throw Error('Staging has not passed for this exact release');
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{console.log(JSON.stringify(await requireStaging(process.env)));}catch{console.error('Production promotion blocked: verified staging result missing for this exact commit.');process.exitCode=1;}
}
