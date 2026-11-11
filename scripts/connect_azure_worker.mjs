// Protected production release. Never log provider bodies or credential subprocess output.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHmac, randomBytes} from 'node:crypto';
import {backendIdentity} from './build_release_identity.mjs';
import {preflight} from './production_worker_preflight.mjs';
import {verifyService} from './production_service_health.mjs';
import {azureConfiguration} from '../account-backend/src/azure-client.js';
import {probeMessage, probePath} from '../account-backend/src/azure-connection.js';
import {diagnosticFetch} from './azure_connection_diagnostics.mjs';

const account = 'aa99b9b15e0492302e4f6484b8d27bc2';
const predecessor = 'f903b738021362b5a008a8b9704481699af4b9cc41c49d2f8ae75503d8d87abc';
const api = 'https://api.cloudflare.com/client/v4/accounts/'+account+'/workers/scripts/cveharbor-accounts';
const report = {status:'failed',source_commit:process.env.GITHUB_SHA,usage_category:'platform_verification',
  inference_attempted:false,customer_ai_enabled:false,started_at:new Date().toISOString()};
let privateDirectory, stage = 'release_validation';
const checkedFetch = diagnosticFetch(report, value => {stage=value;});
async function provider(suffix) {
  const res = await checkedFetch(api+suffix,{headers:{Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN},redirect:'error',signal:AbortSignal.timeout(20000)});
  if(!res.ok) throw Error('cloudflare_read_failed');
  const data=await res.json();
  if(!data.success) throw Error('cloudflare_read_failed');
  return data.result;
}
const stable = bindings => bindings.map(b=>JSON.stringify(Object.fromEntries(Object.entries(b).sort()))).sort();
try {
  assert.equal(process.env.GITHUB_REPOSITORY,'Prat007ai/cveharbor');
  assert.equal(process.env.GITHUB_REF,'refs/heads/main');
  assert.equal(process.env.GITHUB_EVENT_NAME,'workflow_dispatch');
  assert.equal(process.env.GITHUB_RUN_ATTEMPT,'1');
  assert.equal(process.env.REVIEWED_COMMIT,process.env.GITHUB_SHA);
  assert.equal(process.env.CLOUDFLARE_ACCOUNT_ID,account);
  assert.ok(process.env.CLOUDFLARE_API_TOKEN);
  // This script executes only after package assembly, preserving the serving migrations.
  const release=(await fs.readFile('release/azure-worker-backend.txt','utf8')).trim();
  assert.equal(backendIdentity(),release);
  report.release=release;
  const config=JSON.parse(execFileSync('python3',['-c','import json,tomllib; print(json.dumps(tomllib.load(open("account-backend/wrangler.toml","rb"))))'],{encoding:'utf8'}));
  azureConfiguration({...config.vars,CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET:process.env.CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET});
  stage='production_preflight';
  await verifyService({expectedRelease:predecessor,fetcher:checkedFetch});
  stage='production_compatibility';
  await preflight(process.env,config,checkedFetch);
  const before=await provider('/settings');
  const deployment=(await provider('/deployments')).deployments[0];
  assert.equal(deployment.versions.length,1);
  assert.equal(deployment.versions[0].percentage,100);
  report.previous_version=deployment.versions[0].version_id;
  report.previous_deployment=deployment.id;
  // Verify that the previous version remains retrievable before uploading a successor.
  await provider('/versions/'+report.previous_version);
  const added=new Set([...Object.keys(config.vars).filter(n=>n.startsWith('CVEHARBOR_AZURE_')),
    'CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET','CVEHARBOR_AZURE_CONNECTION_PROBE']);
  // This successor preserves the installed Azure credential and refreshes only
  // the short-lived deployment probe. Refuse an unexpected existing setup.
  for(const name of added){
    const binding=before.bindings.find(b=>b.name===name);
    assert.ok(binding);
    if(name in config.vars){assert.equal(binding.type,'plain_text');assert.equal(binding.text,config.vars[name]);}
    else assert.equal(binding.type,'secret_text');
  }
  const created=Math.floor(Date.now()/1000), key=randomBytes(32).toString('hex');
  const proof={key,created,expires:created+900,release};
  privateDirectory=await fs.mkdtemp(path.join(os.tmpdir(),'cvh-azure-'));
  const secretFile=path.join(privateDirectory,'secrets.json');
  await fs.writeFile(secretFile,JSON.stringify({
    CVEHARBOR_AZURE_CONNECTION_PROBE:JSON.stringify(proof),
  }),{mode:0o600});
  // Do not forward the Azure credential or GitHub token to Wrangler as environment variables.
  const childEnv=Object.fromEntries(Object.entries(process.env).filter(([name])=>
    !name.startsWith('CVEHARBOR_AZURE_') && !['GH_TOKEN','GITHUB_TOKEN'].includes(name)));
  childEnv.WRANGLER_SEND_METRICS='false';
  childEnv.WRANGLER_LOG='error';
  stage='worker_deployment';
  execFileSync('npx',['--yes','wrangler@4.156.0','deploy','--config','wrangler.toml','--secrets-file',secretFile],{
    cwd:'account-backend',env:childEnv,stdio:'pipe',timeout:180000,maxBuffer:1048576,
  });
  report.deployment_command_completed=true;
  await fs.rm(secretFile);
  stage='runtime_verification';
  await verifyService({expectedRelease:release,fetcher:checkedFetch});
  const after=await provider('/settings');
  assert.deepEqual(stable(after.bindings.filter(b=>!added.has(b.name))),stable(before.bindings.filter(b=>!added.has(b.name))));
  for(const name of added){
    const binding=after.bindings.find(b=>b.name===name);
    assert.ok(binding);
    if(name in config.vars){assert.equal(binding.type,'plain_text');assert.equal(binding.text,config.vars[name]);}
    else assert.equal(binding.type,'secret_text');
  }
  const current=(await provider('/deployments')).deployments[0];
  assert.equal(current.versions.length,1);
  assert.equal(current.versions[0].percentage,100);
  assert.notEqual(current.versions[0].version_id,report.previous_version);
  report.deployed_version=current.versions[0].version_id;
  stage='azure_runtime_verification';
  const unsigned=await fetch('https://api.cveharbor.com'+probePath,{method:'POST',headers:{Origin:'https://cveharbor.com'},redirect:'error',signal:AbortSignal.timeout(15000)});
  assert.equal(unsigned.status,404);
  const timestamp=String(Math.floor(Date.now()/1000)),nonce=randomBytes(32).toString('hex');
  const signature=createHmac('sha256',Buffer.from(key,'hex')).update(probeMessage(timestamp,nonce,release)).digest('hex');
  const response=await fetch('https://api.cveharbor.com'+probePath,{method:'POST',headers:{
    Origin:'https://cveharbor.com','X-CVH-Timestamp':timestamp,'X-CVH-Nonce':nonce,'X-CVH-Signature':signature,
  },redirect:'error',signal:AbortSignal.timeout(100000)});
  const result=await response.json();
  report.probe_http_status=response.status;
  if(response.status!==200){
    const allowed=new Set(['invalid_configuration','authentication_http_error','authentication_request_failed',
      'authentication_invalid_response','resource_access_http_error','resource_access_request_failed',
      'resource_access_invalid_response','verification_failed']);
    report.probe_error=allowed.has(result.error)?result.error:'probe_unavailable';
  }
  report.authentication_verified=result.authentication_verified===true;
  report.resource_access_verified=result.resource_access_verified===true;
  assert.equal(response.status,200);
  assert.equal(result.release,release);
  assert.equal(result.inference_attempted,false);
  assert.equal(result.customer_ai_enabled,false);
  assert.ok(report.authentication_verified&&report.resource_access_verified);
  report.probe_expires_at=new Date(proof.expires*1000).toISOString();
  report.status='passed';
} catch {
  // No error object: subprocess/provider messages can contain credentials or private settings.
  report.failure_stage=stage;
  process.exitCode=1;
} finally {
  if(privateDirectory)await fs.rm(privateDirectory,{recursive:true,force:true});
  report.completed_at=new Date().toISOString();
  await fs.writeFile('azure-worker-verification.json',JSON.stringify(report,null,2)+'\n');
  console.log('Cloudflare Azure connection '+report.status+(report.failure_stage?' at '+report.failure_stage:''));
}
