// SELECT-only production schema checks. Never reads customer record contents.
import fs from 'node:fs';import assert from 'node:assert/strict';
import {workflowReady,recordMetadata,statusHistory} from '../account-backend/src/remediation-workflow.js';
export async function verifyWorkflowSchema(DB){
 const user={id:'remediation-workflow-release-probe'},env={DB,REMEDIATION_WORKFLOW_ENABLED:'true'};
 assert.equal(await DB.prepare('SELECT id FROM users WHERE id=?').bind(user.id).first(),null);
 assert.equal(await workflowReady(env),true);const meta=await recordMetadata(env,user);assert.equal(meta.metadata.size,0);assert.equal(meta.changes.size,0);
 assert.deepEqual((await statusHistory(env,user,'CVE-2000-0000',new URL('https://api.cveharbor.com/'))).changes,[]);
 const triggers=await DB.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND name IN ('remediation_status_reason_required','remediation_status_changed','remediation_update_conflict','remediation_insert_conflict')").all();assert.equal(triggers.results.length,4);
 const indices=await DB.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_remediation_status_changes_scope'").all();assert.equal(indices.results.length,1);
 return {ok:true,read_only:true,tenant_probe_empty:true};
}
if(process.argv[1]&&new URL(import.meta.url).pathname===process.argv[1]){
 const config=fs.readFileSync(new URL('../account-backend/wrangler.toml',import.meta.url),'utf8'),database=config.match(/database_id\s*=\s*"([a-f0-9-]+)"/)[1];
 const account=process.env.CLOUDFLARE_ACCOUNT_ID,token=process.env.CLOUDFLARE_API_TOKEN;assert.ok(account&&token);let queries=0;
 const DB={prepare(sql){assert.match(sql,/^SELECT\b/);const make=params=>({bind:(...args)=>make(args),async all(){queries++;const response=await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/d1/database/${database}/query`,{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({sql,params})});const data=await response.json();assert.ok(response.ok&&data.success&&data.result?.[0]?.success,'Read-only D1 probe failed');assert.equal(data.result[0].meta?.rows_written||0,0);return {results:data.result[0].results}},async first(){return (await this.all()).results[0]||null}});return make([])}};
 const result=await verifyWorkflowSchema(DB);
 if(process.argv.includes('--after')){
  const url='https://api.cveharbor.com/v1/acknowledge/'+'0'.repeat(64),response=await fetch(url);
  assert.equal(response.status,404,'Guest acknowledgement route and rate binding must be ready');assert.match(response.headers.get('cache-control'),/no-store/);assert.equal(response.headers.get('referrer-policy'),'no-referrer');assert.match(response.headers.get('content-security-policy'),/frame-ancestors 'none'/);
  const invalidPost=await fetch(url,{method:'POST',headers:{Origin:'https://evil.example','Content-Type':'application/x-www-form-urlencoded'},body:'confirm=receipt'});assert.equal(invalidPost.status,403);
  for(const path of ['/remediations','/remediations/CVE-2000-0000/status-history'])assert.equal((await fetch('https://api.cveharbor.com/v1'+path)).status,401);
  const retry=await fetch('https://api.cveharbor.com/v1/remediations/CVE-2000-0000/assignments/00000000-0000-4000-8000-000000000001/fyi/retry',{method:'POST',headers:{Origin:'https://cveharbor.com','Content-Type':'application/json'},body:'{}'});assert.equal(retry.status,401);
  result.public_route_ready=true;result.private_routes_protected=true;
 }
 console.log(JSON.stringify({...result,queries,rows_written:0}));
}
