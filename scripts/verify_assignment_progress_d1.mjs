// SELECT-only production schema checks. No customer content, real invitations or mail.
import fs from 'node:fs';import assert from 'node:assert/strict';
import {progressReady,activeReviewSQL} from '../account-backend/src/assignment-progress-common.js';
import {reviewActivity} from '../account-backend/src/assignment-progress.js';
export async function verifyProgressSchema(DB){
 const user={id:'assignment-progress-release-probe'},env={DB,ASSIGNMENT_PROGRESS_ENABLED:'true'};
 assert.equal(await DB.prepare('SELECT id FROM users WHERE id=?').bind(user.id).first(),null);
 assert.equal(await progressReady(env),true);
 const result=await reviewActivity(env,user,'CVE-2000-0000',new URL('https://api.cveharbor.com/'));
 for(const key of ['activity','assignments','notifications'])assert.deepEqual(result[key],[]);
 assert.equal(await DB.prepare(activeReviewSQL).bind('00000000-0000-4000-8000-000000000001',Math.floor(Date.now()/1000)).first(),null);
 const triggers=await DB.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND name IN ('review_assignment_sent','review_status_progress','review_comment_progress','review_assignment_revoked','review_record_updated')").all();assert.equal(triggers.results.length,5);
 const indices=await DB.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name IN ('idx_review_progress_due','idx_review_challenge_scope','idx_review_session_scope','idx_review_activity_scope','idx_review_activity_assignment','idx_review_notification_queue')").all();assert.equal(indices.results.length,6);
 return {ok:true,read_only:true,tenant_probe_empty:true};
}
if(process.argv[1]&&new URL(import.meta.url).pathname===process.argv[1]){
 const config=fs.readFileSync(new URL('../account-backend/wrangler.toml',import.meta.url),'utf8'),database=config.match(/database_id\s*=\s*"([a-f0-9-]+)"/)[1];
 const account=process.env.CLOUDFLARE_ACCOUNT_ID,token=process.env.CLOUDFLARE_API_TOKEN;assert.ok(account&&token);let queries=0;
 const DB={prepare(sql){assert.match(sql,/^SELECT\b/);const make=params=>({bind:(...args)=>make(args),async all(){queries++;const response=await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/d1/database/${database}/query`,{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({sql,params})});const data=await response.json();assert.ok(response.ok&&data.success&&data.result?.[0]?.success,'Read-only D1 probe failed');assert.equal(data.result[0].meta?.rows_written||0,0);return {results:data.result[0].results}},async first(){return (await this.all()).results[0]||null}});return make([])}};
 const result=await verifyProgressSchema(DB);
 if(process.argv.includes('--after')){
  const response=await fetch('https://confirm.cveharbor.com/assignment/00000000-0000-4000-8000-000000000001');
  assert.equal(response.status,410,'Guest route, native rate binding and migration must be ready');assert.match(response.headers.get('cache-control'),/no-store/);assert.equal(response.headers.get('referrer-policy'),'same-origin');assert.match(response.headers.get('content-security-policy'),/frame-ancestors 'none'/);
  for(const path of ['/remediations','/remediations/CVE-2000-0000/review-activity'])assert.equal((await fetch('https://api.cveharbor.com/v1'+path)).status,401);
  assert.equal((await fetch('https://confirm.cveharbor.com/v1/remediations')).status,404);
  result.public_route_ready=true;result.private_routes_protected=true;
 }
 console.log(JSON.stringify({...result,queries,rows_written:0}));
}
