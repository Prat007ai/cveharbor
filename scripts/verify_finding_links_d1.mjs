// Read-only production schema and tenant-boundary probes; no customer content or emails.
import fs from 'node:fs';import assert from 'node:assert/strict';
import {linkedReady,scopeSQL} from '../account-backend/src/remediation-identity.js';
export async function verifyLinkSchema(DB){
 const user='finding-link-release-probe';assert.equal(await DB.prepare('SELECT id FROM users WHERE id=?').bind(user).first(),null);assert.equal(await linkedReady({DB}),true);
 for(const table of ['remediation_link_audit','remediation_retired_records'])assert.deepEqual((await DB.prepare('SELECT user_id FROM '+table+' WHERE user_id=?').bind(user).all()).results,[]);
 const triggers=await DB.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND name IN ('prevent_retired_remediation_insert','validate_link_snapshot')").all();assert.equal(triggers.results.length,2);
 return {ok:true,read_only:true,tenant_probe_empty:true};
}
if(process.argv[1]&&new URL(import.meta.url).pathname===process.argv[1]){
 const config=fs.readFileSync(new URL('../account-backend/wrangler.toml',import.meta.url),'utf8'),database=config.match(/database_id\s*=\s*"([a-f0-9-]+)"/)[1];
 const account=process.env.CLOUDFLARE_ACCOUNT_ID,token=process.env.CLOUDFLARE_API_TOKEN;assert.ok(account&&token);let queries=0;
 const DB={prepare(sql){assert.match(sql,/^SELECT\b/);const make=params=>({bind:(...args)=>make(args),async all(){queries++;const response=await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/d1/database/${database}/query`,{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({sql,params})});const data=await response.json();assert.ok(response.ok&&data.success&&data.result?.[0]?.success,'Read-only D1 probe failed');assert.equal(data.result[0].meta?.rows_written||0,0);return {results:data.result[0].results}},async first(){return (await this.all()).results[0]||null}});return make([])}};
 const result=await verifyLinkSchema(DB);
 if(process.argv.includes('--after')){
  const response=await fetch('https://confirm.cveharbor.com/assignment/00000000-0000-4000-8000-000000000001');
  assert.equal(response.status,410,'Guest route, native rate binding and migration must be ready');assert.match(response.headers.get('cache-control'),/no-store/);assert.equal(response.headers.get('referrer-policy'),'same-origin');assert.match(response.headers.get('content-security-policy'),/frame-ancestors 'none'/);
  for(const path of ['/finding-assignments','/remediation-records/CVE-2000-0000','/finding-remediations/00000000-0000-4000-8000-000000000001/CVE-2000-0000'])assert.equal((await fetch('https://api.cveharbor.com/v1'+path)).status,401);
  assert.equal((await fetch('https://confirm.cveharbor.com/v1/remediations')).status,404);
  result.public_route_ready=true;result.private_routes_protected=true;
 }
 console.log(JSON.stringify({...result,queries,rows_written:0}));
}
