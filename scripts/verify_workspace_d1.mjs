// Exercise the shipped read model against production D1 with a nonexistent identity.
// No sessions, customer records, migrations, scans or email sends are created.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {workspaceRoute} from '../account-backend/src/workspace-summary.js';
export async function verifyWorkspace(DB){
 const user={id:'workspace-readonly-release-probe'};
 assert.equal((await DB.prepare('SELECT id FROM users WHERE id=?').bind(user.id).all()).results.length,0,'Probe identity must not be a real account');
 const request=path=>new Request('https://api.cveharbor.com/v1/workspace/'+path);
 const summary=await(await workspaceRoute(request('summary'),{DB},user)).json();
 for(const key of ['inventory','remediation','findings'])assert.equal(summary[key].available,true,'Required workspace query unavailable: '+key);
 assert.equal(summary.inventory.customers,0);assert.equal(summary.inventory.environments,0);assert.equal(summary.inventory.inventory_entries,0);
 assert.deepEqual(summary.remediation.rows,[]);assert.deepEqual(summary.findings.rows,[]);
 const optional={monitoring:summary.monitoring.available,notifications:summary.notifications.available,provider_delivery:summary.provider_delivery.available};
 for(const view of ['activity','assets','environments','review']){
  const page=await(await workspaceRoute(request('items?view='+view),{DB},user)).json();
  if(view==='activity')optional.software_history=page.available;else assert.equal(page.available,true,'Required workspace list unavailable: '+view);
  assert.deepEqual(page.items,[]);assert.equal(page.next_offset,null);
 }
 return {ok:true,read_only:true,nonexistent_account:true,optional_sources:optional};
}
if(process.argv[1]&&new URL(import.meta.url).pathname===process.argv[1]){
 const config=fs.readFileSync(new URL('../account-backend/wrangler.toml',import.meta.url),'utf8');
 const database=config.match(/database_id\s*=\s*"([a-f0-9-]+)"/)[1];
 const account=process.env.CLOUDFLARE_ACCOUNT_ID,token=process.env.CLOUDFLARE_API_TOKEN;
 assert.ok(account&&token,'Cloudflare deployment credentials are required');
 let queries=0,writes=0;
 const DB={prepare(sql){
  assert.match(sql,/^SELECT\b/,'Only SELECT statements are permitted');
  const make=params=>({bind:(...args)=>make(args),async all(){
   queries++;
   const response=await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/d1/database/${database}/query`,{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({sql,params})});
   const data=await response.json();assert.ok(response.ok&&data.success&&data.result?.[0]?.success,'D1 read-only query failed');
   writes+=data.result[0].meta?.rows_written||0;assert.equal(writes,0,'Workspace verification must not write to D1');
   return {results:data.result[0].results};
  }});return make([]);
 }};
 const report=await verifyWorkspace(DB);assert.equal(writes,0);
 if(process.argv.includes('--after')){
  const health=await fetch('https://api.cveharbor.com/v1/health');assert.ok(health.ok);assert.equal((await health.json()).accounts,'configured');
  for(const path of ['summary','items?view=assets']){const r=await fetch('https://api.cveharbor.com/v1/workspace/'+path);assert.equal(r.status,401,'Workspace API requires authentication');}
  report.production_api_auth_boundary=true;
 }
 console.log(JSON.stringify({...report,queries,rows_written:writes}));
}
