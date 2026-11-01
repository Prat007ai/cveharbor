// SELECT-only production compatibility/aggregate check. No customer names or IDs logged.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {cvieRoute} from '../account-backend/src/cvie.js';
import {activeSubscription,catalogueAllows} from '../account-backend/src/catalogue-selection.js';
const database=fs.readFileSync(new URL('../account-backend/wrangler.toml',import.meta.url),'utf8').match(/database_id\s*=\s*"([a-f0-9-]+)"/)[1];
let reads=0,writes=0,queries=0;
const DB={prepare(sql){
 assert.match(sql,/^\s*SELECT\b/,'Production catalogue probe permits only SELECT');
 let params=[];const stmt={bind(...args){params=args;return stmt},async all(){
  const r=await fetch(`https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID}/d1/database/${database}/query`,{method:'POST',headers:{Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN,'Content-Type':'application/json'},body:JSON.stringify({sql,params})});
  const data=await r.json();assert.ok(r.ok&&data.success&&data.result?.[0]?.success,'D1 SELECT failed');
  const result=data.result[0];reads+=result.meta?.rows_read||0;writes+=result.meta?.rows_written||0;queries++;assert.equal(writes,0);return {results:result.results};
 },async first(){return (await stmt.all()).results[0]||null}};return stmt;
}};
const env={DB,CVIE_SHARED_SCANS_ENABLED:'true'},user={id:'catalogue-readonly-nonexistent-account'};
for(const scope of ['catalogue','inventory','stack'])for(const path of ['/progress','','/advisories']){
 const r=await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie'+path+'?scope='+scope),env,user);
 assert.equal(r.status,200);const result=await r.json();assert.deepEqual(result.products||result.advisories,[]);
}
const totals=await DB.prepare(`SELECT COUNT(*) AS registered_products,
 SUM(CASE WHEN ${activeSubscription('p','catalogue')} THEN 1 ELSE 0 END) AS current_catalogue_products,
 SUM(CASE WHEN ${activeSubscription('p','inventory')} THEN 1 ELSE 0 END) AS inventory_products,
 SUM(CASE WHEN ${activeSubscription('p','stack')} THEN 1 ELSE 0 END) AS watchlist_products,
 SUM(CASE WHEN EXISTS(SELECT 1 FROM cvie_subscriptions s WHERE s.product_id=p.id AND s.origin='catalogue') AND NOT ${catalogueAllows()} THEN 1 ELSE 0 END) AS obsolete_catalogue_subscriptions
 FROM cvie_products p`).first();
const preferences=await DB.prepare("SELECT COUNT(*) AS saved_catalogues,SUM(json_array_length(preferences_json,'$.defaults')) AS checked_builtin_technologies FROM user_technology_catalogue").first();
console.log(JSON.stringify({ok:true,read_only:true,queries,rows_read:reads,rows_written:writes,totals,preferences}));
