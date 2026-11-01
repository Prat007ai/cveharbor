// Read schema metadata and exercise the history reader with nonexistent IDs.
// Never read customer records, create sessions, or execute migration SQL.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {inventoryRoute} from '../account-backend/src/inventory.js';
export async function verifyHistory(DB){
 const schema=fs.readFileSync(new URL('../account-backend/software-upgrade-history-schema.sql',import.meta.url),'utf8');
 const expected=[
  ['inventory_software_history',schema.match(/CREATE TABLE IF NOT EXISTS[\s\S]*?\n\);/)[0]],
  ['idx_inventory_software_history_scope',schema.match(/CREATE INDEX IF NOT EXISTS[\s\S]*?;/)[0]],
  ['inventory_software_version_changed',schema.match(/CREATE TRIGGER IF NOT EXISTS[\s\S]*?END;/)[0]]
 ];
 const rows=(await DB.prepare("SELECT name,sql FROM sqlite_schema WHERE name IN ('inventory_software_history','idx_inventory_software_history_scope','inventory_software_version_changed')").all()).results;
 const normalize=s=>s.replace(/IF NOT EXISTS/gi,'').replace(/\s+/g,'').replace(/;$/,'').toLowerCase();
 for(const [name,sql] of expected){
  const actual=rows.find(r=>r.name===name);
  assert.ok(actual,'Required software history setup is missing: '+name);
  assert.equal(normalize(actual.sql),normalize(sql),'Software history definition differs: '+name);
 }
 const customer='00000000-0000-4000-8000-000000000001',environment='00000000-0000-4000-8000-000000000002';
 const probe={prepare(sql){
  // Ownership/readiness responses are synthetic; no account inventory is read.
  if(/^SELECT id FROM inventory_(customers|environments)/.test(sql)){
   const stmt={bind(){return stmt},async first(){return {id:customer}}};return stmt;
  }
  return DB.prepare(sql);
 }};
 const path='/v1/inventory/software-history',req=new Request('https://api.cveharbor.com'+path+'?customer_id='+customer+'&environment_id='+environment);
 const response=await inventoryRoute(req,{DB:probe},{id:'software-history-readonly-nonexistent-user'},path);
 const result=await response.json();
 assert.equal(response.status,200);assert.equal(result.ready,true);assert.deepEqual(result.entries,[]);assert.equal(result.next_before,null);
 return {ok:true,schema_verified:true,history_reader_verified:true,customer_records_read:false};
}
if(process.argv[1]&&new URL(import.meta.url).pathname===process.argv[1]){
 let writes=0,queries=0;
 const config=fs.readFileSync(new URL('../account-backend/wrangler.toml',import.meta.url),'utf8');
 const database=config.match(/database_id\s*=\s*"([a-f0-9-]+)"/)[1];
 const account=process.env.CLOUDFLARE_ACCOUNT_ID,token=process.env.CLOUDFLARE_API_TOKEN;
 assert.ok(account&&token,'Cloudflare deployment credentials are required');
 const DB={prepare(sql){
  assert.match(sql,/^SELECT\b/,'Only read-only SELECT statements are permitted');let params=[];
  const stmt={bind(...values){params=values;return stmt},async all(){
   const response=await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/d1/database/${database}/query`,{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({sql,params})});
   const data=await response.json();assert.ok(response.ok&&data.success&&data.result?.[0]?.success,'D1 read-only query failed');
   queries++;writes+=data.result[0].meta?.rows_written||0;assert.equal(writes,0,'Read-only preflight must not write to D1');
   return {results:data.result[0].results};
  },async first(){return (await stmt.all()).results[0]||null}};return stmt;
 }};
 try{console.log(JSON.stringify({...await verifyHistory(DB),queries,rows_written:writes}))}
 catch(error){console.error('Software history preflight failed: '+error.message);process.exitCode=1}
}
