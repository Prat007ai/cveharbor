import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
import {inventoryOnly,monitorCodeOnly} from './worker_release_mode.mjs';
import {verifyHistory} from './verify_software_history_d1.mjs';
const inventory='account-backend/src/inventory.js';
assert.equal(inventoryOnly([inventory,'customer-security.js']),true);
for(const path of ['account-backend/src/cvie.js','account-backend/wrangler.toml','account-backend/migrations/0021_cvie_audit_refresh.sql','scripts/verify_cvie_d1.mjs'])assert.equal(inventoryOnly([inventory,path]),false,path);
assert.equal(inventoryOnly(['customer-security.js']),false);
const sql=new DatabaseSync(':memory:');
try{
 sql.exec('CREATE TABLE users(id TEXT PRIMARY KEY)');
 sql.exec(fs.readFileSync(new URL('../account-backend/inventory-schema.sql',import.meta.url),'utf8'));
 sql.exec(fs.readFileSync(new URL('../account-backend/software-upgrade-history-schema.sql',import.meta.url),'utf8'));
 const DB={prepare(query){
  assert.match(query,/^SELECT\b/);
  assert.doesNotMatch(query,/FROM inventory_(customers|environments|assets)\b/);
  const make=params=>({bind:(...args)=>make(args),async all(){return {results:sql.prepare(query).all(...params)}},async first(){return sql.prepare(query).get(...params)||null}});
  return make([]);
 }};
 assert.equal((await verifyHistory(DB)).ok,true);
 sql.exec('DROP TRIGGER inventory_software_version_changed');
 await assert.rejects(()=>verifyHistory(DB),/setup is missing/);
 sql.exec("CREATE TRIGGER inventory_software_version_changed AFTER UPDATE ON inventory_assets BEGIN SELECT 1; END");
 await assert.rejects(()=>verifyHistory(DB),/definition differs/);
 console.log('PASS: inventory-only release classification and SELECT-only schema/reader preflight');
}finally{sql.close()}


assert.equal(monitorCodeOnly(['account-backend/src/monitoring.js','account-backend/src/index.js','account-backend/migrations/0023_lifecycle_monitoring.sql','index.html']),true);
assert.equal(monitorCodeOnly(['account-backend/src/monitoring.js','account-backend/src/cvie.js']),false);
assert.equal(monitorCodeOnly(['account-backend/src/index.js']),false);
