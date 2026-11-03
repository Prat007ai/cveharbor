import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {project,loadManifest,validateSchema} from './schema.mjs';
import {normalizedDDL} from '../../account-backend/src/recovery-schema.js';
import {installGuards,holdStatus} from '../../scripts/recovery_control.mjs';
const quote=s=>"'"+s.replaceAll("'","''")+"'";
export async function migrationState(DB){
 const objects=(await DB.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' AND name NOT GLOB '_cf_*' AND name NOT GLOB 'd1_*' ORDER BY type,name").all()).results;
 const hasLedger=objects.some(x=>x.name==='staging_schema_history');
 if(objects.length&&!hasLedger)throw Error('Nonempty database has no reviewed staging ledger; adoption requires separate review.');
 const rows=hasLedger?(await DB.prepare('SELECT path,sha256,manifest_version FROM staging_schema_history ORDER BY rowid').all()).results:[];
 const manifest=loadManifest();
 for(let i=0;i<rows.length;i++){const expected=manifest.entries[i];assert.ok(expected&&rows[i].path===expected.path&&rows[i].sha256===expected.sha256&&rows[i].manifest_version===1,'Unknown, changed or out-of-order installed migration');}
 return {objects,rows,pending:manifest.entries.slice(rows.length),manifest};
}
export async function verifySchema(DB){
 const state=await migrationState(DB);assert.equal(state.pending.length,0,'Migrations pending');
 const expected=validateSchema().objects;
 assert.deepEqual(state.objects.map(x=>({...x,sql:normalizedDDL(x.sql)})),expected,'Schema drift: tables/indexes/triggers/views differ');
 assert.equal(Number((await DB.prepare('SELECT COUNT(*) n FROM pragma_foreign_key_check').first()).n),0);
 return {schema_complete:true,entries:state.rows.length,objects:expected.length};
}
export async function applyManifest(DB){
 const plan=validateSchema(),state=await migrationState(DB);
 if(state.rows.some(x=>x.path.endsWith('0032_recovery_control.sql'))){const hold=await holdStatus(DB);assert.equal(hold.write_hold,1,'Hold admission before an existing-database migration');assert.equal(hold.active_leases,0,'Drain existing operations first');assert.equal(hold.database_frozen,0,'Migrations require drained admission hold, not frozen database');}
 for(const entry of state.pending){
  // D1 executes one multi-statement request transactionally: SQL and receipt succeed together.
  const sql=fs.readFileSync(path.join(project,entry.path),'utf8');
  await DB.query(sql+'\nINSERT INTO staging_schema_history(path,sha256,manifest_version) VALUES('+quote(entry.path)+','+quote(entry.sha256)+',1);');
 }
 await installGuards(DB);
 return {...await verifySchema(DB),applied:state.pending.map(x=>x.path),guard_statements:plan.guards.length};
}
