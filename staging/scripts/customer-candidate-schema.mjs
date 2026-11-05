import fs from 'node:fs';import assert from 'node:assert/strict';import {DatabaseSync} from 'node:sqlite';
import {schemaSQL,canonical,digest} from '../../scripts/production_schema_baseline.mjs';
export const journalTable='d1_customer_remediation_migrations';
export const migrationName=profile=>'0001_customer_remediation_'+profile.migration_sha256+'.sql';
export const journalDDL=`CREATE TABLE IF NOT EXISTS "${journalTable}"(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE,applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL);`;
export const receiptPath='deployment/proposals/customer-remediation/schema.sql';
export const literal=x=>"'"+String(x).replaceAll("'","''")+"'";
const identifier=x=>'"'+x.replaceAll('"','""')+'"';
export function baselineSchema(){const db=new DatabaseSync(':memory:');try{db.exec(fs.readFileSync('staging/schema.sql','utf8'));for(const f of JSON.parse(fs.readFileSync('release/baseline.json')).application_schema_files)db.exec(fs.readFileSync(f.path,'utf8'));return db.prepare(schemaSQL).all();}finally{db.close();}}
export async function verifyJournal(DB,profile,state){
 const objects=(await DB.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type,name').bind(journalTable).all()).results;
 if(!objects.length){assert.equal(state,'baseline','Completed schema requires native migration receipt');return 'absent';}
 const local=new DatabaseSync(':memory:');try{local.exec(journalDDL);assert.deepEqual(canonical(objects),canonical(local.prepare('SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE tbl_name=? AND sql IS NOT NULL').all(journalTable)),'Unexpected migration metadata schema');}finally{local.close();}
 const entries=(await DB.prepare('SELECT name FROM '+journalTable+' ORDER BY id').all()).results.map(r=>r.name);
 assert.deepEqual(entries,state==='candidate'?[migrationName(profile)]:[],'Native migration receipt mismatch');return entries.length?'complete':'empty';
}
export async function schemaState(DB,profile){
 const rows=(await DB.prepare(schemaSQL).all()).results,actual=digest(canonical(rows)),base=baselineSchema();
 const state=actual===profile.schema_sha256?'candidate':actual===digest(canonical(base))?'baseline':'unknown';assert.notEqual(state,'unknown','Unreviewed or partial schema');
 assert.equal(Number((await DB.prepare('SELECT COUNT(*) n FROM pragma_foreign_key_check').first()).n),0);
 const receipts=(await DB.prepare('SELECT path,sha256,manifest_version FROM staging_schema_history ORDER BY rowid').all()).results.map(x=>({...x}));
 const baseline=JSON.parse(fs.readFileSync('release/baseline.json')),staged=JSON.parse(fs.readFileSync('staging/migrations.v1.json')).entries[0];
 const expected=[staged,...baseline.application_schema_files].map(f=>({path:f.path,sha256:f.sha256,manifest_version:1}));
 if(state==='candidate')expected.push({path:receiptPath,sha256:profile.migration_sha256,manifest_version:267});
 assert.deepEqual(receipts,expected,'Schema receipt mismatch; stop for investigation');const journal=await verifyJournal(DB,profile,state);return {state,rows,journal};
}
export async function counts(DB,rows){const result={};for(const row of rows.filter(r=>r.type==='table'))result[row.name]=Number((await DB.prepare('SELECT COUNT(*) n FROM '+identifier(row.name)).first()).n);return result;}
export function migrationBatch(rows,before,statements,profile){
 const checks=[`(SELECT COUNT(*) FROM (${schemaSQL}))=${rows.length}`,...rows.map(r=>`EXISTS(SELECT 1 FROM sqlite_schema WHERE type=${literal(r.type)} AND name=${literal(r.name)} AND tbl_name=${literal(r.tbl_name)} AND sql=${literal(r.sql)})`),...Object.entries(before).map(([n,c])=>`(SELECT COUNT(*) FROM ${identifier(n)})=${c}`),'(SELECT COUNT(*) FROM pragma_foreign_key_check)=0'];
 const guards=[];for(let i=0;i<checks.length;i+=20)guards.push({sql:`SELECT CASE WHEN ${checks.slice(i,i+20).join(' AND ')} THEN 1 ELSE abs(-9223372036854775808) END`});assert.ok(guards.every(g=>Buffer.byteLength(g.sql)<95000));
 return [...guards,...statements.map(sql=>({sql})),{sql:`INSERT INTO staging_schema_history(path,sha256,manifest_version) VALUES(${literal(receiptPath)},${literal(profile.migration_sha256)},267)`}];
}
