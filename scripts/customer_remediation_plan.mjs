// Local-only schema rehearsal. No Cloudflare clients, environment secrets or network.
import fs from 'node:fs';import {DatabaseSync} from 'node:sqlite';import {createHash} from 'node:crypto';import assert from 'node:assert/strict';
import {canonical,digest,schemaSQL} from './production_schema_baseline.mjs';
const base=JSON.parse(fs.readFileSync('release/baseline.json','utf8')),file='deployment/proposals/customer-remediation/schema.sql',sql=fs.readFileSync(file,'utf8');
const db=new DatabaseSync(':memory:');
try{
 db.exec('PRAGMA foreign_keys=ON');db.exec(fs.readFileSync('staging/schema.sql','utf8'));
 for(const entry of base.application_schema_files)db.exec(fs.readFileSync(entry.path,'utf8'));
 const before=db.prepare(schemaSQL).all(),application=before.filter(r=>!r.name.startsWith('staging_'));
 assert.equal(digest(canonical(application)),base.schema_sha256);
 const changes=db.prepare('SELECT total_changes() n').get().n;
 db.exec(sql);
 const after=db.prepare(schemaSQL).all();assert.equal(db.prepare('SELECT total_changes() n').get().n,changes);
 assert.equal(db.prepare('SELECT count(*) n FROM pragma_foreign_key_check').get().n,0);
 const oldNames=new Set(before.map(r=>r.name));assert.deepEqual(canonical(after.filter(r=>oldNames.has(r.name))),canonical(before));
 const report={local_only:true,applied_to_live_database:false,baseline_profile_unchanged:true,migration:file,migration_sha256:createHash('sha256').update(sql).digest('hex'),baseline_application_schema_sha256:base.schema_sha256,baseline_application_objects:application.length,proposed_schema_sha256:digest(canonical(after)),new_objects:after.filter(r=>!oldNames.has(r.name)).map(({type,name})=>({type,name})),rows_written:0,foreign_key_errors:0,backfill:false};
 fs.mkdirSync('work',{recursive:true});fs.writeFileSync('work/customer-remediation-plan.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
}finally{db.close();}
