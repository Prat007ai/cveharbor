// Local profile validation; the existing migration executor owns all remote writes.
import {DatabaseSync} from 'node:sqlite';
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';
import {project,hash} from './schema.mjs';import {loadMigrationPlan} from './migrate.mjs';
import {canonical,digest,objectCounts,schemaSQL} from '../../scripts/production_schema_baseline.mjs';
export function productionBaselinePlan(baseline,base=project){
 const profileBytes=fs.readFileSync(path.join(base,'release/baseline.json'));
 assert.deepEqual(baseline,JSON.parse(profileBytes),'Use the reviewed checked-in baseline');
 const build=spawnSync('python',['staging/scripts/migration-plan.py','--production-baseline'],{cwd:base,encoding:'utf8'});
 assert.equal(build.status,0,'Local production baseline rehearsal failed');
 const bytes=fs.readFileSync(path.join(base,'staging/.build/schema/production-baseline-plan.json')),plan=JSON.parse(bytes);
 assert.equal(plan.profile,'production-baseline');assert.equal(plan.profile_sha256,hash(profileBytes));
 const approval=JSON.parse(fs.readFileSync(path.join(base,'staging/bootstrap-approval.v1.json')));
 const original=loadMigrationPlan({CF_STAGING_SCHEMA_PLAN_SHA256:approval.execution_plan_sha256},base);
 assert.deepEqual(plan.checkpoints.slice(0,38),original.checkpoints.slice(0,38),'Preserve original adopted checkpoint 37');
 assert.deepEqual(plan.files.slice(0,2),original.files.slice(0,2));
 const expected=[original.files[0],...baseline.application_schema_files.map(f=>({file:f.path,sha256:f.sha256}))];
 assert.deepEqual(plan.files.map(f=>({file:f.file,sha256:f.sha256})),expected.map(f=>({file:f.file,sha256:f.sha256})));
 const objects=plan.schemas[plan.checkpoints.at(-1).schema_sha256].objects.map(([type,name,tbl_name,sql])=>({type,name,tbl_name,sql})).filter(o=>!o.name.startsWith('staging_'));
 assert.equal(digest(canonical(objects)),baseline.schema_sha256);assert.deepEqual(objectCounts(objects),baseline.object_counts);
 return {plan,sha256:hash(bytes),endStep:plan.checkpoints.length-1};
}
export async function verifyProductionBaseline(DB,baseline){
 const local=new DatabaseSync(':memory:');let expected;
 try{for(const f of [{path:'staging/schema.sql'},...baseline.application_schema_files])local.exec(fs.readFileSync(path.join(project,f.path),'utf8'));expected=canonical(local.prepare(schemaSQL).all());}finally{local.close();}
 const rows=(await DB.prepare(schemaSQL).all()).results;
 assert.deepEqual(canonical(rows),expected,'Installed schema differs from reviewed production plus staging support objects');
 const application=rows.filter(o=>!o.name.startsWith('staging_'));
 assert.equal(digest(canonical(application)),baseline.schema_sha256,'Installed schema differs from production');
 assert.deepEqual(objectCounts(application),baseline.object_counts);
 const receipts=(await DB.prepare('SELECT path,sha256,manifest_version FROM staging_schema_history ORDER BY rowid').all()).results;
 const staged=JSON.parse(fs.readFileSync(path.join(project,'staging/migrations.v1.json'))).entries[0];
 assert.deepEqual(receipts.map(r=>({...r})),[staged,...baseline.application_schema_files].map(f=>({path:f.path,sha256:f.sha256,manifest_version:1})),'Unexpected migration receipts');
 assert.equal(Number((await DB.prepare('SELECT COUNT(*) n FROM pragma_foreign_key_check').first()).n),0);
 return {schema_complete:true,profile:baseline.profile,objects:application.length};
}
