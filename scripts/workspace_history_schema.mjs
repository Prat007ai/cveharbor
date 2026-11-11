// Invoked through the existing protected customer schema workflow only after owner approval.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
import {canonical,schemaSQL,digest,PRODUCTION_DB} from './production_schema_baseline.mjs';
import {d1Client} from './cloudflare_d1.mjs';
import {holdStatus} from './recovery_control.mjs';
import {verifyService} from './production_service_health.mjs';

const account='aa99b9b15e0492302e4f6484b8d27bc2';
const predecessor='3e7311dc8ffb33a06324b3e7f601f801139b6ea74f5d39323f5dbff221169991';
const sql=fs.readFileSync('deployment/proposals/workspace-history/schema.sql','utf8').replaceAll('\r\n','\n');
const hash='317c1d4a42ad569554ecaeee644d552d4bd1420037754861375721627418c8ce';
assert.equal(digest(sql),hash,'Only the reviewed exact SQL is permitted');
const local=new DatabaseSync(':memory:');
for(const file of ['schema.sql','inventory-schema.sql','finding-status-schema.sql','migrations/0032_recovery_control.sql'])local.exec(fs.readFileSync('account-backend/'+file,'utf8'));
const original=local.prepare(schemaSQL).all(),oldNames=new Set(original.map(r=>r.name));
const changes=local.prepare('SELECT total_changes() n').get().n;
local.exec(sql);
assert.equal(local.prepare('SELECT total_changes() n').get().n,changes,'DDL must not write application records');
const added=local.prepare(schemaSQL).all().filter(r=>!oldNames.has(r.name));
assert.equal(added.filter(r=>r.type==='table').length,1);assert.equal(added.filter(r=>r.type==='trigger').length,3);assert.equal(added.length,4);
const names=new Set(added.map(r=>r.name)),deps=new Set(['users','inventory_customers','inventory_environments','inventory_assets','customer_finding_statuses','operations_control']);
const dependent=rows=>canonical(rows.filter(r=>r.type==='table'&&deps.has(r.name)));
assert.equal(dependent(original).length,deps.size);local.close();

if(process.argv[2]==='--apply'){
 assert.equal(process.env.GITHUB_REF,'refs/heads/main');
 assert.match(process.env.GITHUB_SHA||'',/^[a-f0-9]{40}$/);
 assert.equal(process.env.CLOUDFLARE_ACCOUNT_ID,account);
 const db=d1Client({database:PRODUCTION_DB,readOnly:false}),metadata=await db.metadata();
 assert.equal(metadata.uuid,PRODUCTION_DB);assert.equal(metadata.name,'cveharbor-accounts');
 const state=await holdStatus(db);assert.equal(state.write_hold,0);assert.equal(state.database_frozen,0);assert.equal(state.guards_complete,true);
 await verifyService({expectedRelease:predecessor});
 const readSchema=async()=>(await db.prepare(schemaSQL).all()).results;
 const before=await readSchema();assert.deepEqual(dependent(before),dependent(original),'Live prerequisites differ: stop for review');
 assert.equal((await db.prepare('SELECT count(*) n FROM pragma_foreign_key_check').first()).n,0);
 const found=before.filter(r=>names.has(r.name));
 const receipt={commit:process.env.GITHUB_SHA,database_id:PRODUCTION_DB,sql_sha256:hash,predecessor,started_at:new Date().toISOString(),before_schema_sha256:digest(canonical(before)),status:'preflight'};
 const save=()=>fs.writeFileSync('workspace-history-migration.json',JSON.stringify(receipt,null,2)+'\n');save();
 if(found.length){
  assert.deepEqual(canonical(found),canonical(added),'Partial or incompatible migration: do not retry');
  receipt.status='already_present';
 }else{
  const response=await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/d1/database/${PRODUCTION_DB}/time_travel/bookmark`,{headers:{Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN},redirect:'error',signal:AbortSignal.timeout(20000)});
  assert.ok(response.ok,'Recovery bookmark unavailable');
  const result=await response.json();assert.equal(result.success,true);assert.ok(typeof result.result?.bookmark==='string'&&result.result.bookmark.length);
  receipt.recovery_bookmark=result.result.bookmark;receipt.status='ready_to_apply';save();
  const admission="SELECT CASE WHEN EXISTS (SELECT 1 FROM operations_control WHERE id=1 AND write_hold=0 AND database_frozen=0 AND revision=?) THEN 1 ELSE abs(-9223372036854775808) END";
  receipt.status='applying';save();
  // One transaction. A timeout is uncertain: inspect, never blindly retry or restore.
  await db.batch([db.prepare(admission).bind(state.revision),db.prepare(sql)]);
  receipt.status='applied_pending_verification';save();
 }
 const after=await readSchema();assert.deepEqual(canonical(after.filter(r=>names.has(r.name))),canonical(added));
 assert.deepEqual(canonical(after.filter(r=>!names.has(r.name))),canonical(before.filter(r=>!names.has(r.name))),'Existing schema changed');
 assert.equal((await db.prepare('SELECT count(*) n FROM pragma_foreign_key_check').first()).n,0);
 assert.equal((await holdStatus(db)).guards_complete,true);await verifyService({expectedRelease:predecessor});
 receipt.status='verified';receipt.after_schema_sha256=digest(canonical(after));receipt.completed_at=new Date().toISOString();save();
 console.log('Verified additive Workspace history storage, unchanged existing schema, recovery guards, foreign keys and serving backend.');
}else{
 assert.equal(process.argv[2],'--rehearse');
 console.log('Verified one additive history table and three existing-policy recovery guards; no application records changed. SQL SHA256 '+hash);
}
