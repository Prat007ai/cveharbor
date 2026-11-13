// Additive migration through the existing protected customer-schema lane.
// No holds, recovery operations, deletions or application record rewrites.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {capacityFixture} from '../account-backend/tests/helpers/capacity-db.mjs';
import {canonical,schemaSQL,digest,PRODUCTION_DB} from './production_schema_baseline.mjs';
import {d1Client} from './cloudflare_d1.mjs';
import {holdStatus} from './recovery_control.mjs';
import {verifyService} from './production_service_health.mjs';
const account='aa99b9b15e0492302e4f6484b8d27bc2';
const predecessor='0b15e96eb98e5d1a2f7e2961e858886c62c632f7eaed1b02d7241a0e7ff34a34';
const sql=fs.readFileSync('account-backend/inventory-capacity-schema.sql','utf8').replaceAll('\r\n','\n');
const hash=fs.readFileSync('release/inventory-capacity-schema.txt','utf8').trim();assert.equal(digest(sql),hash);
const fixture=capacityFixture({owners:0,customers:0,environments:0,assets:0});
const expected=fixture.sql.prepare(schemaSQL).all();fixture.close();
const isAdded=o=>/^(?:inventory_capacity_|capacity_|idx_capacity_|recovery_hold_inventory_capacity_)/.test(o.name);
const added=expected.filter(isAdded),names=new Set(added.map(o=>o.name));
assert.equal(added.filter(o=>o.type==='table').length,2);assert.equal(added.filter(o=>o.type==='trigger').length,40);
const dependencies=new Set(['users','operations_control','inventory_customers','inventory_environments','inventory_assets','customer_finding_statuses','customer_finding_ticket_history','plugin_source_mappings','plugin_installation_status','plugin_monitor_checks','plugin_release_checks','inventory_server_network','inventory_packages']);
const dependent=rows=>canonical(rows.filter(o=>o.type==='table'&&dependencies.has(o.name)));
assert.equal(dependent(expected).length,dependencies.size);
if(process.argv[2]==='--apply'){
 assert.equal(process.env.GITHUB_REF,'refs/heads/main');assert.match(process.env.GITHUB_SHA||'',/^[a-f0-9]{40}$/);assert.equal(process.env.CLOUDFLARE_ACCOUNT_ID,account);
 const db=d1Client({database:PRODUCTION_DB,readOnly:false}),metadata=await db.metadata();assert.equal(metadata.uuid,PRODUCTION_DB);assert.equal(metadata.name,'cveharbor-accounts');
 const control=await holdStatus(db);assert.equal(control.write_hold,0);assert.equal(control.database_frozen,0);assert.equal(control.guards_complete,true);
 await verifyService({expectedRelease:predecessor});
 const before=(await db.prepare(schemaSQL).all()).results;assert.deepEqual(dependent(before),dependent(expected),'Live prerequisite definitions differ');
 assert.equal((await db.prepare('SELECT count(*) n FROM pragma_foreign_key_check').first()).n,0);
 assert.ok((await db.prepare('SELECT COALESCE(MAX(n),0) n FROM (SELECT COUNT(*) n FROM inventory_assets GROUP BY user_id)').first()).n<=50000);
 const receipt={commit:process.env.GITHUB_SHA,database_id:PRODUCTION_DB,sql_sha256:hash,predecessor,status:'preflight',started_at:new Date().toISOString(),before_schema_sha256:digest(canonical(before))};
 const save=()=>fs.writeFileSync('inventory-capacity-migration.json',JSON.stringify(receipt,null,2)+'\n');save();
 const existing=before.filter(o=>names.has(o.name));
 if(existing.length){assert.deepEqual(canonical(existing),canonical(added),'Partial or incompatible migration; inspect without retry');receipt.status='already_present';}
 else{
  const response=await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/d1/database/${PRODUCTION_DB}/time_travel/bookmark`,{headers:{Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN},redirect:'error',signal:AbortSignal.timeout(20000)});
  const data=await response.json();assert.ok(response.ok&&data.success&&typeof data.result?.bookmark==='string');receipt.recovery_bookmark=data.result.bookmark;receipt.status='ready';save();
  const admission="SELECT CASE WHEN EXISTS(SELECT 1 FROM operations_control WHERE id=1 AND write_hold=0 AND database_frozen=0 AND revision=?) THEN 1 ELSE abs(-9223372036854775808) END";
  receipt.status='applying';save();await db.batch([db.prepare(admission).bind(control.revision),db.prepare(sql)]);receipt.status='applied_pending_verification';save();
 }
 const after=(await db.prepare(schemaSQL).all()).results;
 assert.deepEqual(canonical(after.filter(o=>names.has(o.name))),canonical(added));
 assert.deepEqual(canonical(after.filter(o=>!names.has(o.name))),canonical(before.filter(o=>!names.has(o.name))),'Existing schema changed');
 assert.equal((await db.prepare('SELECT version FROM inventory_capacity_schema').first()).version,1);
 assert.equal((await db.prepare('SELECT count(*) n FROM pragma_foreign_key_check').first()).n,0);
 const mismatch="SELECT COUNT(*) n FROM users u LEFT JOIN inventory_capacity_revisions r ON r.user_id=u.id LEFT JOIN (SELECT user_id,COUNT(*) n FROM inventory_assets GROUP BY user_id) a ON a.user_id=u.id WHERE COALESCE(r.software_count,0)!=COALESCE(a.n,0)";
 assert.equal((await db.prepare(mismatch).first()).n,0,'Counter verification failed; do not activate the new backend');
 assert.equal((await holdStatus(db)).guards_complete,true);await verifyService({expectedRelease:predecessor});
 receipt.status='verified';receipt.after_schema_sha256=digest(canonical(after));receipt.completed_at=new Date().toISOString();save();console.log('Verified additive capacity storage, counts, guards, foreign keys and unchanged serving backend.');
}else{
 assert.equal(process.argv[2],'--rehearse');console.log(JSON.stringify({sql_sha256:hash,tables:2,triggers:40,indexes:added.filter(o=>o.type==='index').length,existing_schema_changed:false}));
}
