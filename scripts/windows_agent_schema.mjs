// Additive migration through the existing protected customer-schema lane.
// No holds, recovery operations, deletions or application record rewrites.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {capacityFixture} from '../account-backend/tests/helpers/capacity-db.mjs';
import {canonical,schemaSQL,digest,PRODUCTION_DB} from './production_schema_baseline.mjs';
import {d1Client} from './cloudflare_d1.mjs';
import {holdStatus} from './recovery_control.mjs';
import {recoveryGuardSQL,normalizedDDL} from '../account-backend/src/recovery-schema.js';
import {verifyService} from './production_service_health.mjs';
const account='aa99b9b15e0492302e4f6484b8d27bc2';
const predecessor='611f3576f8b30323f6a2d0625891b102515f5ab8805d37c18801f4ba6cc54047';
const sql=fs.readFileSync('account-backend/agent-schema.sql','utf8').replaceAll('\r\n','\n');
const hash=fs.readFileSync('release/windows-agent-schema.txt','utf8').trim();assert.equal(digest(sql),hash);
const fixture=capacityFixture({owners:0,customers:0,environments:0,assets:0});
const original=fixture.sql.prepare(schemaSQL).all(),beforeWrites=fixture.sql.prepare('SELECT total_changes() n').get().n;
fixture.sql.exec(sql);assert.equal(fixture.sql.prepare('SELECT total_changes() n').get().n,beforeWrites);
const expected=fixture.sql.prepare(schemaSQL).all();
for(const item of original)assert.deepEqual(expected.find(x=>x.name===item.name),item);
fixture.close();
const isAdded=o=>/^(?:inventory_agent|recovery_hold_inventory_agent)/.test(o.name);
const added=expected.filter(isAdded),names=new Set(added.map(o=>o.name));
for(const item of added.filter(o=>o.type==='table'))for(const op of ['insert','update','delete'])assert.equal(normalizedDDL(added.find(o=>o.name==='recovery_hold_'+item.name+'_'+op)?.sql),normalizedDDL(recoveryGuardSQL(item.name,op)));
assert.equal(added.filter(o=>o.type==='table').length,8);assert.equal(added.filter(o=>o.type==='trigger').length,24);
const dependencies=new Set(['users','operations_control','inventory_customers','inventory_environments','inventory_assets','customer_finding_statuses','customer_finding_ticket_history','plugin_source_mappings','plugin_installation_status','plugin_monitor_checks','plugin_release_checks','inventory_server_network','inventory_packages','inventory_capacity_revisions']);
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
 const save=()=>fs.writeFileSync('windows-agent-migration.json',JSON.stringify(receipt,null,2)+'\n');save();
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
 assert.equal((await db.prepare('SELECT count(*) n FROM pragma_foreign_key_check').first()).n,0);
 const finalControl=await holdStatus(db);assert.equal(finalControl.guards_complete,true);assert.equal(finalControl.write_hold,0);assert.equal(finalControl.database_frozen,0);assert.equal(finalControl.revision,control.revision);
 await verifyService({expectedRelease:predecessor});
 receipt.status='verified';receipt.after_schema_sha256=digest(canonical(after));receipt.completed_at=new Date().toISOString();save();console.log('Verified additive agent storage, guards, foreign keys and unchanged serving backend.');
}else{
 assert.equal(process.argv[2],'--rehearse');console.log(JSON.stringify({sql_sha256:hash,tables:8,triggers:24,indexes:added.filter(o=>o.type==='index').length,existing_schema_changed:false}));
}
