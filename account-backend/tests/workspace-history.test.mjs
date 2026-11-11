import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
import {captureWorkspaceHistory,captureSQL,readWorkspaceHistory} from '../src/workspace-history.js';
import {workspaceRoute} from '../src/workspace-summary.js';
import {recoveryGuardSQL,normalizedDDL} from '../src/recovery-schema.js';
import worker from '../src/index.js';

const migration=fs.readFileSync(new URL('../../deployment/proposals/workspace-history/schema.sql',import.meta.url),'utf8');
function setup(){
 const sql=new DatabaseSync(':memory:');
 for(const file of ['schema.sql','inventory-schema.sql','finding-status-schema.sql','migrations/0032_recovery_control.sql'])sql.exec(fs.readFileSync(new URL('../'+file,import.meta.url),'utf8'));
 sql.exec(`INSERT INTO users(id,email) VALUES('a','a@example.test'),('b','b@example.test'),('empty','empty@example.test');
 INSERT INTO inventory_customers(id,user_id,name) VALUES('ca','a','Fictional A'),('cb','b','Fictional B');
 INSERT INTO inventory_environments(id,user_id,customer_id,name) VALUES('ea','a','ca','A'),('eb','b','cb','B');
 INSERT INTO inventory_assets(id,user_id,environment_id,name,asset_type,technology) VALUES('aa','a','ea','A','Server','Linux'),('ab','b','eb','B','Server','Linux');
 INSERT INTO customer_finding_statuses(user_id,asset_id,cve_id,status) VALUES
 ('a','aa','CVE-2026-10001','Needs Review'),('a','aa','CVE-2026-10002','Fix in Progress'),
 ('a','aa','CVE-2026-10003','Fixed/Patched'),('a','aa','CVE-2026-10004','Accepted Risk'),
 ('a','aa','CVE-2026-10005','Not Applicable'),('b','ab','CVE-2026-20001','Needs Review');`);
 const DB={sql,prepare(query){const s=sql.prepare(query);const q=args=>({bind:(...v)=>q(v),all:async()=>({success:true,results:s.all(...args)}),first:async()=>s.get(...args),run:async()=>({success:true,meta:s.run(...args)})});return q([]);}};
 return {DB,WORKSPACE_HISTORY_ENABLED:'true'};
}
const rows=env=>env.DB.sql.prepare('SELECT * FROM workspace_finding_daily_snapshots ORDER BY user_id').all();
test('additive DDL preserves every existing object and record, adds exact recovery guards',()=>{
 const env=setup(),db=env.DB.sql,before=db.prepare("SELECT name,sql FROM sqlite_master ORDER BY name").all(),changes=db.prepare('SELECT total_changes() n').get().n;
 db.exec(migration);
 assert.equal(db.prepare('SELECT total_changes() n').get().n,changes);
 for(const row of before)assert.deepEqual(db.prepare('SELECT name,sql FROM sqlite_master WHERE name=?').get(row.name),row);
 assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(),[]);
 for(const op of ['insert','update','delete'])assert.equal(normalizedDDL(db.prepare('SELECT sql FROM sqlite_master WHERE name=?').get('recovery_hold_workspace_finding_daily_snapshots_'+op).sql),normalizedDDL(recoveryGuardSQL('workspace_finding_daily_snapshots',op)));
});
test('actual-day capture keeps five statuses separate, includes real zero and is retry safe',async()=>{
 const env=setup();env.DB.sql.exec(migration);await captureWorkspaceHistory(env);const first=rows(env);
 assert.equal(first.length,3);assert.equal(first[0].needs_review,1);assert.equal(first[0].in_progress,1);assert.equal(first[0].fixed,1);assert.equal(first[0].accepted_risk,1);assert.equal(first[0].not_applicable,1);assert.equal(first[0].inventory_records,1);assert.equal(first[2].needs_review,0);
 assert.equal(first[0].day,env.DB.sql.prepare("SELECT date('now') d").get().d);assert.equal(first[0].captured_at.slice(0,10),first[0].day);
 env.DB.sql.exec("UPDATE customer_finding_statuses SET status='Fixed/Patched'");await Promise.all([captureWorkspaceHistory(env),captureWorkspaceHistory(env)]);assert.deepEqual(rows(env),first);
});
test('ownership joins exclude malformed cross-account links',async()=>{
 const env=setup();env.DB.sql.exec(migration);env.DB.sql.exec(`INSERT INTO customer_finding_statuses(user_id,asset_id,cve_id,status) VALUES('a','ab','CVE-2026-30001','Needs Review');
 INSERT INTO inventory_environments(id,user_id,customer_id,name) VALUES('bad','a','cb','Cross-owned');
 INSERT INTO inventory_assets(id,user_id,environment_id,name,asset_type,technology) VALUES('bad','a','bad','Bad','Server','Linux');
 INSERT INTO customer_finding_statuses(user_id,asset_id,cve_id,status) VALUES('a','bad','CVE-2026-30002','Needs Review');`);
 await captureWorkspaceHistory(env);assert.equal(rows(env)[0].needs_review,1);assert.equal(rows(env)[0].inventory_records,1);
});
test('capture is atomic on failure, honors frozen storage, and disabled mode never touches DB',async()=>{
 const env=setup();env.DB.sql.exec(migration);env.DB.sql.exec("CREATE TRIGGER fail_capture BEFORE INSERT ON workspace_finding_daily_snapshots WHEN NEW.user_id='b' BEGIN SELECT RAISE(ABORT,'fixture failure');END");
 await assert.rejects(captureWorkspaceHistory(env),/fixture failure/);assert.equal(rows(env).length,0);
 env.DB.sql.exec('DROP TRIGGER fail_capture; UPDATE operations_control SET write_hold=1,database_frozen=1 WHERE id=1');
 await assert.rejects(captureWorkspaceHistory(env),/recovery write hold/);assert.equal(rows(env).length,0);
 assert.deepEqual(await captureWorkspaceHistory({WORKSPACE_HISTORY_ENABLED:'false'}),{enabled:false});
});
test('read endpoint is authenticated, account-scoped, bounded and never writes',async()=>{
 const env=setup();env.DB.sql.exec(migration);await captureWorkspaceHistory(env);
 env.DB.sql.exec("UPDATE workspace_finding_daily_snapshots SET day=date('now','-40 days'),captured_at=date('now','-40 days')||'T00:05:00Z' WHERE user_id='b'");
 const before=env.DB.sql.prepare('SELECT total_changes() n').get().n,req=new Request('https://api.cveharbor.com/v1/workspace/trend?user_id=b');
 const response=await workspaceRoute(req,env,{id:'a'}),data=await response.json();assert.equal(response.headers.get('Cache-Control'),'no-store');assert.equal(data.rows.length,1);assert.equal(data.rows[0].needs_review,1);assert.equal(data.rows[0].user_id,undefined);
 assert.equal((await readWorkspaceHistory(env,'b')).rows.length,0);assert.equal(env.DB.sql.prepare('SELECT total_changes() n').get().n,before);
 assert.equal((await workspaceRoute(req,env,null)).status,401);assert.equal((await workspaceRoute(new Request(req,{method:'POST'}),env,{id:'a'})).status,405);
 env.DB.sql.exec('DROP TABLE workspace_finding_daily_snapshots');assert.deepEqual((await readWorkspaceHistory(env,'a')).rows,[]);assert.equal((await readWorkspaceHistory(env,'a')).available,false);
 assert.doesNotMatch(captureSQL,/scheduledTime|INSERT OR REPLACE|UPDATE workspace/i);
});
test('shipped hourly schedule captures today under its recovery lease and skips a write hold',async()=>{
 const env=setup();env.RECOVERY_CONTROL_REQUIRED='true';env.DB.sql.exec(migration);
 env.DB.sql.exec('UPDATE operations_control SET write_hold=1 WHERE id=1');
 await worker.scheduled({cron:'5 * * * *',scheduledTime:0},env,{});assert.equal(rows(env).length,0);
 env.DB.sql.exec('UPDATE operations_control SET write_hold=0 WHERE id=1');
 await worker.scheduled({cron:'5 * * * *',scheduledTime:0},env,{});assert.equal(rows(env).length,3);
 assert.equal(rows(env)[0].day,new Date().toISOString().slice(0,10),'Delayed events must not backdate observations');
 assert.equal(env.DB.sql.prepare('SELECT COUNT(*) n FROM operations_leases').get().n,0);
});
