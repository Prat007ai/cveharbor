import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import worker from '../src/index.js';
import {releaseReadiness} from '../src/release-readiness.js';
import {integrityChecks} from '../src/release-integrity-checks.js';
import {recoveryProtected} from '../src/recovery-control.js';
import {unifiedFixture,assetOne,assetOther} from './helpers/unified-db.mjs';
import {fixtureCve as cve} from './helpers/assignment-db.mjs';
import {holdStatus,setHold,freezeHold,installGuards} from '../../scripts/recovery_control.mjs';
import {baselineDB,baseline,applyLocally,proposedSQL,schemaHash,read,evidence} from '../../deployment/proposals/production-compatibility/rehearsal.mjs';

const quote=s=>'"'+s.replaceAll('"','""')+'"';
const snapshot=db=>Object.fromEntries(db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'operations_%' ORDER BY name").all().map(({name})=>[name,db.prepare('SELECT * FROM '+quote(name)).all()]));
async function fixture(t){
 const f=await unifiedFixture(),old=f.DB.sql,db=baselineDB();
 // Transfer fictional fixtures only. The target contains the complete audited schema.
 db.exec('BEGIN; PRAGMA defer_foreign_keys=ON');
 for(const {name} of old.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").all())for(const row of old.prepare('SELECT * FROM '+quote(name)).all()){
  const keys=Object.keys(row);db.prepare('INSERT INTO '+quote(name)+'('+keys.map(quote).join(',')+') VALUES('+keys.map(()=>'?').join(',')+')').run(...keys.map(k=>row[k]));
 }
 db.exec('COMMIT');old.close();f.DB.sql=db;f.env.RECOVERY_CONTROL_REQUIRED='true';
 const native=globalThis.fetch;globalThis.fetch=f.fetcher;t.after(()=>{globalThis.fetch=native;db.close();});
 f.call=async(path,method='GET',data,account='a')=>{const pending=[];const response=await worker.fetch(f.request(path,method,data,account),f.env,{waitUntil:p=>pending.push(p)});await Promise.all(pending);return response;};
 return f;
}
const resume=f=>setHold(f.DB,{hold:false,revision:0,reason:'Fictional local acceptance complete'});

test('complete audited schema reproduces live failure before any application writes or mail',async t=>{
 const f=await fixture(t),before=snapshot(f.DB.sql),changes=f.DB.sql.prepare('SELECT total_changes() n').get().n;
 assert.equal(schemaHash(f.DB.sql),baseline.schema_sha256);
 assert.throws(()=>f.DB.sql.prepare('SELECT write_hold,revision FROM operations_control WHERE id=1').get(),/no such table/);
 const readiness=await releaseReadiness(f.env);assert.equal(readiness.status,503);assert.deepEqual(Object.fromEntries(Object.entries(await readiness.json()).filter(([k])=>['ready','held','schema_ready'].includes(k))),{ready:false,held:true,schema_ready:false});
 for(const route of ['/health','/me','/remediations'])assert.equal((await f.call(route)).status,503);
 for(const cron of ['* * * * *','*/5 * * * *','5 * * * *'])await worker.scheduled({cron},f.env,{waitUntil:()=>assert.fail('Blocked scheduler')});
 assert.deepEqual(snapshot(f.DB.sql),before);assert.equal(f.DB.sql.prepare('SELECT total_changes() n').get().n,changes);assert.equal(f.emails.length,0);
});

test('operations_control alone and an unguarded recovery migration do not establish compatibility',async t=>{
 const f=await fixture(t),migration=read('account-backend/migrations/0032_recovery_control.sql');
 f.DB.sql.exec(migration.slice(0,migration.indexOf('CREATE TABLE IF NOT EXISTS operations_leases')));
 assert.equal((await releaseReadiness(f.env)).status,503);
 assert.equal((await f.call('/health')).status,503,'Control alone cannot acquire a lease');
 f.DB.sql.exec(migration);
 assert.equal((await releaseReadiness(f.env)).status,503);assert.equal((await holdStatus(f.DB)).guards_complete,false);
 // Default-open upstream migration can admit a health request while readiness fails.
 assert.equal((await f.call('/health')).status,200);
 assert.throws(()=>applyLocally(f.DB.sql),/Unknown\/partial/);
});

test('proposal preserves existing rows and objects, starts frozen, and requires explicit local resume',async t=>{
 const f=await fixture(t),before=snapshot(f.DB.sql);applyLocally(f.DB.sql);
 for(const [table,rows] of Object.entries(before))assert.deepEqual(f.DB.sql.prepare('SELECT * FROM '+quote(table)).all(),rows,table);
 const state=await holdStatus(f.DB);assert.equal(state.write_hold,1);assert.equal(state.database_frozen,1);assert.equal(state.active_leases,0);assert.equal(state.guards_complete,true);
 const r=await(await releaseReadiness(f.env)).json();assert.equal(r.held,true);assert.equal(r.schema_ready,true);assert.equal(r.ready,false);
 assert.equal((await f.call('/health')).status,503);assert.equal(f.emails.length,0);
 assert.throws(()=>f.DB.sql.exec("UPDATE remediations SET owner='blocked'"),/recovery write hold/);
 await resume(f);assert.equal((await releaseReadiness(f.env)).status,200);
 assert.throws(()=>applyLocally(f.DB.sql),/Unknown\/partial/);
 assert.equal(evidence().preserved_baseline_objects,143);
 assert.equal(fs.readFileSync(new URL('../../deployment/proposals/production-compatibility/proposed-repair.sql',import.meta.url),'utf8'),proposedSQL());
});

test('missing guards, missing control rows and unknown schema stop readiness or execution',async t=>{
 const f=await fixture(t);applyLocally(f.DB.sql);await resume(f);
 f.DB.sql.exec('DROP TRIGGER validate_finding_write');assert.equal((await releaseReadiness(f.env)).status,503);
 f.DB.sql.exec(read('account-backend/migrations/0031_remediation_integrity.sql'));
 f.DB.sql.exec('CREATE TABLE unreviewed(id TEXT)');assert.equal((await releaseReadiness(f.env)).status,503);
 f.DB.sql.exec('DELETE FROM operations_control');assert.equal((await f.call('/health')).status,503);
});

test('interrupted preparation remains closed and cannot be blindly reapplied',async t=>{
 const f=await fixture(t);f.DB.sql.exec(read('account-backend/migrations/0031_remediation_integrity.sql'));
 assert.equal((await f.call('/health')).status,503);assert.throws(()=>applyLocally(f.DB.sql),/Unknown\/partial/);
 const held=read('account-backend/migrations/0032_recovery_control.sql').replace('INSERT OR IGNORE INTO operations_control(id) VALUES(1);',"INSERT INTO operations_control(id,write_hold,database_frozen) VALUES(1,1,1);");
 f.DB.sql.exec(held);assert.equal((await f.call('/health')).status,503);assert.equal((await holdStatus(f.DB)).guards_complete,false);
 await assert.rejects(()=>setHold(f.DB,{hold:false,revision:0,reason:'Must remain closed until verified'}),/guard/);
});

test('lease covers background effects; freeze/resume reject active or stale leases',async t=>{
 const f=await fixture(t);applyLocally(f.DB.sql);await resume(f);
 let finish;const background=new Promise(r=>finish=r),pending=[];
 const app=recoveryProtected({async fetch(req,env,ctx){ctx.waitUntil(background);return new Response('fictional');},async scheduled(){assert.fail('Blocked schedule');}});
 await app.fetch(new Request('https://api.cveharbor.com/test'),f.env,{waitUntil:p=>pending.push(p)});
 const state=await setHold(f.DB,{hold:true,revision:1,reason:'Fictional interruption rehearsal'});assert.equal(state.active_leases,1);
 f.DB.sql.exec("UPDATE operations_leases SET started_at='2000-01-01'");
 await assert.rejects(()=>freezeHold(f.DB,{revision:2,reason:'Cannot freeze an active lease'}),/background/);
 await assert.rejects(()=>setHold(f.DB,{hold:false,revision:2,reason:'Cannot expire a stale lease'}),/leases/);
 finish();await Promise.all(pending);assert.equal((await holdStatus(f.DB)).active_leases,0);
 await freezeHold(f.DB,{revision:2,reason:'Fictional background work drained'});
 await app.scheduled({},f.env,{});assert.equal((await f.call('/health')).status,503);
});

test('authentication, MFA and tenant boundaries survive the proposed repair',async t=>{
 const f=await fixture(t);applyLocally(f.DB.sql);await resume(f);
 assert.equal((await f.call('/me','GET',null,null)).status,401);
 assert.equal((await f.call('/me')).status,200);
 f.DB.sql.exec("UPDATE user_totp SET enabled=0 WHERE user_id='a'");assert.notEqual((await f.call('/remediations')).status,200);
 f.DB.sql.exec("UPDATE user_totp SET enabled=1 WHERE user_id='a'");
 const a=await(await f.call('/remediations')).json(),b=await(await f.call('/remediations','GET',null,'b')).json();
 assert.equal(a.remediations.length,1);assert.equal(b.remediations.length,0);
 assert.equal((await f.call('/remediations?customer_id=c-'+assetOther)).status,404);
 assert.equal((await f.call('/remediation-records/'+cve,'GET',null,'b')).status,404);
 const original=f.DB.sql.prepare("SELECT * FROM remediations WHERE user_id='a'").all();
 // An unassigned CVE key is scoped by user; another tenant may create its own.
 assert.equal((await f.call('/remediations/'+cve,'PUT',{status:'Open',owner:'Tenant B engineer'},'b')).status,200);
 assert.deepEqual(f.DB.sql.prepare("SELECT * FROM remediations WHERE user_id='a'").all(),original);
 assert.equal(f.DB.sql.prepare("SELECT owner FROM remediations WHERE user_id='b' AND cve_id=?").get(cve).owner,'Tenant B engineer');
});

test('existing remediation IDs/history remain; optional customer-only records stay explicitly unavailable',async t=>{
 const f=await fixture(t);applyLocally(f.DB.sql);await resume(f);
 assert.equal((await(await f.call('/remediations/features')).json()).customer_records_available,false);
 const data={cve_id:cve,customer_id:'c-'+assetOne,status:'Open',owner:'Fictional engineer',due:'2026-12-15',notes:'Fictional'};
 assert.equal((await f.call('/customer-remediations','POST',data)).status,503);
 const row=(await(await f.call('/remediations')).json()).remediations[0];
 assert.equal((await f.call('/remediations/'+cve,'PUT',{...row,status:'Remediated',expected_updated:row.updated,status_change_reason:'Fictional patch verified'})).status,200);
 assert.equal((await(await f.call('/remediations')).json()).remediations[0].id,cve);
 assert.equal((await(await f.call('/remediations/'+cve+'/status-history')).json()).changes.length,1);
 assert.deepEqual(f.DB.sql.prepare('PRAGMA foreign_key_check').all(),[]);
});

test('optional customer schema needs freeze guards AND a customer-aware integrity contract',async t=>{
 const f=await fixture(t);applyLocally(f.DB.sql);await resume(f);
 f.DB.sql.exec(read('deployment/proposals/customer-remediation/schema.sql'));
 assert.equal((await releaseReadiness(f.env)).status,503,'New tables invalidate freeze coverage');
 await installGuards(f.DB);assert.equal((await releaseReadiness(f.env)).status,200);
 assert.equal((await(await f.call('/remediations/features')).json()).customer_records_available,true);
 const response=await f.call('/customer-remediations','POST',{cve_id:cve,customer_id:'c-'+assetOne,status:'Open',owner:'Fictional engineer',due:'2026-12-15',notes:'Fictional'});
 assert.equal(response.status,200,JSON.stringify(await response.clone().json()));
 const record=await response.json();assert.ok(record.id.includes('~'));
 assert.equal(f.DB.sql.prepare(integrityChecks.detached_asset_records).get().n,1);
 assert.equal((await releaseReadiness(f.env)).status,503,'Valid customer-only records conflict with the current asset-only integrity predicate');
 assert.equal((await f.call('/remediation-records/'+record.id,'GET',null,'b')).status,404);
});
