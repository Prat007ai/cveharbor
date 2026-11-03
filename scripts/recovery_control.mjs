import assert from 'node:assert/strict';import path from 'node:path';import {fileURLToPath} from 'node:url';
import {d1Client} from './cloudflare_d1.mjs';import {recoveryCoverage} from '../account-backend/src/release-readiness.js';
import {verifyIntegrity} from './verify_remediation_integrity_d1.mjs';
import {recoveryTablesSQL as tablesSQL,recoveryGuardSQL as guardSQL} from '../account-backend/src/recovery-schema.js';
export {guardSQL};
export async function installGuards(DB){const tables=(await DB.prepare(tablesSQL).all()).results;const statements=tables.flatMap(({name})=>['insert','update','delete'].map(op=>DB.prepare(guardSQL(name,op))));for(let i=0;i<statements.length;i+=30)await DB.batch(statements.slice(i,i+30));assert.equal(await recoveryCoverage(DB),true);return {guarded_tables:tables.length};}
export async function holdStatus(DB){const state=await DB.prepare('SELECT write_hold,database_frozen,revision FROM operations_control WHERE id=1').first();assert.ok(state,'Recovery control missing');const leases=await DB.prepare('SELECT count(*) n FROM operations_leases').first();return {...state,active_leases:Number(leases.n),guards_complete:await recoveryCoverage(DB)};}
export async function setHold(DB,{hold,revision,reason}){
 assert.ok(Number.isSafeInteger(revision)&&revision>=0,'Expected revision is required');assert.ok(typeof reason==='string'&&reason.trim().length>=10&&reason.length<=500,'An operational reason of 10–500 characters is required');
 const before=await holdStatus(DB);assert.equal(before.guards_complete,true,'Install every table guard first');assert.equal(before.revision,revision,'Control changed; inspect status again');
 if(!hold){assert.equal(before.write_hold,1,'No active hold to resume');assert.equal(before.active_leases,0,'Active/stale leases require investigation, not automatic expiry');assert.equal((await verifyIntegrity(DB)).ok,true,'Resolve integrity failures before resuming');assert.equal(Number((await DB.prepare('SELECT COUNT(*) n FROM pragma_foreign_key_check').first()).n),0,'Resolve foreign-key violations before resuming');}
 const r=await DB.prepare('UPDATE operations_control SET write_hold=?,database_frozen=CASE WHEN ?=0 THEN 0 ELSE database_frozen END,revision=revision+1,reason=?,changed_at=CURRENT_TIMESTAMP WHERE id=1 AND revision=?').bind(hold?1:0,hold?1:0,reason.trim(),revision).run();assert.equal(r.meta.changes,1,'Control changed concurrently');return holdStatus(DB);
}
export async function freezeHold(DB,{revision,reason}){
 assert.ok(Number.isSafeInteger(revision)&&revision>=0);assert.ok(typeof reason==='string'&&reason.trim().length>=10&&reason.length<=500);
 const before=await holdStatus(DB);assert.equal(before.guards_complete,true);assert.equal(before.write_hold,1,'Stop admission before freezing');assert.equal(before.active_leases,0,'Wait for every background operation to finish; never expire leases automatically');
 const r=await DB.prepare('UPDATE operations_control SET database_frozen=1,revision=revision+1,reason=?,changed_at=CURRENT_TIMESTAMP WHERE id=1 AND revision=? AND write_hold=1 AND NOT EXISTS(SELECT 1 FROM operations_leases)').bind(reason.trim(),revision).run();assert.equal(r.meta.changes,1,'Control changed concurrently');return holdStatus(DB);
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const action=process.argv[2]||'status';assert.ok(['status','install','hold','freeze','resume'].includes(action),'Choose status/install/hold/freeze/resume');
 if(['hold','freeze','resume'].includes(action))assert.match(process.env.EXPECTED_HOLD_REVISION||'',/^\d+$/,'Explicit expected revision required');
 const DB=d1Client({readOnly:action==='status'});
 const result=action==='status'?await holdStatus(DB):action==='install'?await installGuards(DB):action==='freeze'?await freezeHold(DB,{revision:Number(process.env.EXPECTED_HOLD_REVISION),reason:process.env.RECOVERY_REASON}):await setHold(DB,{hold:action==='hold',revision:Number(process.env.EXPECTED_HOLD_REVISION),reason:process.env.RECOVERY_REASON});
 console.log(JSON.stringify(result));
 // A hold command succeeds in activating the hold even when work is still draining.
 // Recovery must independently require active_leases=0. There is no forced expiry.
}
