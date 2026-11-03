import assert from 'node:assert/strict';import {d1Client} from './cloudflare_d1.mjs';import {verifyIntegrity} from './verify_remediation_integrity_d1.mjs';import {holdStatus} from './recovery_control.mjs';
const phase=process.env.AUDIT_PHASE||'preflight';assert.ok(['preflight','installed'].includes(phase));const DB=d1Client({readOnly:true});
const result=await verifyIntegrity(DB,{preflight:phase==='preflight'});
const foreignKeys=Number((await DB.prepare('SELECT COUNT(*) n FROM pragma_foreign_key_check').first()).n);
const recovery=phase==='installed'?await holdStatus(DB):null;
console.log(JSON.stringify({...result,foreign_key_violations:foreignKeys,recovery,queries:DB.queries,rows_written:0}));
if(!result.ok||foreignKeys||recovery&&!recovery.guards_complete)process.exitCode=1;
