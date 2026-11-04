// Admission gate for every credentialed production writer workflow; SELECTs only.
import assert from 'node:assert/strict';import {d1Client} from './cloudflare_d1.mjs';import {holdStatus} from './recovery_control.mjs';
const DB=d1Client({readOnly:true});const installed=await DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='operations_control'").first();
if(installed){const state=await holdStatus(DB);if(process.env.RECOVERY_RELEASE==='true'){assert.equal(state.write_hold,1);assert.equal(state.database_frozen,1);assert.equal(state.active_leases,0);assert.equal(state.guards_complete,true);}else assert.equal(state.write_hold,0,'Recovery hold active: production writer workflow blocked');}
else assert.notEqual(process.env.RECOVERY_RELEASE,'true','Recovery controls are not installed');
console.log('Read-only production workflow hold check passed.');
