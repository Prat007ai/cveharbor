import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';
const action=process.env.RECOVERY_OPERATION;assert.ok(['status','hold','freeze','resume'].includes(action));
if(action!=='status')assert.match(process.env.EXPECTED_HOLD_REVISION||'',/^\d+$/,'Explicit expected revision required');
if(action!=='status'){
 // Older Workers have no leases; never declare their traffic drained by counting an empty table.
 const response=await fetch('https://api.cveharbor.com/v1/release-readiness?check='+crypto.randomUUID(),{signal:AbortSignal.timeout(15000),redirect:'error',headers:{'Cache-Control':'no-cache'}});
 assert.ok([200,503].includes(response.status),'Compatible recovery Worker must be reachable');const live=await response.json();
 assert.equal(live.schema,'phase1-integrity-recovery-v1','Deploy the compatible Worker before using recovery controls');assert.match(live.release||'',/^[a-f0-9]{64}$/);
 if(action!=='hold')assert.equal(live.held,true,'Admission must already be held');
}
const r=spawnSync(process.execPath,['scripts/recovery_control.mjs',action],{stdio:'inherit'});process.exit(r.status??1);
