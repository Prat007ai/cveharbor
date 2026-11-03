import assert from 'node:assert/strict';import {backendIdentity} from './build_release_identity.mjs';import {verifyFrontendBackend} from './verify_frontend_backend.mjs';
if(process.env.RECOVERY_RELEASE!=='true')console.log(JSON.stringify(await verifyFrontendBackend()));
else{
 const r=await fetch('https://api.cveharbor.com/v1/release-readiness?check='+crypto.randomUUID(),{signal:AbortSignal.timeout(15000),redirect:'error',headers:{'Cache-Control':'no-cache'}});const d=await r.json();
 assert.equal(r.status,503);assert.equal(d.release,backendIdentity());assert.equal(d.held,true);assert.equal(d.schema_ready,true);assert.equal(d.ready,false);
 console.log('Compatible recovery backend deployed; write hold retained; frontend publication remains blocked.');
}
