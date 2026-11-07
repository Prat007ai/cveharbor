// Corruption tests touch only ignored local build outputs and always restore them.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {verifyArtifact,output} from './customer-candidate-artifact.mjs';
const original=verifyArtifact();
for(const relative of ['api.mjs','site.mjs','seal.json','manifest.json','public/customer-remediation-ui.js']){
 const file=path.join(output,relative),bytes=fs.readFileSync(file);
 try{fs.appendFileSync(file,'\ncorrupted-test-artifact');assert.throws(()=>verifyArtifact(),relative+' must reject corruption');}
 finally{fs.writeFileSync(file,bytes);}
}
assert.equal(verifyArtifact().seal_sha256,original.seal_sha256);
console.log('PASS: exact source/profile seal and corrupted backend/frontend/manifest/seal rejection.');
