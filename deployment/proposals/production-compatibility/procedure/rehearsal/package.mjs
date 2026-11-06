// Local encryption only: reuse the established CMS implementation; no export API.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {encrypt,hash} from '../../../../../staging/recovery/crypto.mjs';
import {target} from '../build.mjs';
import {verifyStorage} from './storage-policy.mjs';
export function encryptPackage(source,destination,certificateFile,fingerprint,storage){
 verifyStorage(storage,target.private_destination);
 assert.equal(storage.recipient_fingerprint_sha256,fingerprint,'Approved custody recipient');
 const base=fs.realpathSync(target.private_destination),input=fs.realpathSync(source),directory=fs.realpathSync(path.dirname(destination));
 for(const p of [input,directory]){const r=path.relative(base,p);assert.ok(r&&!r.startsWith('..')&&!path.isAbsolute(r),'Private storage only');}
 assert.ok(!fs.lstatSync(destination,{throwIfNoEntry:false}),'Never overwrite a recovery package or follow an output symlink');
 assert.ok(fs.statSync(source).size<=1000000000,'Package exceeds approved ceiling');
 // Windows ACL/custody/exclusions are operator evidence; chmod is not an ACL check.
 // Disk encryption is unverified and explicitly excepted, never implicitly verified.
 encrypt(input,destination,fs.readFileSync(certificateFile,'utf8'),fingerprint,directory);
 return {ciphertext_sha256:hash(fs.readFileSync(destination)),plaintext_deleted:false};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{assert.equal(process.env.REHEARSAL_PRIVATE_STORAGE_VERIFIED,'true');const args=process.argv.slice(2);assert.equal(args.length,5);const storage=JSON.parse(fs.readFileSync(args.pop(),'utf8'));console.log(JSON.stringify(encryptPackage(...args,storage)));}
 catch{console.error('STOP: private package encryption failed; preserve files and investigate.');process.exitCode=1;}
}
