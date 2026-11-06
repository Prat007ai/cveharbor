// Local encryption only: reuse the established CMS implementation; no export API.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {encrypt,hash} from '../../../../../staging/recovery/crypto.mjs';
import {target} from '../build.mjs';
export function encryptPackage(source,destination,certificateFile,fingerprint){
 const base=fs.realpathSync(target.private_destination),input=fs.realpathSync(source),directory=fs.realpathSync(path.dirname(destination));
 for(const p of [input,directory]){const r=path.relative(base,p);assert.ok(r&&!r.startsWith('..')&&!path.isAbsolute(r),'Private storage only');}
 assert.ok(!fs.lstatSync(destination,{throwIfNoEntry:false}),'Never overwrite a recovery package or follow an output symlink');
 assert.ok(fs.statSync(source).size<=1000000000,'Package exceeds approved ceiling');
 // Windows ACL, encrypted volume, offline private-key custody and unsynced path
 // are explicit operator prerequisites; chmod is not evidence of Windows ACLs.
 encrypt(input,destination,fs.readFileSync(certificateFile,'utf8'),fingerprint,directory);
 return {ciphertext_sha256:hash(fs.readFileSync(destination)),plaintext_deleted:false};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{assert.equal(process.env.REHEARSAL_PRIVATE_STORAGE_VERIFIED,'true');const args=process.argv.slice(2);assert.equal(args.length,4);console.log(JSON.stringify(encryptPackage(...args)));}
 catch{console.error('STOP: private package encryption failed; preserve files and investigate.');process.exitCode=1;}
}
