import assert from 'node:assert/strict';import {fileURLToPath} from 'node:url';import path from 'node:path';import {backendIdentity} from './build_release_identity.mjs';
export async function verifyFrontendBackend(fetcher=fetch,expected=backendIdentity()){
 const r=await fetcher('https://api.cveharbor.com/v1/release-readiness?check='+crypto.randomUUID(),{headers:{'Cache-Control':'no-cache'},signal:AbortSignal.timeout(15000),redirect:'error'});
 assert.equal(r.status,200,'Frontend publication blocked: backend/schema unavailable or recovery hold active');const d=await r.json();
 assert.equal(d.ready,true,'Backend is not ready');assert.equal(d.schema,'phase1-integrity-recovery-v1','Required schema release is missing');assert.equal(d.release,expected,'Frontend publication blocked: the deployed backend does not match this checkout');return {ready:true,release:expected};
}
export async function waitFrontendBackend({verify=verifyFrontendBackend,sleep=ms=>new Promise(r=>setTimeout(r,ms)),attempts=120}={}){
 for(let i=0;i<attempts;i++){try{return await verify();}catch(error){if(i===attempts-1)throw error;await sleep(15000);}}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))console.log(JSON.stringify(await (process.argv.includes('--wait')?waitFrontendBackend():verifyFrontendBackend())));
