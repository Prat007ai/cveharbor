import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
export function importPreflight(bytes,expectedSha256){
 assert.ok(Buffer.isBuffer(bytes));assert.match(expectedSha256||'',/^[a-f0-9]{64}$/);
 assert.ok(bytes.length<=200000000,'Rehearsal import size limit');
 assert.equal(createHash('sha256').update(bytes).digest('hex'),expectedSha256,'Approved import checksum mismatch');
 const check=spawnSync(process.platform==='win32'?'python':'python3',[fileURLToPath(new URL('lossless-import.py',import.meta.url)),'--preflight-stdin'],{input:bytes,maxBuffer:65536,timeout:120000,windowsHide:true});
 // Never print raw parser errors or SQL. No initialization/upload if this fails.
 assert.equal(check.status,0,'Offline SQL size/completeness preflight failed');
 const result=JSON.parse(check.stdout.toString('utf8'));assert.equal(result.sha256,expectedSha256);return result;
}
export function transferURL(value){const u=new URL(value);assert.equal(u.protocol,'https:');assert.ok(!u.username&&!u.password&&!u.port);assert.ok(u.hostname.endsWith('.r2.cloudflarestorage.com'),'Unexpected provider transfer host');return u;}
// A failed call propagates immediately. Only status polling repeats, always for
// the already returned bookmark. Intent persistence must reject duplicate names.
export async function transferAndImport({etag,bytes,expectedSha256,api,put,save,checkWindow,beforeIngest,sleep}){
 checkWindow();const preflight=importPreflight(bytes,expectedSha256);
 assert.equal(etag,createHash('md5').update(bytes).digest('hex'),'Transfer checksum mismatch');
 save('import-attempt',{etag,bytes:bytes.length,preflight});
 const init=await api({action:'init',etag});save('init-reply',init);
 assert.ok(typeof init.filename==='string'&&init.filename.length>0);
 if(init.upload_url){
  const url=transferURL(init.upload_url);checkWindow();save('upload-intent',{hostname:url.hostname,bytes:bytes.length});
  const response=await put(url,bytes);save('upload-reply',response);assert.ok(response.ok,'Upload outcome rejected');
 }
 await beforeIngest();checkWindow();save('ingest-intent',{etag,filename:init.filename});
 let result=await api({action:'ingest',etag,filename:init.filename});save('ingest-reply',result);
 for(let n=0;result.status!=='complete';n++){
  assert.ok(n<180&&result.status!=='error'&&typeof result.at_bookmark==='string','Import stopped or no polling bookmark');
  await sleep(1000);checkWindow();result=await api({action:'poll',current_bookmark:result.at_bookmark});
 }
 assert.ok(result.success!==false);return result;
}
