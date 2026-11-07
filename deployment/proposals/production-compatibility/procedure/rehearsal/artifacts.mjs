// Credential-free artifacts for the separate isolated rehearsal. No target override.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {baseline,read,root,baselineDB} from '../../rehearsal.mjs';
import {verifyFiles,target,originalTables,quote,literal,receiptTable,sqlFiles,allOf,snapshotPredicate} from '../build.mjs';
import {digest} from '../../../../../scripts/production_schema_baseline.mjs';
export const folder=path.dirname(fileURLToPath(import.meta.url));
export const cases=['success','schema','count','expiry','race','rejected','interrupt','lost'];
export const account='9706b4d98ad72884e67fd1eb875c8a61';
export const names=Object.fromEntries(cases.map(c=>[c,c==='success'?target.restore_name:'cveharbor-pr270-rehearsal-'+c]));
export const denied=[target.database,'fac61562-fc31-426d-8032-550aba63b7f6'];
export const marker='d1_pr270_rehearsal_attempts';
export const markerSQL=`CREATE TABLE ${marker}(id TEXT PRIMARY KEY CHECK(id IN('plan','perturb','install')),payload TEXT NOT NULL CHECK(json_valid(payload)));
CREATE TRIGGER ${marker}_update BEFORE UPDATE ON ${marker} BEGIN SELECT RAISE(ABORT,'Immutable rehearsal claim'); END;
CREATE TRIGGER ${marker}_delete BEFORE DELETE ON ${marker} BEGIN SELECT RAISE(ABORT,'Immutable rehearsal claim'); END;
CREATE TRIGGER ${marker}_insert BEFORE INSERT ON ${marker} WHEN NEW.id!='plan' BEGIN SELECT CASE WHEN NEW.payload IS NOT (SELECT payload FROM ${marker} WHERE id='plan') THEN RAISE(ABORT,'Rehearsal plan mismatch') END; END;
`;
// Exact preserved success claim, not a general resume/reset facility.
export const successContinuation=Object.freeze({version:1,
 previous_source_sha:'12befb50bd605a7525506f6fd206c9549054a8b0',
 previous_manifest_sha256:'a18a9f229f3d44b3adb18ee77bbd9094ed1ca7a61aeeeeb687f2c642b4affbf9',
 previous_phase_approval_sha256:'2aed73935ac80452cf0f86d8b672eba89523dc730a66e23d043a7e224858aa89',
 stopped_content_proof_sha256:'3b1319424e5174656a299d578bd682d7c806b2dfc426dfc8546cb38e258722a9'
});
export function previousPlan(){return JSON.stringify({approval_sha256:successContinuation.previous_phase_approval_sha256,scenario:'success',database:'84dab6e9-9344-4e0f-a79a-4f0b43395754',manifest_sha256:successContinuation.previous_manifest_sha256});}
export function rehearsalJournalObjects(previous=false){
 const db=baselineDB();try{
  const old=fs.readFileSync(path.join(folder,'previous-bootstrap.sql'),'utf8');assert.equal(digest(old),'01e3ef913b44194b26aecf0e103b077ca5a144ea84a09db8c1f227a0501ef98c');
  db.exec(markerSQL);db.exec(previous?old:sqlFiles()['bootstrap.sql']);
  return db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name GLOB 'd1_*' AND sql IS NOT NULL ORDER BY type,name").all().map(r=>({...r}));
 }finally{db.close();}
}
export function journalCorrectionSQL(payload){
 const p='a.p',defs="SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name GLOB 'd1_*' AND sql IS NOT NULL";
 const checks=allOf([
  `(SELECT COUNT(*) FROM ${receiptTable})=0`,
  `(SELECT COUNT(*) FROM ${marker})=1`,
  `(SELECT payload FROM ${marker} WHERE id='plan')=json_extract(${p},'$.previous_plan')`,
  `CAST(strftime('%s','now') AS INTEGER) BETWEEN json_extract(${p},'$.not_before') AND json_extract(${p},'$.expires_at')`,
  `json_array_length(json_extract(${p},'$.previous_journal_rows'))=(SELECT COUNT(*) FROM (${defs}))`,
  `NOT EXISTS(SELECT 1 FROM json_each(${p},'$.previous_journal_rows') e WHERE NOT EXISTS(SELECT 1 FROM sqlite_schema s WHERE s.type=json_extract(e.value,'$.type') AND s.name=json_extract(e.value,'$.name') AND s.tbl_name=json_extract(e.value,'$.tbl_name') AND s.sql=json_extract(e.value,'$.sql')))`,
  snapshotPredicate(p,'a.c')
 ]);
 const bootstrap=sqlFiles()['bootstrap.sql'],start=bootstrap.indexOf(`CREATE TRIGGER ${receiptTable}_sequence `);assert.ok(start>0);
 // Embed the one fully quoted, approved JSON input once. The REST batch uses no
 // parameters shared across statements. Never interpolate unescaped input.
 const input=payload===undefined?'?1':literal(JSON.stringify(payload));
 const result=`-- Success-only correction of the exact empty journal. One submission; reconcile on uncertainty.\nSELECT json_extract(CASE WHEN COALESCE(${checks},0) THEN 'true' ELSE 'Preserved journal correction rejected' END,'$') AS journal_correction_precondition FROM (SELECT p,json_extract(p,'$.counts') AS c FROM (SELECT ${input} AS p)) AS a;\nDROP TRIGGER ${receiptTable}_sequence;\n${bootstrap.slice(start)}`;
 assert.ok(Buffer.byteLength(result)<=100000,'Journal correction request exceeds conservative SQL request bound');
 if(payload!==undefined)assert.ok(Buffer.byteLength(JSON.stringify({sql:result,params:[]}))<=100000,'Serialized correction exceeds conservative request bound');return result;
}
export const driftSQL={schema:'CREATE TABLE unexpected_after_claim(id TEXT);',count:"INSERT INTO remediations(user_id,cve_id,status,updated_at) VALUES('pr270-fictional','CVE-2026-999999','Open','2026-11-06');"};
export function syntheticSQL(){return baseline.application_schema_files.map(f=>{const s=read(f.path);assert.equal(digest(s),f.sha256);return s.replace(/^([\t ]*--[^\r\n]*?)[\t ]+$/gm,'$1');}).join('\n')+"\nINSERT INTO users(id,email) VALUES('pr270-fictional','pr270-fictional@example.invalid');\n";}
export function syntheticCounts(){const db=baselineDB();try{db.exec("INSERT INTO users(id,email) VALUES('pr270-fictional','pr270-fictional@example.invalid')");return Object.fromEntries(originalTables().map(t=>[t,db.prepare('SELECT COUNT(*) n FROM '+quote(t)).get().n]));}finally{db.close();}}
const sources=['artifacts.mjs','adapter.mjs','development-exception.mjs','private-log.mjs','package.mjs','storage-policy.mjs','owner-key-setup.ps1','lossless-import.py','import-once.mjs','import-cost.mjs','lossless-import-evidence.json','verify-content.mjs','previous-bootstrap.sql','journal-correction.sql'].map(f=>'deployment/proposals/production-compatibility/procedure/rehearsal/'+f);
export function manifest(){return {version:1,production_manifest_sha256:verifyFiles().sha256,account,names,denied,synthetic_sql_sha256:digest(syntheticSQL()),marker_sql_sha256:digest(markerSQL),drift_sql_sha256:Object.fromEntries(Object.entries(driftSQL).map(([k,v])=>[k,digest(v)])),files:Object.fromEntries([...sources,'staging/recovery/crypto.mjs'].map(f=>[f,digest(read(f))]))};}
export function artifacts(){const m=manifest();assert.deepEqual(JSON.parse(fs.readFileSync(path.join(folder,'manifest.json'))),m);assert.equal(fs.readFileSync(path.join(folder,'synthetic.sql'),'utf8'),syntheticSQL());assert.equal(fs.readFileSync(path.join(folder,'journal-correction.sql'),'utf8'),journalCorrectionSQL());return {manifest:m,sha256:digest(m)};}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.includes('--write')){fs.writeFileSync(path.join(folder,'synthetic.sql'),syntheticSQL());fs.writeFileSync(path.join(folder,'journal-correction.sql'),journalCorrectionSQL());fs.writeFileSync(path.join(folder,'manifest.json'),JSON.stringify(manifest(),null,2)+'\n');}
 console.log(JSON.stringify({rehearsal_manifest_sha256:artifacts().sha256,production:verifyFiles().sha256}));
}
