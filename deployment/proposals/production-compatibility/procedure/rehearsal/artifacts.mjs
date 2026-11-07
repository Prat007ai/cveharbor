// Credential-free artifacts for the separate isolated rehearsal. No target override.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {baseline,read,root,baselineDB} from '../../rehearsal.mjs';
import {verifyFiles,target,originalTables,quote} from '../build.mjs';
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
export const driftSQL={schema:'CREATE TABLE unexpected_after_claim(id TEXT);',count:"INSERT INTO remediations(user_id,cve_id,status,updated_at) VALUES('pr270-fictional','CVE-2026-999999','Open','2026-11-06');"};
export function syntheticSQL(){return baseline.application_schema_files.map(f=>{const s=read(f.path);assert.equal(digest(s),f.sha256);return s.replace(/^([\t ]*--[^\r\n]*?)[\t ]+$/gm,'$1');}).join('\n')+"\nINSERT INTO users(id,email) VALUES('pr270-fictional','pr270-fictional@example.invalid');\n";}
export function syntheticCounts(){const db=baselineDB();try{db.exec("INSERT INTO users(id,email) VALUES('pr270-fictional','pr270-fictional@example.invalid')");return Object.fromEntries(originalTables().map(t=>[t,db.prepare('SELECT COUNT(*) n FROM '+quote(t)).get().n]));}finally{db.close();}}
const sources=['artifacts.mjs','adapter.mjs','development-exception.mjs','private-log.mjs','package.mjs','storage-policy.mjs','owner-key-setup.ps1','lossless-import.py','import-once.mjs','import-cost.mjs','lossless-import-evidence.json'].map(f=>'deployment/proposals/production-compatibility/procedure/rehearsal/'+f);
export function manifest(){return {version:1,production_manifest_sha256:verifyFiles().sha256,account,names,denied,synthetic_sql_sha256:digest(syntheticSQL()),marker_sql_sha256:digest(markerSQL),drift_sql_sha256:Object.fromEntries(Object.entries(driftSQL).map(([k,v])=>[k,digest(v)])),files:Object.fromEntries([...sources,'staging/recovery/crypto.mjs'].map(f=>[f,digest(read(f))]))};}
export function artifacts(){const m=manifest();assert.deepEqual(JSON.parse(fs.readFileSync(path.join(folder,'manifest.json'))),m);assert.equal(fs.readFileSync(path.join(folder,'synthetic.sql'),'utf8'),syntheticSQL());return {manifest:m,sha256:digest(m)};}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.includes('--write')){fs.writeFileSync(path.join(folder,'synthetic.sql'),syntheticSQL());fs.writeFileSync(path.join(folder,'manifest.json'),JSON.stringify(manifest(),null,2)+'\n');}
 console.log(JSON.stringify({rehearsal_manifest_sha256:artifacts().sha256,production:verifyFiles().sha256}));
}
