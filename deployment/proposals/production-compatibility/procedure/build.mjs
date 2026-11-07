// Generates reviewable SQL locally. Never opens a remote connection.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {baselineDB,proposedSQL,root} from '../rehearsal.mjs';
import {digest,schemaSQL,canonical} from '../../../../scripts/production_schema_baseline.mjs';
import {integrityChecks} from '../../../../account-backend/src/release-integrity-checks.js';
export const folder=path.dirname(fileURLToPath(import.meta.url));
export const target=JSON.parse(fs.readFileSync(path.join(folder,'target.json')));
export const receiptTable='d1_cveharbor_repair_receipts';
export const quote=s=>'"'+s.replaceAll('"','""')+'"';
export const literal=s=>"'"+s.replaceAll("'","''")+"'";
export function originalTables(){const db=baselineDB();try{return db.prepare(schemaSQL).all().filter(r=>r.type==='table').map(r=>r.name).sort();}finally{db.close();}}
// SQLite measures expression-tree depth, not just SQL length. Preserve SQL's
// three-valued AND semantics while avoiding a left-deep chain of 70+ counts.
export function allOf(conditions){
 assert.ok(conditions.length>0);
 if(conditions.length===1)return conditions[0];
 const middle=Math.floor(conditions.length/2);
 return `(${allOf(conditions.slice(0,middle))} AND ${allOf(conditions.slice(middle))})`;
}
export const noViolations=()=>allOf([...Object.values(integrityChecks),'SELECT COUNT(*) n FROM pragma_foreign_key_check'].map(sql=>`(${sql})=0`));
export function snapshotPredicate(payload){
 const schema=`json_array_length(json_extract(${payload},'$.schema_rows'))=(SELECT COUNT(*) FROM (${schemaSQL})) AND NOT EXISTS(SELECT 1 FROM json_each(${payload},'$.schema_rows') e WHERE NOT EXISTS(SELECT 1 FROM sqlite_schema s WHERE s.type=json_extract(e.value,'$.type') AND s.name=json_extract(e.value,'$.name') AND s.tbl_name=json_extract(e.value,'$.tbl_name') AND s.sql=json_extract(e.value,'$.sql')))`;
 return allOf([schema,...originalTables().map(t=>`(SELECT COUNT(*) FROM ${quote(t)})=json_extract(${payload},'$.counts.${t}')`),noViolations()]);
}
// Install receipts with version 2 are bound to the reviewed run instead of a clock.
// The trigger passes the receipt ID check so a resume receipt cannot use this path.
function installApprovalTiming(payload, installPhase) {
 const field = key => `json_extract(${payload},'$.${key}')`;
 const type = key => `json_type(${payload},'$.${key}')`;
 return `CASE
 WHEN ${type('version')} IS NOT 'integer' THEN 0
 WHEN EXISTS(SELECT 1 FROM json_each(${payload}) WHERE key IN('version','not_before','expires_at') GROUP BY key HAVING COUNT(*)>1) THEN 0
 WHEN ${field('version')}=1 THEN (
  ${type('not_before')}='integer' AND ${type('expires_at')}='integer'
  AND ${field('expires_at')} - ${field('not_before')} BETWEEN 0 AND 1800
  AND CAST(strftime('%s','now') AS INTEGER) BETWEEN ${field('not_before')} AND ${field('expires_at')}
 )
 WHEN ${field('version')}=2 THEN (
  ${installPhase} AND ${field('operation')}='install'
  AND json_type(${payload},'$.not_before') IS NULL AND json_type(${payload},'$.expires_at') IS NULL
  AND json_type(${payload},'$.run_id')='text' AND length(${field('run_id')})>0 AND ${field('run_id')} NOT GLOB '*[^0-9]*'
  AND json_type(${payload},'$.source_sha')='text' AND length(${field('source_sha')})=40 AND ${field('source_sha')} NOT GLOB '*[^0-9a-f]*'
  AND ${field('database')}=${literal(target.database)}
 ) ELSE 0 END`;
}
export function sqlFiles(){
 const table=receiptTable;
 const bootstrap=`-- Separate operational journal; no IF NOT EXISTS, reset or deletion path.\nCREATE TABLE ${table}(id TEXT PRIMARY KEY CHECK(id IN('install-intent','install-started','installed','resume-intent','resume-started')),payload TEXT NOT NULL CHECK(json_valid(payload)),recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);\nCREATE TRIGGER ${table}_immutable_update BEFORE UPDATE ON ${table} BEGIN SELECT RAISE(ABORT,'Repair receipts are immutable'); END;\nCREATE TRIGGER ${table}_immutable_delete BEFORE DELETE ON ${table} BEGIN SELECT RAISE(ABORT,'Repair receipts are immutable'); END;\nCREATE TRIGGER ${table}_sequence BEFORE INSERT ON ${table} BEGIN
 SELECT CASE WHEN NOT (
 (NEW.id='install-intent' AND (SELECT COUNT(*) FROM ${table})=0) OR
 (NEW.id='install-started' AND (SELECT COUNT(*) FROM ${table})=1 AND NEW.payload=(SELECT payload FROM ${table} WHERE id='install-intent')) OR
 (NEW.id='installed' AND (SELECT COUNT(*) FROM ${table})=2 AND NEW.payload=(SELECT payload FROM ${table} WHERE id='install-started')) OR
 (NEW.id='resume-intent' AND (SELECT COUNT(*) FROM ${table})=3 AND EXISTS(SELECT 1 FROM ${table} WHERE id='installed')) OR
 (NEW.id='resume-started' AND (SELECT COUNT(*) FROM ${table})=4 AND NEW.payload=(SELECT payload FROM ${table} WHERE id='resume-intent'))
 ) THEN RAISE(ABORT,'Repair sequence or receipt mismatch') END;
 SELECT CASE WHEN NEW.id IN('install-intent','install-started','resume-intent','resume-started') AND NOT COALESCE((
 ${installApprovalTiming('NEW.payload', "NEW.id IN('install-intent','install-started')")} AND
 ${snapshotPredicate('NEW.payload')}
 ),0) THEN RAISE(ABORT,'Repair approval expired or database drifted') END;
END;\n`;
 const installStart=`INSERT INTO ${table}(id,payload) SELECT 'install-started',payload FROM ${table} WHERE id='install-intent';\n`;
 const installPayload=`(SELECT payload FROM ${table} WHERE id='install-started')`;
 // A SELECT returning zero/false would NOT stop D1. Deliberately evaluate invalid
 // JSON on a failed predicate so the database raises an error before any DDL.
 // The scalar expression also fails when a claim is absent (never zero rows).
 // Keep this and all installation statements in ONE documented REST SQL batch.
 // Do not send BEGIN/COMMIT or infer remote guarantees from the SQLite tests.
 const install=`-- Exactly one submission after a durable install-started claim. Never retry.
-- This database-side assertion must remain first in the SAME SQL batch as DDL.
SELECT json_extract(CASE WHEN COALESCE((
 (SELECT COUNT(*) FROM ${table})=2
 AND ${installPayload}=(SELECT payload FROM ${table} WHERE id='install-intent')
 AND json_extract(${installPayload},'$.operation')='install'
 AND ${installApprovalTiming(installPayload, "1")}
 AND ${snapshotPredicate(installPayload)}
),0) THEN 'true' ELSE 'Repair installation boundary rejected' END,'$') AS installation_precondition;
-- END INSTALLATION PRECONDITION
${proposedSQL()}
INSERT INTO ${table}(id,payload) SELECT 'installed',payload FROM ${table} WHERE id='install-started';\n`;
 const resumeStart=`INSERT INTO ${table}(id,payload) SELECT 'resume-started',payload FROM ${table} WHERE id='resume-intent';\n`;
 const resumePayload=`(SELECT payload FROM ${table} WHERE id='resume-started')`;
 const resume=`-- Separate approved operation. A lost response requires SELECT-only reconciliation.
UPDATE operations_control SET write_hold=0,database_frozen=0,revision=revision+1,
 reason='PR270 resume '||json_extract((SELECT payload FROM ${table} WHERE id='resume-intent'),'$.approval_id'),changed_at=CURRENT_TIMESTAMP
 WHERE id=1 AND write_hold=1 AND database_frozen=1
 AND revision=json_extract((SELECT payload FROM ${table} WHERE id='resume-intent'),'$.expected_revision')
 AND NOT EXISTS(SELECT 1 FROM operations_leases) AND NOT EXISTS(SELECT 1 FROM remediation_finding_write_context)
 AND CAST(strftime('%s','now') AS INTEGER) BETWEEN json_extract(${resumePayload},'$.not_before') AND json_extract(${resumePayload},'$.expires_at')
 AND ${snapshotPredicate(resumePayload)};\n`;
 assert.equal(digest(proposedSQL()),target.proposal_sha256);
 return {'bootstrap.sql':bootstrap,'install-start.sql':installStart,'install.sql':install,'resume-start.sql':resumeStart,'resume.sql':resume};
}
export function journalObjects(){const db=baselineDB();try{db.exec(sqlFiles()['bootstrap.sql']);return canonical(db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name GLOB 'd1_*' AND sql IS NOT NULL").all());}finally{db.close();}}
export const sourceFiles=[
 'deployment/proposals/production-compatibility/rehearsal.mjs',
 ...['build.mjs','target.json','execute.mjs','transport.mjs','bootstrap.sql','install-start.sql','install.sql','resume-start.sql','resume.sql'].map(n=>'deployment/proposals/production-compatibility/procedure/'+n),
 'scripts/production_schema_baseline.mjs','scripts/sql_schema_tokens.mjs','scripts/build_release_identity.mjs',
 'release/baseline.json','account-backend/migrations/0031_remediation_integrity.sql','account-backend/migrations/0032_recovery_control.sql',
 'account-backend/src/recovery-schema.js','account-backend/src/release-integrity-checks.js',
 '.github/workflows/production-compatibility-repair.yml','scripts/check_workflow_security.py'
];
export function manifest(){return {version:1,target,files:Object.fromEntries(sourceFiles.map(f=>[f,digest(fs.readFileSync(path.join(root,f),'utf8'))])),sql_sha256:Object.fromEntries(Object.entries(sqlFiles()).map(([n,s])=>[n,digest(s)])),journal_schema_sha256:digest(journalObjects())};}
export function verifyFiles(){
 for(const [name,sql] of Object.entries(sqlFiles()))assert.equal(fs.readFileSync(path.join(folder,name),'utf8'),sql,'Generated SQL changed');
 const expected=JSON.parse(fs.readFileSync(path.join(folder,'manifest.json')));assert.deepEqual(manifest(),expected,'Procedure source/checksum changed; review and regenerate');return {manifest:expected,sha256:digest(expected)};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.includes('--write')){for(const [name,sql] of Object.entries(sqlFiles()))fs.writeFileSync(path.join(folder,name),sql);fs.writeFileSync(path.join(folder,'manifest.json'),JSON.stringify(manifest(),null,2)+'\n');}
 const a=verifyFiles();console.log(JSON.stringify({manifest_sha256:a.sha256,sql_sha256:a.manifest.sql_sha256}));
}
