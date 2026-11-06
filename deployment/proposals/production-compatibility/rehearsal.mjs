// REVIEW ONLY. Local SQLite preparation; no Cloudflare client or remote executor.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {DatabaseSync} from 'node:sqlite';
import {canonical,digest,schemaSQL} from '../../../scripts/production_schema_baseline.mjs';
import {recoveryTablesSQL,recoveryGuardSQL} from '../../../account-backend/src/recovery-schema.js';

export const root=fileURLToPath(new URL('../../../',import.meta.url));
export const folder=path.dirname(fileURLToPath(import.meta.url));
export const baseline=JSON.parse(fs.readFileSync(path.join(root,'release/baseline.json')));
export const read=p=>fs.readFileSync(path.join(root,p),'utf8');
export const schemaHash=db=>digest(canonical(db.prepare(schemaSQL).all()));
export function baselineDB(){
 const db=new DatabaseSync(':memory:');db.exec('PRAGMA foreign_keys=ON');
 for(const f of baseline.application_schema_files){const sql=read(f.path);assert.equal(digest(sql),f.sha256);db.exec(sql);}
 assert.equal(schemaHash(db),baseline.schema_sha256);
 return db;
}
export function proposedSQL(){
 const db=baselineDB();
 try{
  const integrity=read('account-backend/migrations/0031_remediation_integrity.sql');
  const recovery=read('account-backend/migrations/0032_recovery_control.sql');
  const seed='INSERT OR IGNORE INTO operations_control(id) VALUES(1);';
  assert.equal(recovery.split(seed).length,2);
  // Never install the upstream default-open row during incident repair.
  const held=recovery.replace(seed,"INSERT INTO operations_control(id,write_hold,database_frozen,revision,reason) VALUES(1,1,1,0,'Proposed compatibility repair: awaiting separate acceptance and resume approval');");
  db.exec(integrity);db.exec(held);
  const guards=db.prepare(recoveryTablesSQL).all().flatMap(({name})=>['insert','update','delete'].map(op=>recoveryGuardSQL(name,op)+';'));
  return '-- INACTIVE REVIEW PROPOSAL: DO NOT APPLY TO A LIVE DATABASE.\n-- Requires an exact baseline, private recovery evidence, a guarded executor and separate approval.\n-- No automatic migration directory consumes this file. No resume is included.\n'+integrity+'\n'+held+'\n'+guards.join('\n')+'\n';
 }finally{db.close();}
}
export function applyLocally(db,sql=proposedSQL()){
 assert.equal(schemaHash(db),baseline.schema_sha256,'Unknown/partial schema: reconcile, never retry blindly');
 // This transaction establishes local SQLite behavior only, not remote D1 atomicity.
 db.exec('BEGIN');try{db.exec(sql);db.exec('COMMIT');}catch(e){db.exec('ROLLBACK');throw e;}
}
export function evidence(){
 const db=baselineDB(),before=db.prepare(schemaSQL).all();
 try{
  const sql=proposedSQL();applyLocally(db,sql);
  const after=db.prepare(schemaSQL).all(),prior=new Map(before.map(r=>[r.name,r]));
  for(const r of before)assert.deepEqual(canonical([r]),canonical([after.find(x=>x.name===r.name)]));
  return {status:'LOCAL REHEARSAL ONLY; NOT READY FOR PRODUCTION EXECUTION',base_commit:'1532e732b771f960b6ae7791a9bd2205e1d59390',baseline_schema_sha256:baseline.schema_sha256,baseline_objects:before.length,proposed_sql_sha256:digest(sql),proposed_schema_sha256:schemaHash(db),proposed_objects:after.length,added_objects:after.filter(r=>!prior.has(r.name)).map(r=>({type:r.type,name:r.name})),preserved_baseline_objects:before.length,control:db.prepare('SELECT write_hold,database_frozen,revision FROM operations_control').get(),input_files:[...baseline.application_schema_files,{path:'account-backend/migrations/0031_remediation_integrity.sql',sha256:digest(read('account-backend/migrations/0031_remediation_integrity.sql'))},{path:'account-backend/migrations/0032_recovery_control.sql',sha256:digest(read('account-backend/migrations/0032_recovery_control.sql'))}]};
 }finally{db.close();}
}
export function missingContracts(){
 const installed=new Set(baseline.application_schema_files.map(f=>f.path));
 const files=[...fs.readdirSync(path.join(root,'account-backend/migrations')).filter(p=>p.endsWith('.sql')).map(p=>'account-backend/migrations/'+p),'deployment/proposals/customer-remediation/schema.sql'];
 return {baseline_schema_sha256:baseline.schema_sha256,groups:files.filter(p=>!installed.has(p)).map(file=>{
  const db=baselineDB();try{
   const before=db.prepare(schemaSQL).all(),prior=new Map(before.map(r=>[r.name,r]));
   db.exec(read(file));const after=db.prepare(schemaSQL).all();
   return {file,sha256:digest(read(file)),added:after.filter(r=>!prior.has(r.name)).map(r=>({type:r.type,name:r.name})),changed:after.filter(r=>prior.has(r.name)&&digest(canonical([r]))!==digest(canonical([prior.get(r.name)]))).map(r=>({type:r.type,name:r.name}))};
  }finally{db.close();}
 })};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 fs.writeFileSync(path.join(folder,'proposed-repair.sql'),proposedSQL());
 fs.writeFileSync(path.join(folder,'local-evidence.json'),JSON.stringify(evidence(),null,2)+'\n');
 fs.writeFileSync(path.join(folder,'missing-contracts.json'),JSON.stringify(missingContracts(),null,2)+'\n');
 console.log('Generated inactive proposal and local metadata. No network access or live execution.');
}
