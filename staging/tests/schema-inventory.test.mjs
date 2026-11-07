import test from 'node:test';import assert from 'node:assert/strict';
import {loadManifest,validateSchema} from '../scripts/schema.mjs';
import {applyManifest,verifySchema,migrationState} from '../scripts/migrate.mjs';
import {validateResources,checkDatabases,resourceManifest} from '../scripts/inventory.mjs';
import {FullDB} from './helpers/full-db.mjs';
import {setHold,holdStatus} from '../../scripts/recovery_control.mjs';
test('full manifest preserves duplicate numeric prefixes and explicit Phase 1 order',()=>{
 const m=loadManifest(),names=m.entries.map(e=>e.path);assert.equal(names.filter(n=>n.includes('/0028_')).length,2);assert.equal(names.filter(n=>n.includes('/0029_')).length,2);
 assert.ok(names.indexOf('account-backend/migrations/0030_status_update_notifications.sql')<names.indexOf('account-backend/migrations/0031_remediation_integrity.sql'));
 const built=validateSchema();assert.equal(built.table_count,103);assert.ok(built.objects.some(o=>o.name==='finding_link_identity'));assert.ok(built.objects.some(o=>o.name==='cvie_identity_members'));
});
test('complete migration, repeat under hold, data/history preservation and drift detection',async()=>{
 const db=new FullDB({empty:true});try{
  assert.equal((await applyManifest(db)).applied.length,35);
  db.sql.exec("INSERT INTO users(id,email) VALUES('synthetic','synthetic@example.invalid')");
  const before=db.sql.prepare('SELECT * FROM users').all();await setHold(db,{hold:true,revision:0,reason:'Synthetic migration repeat'});
  assert.equal((await applyManifest(db)).applied.length,0);assert.deepEqual(db.sql.prepare('SELECT * FROM users').all(),before);assert.equal((await holdStatus(db)).write_hold,1);
  await verifySchema(db);db.sql.exec('DROP INDEX staging_mail_created');await assert.rejects(verifySchema(db),/Schema drift/);
 }finally{db.close();}
});
test('nonempty untracked database and altered migration receipt fail before changes',async()=>{
 const db=new FullDB({empty:true});try{db.sql.exec('CREATE TABLE customer_data(id TEXT)');await assert.rejects(migrationState(db),/adoption/);}finally{db.close();}
 const full=new FullDB();try{full.sql.exec("UPDATE staging_schema_history SET sha256='modified' WHERE path='staging/schema.sql'");await assert.rejects(migrationState(full),/changed/);}finally{full.close();}
});
test('approved disposable name and UUID accepted; unknown, swapped, duplicate and production IDs rejected',()=>{
 const m=structuredClone(resourceManifest()),d={name:'cveharbor-phase1-staging-test',uuid:'11111111-2222-4333-8444-555555555555'};m.disposable_databases.push(d);
 const known=[m.permanent_database,...m.retained_rehearsal_databases];
 assert.ok(checkDatabases([...known,d],{manifest:m,permanentId:m.permanent_database.uuid}));
 for(const rows of [[...known,{...d,uuid:'22222222-2222-4333-8444-555555555555'}],[...known,d,d],[...known,{...d,name:'unknown'}]])assert.throws(()=>checkDatabases(rows,{manifest:m,permanentId:m.permanent_database.uuid}));
 assert.throws(()=>validateResources({...m,disposable_databases:[{...d,uuid:'46710e51-7ca4-4571-b89c-921b9969de0b'}]}));
});
