import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {spawnSync} from 'node:child_process';import {DatabaseSync} from 'node:sqlite';
import {manualRelease,remediationIntegrityRelease} from './worker_release_mode.mjs';import {verifyFrontendBackend} from './verify_frontend_backend.mjs';import {d1Client,productionDatabase} from './cloudflare_d1.mjs';import {bootstrapStaging,rehearseStaging,validateStagingTarget} from './phase1_staging.mjs';
import {backendIdentity} from './build_release_identity.mjs';
test('manual deployment defaults to no migrations/maintenance; Phase 1 explicitly selects only its release',()=>{
 assert.deepEqual(manualRelease(),{integrity:false,maintenance:false,codeOnly:true,recovery:false});assert.deepEqual(manualRelease('phase1-integrity'),{integrity:true,maintenance:false,codeOnly:false,recovery:false});assert.equal(manualRelease('recovery-code-only').maintenance,false);assert.throws(()=>manualRelease('auto'));
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'phase1-mode-'));try{for(const mode of ['', 'code-only','phase1-integrity','recovery-code-only','cvie-maintenance']){const output=path.join(dir,'output');fs.writeFileSync(output,'');const r=spawnSync(process.execPath,['scripts/worker_release_mode.mjs'],{env:{...process.env,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_OUTPUT:output,WORKER_RELEASE_MODE:mode},encoding:'utf8'});assert.equal(r.status,0,r.stderr);const values=fs.readFileSync(output,'utf8');assert.match(values,new RegExp('maintenance='+(mode==='cvie-maintenance')+'\n'));assert.match(values,new RegExp('remediation_integrity='+(mode==='phase1-integrity')+'\n'));}}finally{fs.rmSync(dir,{recursive:true,force:true});}
 const approved=['account-backend/migrations/0031_remediation_integrity.sql','account-backend/migrations/0032_recovery_control.sql','account-backend/src/remediation-integrity.js','account-backend/src/recovery-control.js','account-backend/wrangler.toml'];assert.equal(remediationIntegrityRelease(approved),true);assert.equal(remediationIntegrityRelease([...approved,'account-backend/migrations/9999_unrelated.sql']),false);
});
test('publication gate rejects old backend, missing schema, hold, failure and malformed responses',async()=>{
 const release='a'.repeat(64),response=d=>new Response(JSON.stringify(d));const good={ready:true,schema:'phase1-integrity-recovery-v1',release};assert.equal((await verifyFrontendBackend(async()=>response(good),release)).ready,true);
 for(const d of [{...good,release:'b'.repeat(64)},{...good,ready:false},{...good,schema:'old'},{}])await assert.rejects(()=>verifyFrontendBackend(async()=>response(d),release));await assert.rejects(()=>verifyFrontendBackend(async()=>new Response('',{status:503}),release));await assert.rejects(()=>verifyFrontendBackend(async()=>{throw Error('unavailable')},release));assert.match(backendIdentity(),/^[a-f0-9]{64}$/);
});
test('read-only D1 adapter rejects writes and multiple statements before any request, checks rows_written',async()=>{
 let calls=0;const env={CLOUDFLARE_ACCOUNT_ID:'a'.repeat(32),CLOUDFLARE_API_TOKEN:'synthetic-test-only'},fetcher=async()=>{calls++;return new Response(JSON.stringify({success:true,result:[{success:true,results:[{n:0}],meta:{rows_written:0}}]}));};const DB=d1Client({env,fetcher});
 for(const sql of ['UPDATE users SET email=?','DELETE FROM users','SELECT 1; DELETE FROM users','PRAGMA writable_schema=ON'])await assert.rejects(()=>DB.prepare(sql).run());assert.equal(calls,0);assert.equal((await DB.prepare('SELECT COUNT(*) n FROM pragma_foreign_key_check').first()).n,0);assert.equal(calls,1);
 const bad=d1Client({env,fetcher:async()=>new Response(JSON.stringify({success:true,result:[{success:true,results:[],meta:{rows_written:1}}]}))});await assert.rejects(()=>bad.prepare('SELECT 1').all(),/unexpectedly wrote/);
});
test('staging refuses production UUID, wrong name/identity and non-disposable environments',()=>{
 const d='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',good={database:d,name:'cveharbor-phase1-staging',metadata:{uuid:d,name:'cveharbor-phase1-staging'},disposable:'true'};validateStagingTarget(good);for(const input of [{...good,database:productionDatabase()},{...good,disposable:'false'},{...good,name:'cveharbor-accounts'},{...good,metadata:{...good.metadata,uuid:productionDatabase()}}])assert.throws(()=>validateStagingTarget(input));
});
test('same staging bootstrap and rehearsal operate on disposable SQLite, preserve data and refuse reseeding',async()=>{
 const sql=new DatabaseSync(':memory:');sql.exec('PRAGMA foreign_keys=ON');
 const DB={prepare(q){const make=params=>({sql:q,params,bind:(...p)=>make(p),first:async()=>sql.prepare(q).get(...params)||null,all:async()=>({results:sql.prepare(q).all(...params)}),run:async()=>({meta:{changes:Number(sql.prepare(q).run(...params).changes)}})});return make([]);},query:async q=>{sql.exec(q);return [];},async batch(statements){sql.exec('BEGIN');try{const r=[];for(const s of statements)r.push(await s.run());sql.exec('COMMIT');return r;}catch(e){sql.exec('ROLLBACK');throw e;}}};
 try{assert.equal((await bootstrapStaging(DB)).synthetic_only,true);await assert.rejects(()=>bootstrapStaging(DB),/empty staging/);const r=await rehearseStaging(DB);assert.equal(r.passed,true);assert.equal(r.real_emails_sent,0);assert.equal(r.audit.ok,true);assert.equal((await rehearseStaging(DB)).passed,true,'Repeat validation keeps canonical records and operational state valid');assert.deepEqual(sql.prepare('PRAGMA foreign_key_check').all(),[]);}finally{sql.close();}
});
test('workflow publication order and recovery steps are enforced for every site publication',()=>{
 const backend=fs.readFileSync('.github/workflows/deploy-worker-code.yml','utf8'),site=fs.readFileSync('.github/workflows/bootstrap.yml','utf8'),deployer=fs.readFileSync('scripts/deploy_site_gate.py','utf8');
 for(const w of [backend,site])assert.match(w,/group: cveharbor-production-release/);assert.ok(site.indexOf('node scripts/verify_frontend_backend.mjs')<site.indexOf('run: python scripts/deploy_site_gate.py'));const main=deployer.slice(deployer.indexOf('def main():'));assert.ok(main.indexOf('verify_backend()')<main.indexOf('routing_plan(config)'));
 assert.ok(backend.indexOf('--file=migrations/0031')<backend.indexOf('--file=migrations/0032'));assert.ok(backend.indexOf('node ../scripts/recovery_control.mjs install')<backend.indexOf('- name: Deploy Worker source'));assert.match(backend,/RECOVERY_RELEASE: \$\{\{ steps.mode.outputs.recovery_code_only \}\}/);
 const audit=fs.readFileSync('.github/workflows/security-phase1-audit.yml','utf8');assert.doesNotMatch(audit,/wrangler|secret put|d1 execute|deploy-worker/);assert.match(audit,/cloudflare-production-audit/);
});
test('hourly public-feed collection cannot invalidate the backend compatibility identity',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'phase1-identity-'));try{
  for(const p of ['account-backend/src','account-backend/migrations','data'])fs.mkdirSync(path.join(dir,p),{recursive:true});
  fs.writeFileSync(path.join(dir,'account-backend/src/index.js'),'export default {}');fs.writeFileSync(path.join(dir,'account-backend/wrangler.toml'),'name="synthetic"');fs.writeFileSync(path.join(dir,'data/lifecycle-products.json'),'[]');const before=backendIdentity(dir);
  fs.writeFileSync(path.join(dir,'data/lifecycle-products.json'),'[{"new_public_feed":true}]');assert.equal(backendIdentity(dir),before);fs.writeFileSync(path.join(dir,'account-backend/src/index.js'),'export default {fetch(){}}');assert.notEqual(backendIdentity(dir),before);
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('all auxiliary production writers share serialization and check the hold before mutation',()=>{
 const names=fs.readdirSync('.github/workflows').filter(n=>n.startsWith('activate-')||['deploy-account-worker.yml'].includes(n));
 for(const name of names){const text=fs.readFileSync('.github/workflows/'+name,'utf8');assert.match(text,/group: cveharbor-production-release/,name);assert.match(text,/node scripts\/verify_release_hold.mjs/,name);const mutation=text.search(/run: (?:\|\n[^]*?)?npx --yes wrangler/);if(mutation>=0)assert.ok(text.indexOf('node scripts/verify_release_hold.mjs')<mutation,name);}
});
