// Explicitly isolated D1 rehearsal. No production Worker deployment, customer copy, or live email.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {fileURLToPath} from 'node:url';import {createHash} from 'node:crypto';
import {d1Client,productionDatabase} from './cloudflare_d1.mjs';import {restBatch} from './cvie_rest_batch.mjs';
import {installGuards,holdStatus,setHold,freezeHold} from './recovery_control.mjs';import {verifyIntegrity} from './verify_remediation_integrity_d1.mjs';
import {unifiedFixture,assetOne} from '../account-backend/tests/helpers/unified-db.mjs';import {fixtureCve} from '../account-backend/tests/helpers/assignment-db.mjs';import worker from '../account-backend/src/index.js';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');const sqlFile=n=>fs.readFileSync(path.join(root,'account-backend',n),'utf8');
export function validateStagingTarget({database,name,metadata,disposable}){
 assert.equal(disposable,'true','Staging must be explicitly marked disposable');assert.match(database||'',/^[a-f0-9-]{36}$/);assert.notEqual(database,productionDatabase(),'Production database is forbidden');
 assert.match(name||'',/^cveharbor-phase1-staging(?:-[a-z0-9-]+)?$/);assert.equal(metadata.name,name,'Staging database name does not match configured resource');assert.equal(metadata.uuid,database,'Staging database UUID mismatch');
}
export async function syntheticFixture(){
 const f=await unifiedFixture();const loaded=new Set(['schema.sql','totp-schema.sql','remediation-schema.sql','inventory-schema.sql','finding-status-schema.sql','finding-ticket-schema.sql','finding-ticket-history-schema.sql']);
 for(const n of fs.readdirSync(path.join(root,'account-backend')).filter(n=>n.endsWith('-schema.sql')&&!loaded.has(n)).sort())f.DB.sql.exec(sqlFile(n));
 for(const n of fs.readdirSync(path.join(root,'account-backend/migrations')).filter(n=>n.endsWith('.sql')&&n.slice(0,4)<'0031').sort())f.DB.sql.exec(sqlFile('migrations/'+n));return f;
}
export async function bootstrapStaging(DB){
 const existing=await DB.prepare("SELECT COUNT(*) n FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' AND name NOT LIKE 'd1_%'").first();assert.equal(Number(existing.n),0,'Bootstrap requires an empty staging database; never reset an existing database');
 const f=await syntheticFixture();try{
  const schema=f.DB.sql.prepare("SELECT name,type,sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 WHEN 'view' THEN 2 ELSE 3 END,rowid").all();
  // Install the schema and initial fixture before triggers to avoid manufacturing history.
  for(const row of schema.filter(x=>x.type==='table'))await DB.query(row.sql);
  for(const {name} of schema.filter(x=>x.type==='table')){const rows=f.DB.sql.prepare('SELECT * FROM '+name).all();for(const row of rows){const cols=Object.keys(row);await DB.prepare('INSERT INTO '+name+'('+cols.join(',')+') VALUES('+cols.map(()=>'?').join(',')+')').bind(...cols.map(k=>row[k])).run();}}
  for(const row of schema.filter(x=>x.type!=='table'))await DB.query(row.sql);
  await DB.query("CREATE TABLE phase1_staging_marker(id TEXT PRIMARY KEY CHECK(id='synthetic-phase1-v1')); INSERT INTO phase1_staging_marker VALUES('synthetic-phase1-v1')");
 }finally{f.DB.sql.close();}
 return {bootstrapped:true,synthetic_only:true};
}
export async function rehearseStaging(DB){
 assert.equal((await DB.prepare('SELECT id FROM phase1_staging_marker').first())?.id,'synthetic-phase1-v1');
 assert.equal(Number((await DB.prepare("SELECT COUNT(*) n FROM users WHERE id NOT IN ('a','b') OR email NOT IN ('sender@example.test','other@example.test')").first()).n),0,'Unexpected data: use a fresh synthetic staging database');
 const names=(await DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' AND name NOT LIKE 'd1_%' AND name NOT LIKE 'operations_%' AND name!='remediation_finding_write_context' ORDER BY name").all()).results.map(r=>r.name);
 const snapshot=async()=>{const digest=createHash('sha256');for(const n of names){digest.update(n);const rows=(await DB.prepare('SELECT * FROM '+n).all()).results;digest.update(JSON.stringify(rows.map(r=>JSON.stringify(Object.fromEntries(Object.entries(r).sort()))).sort()));}return digest.digest('hex');};
 const before=await snapshot();for(let i=0;i<2;i++){await DB.query(sqlFile('migrations/0031_remediation_integrity.sql'));await DB.query(sqlFile('migrations/0032_recovery_control.sql'));await installGuards(DB);}assert.equal(await snapshot(),before,'Existing synthetic data changed during additive installation');
 const f=await syntheticFixture(),originalFetch=globalThis.fetch;globalThis.fetch=f.fetcher;
 try{
  const env={...f.env,DB,RECOVERY_CONTROL_REQUIRED:'true'};
  await DB.prepare("UPDATE sessions SET expires_at=? WHERE user_id IN ('a','b')").bind(Math.floor(Date.now()/1000)+3600).run();
  const request=async req=>{const pending=[];const r=await worker.fetch(req,env,{waitUntil:p=>pending.push(p)});await Promise.all(pending);return r;};
  const api=async(p,m='GET',data)=>{const r=await request(f.request(p,m,data));const body=await r.json();assert.equal(r.status,200,JSON.stringify(body));return body;};
  const endpoint='/finding-remediations/'+assetOne+'/'+fixtureCve;
  const p=await api(endpoint);if(!p.record)await api(endpoint,'POST',{keep_separate:true,expected_manual:p.manual.updated});
  await api('/remediations/'+fixtureCve+'/assign','POST',{email:'staging-reviewer@example.net',assigned_severity:'high',fyi_recipients:['staging-manager@example.net'],resend:true});
  const url=f.emails.findLast(m=>m.text_body.includes('/acknowledge/')).text_body.match(/https:\/\/[^\s]+\/acknowledge\/[a-f0-9]{64}/)[0];
  const state=await holdStatus(DB);assert.equal((await setHold(DB,{hold:true,revision:state.revision,reason:'Synthetic D1 recovery rehearsal'})).active_leases,0);await freezeHold(DB,{revision:state.revision+1,reason:'Synthetic work is fully drained'});const heldSnapshot=await snapshot(),mailCount=f.emails.length;
  assert.equal((await request(new Request(url))).status,503);await worker.scheduled({cron:'* * * * *'},env,{waitUntil:p=>{throw Error('Held cron scheduled work')}});
  await assert.rejects(()=>DB.prepare("UPDATE remediations SET owner='blocked late writer'").run());assert.equal(await snapshot(),heldSnapshot);assert.equal(f.emails.length,mailCount);
  await setHold(DB,{hold:false,revision:state.revision+2,reason:'Synthetic D1 rehearsal complete'});
  const proof=createHash('sha256').update('confirm:'+new URL(url).pathname.split('/').pop()).digest('hex');assert.equal((await request(new Request(url,{method:'POST',headers:{Origin:new URL(url).origin,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({confirm:'receipt',proof})}))).status,200);
  const preview=await api(endpoint);if(preview.manual)await api(endpoint+'/link-existing','POST',{confirm:true,status:preview.record.status,status_change_reason:'Preserve the reviewed synthetic asset status.',expected_source:preview.manual.updated,expected_target:preview.record.updated,expected_finding:JSON.stringify(preview.finding),expected_asset:JSON.stringify(preview.asset)});
  const record=(await api(endpoint)).record;await api('/finding-statuses/'+assetOne+'/'+fixtureCve,'PUT',{status:record.fix_status==='Fixed/Patched'?'Fix in Progress':'Fixed/Patched',expected_updated:record.updated,status_change_reason:'Synthetic D1 end-to-end status validation.'});
  const audit=await verifyIntegrity(DB);assert.equal(audit.ok,true);assert.equal(Number((await DB.prepare('SELECT COUNT(*) n FROM pragma_foreign_key_check').first()).n),0);assert.equal((await holdStatus(DB)).active_leases,0);
  return {passed:true,existing_table_data_unchanged_on_migration:true,migration_applied_twice:true,hold_and_resume:true,original_ack_link:true,status_link_and_notifications:true,real_emails_sent:0,intercepted_emails:f.emails.length,audit};
 }finally{globalThis.fetch=originalFetch;f.DB.sql.close();}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const action=process.argv[2];assert.ok(['bootstrap','validate'].includes(action));const database=process.env.STAGING_DATABASE_ID;
 // Refuse production BEFORE making any request, even with incorrect staging configuration.
 assert.ok(database&&database!==productionDatabase(),'A separate staging UUID is required');const DB=d1Client({database,readOnly:false});
 validateStagingTarget({database,name:process.env.STAGING_DATABASE_NAME,metadata:await DB.metadata(),disposable:process.env.STAGING_DISPOSABLE});
 console.log(JSON.stringify(action==='bootstrap'?await bootstrapStaging(DB):await rehearseStaging(DB)));
}
