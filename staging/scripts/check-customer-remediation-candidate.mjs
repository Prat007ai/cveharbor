// Built candidate, disposable SQLite and synthetic R2 only. No credentials/network.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import application from '../.build/customer-remediation-candidate/api.mjs';
import {FullDB,bucketFixture} from '../tests/helpers/full-db.mjs';
import {TARGET} from '../target.mjs';
import {verifyCandidateProfile} from './customer-remediation-profile.mjs';
const {profile}=verifyCandidateProfile(),manifest=JSON.parse(fs.readFileSync('staging/.build/customer-remediation-candidate/manifest.json'));
assert.deepEqual(manifest.candidate_profile,profile);assert.equal(manifest.schema_sha256,profile.schema_sha256);assert.equal(manifest.application_profile,profile.name);
assert.equal(manifest.activation,'separate-approval-required');
const DB=new FullDB({empty:true}),native=globalThis.fetch;let outbound=0;
globalThis.fetch=async()=>{outbound++;throw Error('No network permitted');};
try{
 DB.sql.exec(fs.readFileSync('staging/schema.sql','utf8'));
 for(const f of JSON.parse(fs.readFileSync('release/baseline.json')).application_schema_files)DB.sql.exec(fs.readFileSync(f.path,'utf8'));
 const env={DB,STAGING_MODE:'true',STAGING_APPLICATION_PROFILE:profile.name,STAGING_RELEASE:manifest.commit,STAGING_EMAIL_CAPTURE_ENABLED:'true',STAGING_TOTP_ENCRYPTION_KEY:'fictional-candidate-test-key-at-least-32',STAGING_MONITOR_WEBHOOK_TOKEN:'fictional-only',INTELLIGENCE_BUCKET:await bucketFixture()};
 const call=(patch={},path='/v1/staging-readiness')=>application.fetch(new Request(TARGET.origin+path),{...env,...patch},{waitUntil(){assert.fail('Unexpected task');}});
 assert.equal((await call()).status,503,'The unchanged step-209 schema cannot pass candidate readiness');
 DB.sql.exec(fs.readFileSync(profile.migration,'utf8'));
 const changes=DB.sql.prepare('SELECT total_changes() n').get().n;
 const result=await call();assert.equal(result.status,200);const readiness=await result.json();assert.equal(readiness.ready,true);assert.equal(readiness.schema_ready,true);assert.equal(readiness.release,manifest.commit);assert.equal(readiness.application_profile,profile.name);
 for(const patch of [{STAGING_EMAIL_CAPTURE_ENABLED:'false'},{STAGING_TOTP_ENCRYPTION_KEY:''},{STAGING_MONITOR_WEBHOOK_TOKEN:''},{INTELLIGENCE_BUCKET:null},{STAGING_APPLICATION_PROFILE:'production-baseline'},{STAGING_APPLICATION_PROFILE:'candidate'}])assert.equal((await call(patch)).status,503);
 assert.equal((await call({},'/v1/me')).status,401);
 await application.scheduled({},env,{waitUntil(){assert.fail('Native schedules must be disabled');}});
 assert.equal(DB.sql.prepare('SELECT total_changes() n').get().n,changes,'Readiness and scheduled checks are read-only');
 DB.sql.exec('DROP TRIGGER remediation_customer_scope_retained');assert.equal((await call()).status,503,'A missing retention guard must fail readiness');
 DB.sql.exec("CREATE TABLE candidate_unreviewed(extra TEXT)");assert.equal((await call()).status,503,'Unreviewed schema drift must fail readiness');
 assert.equal(outbound,0);
 for(const file of ['customer-remediation-ui.js','operations.js','remediation.css'])assert.ok(fs.existsSync('staging/.build/customer-remediation-candidate/public/'+file));
 console.log('PASS: inactive candidate pins, exact schema/retention readiness, profile mismatch, MFA, captured mail, intelligence, monitoring, schedules and no outbound requests.');
}finally{globalThis.fetch=native;DB.close();}
