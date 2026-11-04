import fs from 'node:fs';
import test from 'node:test';import assert from 'node:assert/strict';
import application from '../.build/api.mjs';
import {FullDB,bucketFixture} from './helpers/full-db.mjs';
import {TARGET} from '../target.mjs';
import {totp} from '../../account-backend/src/totp.js';
import {unifiedFixture,assetOne} from '../../account-backend/tests/helpers/unified-db.mjs';
import {fixtureCve} from '../../account-backend/tests/helpers/assignment-db.mjs';
const production=JSON.parse(fs.readFileSync(new URL('../.build/manifest.json',import.meta.url))).application_profile==='production-baseline';
class ApplicationDB extends FullDB{
 constructor(){super({empty:production});if(production){this.sql.exec(fs.readFileSync(new URL('../schema.sql',import.meta.url),'utf8'));for(const f of JSON.parse(fs.readFileSync(new URL('../../release/baseline.json',import.meta.url))).application_schema_files)this.sql.exec(fs.readFileSync(new URL('../../'+f.path,import.meta.url),'utf8'));}}
}
const envFor=async DB=>({DB,...(production?{STAGING_APPLICATION_PROFILE:'production-baseline'}:{}),STAGING_MODE:'true',STAGING_EMAIL_CAPTURE_ENABLED:'true',STAGING_TOTP_ENCRYPTION_KEY:'synthetic-staging-key-not-used-in-production',STAGING_MONITOR_WEBHOOK_TOKEN:'synthetic-webhook-only',STAGING_ADMIN_EMAILS:'admin@example.invalid',STAGING_MANUAL_JOBS_ENABLED:'true',INTELLIGENCE_BUCKET:await bucketFixture(),ASSIGNMENT_ACK_RATE_LIMITER:{limit:async()=>({success:true})}});
async function call(env,path,method='GET',data,cookie='',headers={}){
 const pending=[],req=new Request(TARGET.origin+path,{method,headers:{Origin:TARGET.origin,...(cookie?{Cookie:cookie}:{}),...(data?{'Content-Type':'application/json'}:{}),...headers},...(data?{body:typeof data==='string'?data:JSON.stringify(data)}:{})});
 const response=await application.fetch(req,env,{waitUntil:p=>pending.push(p)});while(pending.length)await Promise.all(pending.splice(0));return response;
}
const captured=DB=>DB.sql.prepare('SELECT payload_json FROM staging_mail ORDER BY rowid').all().map(r=>JSON.parse(r.payload_json));
async function seed(db){const f=await unifiedFixture();try{for(const table of ['users','user_totp','sessions','remediations','inventory_customers','inventory_environments','inventory_assets','customer_finding_statuses','customer_finding_ticket_history'])for(const row of f.DB.sql.prepare('SELECT * FROM '+table).all()){const cols=Object.keys(row);db.sql.prepare('INSERT INTO '+table+'('+cols.join(',')+') VALUES('+cols.map(()=>'?').join(',')+')').run(...Object.values(row));}}finally{f.DB.sql.close();}}
test('built application registration, captured OTP, MFA, session and OTP replay controls',async()=>{
 const DB=new ApplicationDB(),env=await envFor(DB),native=globalThis.fetch;let calls=0;globalThis.fetch=async()=>{calls++;throw Error('Network forbidden');};
 try{
  const r=await call(env,'/v1/auth/request','POST',{email:'new-user@example.invalid'});assert.equal(r.status,200);const challenge=await r.json(),mail=captured(DB)[0];assert.match(mail.subject,/sign in code/);const code=mail.text_body.match(/code: (\d{6})/)[1];
  const verified=await call(env,'/v1/auth/verify','POST',{...challenge,code});assert.equal(verified.status,200);const mfa=await verified.json();assert.equal(mfa.mfa_enrollment_required,true);
  assert.equal((await call(env,'/v1/auth/verify','POST',{...challenge,code})).status,401);
  const enrolled=await call(env,'/v1/auth/totp/enroll','POST',{mfa_challenge:mfa.mfa_challenge,code:await totp(mfa.secret)});assert.equal(enrolled.status,200);const cookie=enrolled.headers.get('Set-Cookie').split(';')[0];
  assert.equal((await call(env,'/v1/me','GET',null,cookie)).status,200);assert.equal((await call(env,'/v1/me')).status,401);assert.equal(calls,0);
  assert.equal((await call(env,'/__staging/mail')).status,403);
  const inbox=await call(env,'/__staging/mail','GET',null,'',{'X-CVEHarbor-Staging-Admin':'admin@example.invalid'});assert.equal(inbox.status,200);assert.equal((await inbox.json()).messages.length,1);
 }finally{globalThis.fetch=native;DB.close();}
});
test('built full-schema assignment, receipt, asset linking, status mail, tickets and tenant isolation',async()=>{
 const DB=new ApplicationDB(),env=await envFor(DB);await seed(DB);const cookie='cvh_session='+'a'.repeat(64),other='cvh_session='+'b'.repeat(64);
 const ok=async(path,method='GET',data,c=cookie)=>{const r=await call(env,'/v1'+path,method,data,c);const body=await r.json();assert.equal(r.status,200,JSON.stringify(body));return body;};
 try{
  await ok('/remediations/'+fixtureCve+'/assign','POST',{email:'reviewer@example.invalid',assigned_severity:'high',fyi_recipients:['manager@example.invalid']});
  const mails=captured(DB),ack=mails.find(m=>m.text_body.includes('/acknowledge/')).text_body.match(/https:\/\/[^\s]+\/acknowledge\/[a-f0-9]{64}/)[0];assert.equal(new URL(ack).origin,TARGET.origin);
  const token=new URL(ack).pathname.split('/').pop(),proof=Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode('confirm:'+token))).toString('hex');
  const accepted=await call(env,new URL(ack).pathname,'POST',new URLSearchParams({confirm:'receipt',proof}).toString(),' ',{'Content-Type':'application/x-www-form-urlencoded'});assert.equal(accepted.status,200);
  assert.ok(DB.sql.prepare('SELECT acknowledged_at FROM remediation_assignment_requests').get().acknowledged_at);
  const assignedID=DB.sql.prepare('SELECT id FROM remediation_assignment_requests').get().id;
  DB.sql.prepare('UPDATE remediation_review_access SET last_progress_at=? WHERE assignment_id=?').run(Math.floor(Date.now()/1000)-90000,assignedID);
  const runReminder=()=>call(env,'/__staging/jobs','POST',{id:crypto.randomUUID(),job:'remediation',scenario:'synthetic'},'',{'X-CVEHarbor-Staging-Admin':'admin@example.invalid'});
  const reminder=await runReminder();assert.equal(reminder.status,200,await reminder.clone().text());
  assert.ok(captured(DB).some(m=>m.subject.startsWith('Manager Attention Required:')));
  const reminderCount=captured(DB).filter(m=>/Update requested|Manager Attention Required/.test(m.subject)).length;
  await runReminder();assert.equal(captured(DB).filter(m=>/Update requested|Manager Attention Required/.test(m.subject)).length,reminderCount);

  const form=(values,c='')=>call(env,'/assignment/'+assignedID,'POST',new URLSearchParams(values).toString(),c,{'Content-Type':'application/x-www-form-urlencoded'});
  const sentCode=await form({action:'send_code'});assert.equal(sentCode.status,200);const page=await sentCode.text(),challenge=page.match(/name="challenge" value="([^"]+)"/)[1];
  const reviewCode=captured(DB).findLast(m=>m.subject.includes('assignment verification')).text_body.match(/code is (\d{6})/)[1];
  const login=await form({action:'verify',challenge,code:reviewCode});assert.equal(login.status,303);const reviewCookie=login.headers.get('Set-Cookie').split(';')[0];
  const reviewerPage=await (await call(env,'/assignment/'+assignedID,'GET',null,reviewCookie)).text();assert.match(reviewerPage,/Save progress update/);
  const reviewProof=reviewerPage.match(/name="proof" value="([^"]+)"/)[1],updated=reviewerPage.match(/name="expected_updated" value="([^"]+)"/)[1];
  const progress=await form({action:'update',proof:reviewProof,expected_updated:updated,status:'Investigating',comment:'Synthetic reviewer confirms patch testing is underway.'},reviewCookie);assert.equal(progress.status,303);
  assert.equal(DB.sql.prepare('SELECT count(*) n FROM remediation_review_activity').get().n,1);
  const endpoint='/finding-remediations/'+assetOne+'/'+fixtureCve;
  const p=await ok(endpoint);await ok(endpoint+'/link-existing','POST',{confirm:true,status:'Fix in Progress',status_change_reason:'Synthetic customer asset confirmed',expected_source:p.manual.updated,expected_target:p.record?.updated||'',expected_finding:JSON.stringify(p.finding),expected_asset:JSON.stringify(p.asset)});
  let linked=await ok(endpoint);const originalID=linked.record.id;
  await ok('/finding-statuses/'+assetOne+'/'+fixtureCve,'PUT',{status:'Fixed/Patched',status_change_reason:'Synthetic patch validation complete',expected_updated:linked.record.updated});
  linked=await ok(endpoint);assert.equal(linked.record.fix_status,'Fixed/Patched');assert.equal(linked.record.id,originalID);
  assert.equal(DB.sql.prepare('SELECT count(*) n FROM remediation_finding_links').get().n,1);
  assert.equal(DB.sql.prepare('SELECT ticket_number FROM customer_finding_ticket_history').get().ticket_number,'SEC-248');
  assert.ok(captured(DB).some(m=>m.subject.includes(' status changed: ')));assert.ok(captured(DB).every(m=>!m.text_body.includes('https://cveharbor.com')&&!m.text_body.includes('https://confirm.cveharbor.com')));
  assert.equal((await call(env,'/v1'+endpoint,'GET',null,other)).status,404);
  const assignment=DB.sql.prepare('SELECT id FROM remediation_assignment_requests').get().id;
  const review=await call(env,'/assignment/'+assignment);assert.equal(review.status,200);assert.match(await review.text(),/verification|Verify/i);
  await ok('/inventory');await ok('/workspace/summary');
  assert.equal((await DB.prepare('SELECT COUNT(*) n FROM pragma_foreign_key_check').first()).n,0);
 }finally{DB.close();}
});
test('manual scheduler authorization, idempotency, native cron disable and recovery hold',async()=>{
 const DB=new ApplicationDB(),env=await envFor(DB),data={id:crypto.randomUUID(),job:'remediation',scenario:'synthetic'},admin={'X-CVEHarbor-Staging-Admin':'admin@example.invalid'};
 try{
  await application.scheduled({cron:'* * * * *'},env,{waitUntil(){assert.fail('Native schedule ran');}});
  assert.equal((await call(env,'/__staging/jobs','POST',data)).status,403);
  assert.equal((await call({...env,STAGING_MANUAL_JOBS_ENABLED:'false'},'/__staging/jobs','POST',data,'',admin)).status,409);
  const first=await call(env,'/__staging/jobs','POST',data,'',admin);assert.equal(first.status,200,await first.clone().text());
  const repeat=await call(env,'/__staging/jobs','POST',data,'',admin);assert.equal((await repeat.json()).replayed,true);assert.equal(DB.sql.prepare('SELECT COUNT(*) n FROM staging_job_runs').get().n,1);
  DB.sql.exec(production?'CREATE TABLE unreviewed_schema(id TEXT)':'UPDATE operations_control SET write_hold=1');assert.equal((await call(env,'/__staging/jobs','POST',{...data,id:crypto.randomUUID()},'',admin)).status,409);
 }finally{DB.close();}
});

test('built application report, vulnerability digest, lifecycle, website and product monitoring use captured mail and synthetic providers',async()=>{
 const DB=new ApplicationDB(),env=await envFor(DB);await seed(DB);const cookie='cvh_session='+'a'.repeat(64),admin={'X-CVEHarbor-Staging-Admin':'admin@example.invalid'};
 const ok=async(path,method='GET',data)=>{const r=await call(env,'/v1'+path,method,data,cookie),body=await r.json();assert.ok(r.status>=200&&r.status<300,JSON.stringify(body));return body;};
 try{
  const customer=crypto.randomUUID();DB.sql.prepare('INSERT INTO inventory_customers(id,user_id,name) VALUES(?,?,?)').run(customer,'a','Synthetic customer');
  const pdf=Buffer.from('%PDF-1.4\n'+ 'Synthetic report only '.repeat(200)).toString('base64');
  await ok('/customer-report-email','POST',{customer_id:customer,to:'report@example.invalid',pdf_base64:pdf});
  assert.ok(captured(DB).find(m=>m.subject.includes('Security'))?.attachments.length);
  await ok('/stack','PUT',{stack:[{technology:'PHP',product_version:'8.3'}]});
  await ok('/alerts','PUT',{enabled:true,severity:'high',frequency:'hourly'});await ok('/alerts/test','POST',{});
  assert.ok(captured(DB).some(m=>m.subject.includes('Security Alert')));
  await ok('/lifecycle/watches','POST',{product:'Synthetic lifecycle',custom_eol_date:new Date(Date.now()+7*86400000).toISOString().slice(0,10),custom_source_url:'https://example.invalid/support'});
  await ok('/lifecycle/preferences','PUT',{email_enabled:true,lead_days:90});
  const site=await ok('/website-monitor','POST',{url:'https://synthetic-monitor.example.org/',authorized:true,label:'Synthetic only'});
  await ok('/website-monitor/'+site.id+'/check','POST',{});
  assert.equal(DB.sql.prepare('SELECT http_status FROM website_monitor_checks').get().http_status,200);
  if(production){const inactive=await call(env,'/v1/monitoring/watches','POST',{product:'.NET',slug:'dotnet',cycle:'8.0',installed_version:'8.0.9',alert_types:['security','maintenance']},cookie);assert.equal(inactive.status,503);assert.match((await inactive.json()).error,/Monitoring Not Yet Active/);}
  else{await ok('/monitoring/watches','POST',{product:'.NET',slug:'dotnet',cycle:'8.0',installed_version:'8.0.9',alert_types:['security','maintenance']});
  await ok('/monitoring/preferences','PUT',{email_enabled:true,lead_days:90});}
  const result=await call(env,'/__staging/jobs','POST',{id:crypto.randomUUID(),job:'hourly',scenario:'synthetic'},'',admin);
  assert.equal(result.status,200,await result.clone().text());assert.ok(captured(DB).some(m=>/Support|Lifecycle/i.test(m.subject)));
  if(!production)assert.ok(DB.sql.prepare('SELECT COUNT(*) n FROM lifecycle_monitor_events').get().n>0);
  const before=DB.sql.prepare('SELECT COUNT(*) n FROM lifecycle_delivery').get().n;
  await call(env,'/__staging/jobs','POST',{id:crypto.randomUUID(),job:'hourly',scenario:'synthetic'},'',admin);
  assert.equal(DB.sql.prepare('SELECT COUNT(*) n FROM lifecycle_delivery').get().n,before,'No duplicate lifecycle notices');
  assert.equal((await call(env,'/v1/staging-readiness')).status,200);
 }finally{DB.close();}
});
