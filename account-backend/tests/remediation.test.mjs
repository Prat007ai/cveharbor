import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import worker from '../src/index.js';
import {
  normalizeId,normalizeRecord,renderAssignmentEmail,isMigrated,assignmentReady
} from '../src/remediation.js';

if(!globalThis.crypto)globalThis.crypto=webcrypto;
const origin='https://cveharbor.com';
const base='https://api.cveharbor.com/v1';
const id='CVE-2026-12345';
const session='a'.repeat(64);
const user={id:'account-1',email:'security@example.org',sid:'session-1'};

class MockD1{
  constructor(migrated=true){
    this.migrated=migrated;
    this.rows=new Map();
    this.assignments=new Map();
    this.rate=new Map();
  }
  key(uid,cve){return uid+'|'+cve;}
  prepare(query){
    const db=this;
    if(query.includes('SELECT user_id FROM remediation_assignments LIMIT 1')){
      return {async first(){
        if(!db.migrated)throw Error('no such table: remediation_assignments');
        return null;
      }};
    }
    return {bind(...args){
      return {
        async first(){
          if(query.includes('FROM sessions JOIN users'))return user;
          if(query.includes('SELECT user_id FROM remediation_assignments LIMIT 1')){
            if(!db.migrated)throw Error('no such table: remediation_assignments');
            return null;
          }
          if(query.includes('SELECT cve_id FROM remediations WHERE user_id=? AND cve_id=?')){
            const r=db.rows.get(db.key(args[0],args[1]));return r?{cve_id:r.id}:null;
          }
          if(query.includes('COUNT(*) AS total FROM remediations'))return {total:db.rows.size};
          if(query.includes('SELECT assignee_email,state,claimed_at,last_sent_at FROM remediation_assignments')){
            return db.assignments.get(db.key(args[0],args[1]))||null;
          }
          return null;
        },
        async all(){
          if(query.includes('FROM remediations r LEFT JOIN')){
            return {results:[...db.rows.values()].map(r=>{
              const a=db.assignments.get(db.key(user.id,r.id));
              return {...r,assigned_to:a?.assignee_email||null,assignment_status:a?.state||null,notified_at:a?.last_sent_at||null};
            })};
          }
          if(query.includes('FROM remediations WHERE user_id=? ORDER BY'))return {results:[...db.rows.values()]};
          if(query.includes('SELECT cve_id FROM remediations WHERE user_id=?'))
            return {results:[...db.rows.values()].map(r=>({cve_id:r.id}))};
          return {results:[]};
        },
        async run(){
          if(query.includes('DELETE FROM remediation_assignment_limits WHERE window_start<?')){
            const cutoff=args[0];
            for(const [key,value] of db.rate)if(value.window<cutoff)db.rate.delete(key);
            return {meta:{changes:1}};
          }
          if(query.includes('INSERT INTO remediations(user_id,cve_id,status,owner,due,notes,updated_at)')){
            const [uid,cve,status,owner,due,notes,updated]=args;
            db.rows.set(db.key(uid,cve),{id:cve,status,owner,due,notes,updated});
            return {meta:{changes:1}};
          }
          if(query.includes('INSERT OR IGNORE INTO remediations')){
            const [uid,cve,updated]=args,k=db.key(uid,cve);
            if(!db.rows.has(k))db.rows.set(k,{id:cve,status:'Open',owner:'',due:'',notes:'',updated});
            return {meta:{changes:1}};
          }
          if(query.includes('DELETE FROM remediations WHERE user_id=? AND cve_id=?')){
            const k=db.key(args[0],args[1]);db.rows.delete(k);db.assignments.delete(k);
            return {meta:{changes:1}};
          }
          if(query.includes('INSERT INTO remediation_assignment_limits(')){
            const [key,now,cutoff,,,,max]=args,old=db.rate.get(key);
            if(old&&old.window>=cutoff&&old.count>=max)return {meta:{changes:0}};
            db.rate.set(key,{window:!old||old.window<cutoff?now:old.window,
              count:!old||old.window<cutoff?1:old.count+1});
            return {meta:{changes:1}};
          }
          if(query.includes('INSERT INTO remediation_assignments(')){
            const [uid,cve,email,requester,state,claimed,cutoff]=args,k=db.key(uid,cve);
            const previous=db.assignments.get(k);
            if(previous?.state==='sending'&&previous.claimed_at>=cutoff)return {meta:{changes:0}};
            db.assignments.set(k,{assignee_email:email,assigned_by:requester,state,claimed_at:claimed,
              last_sent_at:previous?.last_sent_at||null});
            return {meta:{changes:1}};
          }
          if(query.includes("UPDATE remediation_assignments SET state='sent'")){
            const [sent,providerId,uid,cve,claimed]=args,k=db.key(uid,cve);
            const item=db.assignments.get(k);
            if(item?.claimed_at===claimed){
              item.state='sent';item.last_sent_at=sent;item.provider_id=providerId;
              return {meta:{changes:1}};
            }
          }
          if(query.includes("UPDATE remediation_assignments SET state='failed'")){
            const [uid,cve,claimed]=args,k=db.key(uid,cve);
            const item=db.assignments.get(k);
            if(item?.claimed_at===claimed)item.state='failed';
            return {meta:{changes:1}};
          }
          throw Error('Unmocked D1 statement '+query);
        }
      };
    }};
  }
  async batch(statements){return Promise.all(statements.map(s=>s.run()));}
}
const env=db=>({
  DB:db,EMAIL_FROM:'alerts@cveharbor.com',SMTP2GO_API_KEY:'test-only',
  ASSIGNMENT_EMAIL_ENABLED:'true',ASSIGNMENT_ALLOWED_DOMAINS:'example.org,example.net'
});
const request=(path,method='GET',data,sessionOn=true,headers={})=>new Request(base+path,{
  method,headers:{Origin:origin,...(sessionOn?{'Cookie':'cvh_session='+session}:{}),
    ...(data?{'Content-Type':'application/json'}:{}),...headers},
  body:data?JSON.stringify(data):undefined
});

test('validates CVE identifiers and record formats without accepting invalid dates or statuses',()=>{
  assert.equal(normalizeId(' cve-2026-12345 '),id);
  assert.equal(normalizeId('CVE-2026-123'),null);
  assert.equal(normalizeId('CVE-2026-12345/../../../'),null);
  assert.equal(normalizeRecord(id,{status:'Investigating',notes:'Test'}).id,id);
  assert.throws(()=>normalizeRecord(id,{status:'Administrator'}),/Invalid/);
  assert.throws(()=>normalizeRecord(id,{due:'tomorrow'}),/Invalid/);
});

test('assignment email states exposure is not confirmed and requires Azure DevOps work item',()=>{
  const mail=renderAssignmentEmail(id,'analyst@example.org','security@example.org');
  assert.match(mail.subject,/CVE-2026-12345/);
  assert.match(mail.text,/may affect/i);
  assert.match(mail.text,/not been confirmed/i);
  assert.match(mail.text,/Azure DevOps work item/);
  assert.match(mail.text,/your own Azure DevOps organization/);
  assert.match(mail.text,/does not create a DevOps work item automatically/);
  assert.doesNotMatch(mail.text,/password=\w+/);
  assert.match(mail.html,/VULNERABILITY REVIEW REQUEST/);
  assert.match(mail.html,/www\.cve\.org/);
});

test('branded assignment includes safe notes and authoritative links without inventing CVE severity',()=>{
 const mail=renderAssignmentEmail('CVE-2026-12345','engineer@example.net','security@example.org','Check the public-facing software stack <script>alert(1)</script>');
 assert.match(mail.html,/VULNERABILITY REVIEW REQUEST/);
 assert.match(mail.html,/CVEHarbor/);
 assert.match(mail.html,/NVD vulnerability details/);
 assert.match(mail.html,/Sender notes/);
 assert.match(mail.html,/&lt;script&gt;/);
 assert.doesNotMatch(mail.html,/<script>alert/);
 assert.match(mail.text,/Check the public-facing software stack/);
 assert.doesNotMatch(mail.html,/Severity:\\s*Critical/);
 assert.throws(()=>renderAssignmentEmail('CVE-2026-12345','engineer@example.net','security@example.org','a'.repeat(1001)));
});
test('Outlook template uses centered presentation tables and explicit background cells',()=>{
 const mail=renderAssignmentEmail('CVE-2026-12345','engineer@example.net','security@example.org','Investigate the affected versions');
 assert.match(mail.html,/\[if mso\]/);
 assert.match(mail.html,/width="640"/);
 assert.match(mail.html,/bgcolor="#f3f7fa"/);
 assert.match(mail.html,/bgcolor="#ffffff"/);
 assert.match(mail.html,/border-collapse:collapse/);
 assert.match(mail.html,/Investigate the affected versions/);
 assert.match(mail.html,/Review this CVE in CVEHarbor/);
});
test('assignment email identifies verified requester in HTML and plain text',()=>{
 const requester='lini.peram@gmail.com';
 const mail=renderAssignmentEmail('CVE-2026-76418','reviewer@example.org',requester);
 assert.match(mail.text,/A colleague \\(lini\\.peram@gmail\\.com\\) has requested your review of CVE-2026-76418/);
 assert.match(mail.html,/A colleague \\(lini\\.peram@gmail\\.com\\) has requested your review of CVE-2026-76418/);
});
test('D1 feature gate hides assignment emails until migration and explicit configuration',async()=>{
  assert.equal(await isMigrated({DB:new MockD1(false)}),false);
  assert.equal(await isMigrated({DB:new MockD1(true)}),true);
  assert.equal(assignmentReady({...env(new MockD1()),ASSIGNMENT_EMAIL_ENABLED:'false'}),false);
  assert.equal(assignmentReady(env(new MockD1())),true);
});

test('endpoints require a signed-in account and valid browser origin',async()=>{
  const db=new MockD1();
  assert.equal((await worker.fetch(request('/remediations/features','GET',null,false),env(db))).status,401);
  assert.equal((await worker.fetch(request('/remediations/'+id,'PUT',{status:'Open'},true,{Origin:'https://malicious.example'}),env(db))).status,403);
  assert.equal((await worker.fetch(request('/remediations/features'),env(db))).status,200);
});

test('cloud upserts preserve private records, bulk import merges, and deletion is account-scoped',async()=>{
  const db=new MockD1();
  const workerEnv=env(db);
  const record={status:'Investigating',owner:'Engineer',due:'2026-11-10',notes:'Validate installed version'};
  let response=await worker.fetch(request('/remediations/'+id,'PUT',record),workerEnv);
  assert.equal(response.status,200);
  assert.equal((await response.json()).storage,'d1');
  response=await worker.fetch(request('/remediations'),workerEnv);
  assert.equal((await response.json()).remediations[0].notes,record.notes);
  response=await worker.fetch(request('/remediations','PUT',{remediations:[
    {id:'CVE-2026-23456',status:'Open',owner:'',due:'',notes:''}
  ]}),workerEnv);
  assert.equal((await response.json()).saved,1);
  assert.equal(db.rows.size,2,'legacy import does not remove other cloud records');
  response=await worker.fetch(request('/remediations/'+id,'DELETE'),workerEnv);
  assert.equal(response.status,200);
  assert.equal(db.rows.size,1);
});

test('assignment uses verified sender, domain allowlist, sanitized reviewer notes and repeat suppression',async()=>{
  const db=new MockD1(),workerEnv=env(db);
  const original=globalThis.fetch;
  let count=0,submitted=null;
  globalThis.fetch=async(url,options)=>{
    assert.equal(url,'https://api.smtp2go.com/v3/email/send');
    submitted=JSON.parse(options.body);
    count++;
    return new Response(JSON.stringify({data:{succeeded:1,failed:0,email_id:'test-notice-1'}}),{
      status:200,headers:{'Content-Type':'application/json'}
    });
  };
  try{
    const payload={email:'engineer@example.net',notes:'SENSITIVE SHOULD NOT BE EMAILED',subject:'injected'};
    const first=await worker.fetch(request('/remediations/'+id+'/assign','POST',payload),workerEnv);
    assert.equal(first.status,200,await first.text?.());
    assert.equal(count,1);
    assert.equal(submitted.to[0],'engineer@example.net');
    assert.equal(submitted.sender,'alerts@cveharbor.com');
    assert.match(submitted.subject,/CVE-2026-12345/);
    assert.doesNotMatch(submitted.html_body,/SENSITIVE SHOULD NOT BE EMAILED/);
    assert.doesNotMatch(submitted.text_body,/injected/);
    const second=await worker.fetch(request('/remediations/'+id+'/assign','POST',payload),workerEnv);
    assert.equal((await second.json()).duplicate,true);
    assert.equal(count,1);
    const list=await worker.fetch(request('/remediations'),workerEnv);
    const saved=(await list.json()).remediations[0];
    assert.equal(saved.assigned_to,'engineer@example.net');
    assert.equal(saved.assignment_status,'sent');
  }finally{globalThis.fetch=original;}
});

test('external recipients are permitted but disabled delivery is refused',async()=>{
  const db=new MockD1(),workerEnv=env(db);
  assert.equal(assignmentReady(workerEnv),true,'external recipients are allowed when the service is configured');
  assert.equal((await worker.fetch(request('/remediations/'+id+'/assign','POST',{email:'employee@example.org'}),{
    ...workerEnv,ASSIGNMENT_EMAIL_ENABLED:'false'})).status,503);
  assert.equal(db.assignments.size,0);
});

test('missing assignment table blocks mail while leaving existing cloud record storage usable',async()=>{
  const db=new MockD1(false),workerEnv=env(db);
  let response=await worker.fetch(request('/remediations/'+id,'PUT',{status:'Open'}),workerEnv);
  assert.equal(response.status,200);
  response=await worker.fetch(request('/remediations/'+id+'/assign','POST',{email:'employee@example.org'}),workerEnv);
  assert.equal(response.status,503);
  const flags=await worker.fetch(request('/remediations/features'),workerEnv);
  assert.equal((await flags.json()).assignments_available,false);
});


test('assignment sending enforces ten per sender hourly and two per recipient daily',async()=>{
  const previous=globalThis.fetch;
  globalThis.fetch=async()=>new Response(JSON.stringify({data:{succeeded:1,failed:0,email_id:'quota-test'}}),{
    status:200,headers:{'Content-Type':'application/json'}
  });
  try{
    const first=new MockD1();
    for(let i=0;i<10;i++){
      const id='CVE-2026-'+(50000+i);
      const response=await worker.fetch(request('/remediations/'+id+'/assign','POST',{
        email:'colleague'+i+'@example.net'
      }),env(first));
      assert.equal(response.status,200,'ten distinct assignments are accepted');
    }
    const over=await worker.fetch(request('/remediations/CVE-2026-60000/assign','POST',{
      email:'newperson@example.net'
    }),env(first));
    assert.equal(over.status,429,'eleventh assignment in an hour is rejected');

    const second=new MockD1();
    for(const id of ['CVE-2026-70001','CVE-2026-70002']){
      const response=await worker.fetch(request('/remediations/'+id+'/assign','POST',{
        email:'same@example.org'
      }),env(second));
      assert.equal(response.status,200);
    }
    const third=await worker.fetch(request('/remediations/CVE-2026-70003/assign','POST',{
      email:'same@example.org'
    }),env(second));
    assert.equal(third.status,429,'a third email to the same recipient in 24 hours is rejected');
  }finally{globalThis.fetch=previous;}
});

test('provider failure is recorded without falsely reporting email delivery',async()=>{
  const db=new MockD1(),workerEnv=env(db),original=globalThis.fetch;
  globalThis.fetch=async()=>new Response(JSON.stringify({data:{succeeded:0,failed:1}}),{
    status:200,headers:{'Content-Type':'application/json'}
  });
  try{
    const response=await worker.fetch(request('/remediations/'+id+'/assign','POST',{
      email:'reviewer@example.net'
    }),workerEnv);
    assert.equal(response.status,502);
    const status=db.assignments.get(db.key(user.id,id));
    assert.equal(status.state,'failed');
  }finally{globalThis.fetch=original;}
});
