import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import worker from '../src/index.js';
import {unifiedFixture,assetOne,assetTwo,assetOther} from './helpers/unified-db.mjs';
import {fixtureCve} from './helpers/assignment-db.mjs';

async function setup(t){
  const f=await unifiedFixture(), db=f.DB.sql;
  const sql=path=>fs.readFileSync(new URL(path,import.meta.url),'utf8');
  db.exec(sql('../migrations/0029_finding_assignment_links.sql'));
  db.exec(sql('../../deployment/proposals/customer-remediation/schema.sql'));
  db.exec(sql('../migrations/0032_recovery_control.sql'));
  db.exec(sql('../../deployment/proposals/organization-team-access/schema.sql'));
  f.env.TEAM_ACCESS_ENABLED='true';
  t.mock.method(globalThis,'fetch',f.fetcher);
  async function call(user,path,method='GET',body,status=200){
    const res=await worker.fetch(f.request('/team/'+path,method,body,user),f.env);
    const result=await res.json();assert.equal(res.status,status,JSON.stringify(result));return result;
  }
  const org=(await call('a','organizations','POST',{name:'Northstar',include_existing:true},201)).id;
  const base='organizations/'+org;
  const grant={role:'Viewer',scope:'selected',customers:['c-'+assetOne]};
  const invite=async()=>{await call('a',base+'/members','POST',{email:'other@example.test',...grant},201);return f.emails.at(-1).text_body.match(/#team-invite=([a-f0-9]{64})/)[1];};
  const accept=async(token)=>{const info=await call('b','invitation','POST',{token});await call('b','accept','POST',{token,revision:info.revision});};
  return {...f,call,base,org,grant,invite,accept,db};
}

test('email-bound MFA session, one-use invitation, current customer grants and removal',async t=>{
  const {call,base,grant,invite,accept,db,emails}=await setup(t);
  await call('',base+'/members','GET',undefined,401);
  await call('b',base+'/members','GET',undefined,404);
  await call('a',base+'/members','POST',{email:'other@example.test',...grant,customers:['c-'+assetOther]},409);
  const token=await invite();assert.ok(emails[0].html_body.includes('cid:harbor-light.png'));
  assert.ok(!JSON.stringify(db.prepare('SELECT * FROM team_members').all()).includes(token));
  await call('a','invitation','POST',{token},404);
  await accept(token);await call('b','accept','POST',{token,revision:1},404);
  const snapshot=await call('b',base+'/customers');
  assert.deepEqual(snapshot.customers.map(c=>c.id),['c-'+assetOne]);
  const c=await call('b',base+'/customers/c-'+assetOne);assert.equal(c.assets[0].id,assetOne);
  await call('b',base+'/customers/c-'+assetTwo,'GET',undefined,404);
  await call('b',base+'/members','GET',undefined,403);
  const change={...c.assets[0],expected:c.assets[0],asset_id:assetOne,notes:'Fictional team note'};
  await call('b',base+'/asset/c-'+assetOne,'PUT',change,403);
  let b=(await call('a',base+'/members')).members.find(m=>m.email==='other@example.test');
  assert.equal(b.status,'Active');assert.equal(b.signed_at,1);
  await call('a',base+'/members/'+b.id,'PUT',{...grant,role:'Editor',revision:b.revision});
  await call('a',base+'/members/'+b.id,'PUT',{...grant,revision:b.revision},409);
  await call('b',base+'/asset/c-'+assetOne,'PUT',{...change,asset_id:assetTwo},409);
  await call('b',base+'/asset/c-'+assetOne,'PUT',change);
  await call('b',base+'/asset/c-'+assetOne,'PUT',change,409);
  assert.equal((await call('a',base+'/customers/c-'+assetOne)).assets[0].notes,change.notes);
  await call('a',base+'/members/'+b.id,'DELETE',{revision:b.revision+1});
  await call('b',base+'/customers/c-'+assetOne,'GET',undefined,404);
});

test('reissue, expiry, mail failure, new customers, recovery hold and schema compatibility',async t=>{
  const {call,base,grant,invite,accept,db,emails,setMailFailed,env}=await setup(t);
  const token=await invite();
  let b=(await call('a',base+'/members')).members.find(m=>!m.active);
  await call('a',base+'/members/'+b.id,'POST',{revision:b.revision},201);
  await call('b','invitation','POST',{token},404);
  const newer=emails.at(-1).text_body.match(/#team-invite=([a-f0-9]{64})/)[1];
  await accept(newer);
  b=(await call('a',base+'/members')).members.find(m=>m.id===b.id);
  await call('a',base+'/members/'+b.id,'PUT',{revision:b.revision,role:'Editor',scope:'all',customers:[]});
  db.prepare('INSERT INTO inventory_customers(id,user_id,name) VALUES(?,?,?)').run('c-future','a','Future');
  assert.equal((await call('b',base+'/customers')).customers.length,3);
  setMailFailed(true);
  await call('a',base+'/members','POST',{...grant,email:'future@example.test'},503);
  assert.equal((await call('a',base+'/members')).members.find(m=>m.email==='future@example.test').status,'Expired');
  db.prepare('UPDATE operations_control SET write_hold=1 WHERE id=1').run();
  await call('b',base+'/customers','GET',undefined,503);
  db.prepare('UPDATE operations_control SET write_hold=0 WHERE id=1').run();
  env.TEAM_ACCESS_ENABLED='false';await call('a','organizations','GET',undefined,404);
});

test('customer-scoped remediation updates preserve actor and reject stale or unrelated records',async t=>{
  const {call,base,grant,invite,accept,db}=await setup(t);
  await accept(await invite());
  const member=(await call('a',base+'/members')).members.find(m=>m.email==='other@example.test');
  await call('a',base+'/members/'+member.id,'PUT',{...grant,role:'Editor',revision:member.revision});
  db.prepare('INSERT INTO remediation_customer_scopes(user_id,record_id,cve_id,customer_id,associated_by,associated_at) VALUES(?,?,?,?,?,?)').run('a',fixtureCve,fixtureCve,'c-'+assetOne,'sender@example.test','2026-01-10');
  const data={id:fixtureCve,expected_updated:'2026-11-01',status:'Remediated',owner:'Fictional analyst',due:'',notes:'Verified in test',status_change_reason:'Test verification'};
  await call('b',base+'/remediation/c-'+assetTwo,'PUT',data,404);
  await call('b',base+'/remediation/c-'+assetOne,'PUT',data);
  await call('b',base+'/remediation/c-'+assetOne,'PUT',data,409);
  assert.equal(db.prepare('SELECT changed_by FROM remediation_status_changes ORDER BY id DESC LIMIT 1').get().changed_by,'other@example.test');
});

test('independent organization owns its inventory and survives an ownership transfer',async t=>{
  const {call,db,emails}=await setup(t);
  const org=(await call('b','organizations','POST',{name:'Independent'},201)).id, base='organizations/'+org;
  assert.deepEqual((await call('b',base+'/customers')).customers,[]);
  const customer=(await call('b',base+'/customers','POST',{name:'Customer D'},201)).id;
  const env=(await call('b',base+'/environments/'+customer,'POST',{name:'Primary',kind:'Production'},201)).id;
  const asset=(await call('b',base+'/assets/'+customer,'POST',{name:'Example host',technology:'Example OS',environment_id:env,version:'1.2'},201)).id;
  await call('b',base+'/remediation/'+customer,'POST',{cve_id:'CVE-2099-12345',owner:'Test owner',notes:'Team investigation'});
  const snapshot=await call('b',base+'/customers/'+customer);
  assert.equal(snapshot.remediations[0].owner,'Test owner');
  assert.equal(snapshot.assets[0].id,asset);
  const founder=(await call('b',base+'/members')).members[0];
  await call('b',base+'/members/'+founder.id,'PUT',{role:'Viewer',scope:'selected',customers:[customer],revision:founder.revision},409);
  await call('b',base+'/members','POST',{email:'sender@example.test',role:'Owner',scope:'all',customers:[]},201);
  const token=emails.at(-1).text_body.match(/#team-invite=([a-f0-9]{64})/)[1];
  await call('a','accept','POST',{token,revision:1});
  await call('a',base+'/members/'+founder.id,'PUT',{role:'Viewer',scope:'selected',customers:[customer],revision:founder.revision});
  await call('b',base+'/members','GET',undefined,403);
  await call('b',base+'/customers','POST',{name:'Another'},403);
  const old=snapshot.assets[0],payload={...old,asset_id:asset,expected:old,version:'2.0'};
  await call('b',base+'/asset/'+customer,'PUT',payload,403);
  await call('a',base+'/asset/'+customer,'PUT',payload);
  await call('a',base+'/asset/'+customer,'PUT',payload,409);
  assert.equal((await call('b',base+'/customers/'+customer)).assets[0].version,'2.0');
  assert.equal(db.prepare('SELECT user_id FROM inventory_assets WHERE id=?').get(asset).user_id,'org-'+org);
});
