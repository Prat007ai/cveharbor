import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import worker from '../account-backend/src/index.js';

// Ephemeral in-memory SQLite only. This never connects to Cloudflare or runs a migration command.
const customerA='11111111-1111-4111-8111-111111111111',customerB='22222222-2222-4222-8222-222222222222';
const environmentA='33333333-3333-4333-8333-333333333333',environmentB='44444444-4444-4444-8444-444444444444';
const assetA='55555555-5555-4555-8555-555555555555',assetB='66666666-6666-4666-8666-666666666666';
const token='a'.repeat(64),cve='CVE-2026-12345';
function setup(){
 const sql=new DatabaseSync(':memory:');
 sql.exec(`PRAGMA foreign_keys=ON; CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT);
 CREATE TABLE sessions(id TEXT,user_id TEXT,token_hash TEXT,expires_at INTEGER);
 CREATE TABLE user_totp(user_id TEXT,enabled INTEGER);
 CREATE TABLE auth_rate_limits(key TEXT PRIMARY KEY,window_start INTEGER,count INTEGER);
 INSERT INTO users VALUES('a','a@example.test'),('b','b@example.test'); INSERT INTO user_totp VALUES('a',1),('b',1);`);
 for(const name of ['inventory-schema.sql','finding-status-schema.sql','finding-ticket-schema.sql','finding-ticket-history-schema.sql','customer-score-schema.sql','software-upgrade-history-schema.sql'])sql.exec(fs.readFileSync(new URL('../account-backend/'+name,import.meta.url),'utf8'));
 sql.prepare('INSERT INTO sessions VALUES(?,?,?,?)').run('session','a',createHash('sha256').update(token).digest('hex'),Math.floor(Date.now()/1000)+3600);
 for(const [user,customer,environment,asset] of [['a',customerA,environmentA,assetA],['b',customerB,environmentB,assetB]]){
  sql.prepare('INSERT INTO inventory_customers(id,user_id,name) VALUES(?,?,?)').run(customer,user,'Customer '+user);
  sql.prepare('INSERT INTO inventory_environments(id,user_id,customer_id,name) VALUES(?,?,?,?)').run(environment,user,customer,'Environment '+user);
  sql.prepare('INSERT INTO inventory_assets(id,user_id,environment_id,name,asset_type,technology) VALUES(?,?,?,?,?,?)').run(asset,user,environment,'Asset '+user,'Server','PHP');
  sql.prepare('INSERT INTO customer_finding_statuses(user_id,asset_id,cve_id,status) VALUES(?,?,?,?)').run(user,asset,cve,'Needs Review');
  sql.prepare('INSERT INTO customer_finding_ticket_history(user_id,asset_id,cve_id,ticket_number) VALUES(?,?,?,?)').run(user,asset,cve,'TICKET-'+user);
 }
 const db={sql,writes:0,prepare(query){const statement=sql.prepare(query);const make=args=>({bind:(...values)=>make(values),first:async()=>statement.get(...args)||null,all:async()=>({results:statement.all(...args)}),run:async()=>{db.writes++;return {meta:{changes:Number(statement.run(...args).changes)}}}});return make([])}};
 const env={DB:db,EMAIL_FROM:'fixture@example.test'};
 const request=(path,method='GET',data,headers={})=>worker.fetch(new Request('https://api.cveharbor.com/v1/'+path,{method,headers:{origin:'https://cveharbor.com',cookie:'cvh_session='+token,...headers},...(data?{body:JSON.stringify(data)}:{})}),env,{});
 return {db,request};
}
test('report reads isolate account inventory, statuses, tickets and history without D1 writes',async()=>{
 const {db,request}=setup();
 try{
  const inventory=await (await request('inventory')).json();assert.deepEqual(inventory.customers.map(x=>x.id),[customerA]);assert.deepEqual(inventory.assets.map(x=>x.id),[assetA]);
  const statuses=await (await request('finding-statuses')).json();assert.deepEqual(statuses.statuses.map(x=>x.asset_id),[assetA]);
  const tickets=await (await request('finding-tickets')).json();assert.deepEqual(tickets.tickets.map(x=>x.ticket_number),['TICKET-a']);
  assert.equal((await request('customer-score-history?customer_id='+customerB)).status,404);
  assert.equal((await request('customer-score-history?customer_id='+customerA+'&environment_id='+environmentB)).status,404);
  db.sql.prepare('UPDATE inventory_assets SET version=? WHERE id=?').run('8.4.2',assetA);
  db.sql.prepare('UPDATE inventory_assets SET version=? WHERE id=?').run('8.4.3',assetB);
  const history=await (await request('inventory/software-history?customer_id='+customerA)).json();
  assert.equal(history.ready,true);assert.deepEqual(history.entries.map(x=>x.asset_id),[assetA]);
  assert.equal((await request('inventory/software-history?customer_id='+customerB)).status,404);
  assert.equal((await request('inventory/software-history?customer_id='+customerA+'&environment_id='+environmentB)).status,404);
  assert.equal((await request('inventory/software-history?customer_id='+customerA,'GET',null,{cookie:''})).status,401);
  assert.equal(db.writes,0);
 }finally{db.sql.close()}
});
test('existing server authorization rejects foreign asset writes, missing sessions and untrusted origins',async()=>{
 const {db,request}=setup();
 try{
  for(const [route,method,data] of [['finding-statuses','PUT',{status:'Fixed/Patched'}],['finding-tickets','POST',{ticket_number:'OTHER'}]]){
   assert.equal((await request(route+'/'+assetB+'/'+cve,method,data)).status,404);
   assert.equal((await request(route+'/'+assetA+'/'+cve,method,data,{cookie:''})).status,401);
   assert.equal((await request(route+'/'+assetA+'/'+cve,method,data,{origin:'https://untrusted.example.test'})).status,403);
  }
  assert.equal(db.writes,0);
 }finally{db.sql.close()}
});
test('authorized dashboard status and ticket saves are returned by the report read APIs',async()=>{
 const {db,request}=setup();
 try{
  assert.equal((await request('finding-statuses/'+assetA+'/'+cve,'PUT',{status:'Fixed/Patched',notes:'Evidence retained'})).status,200);
  assert.equal((await request('finding-tickets/'+assetA+'/'+cve,'POST',{ticket_number:'DEV-22'})).status,201);
  const saved=await (await request('finding-statuses')).json();assert.equal(saved.statuses[0].status,'Fixed/Patched');assert.equal(saved.statuses[0].notes,'Evidence retained');
  const tickets=await (await request('finding-tickets')).json();assert.deepEqual(tickets.tickets.map(x=>x.ticket_number).sort(),['DEV-22','TICKET-a']);
  assert.equal(db.writes,2,'one write per explicit remediation save');
 }finally{db.sql.close()}
});
test('email rejects foreign or mismatched report scope and preserves supplied PDF bytes on valid delivery',async t=>{
 const {db,request}=setup(),sent=[];
 t.mock.method(globalThis,'fetch',async(_url,options)=>{sent.push(JSON.parse(options.body));return Response.json({data:{failed:0,succeeded:1}})});
 const pdf=Buffer.from('%PDF-1.7\n'+'synthetic fixture '.repeat(20)).toString('base64');
 const data={to:'fixture-recipient@example.test',customer_id:customerA,environment_id:environmentA,pdf_base64:pdf};
 try{
  assert.equal((await request('customer-report-email','POST',{...data,customer_id:customerB})).status,404);
  assert.equal((await request('customer-report-email','POST',{...data,environment_id:environmentB})).status,400);
  assert.equal((await request('customer-report-email','POST',data,{cookie:''})).status,401);
  assert.equal(sent.length,0);assert.equal(db.writes,0);
  assert.equal((await request('customer-report-email','POST',data)).status,200);
  assert.equal(sent.length,1);assert.equal(sent[0].attachments[0].fileblob,pdf);
  assert.match(sent[0].subject,/Customer a/);assert.doesNotMatch(sent[0].subject,/Customer b/);
 }finally{db.sql.close()}
});
