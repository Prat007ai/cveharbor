import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
import {inventoryRoute} from '../src/inventory.js';
const customer='11111111-1111-4111-8111-111111111111',other='22222222-2222-4222-8222-222222222222';
const environment='33333333-3333-4333-8333-333333333333',staging='44444444-4444-4444-8444-444444444444',foreign='55555555-5555-4555-8555-555555555555';
const asset='66666666-6666-4666-8666-666666666666';
const schema=fs.readFileSync(new URL('../software-upgrade-history-schema.sql',import.meta.url),'utf8');
function setup(enabled=true){
 const sql=new DatabaseSync(':memory:');sql.exec("PRAGMA foreign_keys=ON; CREATE TABLE users(id TEXT PRIMARY KEY); INSERT INTO users VALUES('a'),('b');");
 sql.exec(fs.readFileSync(new URL('../inventory-schema.sql',import.meta.url),'utf8'));
 sql.prepare('INSERT INTO inventory_customers(id,user_id,name) VALUES(?,?,?)').run(customer,'a','Customer A');
 sql.prepare('INSERT INTO inventory_customers(id,user_id,name) VALUES(?,?,?)').run(other,'b','Customer B');
 for(const [id,owner,parent] of [[environment,'a',customer],[staging,'a',customer],[foreign,'b',other]])sql.prepare('INSERT INTO inventory_environments(id,user_id,customer_id,name) VALUES(?,?,?,?)').run(id,owner,parent,id);
 sql.prepare('INSERT INTO inventory_assets(id,user_id,environment_id,name,asset_type,technology,version) VALUES(?,?,?,?,?,?,?)').run(asset,'a',environment,'Web','Software','WordPress','6.6.1');
 if(enabled)sql.exec(schema);
 const env={DB:{prepare(q){const statement=sql.prepare(q);const make=args=>({bind:(...a)=>make(a),first:async()=>statement.get(...args)||null,all:async()=>({results:statement.all(...args)}),run:async()=>({meta:{changes:Number(statement.run(...args).changes)}})});return make([])}}};
 const request=(suffix,method='GET',data={},owner='a')=>inventoryRoute(new Request('https://api.cveharbor.com/v1/inventory'+suffix,{method}),env,{id:owner},'/v1/inventory'+suffix.split('?')[0],data);
 const update=(version,extra={})=>request('/assets/'+asset,'PUT',{name:'Web',asset_type:'Software',technology:'WordPress',version,...extra});
 const history=(scope=environment)=>request('/software-history?customer_id='+customer+(scope?'&environment_id='+scope:'')).then(r=>r.json());
 return {sql,request,update,history};
}
test('version edit records old/new values atomically, notes-only and identical saves do not add history',async()=>{
 const {sql,update,history}=setup();try{
  assert.deepEqual((await history()).entries,[]);
  await update('6.6.2');await update('6.6.2',{notes:'Reviewed'});await update('6.6.2');
  const rows=(await history()).entries;assert.equal(rows.length,1);assert.equal(rows[0].previous_version,'6.6.1');assert.equal(rows[0].version,'6.6.2');assert.equal(rows[0].technology,'WordPress');assert.ok(Number.isFinite(Date.parse(rows[0].recorded_at)));
  await update('6.6.1');await update('',{technology:'Replacement software'});
  const all=(await history()).entries;assert.equal(all.length,3);assert.equal(all[0].previous_technology,'WordPress');assert.equal(all[0].technology,'Replacement software');assert.equal(all[1].version,'6.6.1','downgrades are retained without claiming they are upgrades');
  sql.exec(schema);assert.equal((await history()).entries.length,3,'setup is repeatable without deleting data');
  sql.exec("CREATE TRIGGER fail_history BEFORE INSERT ON inventory_software_history BEGIN SELECT RAISE(ABORT,'test failure'); END;");
  await assert.rejects(()=>update('9.0'));assert.equal(sql.prepare('SELECT version FROM inventory_assets WHERE id=?').get(asset).version,'','failed history write rolls the version edit back');
 }finally{sql.close()}
});
test('history is scoped, paginated, read only and cannot expose another account or environment',async()=>{
 const {sql,update,request,history}=setup();try{
  for(let i=0;i<105;i++)await update('6.6.'+(i+2));
  const first=await history();assert.equal(first.entries.length,100);assert.ok(first.next_before);
  const next=await (await request('/software-history?customer_id='+customer+'&before='+first.next_before)).json();assert.equal(next.entries.length,5);assert.equal(next.next_before,null);
  assert.equal(new Set([...first.entries,...next.entries].map(x=>x.id)).size,105);
  assert.equal((await history(staging)).entries.length,0);
  await assert.rejects(()=>request('/software-history?customer_id='+other),e=>e.status===404);
  await assert.rejects(()=>request('/software-history?customer_id='+customer+'&environment_id='+foreign),e=>e.status===404);
  await assert.rejects(()=>request('/assets/'+asset,'PUT',{version:'9.0'},'b'),e=>e.status===404);
  await assert.rejects(()=>request('/software-history?customer_id='+customer+'&before=0'),e=>e.status===400);
  assert.equal((await request('/software-history','POST')).status,404);
  sql.exec("CREATE TRIGGER no_history_write BEFORE INSERT ON inventory_software_history BEGIN SELECT RAISE(ABORT,'read wrote data'); END;");
  assert.equal((await history()).entries.length,100);
  sql.prepare('DELETE FROM inventory_assets WHERE id=?').run(asset);assert.equal((await history()).entries.length,0,'existing cascade deletion policy is respected');
 }finally{sql.close()}
});
test('missing table or trigger reports tracking unavailable; activation never invents past changes',async()=>{
 const {sql,update,history}=setup(false);try{
  assert.equal((await history()).ready,false);await update('6.6.2');sql.exec(schema);
  assert.deepEqual((await history()).entries,[]);
  sql.exec('DROP TRIGGER inventory_software_version_changed');assert.equal((await history()).ready,false);
 }finally{sql.close()}
});
