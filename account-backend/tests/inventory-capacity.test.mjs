import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {inventoryPage} from '../src/inventory-pages.js';
import {inventoryRoute} from '../src/inventory.js';
import {capacityFixture,fixtureId} from './helpers/capacity-db.mjs';
import {readInventory} from '../../inventory-client.js';
const url='https://api.cveharbor.com/v1/inventory/page?';
const read=(env,params={},owner='owner-0',team)=>inventoryPage(new Request(url+new URLSearchParams(params)),env,{id:owner},team);
test('10,000 rows are complete and unique; pages are bounded and scope is enforced',async()=>{
 const f=capacityFixture();try{
  let cursor='',all=[],pages=0;
  do{const page=await read(f,{resource:'assets',...cursor?{cursor}:{}});assert.ok(page.items.length<=250);all.push(...page.items);cursor=page.next_cursor;pages++;}while(cursor);
  assert.equal(pages,40);assert.equal(all.length,10000);assert.equal(new Set(all.map(x=>x.id)).size,10000);
  assert.equal((await read(f,{customer_id:fixtureId(1)})).items.length,200);
  assert.equal((await read(f,{environment_id:fixtureId(1000)})).items.length,100);
  const first=await read(f);await assert.rejects(()=>read(f,{cursor:first.next_cursor},'foreign'),e=>e.status===400);
  await assert.rejects(()=>read(f,{resource:'toString'}),e=>e.status===400);
  await assert.rejects(()=>read(f,{cursor:'garbage'}),e=>e.status===400);
  await assert.rejects(()=>read(f,{cursor:first.next_cursor,customer_id:fixtureId(2)}),e=>e.status===400);
  const legacy=await inventoryRoute(new Request('https://api.cveharbor.com/v1/inventory'),f,{id:'owner-0'},'/v1/inventory');assert.equal(legacy.status,409);
  const status=await (await inventoryRoute(new Request('https://api.cveharbor.com/v1/inventory/status'),f,{id:'owner-0'},'/v1/inventory/status')).json();assert.equal(status.max_assets,50000);assert.equal(status.pagination,true);
 }finally{f.close()}
});
test('edits, inserts and deletes invalidate old pages instead of silently mixing revisions',async()=>{
 const f=capacityFixture({assets:600});try{
  for(const change of ["UPDATE inventory_assets SET name='Renamed' WHERE id='"+fixtureId(10000)+"'","DELETE FROM inventory_assets WHERE id='"+fixtureId(10001)+"'","INSERT INTO inventory_assets(id,user_id,environment_id,name,asset_type,technology) VALUES('"+fixtureId(99999)+"','owner-0','"+fixtureId(1000)+"','New','Software','PHP')"]){
   const first=await read(f);f.sql.exec(change);await assert.rejects(()=>read(f,{cursor:first.next_cursor}),e=>e.status===409);
  }
 }finally{f.close()}
});
test('50 owners and revocation between pages never cross customer boundaries',async()=>{
 const f=capacityFixture({owners:50,assets:30000});try{
  for(let i=0;i<50;i++){const page=await read(f,{},'owner-'+i);assert.equal(page.items.length,250);assert.ok(page.items.every(a=>(parseInt(a.environment_id.slice(0,8),16)-1000)%50===i));}
  const team={owner:'owner-0',org:'demo-org',actor:'viewer',customer:fixtureId(1)};
  f.sql.prepare('INSERT INTO team_visible_customers VALUES(?,?,?,?)').run(team.org,team.actor,team.owner,team.customer);
  const first=await read(f,{customer_id:team.customer},'viewer',team);assert.ok(first.next_cursor);
  f.sql.exec('DELETE FROM team_visible_customers');
  await assert.rejects(()=>read(f,{customer_id:team.customer,cursor:first.next_cursor},'viewer',team),e=>e.status===404);
 }finally{f.close()}
});
test('browser reader retries an invalidated snapshot and returns all rows, never a partial result',async()=>{
 const f=capacityFixture({assets:1000});try{
  let changed=false,calls=0;
  const result=await readInventory('inventory',{fetchPage:async params=>{
   calls++;if(!changed&&params.has('cursor')){changed=true;f.sql.prepare('UPDATE inventory_assets SET version=? WHERE id=?').run('8.0.2',fixtureId(10000));}
   return read(f,Object.fromEntries(params));
  }});
  assert.ok(changed);assert.ok(calls>6);assert.equal(result.assets.length,1000);assert.equal(result.assets.find(a=>a.id===fixtureId(10000)).version,'8.0.2');assert.equal(result.complete,true);
  await assert.rejects(()=>readInventory('inventory',{fetchPage:async params=>{
   if(params.has('cursor'))f.sql.prepare('UPDATE inventory_assets SET notes=? WHERE id=?').run(String(calls++),fixtureId(10000));
   return read(f,Object.fromEntries(params));
  }}),e=>e.status===409);
 }finally{f.close()}
});
test('companion results above old limits remain complete and revision tracked',async()=>{
 const f=capacityFixture({assets:4000});try{
  const insert=f.sql.prepare("INSERT INTO customer_finding_ticket_history(user_id,asset_id,cve_id,ticket_number) VALUES('owner-0',?,'CVE-2026-12345',?)");
  const sources=f.sql.prepare("INSERT INTO plugin_source_mappings(user_id,asset_id,vendor_url) VALUES('owner-0',?,'https://example.test')");
  f.sql.exec('BEGIN');for(let i=0;i<4000;i++){sources.run(fixtureId(i+10000));for(let n=0;n<3;n++)insert.run(fixtureId(i+10000),'TEST-'+n);}f.sql.exec('COMMIT');
  const fetchPage=params=>read(f,Object.fromEntries(params));
  const tickets=await readInventory('finding-tickets',{fetchPage});assert.equal(tickets.tickets.length,12000);assert.equal(new Set(tickets.tickets.map(r=>r.asset_id+'|'+r.ticket_number)).size,12000);
  const mappings=await readInventory('plugin-sources',{fetchPage});assert.equal(mappings.sources.length,4000);
  const first=await read(f,{resource:'sources'});f.sql.prepare('UPDATE plugin_source_mappings SET verification=? WHERE asset_id=?').run('Reviewed',fixtureId(10000));await assert.rejects(()=>read(f,{resource:'sources',cursor:first.next_cursor}),e=>e.status===409);
 }finally{f.close()}
});
test('the 50,000-entry cap is atomic, counted on cascade deletion and schema reapplication preserves counts',async()=>{
 const f=capacityFixture({assets:50000});try{
  assert.equal(f.sql.prepare('SELECT software_count FROM inventory_capacity_revisions').get().software_count,50000);
  assert.throws(()=>f.sql.prepare("INSERT INTO inventory_assets(id,user_id,environment_id,name,asset_type,technology) VALUES(?,'owner-0',?,'Overflow','Software','PHP')").run(fixtureId(99999),fixtureId(1000)),/Inventory limit reached/);
  f.sql.prepare('DELETE FROM inventory_environments WHERE id=?').run(fixtureId(1000));assert.equal(f.sql.prepare('SELECT software_count FROM inventory_capacity_revisions').get().software_count,49500);
  const total=f.sql.prepare('SELECT COUNT(*) n FROM inventory_assets').get().n;assert.equal(total,49500);
  f.sql.exec(fs.readFileSync(new URL('../inventory-capacity-schema.sql',import.meta.url),'utf8'));assert.equal(f.sql.prepare('SELECT software_count FROM inventory_capacity_revisions').get().software_count,total);
 }finally{f.close()}
});
