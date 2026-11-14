import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {inventoryPage} from '../src/inventory-pages.js';
import {inventoryRoute} from '../src/inventory.js';
import {capacityFixture,capacitySessions,fixtureId} from './helpers/capacity-db.mjs';
import worker from '../src/index.js';
import {readInventory} from '../../inventory-client.js';
const url='https://api.cveharbor.com/v1/inventory/page?';
const read=(env,params={},owner='owner-0',team)=>inventoryPage(new Request(url+new URLSearchParams(params)),env,{id:owner},team);

test('parallel menu metadata retries the whole snapshot when its revision changes',async()=>{
 const f=capacityFixture({assets:1000});let changed=false,active=0,peak=0,release;
 const changedSnapshot=new Promise(resolve=>{release=resolve;});
 try{
  const result=await readInventory('inventory',{resourceList:['customers','environments'],fetchPage:async params=>{
   active++;peak=Math.max(peak,active);
   try{
    if(params.get('resource')==='environments')await changedSnapshot;
    const page=await read(f,Object.fromEntries(params));
    if(params.get('resource')==='customers'&&!changed){changed=true;f.sql.prepare('INSERT INTO inventory_environments(id,user_id,customer_id,name) VALUES(?,?,?,?)').run(fixtureId(9999),'owner-0',fixtureId(1),'Added during metadata load');release();}
    await new Promise(resolve=>setTimeout(resolve,1));return page;
   }finally{active--;}
  }});
  assert.equal(peak,2);assert.equal(active,0);assert.equal(result.customers.length,50);assert.equal(result.environments.length,101);assert.equal(result.complete,true);
 }finally{f.close();}
});

test('known pagination avoids duplicate capability probes but never reuses private results or authorization',async t=>{
 const f=capacityFixture({assets:1000});let requests=0,authorized=true;
 t.mock.method(globalThis,'fetch',async input=>{
  requests++;const requestUrl=new URL(input);assert.equal(requestUrl.pathname,'/v1/inventory/page');
  if(!authorized)return Response.json({error:'Sign in required'},{status:401});
  return Response.json(await read(f,Object.fromEntries(requestUrl.searchParams)));
 });
 try{
  const settings={pagination:true,resourceList:['customers','environments']};
  const result=await readInventory('inventory',settings);assert.equal(result.customers.length,50);assert.equal(result.environments.length,100);assert.equal(requests,2);
  authorized=false;await assert.rejects(()=>readInventory('inventory',settings),e=>e.status===401);assert.equal(requests,4);
 }finally{f.close();}
});

test('compact database pages preserve text and empty values while reducing the transferred payload',async()=>{
 const f=capacityFixture({owners:1,customers:1,environments:1,assets:500}),prepare=f.DB.prepare.bind(f.DB);let packed;
 f.DB.prepare=sql=>{const wrap=s=>({...s,bind:(...args)=>wrap(s.bind(...args)),all:async()=>{const result=await s.all();packed=result.results;return result;}});return wrap(prepare(sql));};
 try{
  f.sql.prepare("UPDATE inventory_assets SET notes=?,version=''").run('Quotes " and newlines\nUnicode æ—¥æœ¬èªž and literal [null]');
  const page=await read(f);
  const expected=f.sql.prepare('SELECT id,environment_id,name,asset_type,technology,version,notes FROM inventory_assets ORDER BY environment_id,id LIMIT 251').all().map(row=>({...row}));
  assert.deepEqual(page.items,expected.slice(0,250));assert.ok(page.next_cursor);
  assert.equal(packed.length,1);assert.equal(JSON.parse(packed[0].packed).length,251);
  assert.ok(Buffer.byteLength(JSON.stringify(packed))<Buffer.byteLength(JSON.stringify(expected))*.85);
  assert.deepEqual((await read(f,{},'absent-owner')).items,[]);
 }finally{f.close();}
});

for(const replicas of [false,true])test('full Worker requires current session and enabled MFA, scopes pages and performs no read-side writes'+(replicas?' with anchored replicas':''),async()=>{
 const f=capacityFixture({owners:2,customers:2,environments:2,assets:1000}),tokens=capacitySessions(f.sql,2);
 let bookmarkNumber=0;
 if(replicas)f.DB.withSession=constraint=>{
  let bookmark=null;
  return {getBookmark:()=>bookmark,prepare(sql){
   const page=sql.includes(' AS packed');assert.equal(constraint,page?'fixture-'+bookmarkNumber:'first-primary');
   const wrap=statement=>({bind:(...args)=>wrap(statement.bind(...args)),first:async()=>{assert.equal(constraint,'first-primary');const result=await statement.first();bookmark='fixture-'+(++bookmarkNumber);return result;},all:()=>statement.all()});
   return wrap(f.DB.prepare(sql));
  }};
 };
 const call=(token,query='',origin='https://cveharbor.com')=>worker.fetch(new Request(url+query,{headers:{Origin:origin,...token?{Cookie:'cvh_session='+token}:{}}}),{DB:f.DB,RECOVERY_CONTROL_REQUIRED:'true'});
 try{
  assert.equal((await call()).status,401);
  assert.equal((await call(tokens[0],'','https://foreign.example')).status,403);
  assert.equal((await call(tokens[0],'customer_id='+fixtureId(2))).status,404);
  const before=f.sql.prepare('SELECT total_changes() n').get().n;
  const r=await call(tokens[0]);assert.equal(r.status,200);const first=await r.json();assert.ok(first.next_cursor);
  assert.equal(f.sql.prepare('SELECT total_changes() n').get().n,before);
  f.sql.prepare('UPDATE user_totp SET enabled=0 WHERE user_id=?').run('owner-0');
  assert.equal((await call(tokens[0],'cursor='+first.next_cursor)).status,401);
  f.sql.prepare('UPDATE user_totp SET enabled=1 WHERE user_id=?').run('owner-0');
  f.sql.prepare('DELETE FROM sessions WHERE user_id=?').run('owner-0');
  assert.equal((await call(tokens[0],'cursor='+first.next_cursor)).status,401);
  assert.equal(f.sql.prepare('SELECT count(*) n FROM operations_leases').get().n,0);
 }finally{f.close();}
});

test('inventory read fast path uses only two statements and round trips and still obeys current maintenance holds',async()=>{
 const f=capacityFixture({owners:1,customers:1,environments:1,assets:500}),[token]=capacitySessions(f.sql,1);let calls=0,statements=0;
 const prepare=f.DB.prepare.bind(f.DB),batch=f.DB.batch.bind(f.DB);
 f.DB.prepare=sql=>{statements++;const wrap=s=>{const result={bind:(...args)=>wrap(s.bind(...args))};for(const method of ['first','all','run'])result[method]=(...args)=>{calls++;return s[method](...args);};result.runSync=s.runSync;return result;};return wrap(prepare(sql));};
 f.DB.batch=statements=>{calls++;return batch(statements);};
 const call=()=>worker.fetch(new Request(url,{headers:{Cookie:'cvh_session='+token,Origin:'https://cveharbor.com'}}),{DB:f.DB,RECOVERY_CONTROL_REQUIRED:'true'});
 try{
  assert.equal((await call()).status,200);assert.equal(calls,2);assert.equal(statements,2);
  f.sql.exec('UPDATE operations_control SET write_hold=1');calls=0;assert.equal((await call()).status,503);assert.equal(calls,1);
  f.sql.exec('UPDATE operations_control SET database_frozen=1');assert.equal((await call()).status,503);
  f.sql.exec('DROP TABLE operations_control');assert.equal((await call()).status,503);
 }finally{f.close();}
});

test('temporary D1 overload is retried without writes; missing capacity storage still fails closed',async()=>{
 const f=capacityFixture({owners:1,customers:1,environments:1,assets:500}),[token]=capacitySessions(f.sql,1),prepare=f.DB.prepare.bind(f.DB);let attempts=0;
 f.DB.prepare=sql=>{const wrap=s=>({...s,bind:(...args)=>wrap(s.bind(...args)),all:async()=>{if(++attempts===1)throw new Error('D1 DB is overloaded. Requests queued for too long.');return s.all();}});return sql.includes(' AS packed')?wrap(prepare(sql)):prepare(sql);};
 const call=()=>worker.fetch(new Request(url,{headers:{Cookie:'cvh_session='+token,Origin:'https://cveharbor.com'}}),{DB:f.DB,RECOVERY_CONTROL_REQUIRED:'true'});
 try{
  const before=f.sql.prepare('SELECT total_changes() n').get().n;
  const response=await call();assert.equal(response.status,200);assert.equal((await response.json()).items.length,250);assert.equal(attempts,2);assert.equal(f.sql.prepare('SELECT total_changes() n').get().n,before);
  f.sql.exec('DELETE FROM inventory_capacity_schema');assert.equal((await call()).status,503);
  f.sql.exec('DROP TABLE inventory_capacity_schema');assert.equal((await call()).status,503);
 }finally{f.close();}
});

test('a selected customer uses environment index seeks within a 50,000-entry MSP account',async()=>{
 const f=capacityFixture({assets:50000}),prepare=f.DB.prepare,plans=[];
 f.DB.prepare=query=>{
  const statement=prepare(query);
  if(!query.includes('FROM inventory_assets t'))return statement;
  const bind=statement.bind;statement.bind=(...args)=>{plans.push(...f.sql.prepare('EXPLAIN QUERY PLAN '+query).all(...args).map(r=>r.detail));return bind(...args);};return statement;
 };
 try{
  const page=await read(f,{customer_id:fixtureId(50)});assert.equal(page.items.length,250);assert.ok(page.next_cursor);
  assert.ok(plans.some(p=>p.includes('idx_capacity_asset_environment (user_id=? AND environment_id=?)')));
  assert.ok(!plans.some(p=>p.includes('SCAN t')||p.includes('idx_capacity_inventory_assets (user_id=?)')));
 }finally{f.close();}
});

test('parallel environment reads stay bounded and retry a changed partition list without losing rows',async()=>{
 const f=capacityFixture({assets:10000});let active=0,peak=0,changed=false;
 try{
  const result=await readInventory('inventory',{fetchPage:async params=>{
   active++;peak=Math.max(peak,active);
   try{
    await new Promise(resolve=>setTimeout(resolve,1));
    if(params.get('resource')==='assets'&&!changed){
     changed=true;
     f.sql.prepare('INSERT INTO inventory_environments(id,user_id,customer_id,name) VALUES(?,?,?,?)').run(fixtureId(9999),'owner-0',fixtureId(1),'Added during load');
     f.sql.prepare("INSERT INTO inventory_assets(id,user_id,environment_id,name,asset_type,technology) VALUES(?,?,?,?,'Software','PHP')").run(fixtureId(99999),'owner-0',fixtureId(9999),'New host');
    }
    return await read(f,Object.fromEntries(params));
   }finally{active--;}
  }});
  assert.ok(changed);assert.ok(peak>1&&peak<=4);assert.equal(active,0);
  assert.equal(result.environments.length,101);assert.equal(result.assets.length,10001);assert.equal(new Set(result.assets.map(a=>a.id)).size,10001);
 }finally{f.close();}
});
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
 const f=capacityFixture({assets:1000,environments:4});try{
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
