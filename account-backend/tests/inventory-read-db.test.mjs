import test from 'node:test';
import assert from 'node:assert/strict';
import {inventoryReadDatabase} from '../src/inventory-read-db.js';

test('replica pages are anchored to this request while every authority check reads the primary',async()=>{
 const calls=[];let revision=1;
 const page="SELECT EXISTS(SELECT 1 FROM inventory_capacity_schema WHERE version=1) AS schema_ready, 'fictional' AS packed";
 const db={withSession(constraint){
  let observed=null;
  return {getBookmark:()=>observed,prepare(sql){let args=[];return {
   bind(...values){args=values;return this;},
   async first(){assert.equal(constraint,'first-primary');observed='revision-'+revision;calls.push({constraint,sql,args});return {revision};},
   async all(){calls.push({constraint,sql,args});return {results:[],meta:{served_by_primary:constraint==='first-primary'}};}
  };}};
 }};
 const reader=inventoryReadDatabase(db);
 assert.equal(reader.withSession,undefined);
 await reader.prepare('SELECT write_hold FROM operations_control').first();
 revision=2;
 await reader.prepare('SELECT id FROM sessions WHERE token_hash=?').bind('fictional-session').first();
 await reader.prepare(page).bind('fictional-owner').all();
 assert.deepEqual(calls.map(c=>c.constraint),['first-primary','first-primary','revision-2']);
 assert.deepEqual(calls[2].args,['fictional-owner']);
 revision=3;
 await reader.prepare('SELECT id FROM sessions').first();
 await reader.prepare(page).all();
 assert.deepEqual(calls.slice(-2).map(c=>c.constraint),['first-primary','revision-3']);
 // A new request has no authority bookmark, even on the same binding.
 await inventoryReadDatabase(db).prepare(page).all();
 assert.equal(calls.at(-1).constraint,'first-primary');
 await reader.prepare('SELECT id FROM inventory_customers').all();
 assert.equal(calls.at(-1).constraint,'first-primary');
});
test('read capability retries only transient SELECT failures with bounded backoff',async()=>{
 const delays=[],failure=new Error('D1 DB is overloaded. Requests queued for too long.');let calls=0;
 const db=inventoryReadDatabase({prepare(){return {first:async()=>{if(++calls<4)throw failure;return {id:'fictional'};}};}},{sleep:async ms=>delays.push(ms),random:()=>0});
 assert.deepEqual(await db.prepare('SELECT id FROM users').first(),{id:'fictional'});assert.equal(calls,4);assert.deepEqual(delays,[50,150,450]);
 calls=0;const broken=inventoryReadDatabase({prepare(){return {all:async()=>{calls++;throw failure;}};}},{sleep:async()=>{},random:()=>0});
 await assert.rejects(broken.prepare('SELECT 1').all(),e=>e===failure);assert.equal(calls,4);
});
test('read capability rejects writes, compound SQL and foreign batch statements; permanent errors are never retried',async()=>{
 let calls=0;const failure=new Error('no such table: fixture');
 const db=inventoryReadDatabase({prepare(){return {all:async()=>{calls++;throw failure;}};}},{sleep:async()=>assert.fail('Permanent failure retried')});
 for(const sql of ['DELETE FROM users','INSERT INTO users VALUES(1)','UPDATE users SET id=1','PRAGMA writable_schema=1','SELECT 1; DELETE FROM users','WITH x AS (SELECT 1) DELETE FROM users'])assert.throws(()=>db.prepare(sql));
 assert.equal(db.exec,undefined);assert.equal(db.prepare('SELECT 1').run,undefined);assert.throws(()=>db.batch([{run:()=>{}}]));
 await assert.rejects(db.prepare('SELECT 1').all(),e=>e===failure);assert.equal(calls,1);
});
