import test from 'node:test';
import assert from 'node:assert/strict';
import {inventoryReadDatabase} from '../src/inventory-read-db.js';
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
