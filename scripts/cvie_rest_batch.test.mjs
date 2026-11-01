import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {restBatch} from './cvie_rest_batch.mjs';
test('REST batch safely preserves quotes, SQL-like text, Unicode, nulls and literal question marks',()=>{
 const db=new DatabaseSync(':memory:');db.exec('CREATE TABLE evidence(value TEXT,number INTEGER)');
 const value="Private O'Brien ?; DROP TABLE evidence; -- ☃";
 const body=restBatch([{sql:"INSERT INTO evidence VALUES(?,?); -- ? ignored\n",params:[value,7]},{sql:"INSERT INTO evidence VALUES('literal ? quoted',?)",params:[null]}]);
 db.exec(body.sql);const rows=db.prepare('SELECT * FROM evidence').all();assert.equal(rows[0].value,value);assert.equal(rows[0].number,7);assert.equal(rows[1].number,null);
});
test('large JSON imports split below D1 SQL limits without dropping records',()=>{
 const db=new DatabaseSync(':memory:');db.exec('CREATE TABLE evidence(value TEXT)');
 const values=Array.from({length:100},(_,i)=>({id:i,text:"O'Brien "+'x'.repeat(3000)}));
 const body=restBatch([{sql:"INSERT INTO evidence SELECT value FROM json_each(?) WHERE ?='allowed'",params:[JSON.stringify(values),'allowed']}]);
 assert.ok(body.sql.split(';\n').every(sql=>Buffer.byteLength(sql)<90000));db.exec(body.sql);
 assert.equal(db.prepare('SELECT COUNT(*) AS n FROM evidence').get().n,100);
 assert.deepEqual(db.prepare('SELECT value FROM evidence').all().map(r=>JSON.parse(r.value)),values);
});
