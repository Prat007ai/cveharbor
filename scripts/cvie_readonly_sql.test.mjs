import test from 'node:test';import assert from 'node:assert/strict';import {assertReadOnlySql} from './cvie_readonly_sql.mjs';
test('read-only guard permits normalization functions and rejects mutations and stacked statements',()=>{
 for(const sql of ["SELECT replace(name,' ','') FROM cvie_products",'WITH x AS(SELECT 1) SELECT * FROM x','EXPLAIN QUERY PLAN SELECT 1',"SELECT 'DELETE; UPDATE'"])assert.doesNotThrow(()=>assertReadOnlySql(sql));
 for(const sql of ['UPDATE cvie_products SET name=1','WITH x AS(SELECT 1) DELETE FROM cvie_products','SELECT 1; DELETE FROM cvie_products','REPLACE INTO t VALUES(1)','SELECT 1;','PRAGMA writable_schema=1'])assert.throws(()=>assertReadOnlySql(sql));
});
