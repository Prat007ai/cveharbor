import test from 'node:test';
import assert from 'node:assert/strict';
import {baselineDB} from '../../deployment/proposals/production-compatibility/rehearsal.mjs';
import {referenceFromDatabase,verifyCompleteContent,contentSelect} from '../../deployment/proposals/production-compatibility/procedure/rehearsal/verify-content.mjs';
const plain=x=>JSON.parse(JSON.stringify(x));
function fixture(t,extra=''){
 const db=baselineDB();t.after(()=>db.close());
 db.exec("INSERT INTO users(id,email) VALUES('fictional','fixture@example.invalid');"+extra);
 const reference=referenceFromDatabase(db,'a'.repeat(64)),calls=[],events=[];let bookmarkNumber=0;
 const args={reference,record:e=>events.push(e),bookmark:async()=>({bookmark:++bookmarkNumber===1?'before':'after'}),query:async(sql,params=[])=>{assert.ok(/^SELECT\b/.test(sql)||sql==='PRAGMA quick_check');calls.push(sql);return plain(db.prepare(sql).all(...params));}};
 return {db,reference,args,calls,events};
}
test('bookmark movement alone completes full content verification and retains both bookmarks without attributing cause',async t=>{
 const f=fixture(t);const result=await verifyCompleteContent(f.args);
 assert.equal(result.complete,true);assert.equal(result.bookmark_changed,true);assert.equal(result.decision,'bookmark-moved-content-verified');
 assert.equal(result.bookmark_cause,'not attributed');assert.equal(result.external_writers_excluded,false);assert.equal(f.events.length,2);
 assert.ok(f.calls.some(sql=>sql.includes('encoded FROM "users"')));assert.equal(result.remote_atomicity_established,false);
});
test('changed content with unchanged counts and unchanged bookmarks is rejected',async t=>{
 const f=fixture(t);f.db.exec("UPDATE users SET email='changed@example.invalid' WHERE id='fictional'");
 f.args.bookmark=async()=>({bookmark:'unchanged'});
 assert.equal(f.db.prepare('SELECT COUNT(*) n FROM users').get().n,1);
 await assert.rejects(()=>verifyCompleteContent(f.args),/content or row identifier mismatch/);
});
test('an incomplete page stops verification even when bookmarks are stable',async t=>{
 const f=fixture(t),query=f.args.query;f.args.bookmark=async()=>({bookmark:'same'});
 f.args.query=async(sql,params)=>sql.includes('encoded FROM "users"')?[]:query(sql,params);
 await assert.rejects(()=>verifyCompleteContent(f.args),/Incomplete content page/);
});
test('matching content cannot clear an uncertain write outcome',async t=>{
 const f=fixture(t);f.args.uncertainWriteOutcome=true;
 await assert.rejects(()=>verifyCompleteContent(f.args),/Uncertain write outcome/);assert.equal(f.calls.length,0);assert.equal(f.events.length,0);
});
test('type, rowid and sqlite_sequence differences are detected independently of row counts',async t=>{
 for(const change of ["UPDATE extra SET v='1'","UPDATE extra SET id=7","UPDATE sqlite_sequence SET seq=50 WHERE name='extra'"]){
  const f=fixture(t,'CREATE TABLE extra(id INTEGER PRIMARY KEY AUTOINCREMENT,v);INSERT INTO extra(v) VALUES(1);');
  f.db.exec(change);await assert.rejects(()=>verifyCompleteContent(f.args),/content or row identifier mismatch/);
 }
});
test('wide rows retain Unicode, quotes, newlines, NULL, binary, large integers and real types with bounded JSON arguments',async t=>{
 const f=fixture(t,'CREATE TABLE wide('+Array.from({length:40},(_,i)=>'c'+i).join(',')+');');
 f.db.prepare('INSERT INTO wide(c0,c1,c2,c3,c4,c5,c6) VALUES(?,?,?,?,?,?,?)').run("🌍é'\n",null,new Uint8Array([0,255,128]),9223372036854775807n,1.25,'1',1);
 f.args.reference=referenceFromDatabase(f.db,'a'.repeat(64));
 const wide=f.args.reference.tables.find(t=>t.name==='wide');const sql=contentSelect(wide.name,wide.columns);
 assert.ok(sql.includes("||','||"));assert.ok(sql.length<90000);
 const result=await verifyCompleteContent(f.args);assert.equal(result.complete,true);
});
test('unexpected helper or schema drift prevents a successful verification',async t=>{
 const f=fixture(t);f.db.exec('CREATE TABLE __pr270_import_value_8c21b7(id INTEGER,v)');
 await assert.rejects(()=>verifyCompleteContent(f.args),/Schema mismatch/);
});
test('a failed read cannot be reported complete or retried',async t=>{
 const f=fixture(t);let calls=0;f.args.query=async()=>{calls++;throw Error('incomplete provider read');};
 await assert.rejects(()=>verifyCompleteContent(f.args),/incomplete provider read/);assert.equal(calls,1);
});
