// Read-only rehearsal verification. Bookmarks are evidence, not data-change proofs.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {canonical,digest} from '../../../../../scripts/production_schema_baseline.mjs';
import {integrityChecks} from '../../../../../account-backend/src/release-integrity-checks.js';
export const schemaSQL="SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*' ORDER BY type,name";
const sha=s=>createHash('sha256').update(s).digest('hex');
const quote=s=>'"'+s.replaceAll('"','""')+'"';
const columnSQL='SELECT cid,name,type,"notnull",dflt_value,pk,hidden FROM pragma_table_xinfo(?) ORDER BY cid';
const columnRows=rows=>rows.map(r=>[r.cid,r.name,r.type,r.notnull,r.dflt_value,r.pk,r.hidden]);

export function contentSelect(name,columns){
 assert.ok(typeof name==='string'&&name.length>0);
 assert.ok(!columns.some(c=>c[1].toLowerCase()==='_rowid_'),'Shadowed rowid unsupported');
 const fields=['_rowid_',...columns.filter(c=>c[6]!==1).map(c=>quote(c[1]))],args=[];
 for(const f of fields)args.push(`typeof(${f})`,`CASE typeof(${f}) WHEN 'null' THEN NULL WHEN 'text' THEN hex(CAST(${f} AS BLOB)) WHEN 'blob' THEN hex(${f}) WHEN 'integer' THEN CAST(${f} AS TEXT) WHEN 'real' THEN printf('%!.26g',${f}) ELSE 'UNSUPPORTED' END`);
 // At most 30 arguments per JSON call; D1 documents a 32-argument limit.
 const groups=[];for(let i=0;i<args.length;i+=30)groups.push('json_array('+args.slice(i,i+30).join(',')+')');
 const pieces=groups.map((g,i)=>groups.length===1?g:i===0?`substr(${g},1,length(${g})-1)`:i===groups.length-1?`substr(${g},2)`:`substr(${g},2,length(${g})-2)`);
 const encoded=pieces.join("||','||");
 const sql=`SELECT CAST(_rowid_ AS TEXT) row_key,${encoded} encoded FROM ${quote(name)}`;
 assert.ok(Buffer.byteLength(sql)<90000,'Content query too large');return sql;
}

export function referenceFromDatabase(db,originalSqlSha256){
 assert.match(originalSqlSha256,/^[a-f0-9]{64}$/);
 const tables=[];
 for(const {name}of db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT GLOB '_cf_*' ORDER BY name").all()){
  const columns=columnRows(db.prepare(columnSQL).all(name)),select=contentSelect(name,columns);
  const rows=db.prepare(select+' ORDER BY _rowid_').all(),pages=[];let batch=[],bytes=0;const full=createHash('sha256');
  const flush=()=>{if(batch.length){pages.push({rows:batch.length,last_key:batch.at(-1).row_key,sha256:sha(batch.map(r=>r.encoded+'\n').join(''))});batch=[];bytes=0;}};
  for(const row of rows){const n=Buffer.byteLength(row.encoded)+1;assert.ok(n<4000000);if(batch.length&&(batch.length>=500||bytes+n>4000000))flush();batch.push(row);bytes+=n;full.update(row.encoded+'\n');}
  flush();tables.push({name,columns,rows:rows.length,typed_content_sha256:full.digest('hex'),pages});
 }
 return {version:1,original_sql_sha256:originalSqlSha256,schema:db.prepare(schemaSQL).all().map(r=>({...r})),tables};
}

export async function verifyCompleteContent({reference,query,bookmark,record=()=>{},uncertainWriteOutcome=false}){
 assert.equal(uncertainWriteOutcome,false,'Uncertain write outcome remains a stop condition');
 assert.equal(reference.version,1);assert.match(reference.original_sql_sha256,/^[a-f0-9]{64}$/);
 assert.ok(reference.tables.length>0);assert.equal(new Set(reference.tables.map(t=>t.name)).size,reference.tables.length);
 const before=await bookmark();record({kind:'content-bookmark-before',bookmark:before});
 const expectedSchema=canonical(reference.schema);
 assert.deepEqual(canonical(await query(schemaSQL)),expectedSchema,'Schema mismatch');
 const verified=[];
 for(const table of reference.tables){
  assert.deepEqual(columnRows(await query(columnSQL,[table.name])),table.columns,'Column definition mismatch');
  const select=contentSelect(table.name,table.columns),full=createHash('sha256');let last=null,count=0;
  for(const page of table.pages){
   assert.ok(Number.isSafeInteger(page.rows)&&page.rows>0&&page.rows<=500);assert.match(page.sha256,/^[a-f0-9]{64}$/);
   const rows=await query(select+(last===null?'':' WHERE _rowid_>CAST(? AS INTEGER)')+' ORDER BY _rowid_ LIMIT '+page.rows,last===null?[]:[last]);
   assert.equal(rows.length,page.rows,'Incomplete content page');
   const encoded=rows.map(r=>{assert.equal(typeof r.encoded,'string');assert.match(r.row_key,/^-?\d+$/);if(last!==null)assert.ok(BigInt(r.row_key)>BigInt(last),'Unordered or duplicate row');last=r.row_key;return r.encoded+'\n';}).join('');
   assert.ok(Buffer.byteLength(encoded)<=4000000,'Unexpected content response size');
   assert.equal(sha(encoded),page.sha256,'Typed content or row identifier mismatch');assert.equal(last,page.last_key);full.update(encoded);count+=rows.length;
  }
  const tail=await query(select+(last===null?'':' WHERE _rowid_>CAST(? AS INTEGER)')+' ORDER BY _rowid_ LIMIT 1',last===null?[]:[last]);
  assert.equal(tail.length,0,'Unexpected additional row');assert.equal(count,table.rows);assert.equal(full.digest('hex'),table.typed_content_sha256);
  verified.push({name:table.name,rows:count,typed_content_sha256:table.typed_content_sha256});
 }
 assert.deepEqual(canonical(await query(schemaSQL)),expectedSchema,'Schema changed during verification');
 const integrity={};for(const [name,sql]of Object.entries(integrityChecks))integrity[name]=Number((await query(sql))[0].n);
 integrity.foreign_keys=Number((await query('SELECT COUNT(*) n FROM pragma_foreign_key_check'))[0].n);
 assert.ok(Object.values(integrity).every(n=>n===0),'Integrity check failed');
 assert.deepEqual(await query('PRAGMA quick_check'),[{quick_check:'ok'}]);
 assert.equal((await query("SELECT name FROM sqlite_schema WHERE name='__pr270_import_value_8c21b7'")).length,0,'Import helper remained');
 const after=await bookmark();record({kind:'content-bookmark-after',bookmark:after});
 const changed=digest(before)!==digest(after);
 const counts=Object.fromEntries(verified.filter(t=>!t.name.startsWith('sqlite_')).map(t=>[t.name,t.rows]));
 return {complete:true,schema_equal:true,schema_sha256:digest(expectedSchema),counts_sha256:digest(counts),rows:Object.values(counts).reduce((x,y)=>x+y,0),columns_equal:true,types_and_full_content_equal:true,row_identifiers_equal:true,sequence_values_equal:true,tables:verified,integrity,quick_check:'ok',import_helper_absent:true,bookmark_before_sha256:digest(before),bookmark_after_sha256:digest(after),bookmark_changed:changed,bookmark_cause:'not attributed',decision:changed?'bookmark-moved-content-verified':'content-verified',external_writers_excluded:false,remote_atomicity_established:false};
}
