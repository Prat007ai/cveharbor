// No cloud imports. Exact checked-in manifest, complete SQL inventory, SQLite validation.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,randomUUID} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {recoveryTablesSQL,recoveryGuardSQL,normalizedDDL} from '../../account-backend/src/recovery-schema.js';
export const project = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const hash = text => createHash('sha256').update(text).digest('hex');
function writeAtomic(filename, contents){
 const temporary=filename+'.'+randomUUID()+'.tmp';
 try{fs.writeFileSync(temporary,contents,{flag:'wx'});fs.renameSync(temporary,filename);}
 finally{fs.rmSync(temporary,{force:true});}
}
export function loadManifest(base=project) {
 const manifest=JSON.parse(fs.readFileSync(path.join(base,'staging/migrations.v1.json'),'utf8'));
 if(manifest.version!==1 || manifest.profile!=='permanent-staging-integrated' || !Array.isArray(manifest.entries))throw Error('Unsupported manifest');
 const expected=['staging/schema.sql',...fs.readdirSync(path.join(base,'account-backend')).filter(n=>n.endsWith('.sql')).map(n=>'account-backend/'+n),...fs.readdirSync(path.join(base,'account-backend/migrations')).filter(n=>n.endsWith('.sql')).map(n=>'account-backend/migrations/'+n)];
 const seen=new Set();
 for(const entry of manifest.entries){
  if(seen.has(entry.path)||!expected.includes(entry.path)||entry.depends_on!==(seen.size?manifest.entries[seen.size-1].path:null))throw Error('Duplicate, unknown or out-of-order migration');
  const sql=fs.readFileSync(path.join(base,entry.path),'utf8');
  if(hash(sql)!==entry.sha256)throw Error('Migration checksum mismatch: '+entry.path);
  seen.add(entry.path);
 }
 if(expected.length!==seen.size||expected.some(n=>!seen.has(n)))throw Error('Manifest omits SQL from the application');
 return manifest;
}
export function schemaObjects(db){return db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' AND name NOT GLOB '_cf_*' AND name NOT GLOB 'd1_*' ORDER BY type,name").all().map(x=>({...x,sql:normalizedDDL(x.sql)}));}
export function validateSchema(base=project){
 const manifest=loadManifest(base),db=new DatabaseSync(':memory:');db.exec('PRAGMA foreign_keys=ON');
 try{
  for(const entry of manifest.entries){
   db.exec('BEGIN');
   try{db.exec(fs.readFileSync(path.join(base,entry.path),'utf8'));db.prepare('INSERT INTO staging_schema_history(path,sha256,manifest_version) VALUES(?,?,?)').run(entry.path,entry.sha256,manifest.version);db.exec('COMMIT');}catch(e){db.exec('ROLLBACK');throw e;}
   if(db.prepare('PRAGMA foreign_key_check').all().length)throw Error('Foreign keys failed: '+entry.path);
  }
  const guards=db.prepare(recoveryTablesSQL).all().flatMap(({name})=>['insert','update','delete'].map(op=>recoveryGuardSQL(name,op)));
  for(const sql of guards)db.exec(sql);
  if(db.prepare('PRAGMA integrity_check').get().integrity_check!=='ok')throw Error('Integrity failed');
  return {manifest,guards,objects:schemaObjects(db),table_count:db.prepare("SELECT count(*) n FROM sqlite_master WHERE type='table'").get().n};
 }finally{db.close();}
}
export function prepare(base=project){
 const result=validateSchema(base),out=path.join(base,'staging/.build/schema');fs.mkdirSync(out,{recursive:true});
 writeAtomic(path.join(out,'validated-plan.json'),JSON.stringify({...result,manifest_sha256:hash(JSON.stringify(result.manifest))},null,2)+'\n');
 // Remove the obsolete ambiguous filename, never emit an auto-sorted bootstrap.
 fs.rmSync(path.join(out,'bootstrap-through-0027.sql'),{force:true});
 writeAtomic(path.join(out,'manifest.json'),JSON.stringify(result.manifest,null,2)+'\n');
 console.log(JSON.stringify({local_only:true,tables:result.table_count,entries:result.manifest.entries.length,objects:result.objects.length}));return result;
}
if(process.argv[1]===fileURLToPath(import.meta.url))prepare();
