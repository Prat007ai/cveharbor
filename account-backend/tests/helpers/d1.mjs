import {DatabaseSync} from 'node:sqlite';
import fs from 'node:fs';
export class DB{
 constructor(){
  this.executions=0;
  this.sql=new DatabaseSync(':memory:');
  this.sql.exec(`PRAGMA foreign_keys=ON; CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT); INSERT INTO users VALUES('a','a@example.test'),('b','b@example.test');
   CREATE TABLE sessions(id TEXT,user_id TEXT,token_hash TEXT,expires_at INTEGER);
   CREATE TABLE user_totp(user_id TEXT,enabled INTEGER);
   CREATE TABLE inventory_assets(user_id TEXT,technology TEXT); CREATE TABLE user_stack(user_id TEXT,technology TEXT);
   CREATE TABLE user_technology_catalogue(user_id TEXT PRIMARY KEY,preferences_json TEXT,updated_at INTEGER);`);
  this.sql.exec(fs.readFileSync(new URL('../../migrations/0019_cvie.sql',import.meta.url),'utf8'));
  this.sql.exec(fs.readFileSync(new URL('../../migrations/0020_cvie_evidence.sql',import.meta.url),'utf8'));
  this.sql.exec(fs.readFileSync(new URL('../../migrations/0022_cvie_shared_scans.sql',import.meta.url),'utf8'));
 }
 prepare(sql){const statement=this.sql.prepare(sql),db=this;const make=args=>({
  bind:(...values)=>make(values),
  first:async()=>{db.executions++;return statement.get(...args)||null;},
  all:async()=>{db.executions++;return {results:statement.all(...args)};},
  run:async()=>{db.executions++;return statement.columns().length?{results:statement.all(...args),meta:{changes:0}}:{meta:{changes:Number(statement.run(...args).changes)}};},
 });return make([]);}
 async batch(statements){this.sql.exec('BEGIN');try{const values=[];for(const s of statements)values.push(await s.run());this.sql.exec('COMMIT');return values;}catch(e){this.sql.exec('ROLLBACK');throw e;}}
}
