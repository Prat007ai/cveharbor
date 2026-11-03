import {DatabaseSync} from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import {loadManifest,project,validateSchema} from '../../scripts/schema.mjs';
export class FullDB{
 constructor({empty=false}={}){this.sql=new DatabaseSync(':memory:');this.sql.exec('PRAGMA foreign_keys=ON');if(!empty){for(const e of loadManifest().entries){this.sql.exec(fs.readFileSync(path.join(project,e.path),'utf8'));this.sql.prepare('INSERT INTO staging_schema_history(path,sha256,manifest_version) VALUES(?,?,1)').run(e.path,e.sha256);}for(const sql of validateSchema().guards)this.sql.exec(sql);}}
 prepare(sql){const db=this;const make=params=>({sql,params,bind:(...v)=>make(v),async first(){return db.sql.prepare(sql).get(...params)||null;},async all(){return {results:db.sql.prepare(sql).all(...params)};},async run(){const s=db.sql.prepare(sql);if(s.columns().length)return {results:s.all(...params),meta:{changes:0}};const r=s.run(...params);return {meta:{changes:Number(r.changes),last_row_id:Number(r.lastInsertRowid)}};}});return make([]);}
 async batch(statements){this.sql.exec('BEGIN');try{const values=[];for(const s of statements)values.push(await s.run());this.sql.exec('COMMIT');return values;}catch(e){this.sql.exec('ROLLBACK');throw e;}}
 async query(sql){this.sql.exec('BEGIN');try{this.sql.exec(sql);this.sql.exec('COMMIT');return [{success:true}];}catch(e){this.sql.exec('ROLLBACK');throw e;}}
 close(){this.sql.close();}
}
export async function bucketFixture(versionValue='one'){
 const data=new Map(),encode=x=>new TextEncoder().encode(JSON.stringify(x)),sha=async b=>Buffer.from(await crypto.subtle.digest('SHA-256',b)).toString('hex');
 const stamp=new Date().toISOString(),advisory={mode:'live',last_successful_update:stamp,snapshotDate:stamp.slice(0,10),advisories:[{id:'CVE-2099-12345',title:'Synthetic '+versionValue,severity:'critical',published:stamp,updated:stamp,categories:['PHP'],sources:[]} ]};
 const files={};for(const [name,obj] of Object.entries({'data.js':advisory,'data/advisories.json':advisory,'data/feed-health.json':{mode:'live',last_successful_update:stamp},'lifecycle.js':{checked_at:stamp,cycles:[],errors:[]},'patch-notes.js':{checked_at:stamp,releases:[],errors:[]},'malware-data.js':{samples:[]},'threat-data.js':{indicators:[]}})){
  const raw=encode(obj),h=await sha(raw),key='objects/'+h;data.set(key,raw);files[name]={key,sha256:h,bytes:raw.length};
 }
 const raw=encode({schema:1,files}),version=await sha(raw);data.set('manifests/'+version+'.json',raw);data.set('current.json',encode({schema:1,manifest:'manifests/'+version+'.json'}));
 return {version,data,async get(key){const raw=data.get(key);return raw?{size:raw.length,arrayBuffer:async()=>raw.buffer.slice(raw.byteOffset,raw.byteOffset+raw.byteLength)}:null;}};
}
