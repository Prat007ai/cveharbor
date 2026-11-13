import {DatabaseSync} from 'node:sqlite';
import fs from 'node:fs';
export const fixtureId=n=>Number(n).toString(16).padStart(8,'0')+'-1111-4111-8111-111111111111';
export function capacityFixture({customers=50,environments=100,assets=10000,owners=1}={}){
 const sql=new DatabaseSync(':memory:');sql.exec('PRAGMA foreign_keys=ON; CREATE TABLE users(id TEXT PRIMARY KEY); CREATE TABLE operations_control(id INTEGER PRIMARY KEY,database_frozen INTEGER); INSERT INTO operations_control VALUES(1,0);');
 for(let i=0;i<owners;i++)sql.prepare('INSERT INTO users VALUES(?)').run('owner-'+i);
 for(const file of ['inventory-schema.sql','finding-status-schema.sql','finding-ticket-schema.sql','finding-ticket-history-schema.sql','plugin-source-schema.sql','plugin-monitor-schema.sql','plugin-release-schema.sql','package-inventory-schema.sql','../../deployment/proposals/server-network/schema.sql','inventory-capacity-schema.sql']){
  const url=file.startsWith('../../')?new URL('../../../deployment/proposals/server-network/schema.sql',import.meta.url):new URL('../../'+file,import.meta.url);sql.exec(fs.readFileSync(url,'utf8'));
 }
 sql.exec('CREATE TABLE team_visible_customers(org TEXT,actor TEXT,data_owner TEXT,customer_id TEXT); BEGIN');
 for(let i=0;i<customers;i++)sql.prepare('INSERT INTO inventory_customers(id,user_id,name) VALUES(?,?,?)').run(fixtureId(i+1),'owner-'+i%owners,'Customer '+i);
 for(let i=0;i<environments;i++)sql.prepare('INSERT INTO inventory_environments(id,user_id,customer_id,name) VALUES(?,?,?,?)').run(fixtureId(i+1000),'owner-'+(i%customers)%owners,fixtureId(i%customers+1),'Environment '+i);
 const insert=sql.prepare("INSERT INTO inventory_assets(id,user_id,environment_id,name,asset_type,technology,version) VALUES(?,?,?,?,'Software','.NET Runtime','8.0.1')");
 for(let i=0;i<assets;i++)insert.run(fixtureId(i+10000),'owner-'+((Math.floor(i/5)%environments)%customers)%owners,fixtureId(Math.floor(i/5)%environments+1000),'HOST-'+Math.floor(i/5));
 sql.exec('COMMIT');
 const DB={sql,prepare(query){const statement=sql.prepare(query);const make=args=>({bind:(...values)=>make(values),first:async()=>statement.get(...args)||null,all:async()=>({results:statement.all(...args)}),runSync:()=>statement.columns().length?{results:statement.all(...args),meta:{changes:0}}:{meta:{changes:Number(statement.run(...args).changes)}},run:async()=>statement.columns().length?{results:statement.all(...args),meta:{changes:0}}:{meta:{changes:Number(statement.run(...args).changes)}}});return make([]);},async batch(statements){sql.exec('BEGIN');try{const values=statements.map(s=>s.runSync());sql.exec('COMMIT');return values;}catch(error){sql.exec('ROLLBACK');throw error;}}};
 return {DB,sql,close:()=>sql.close()};
}
