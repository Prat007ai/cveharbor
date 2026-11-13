import {DatabaseSync} from 'node:sqlite';
import fs from 'node:fs';
import {createHash,randomBytes} from 'node:crypto';
export const fixtureId=n=>Number(n).toString(16).padStart(8,'0')+'-1111-4111-8111-111111111111';
export function capacityFixture({customers=50,environments=100,assets=10000,owners=1}={}){
 const sql=new DatabaseSync(':memory:');for(const file of ['schema.sql','totp-schema.sql','migrations/0032_recovery_control.sql'])sql.exec(fs.readFileSync(new URL('../../'+file,import.meta.url),'utf8'));
 for(let i=0;i<owners;i++)sql.prepare('INSERT INTO users(id,email) VALUES(?,?)').run('owner-'+i,'capacity-'+i+'@example.test');
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

// Fictional sessions use the real session hash and enabled-MFA checks. Tokens
// are generated per run and must never be printed or added to test artifacts.
export function capacitySessions(sql,owners=50){
 const tokens=Array.from({length:owners},()=>randomBytes(32).toString('hex'));
 const expires=Math.floor(Date.now()/1000)+1800;
 tokens.forEach((token,i)=>{
  sql.prepare('INSERT INTO user_totp(user_id,encrypted_secret,enabled,created_at) VALUES(?,?,1,1)').run('owner-'+i,'fictional-not-enrollable');
  sql.prepare('INSERT INTO sessions(id,user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,1)').run('load-session-'+i,'owner-'+i,createHash('sha256').update(token).digest('hex'),expires);
 });
 return tokens;
}
