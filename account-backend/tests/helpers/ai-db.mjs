import {DatabaseSync} from 'node:sqlite';
import fs from 'node:fs';
export function fixture({personal=false}={}){
 const store=new DatabaseSync(':memory:');
 let setup=`PRAGMA foreign_keys=ON;
 CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT);
 INSERT INTO users VALUES('owner','owner@example.test'),('staff','staff@example.test'),('other','other@example.test'),('admin','admin@example.test');
 CREATE TABLE user_totp(user_id TEXT,enabled INTEGER);INSERT INTO user_totp SELECT id,1 FROM users;
 CREATE TABLE team_organizations(id TEXT PRIMARY KEY,name TEXT);INSERT INTO team_organizations VALUES('north','Northstar Demo'),('south','South Demo');
 CREATE TABLE team_members(org TEXT,user_id TEXT,role TEXT);INSERT INTO team_members VALUES('north','owner','Owner'),('north','staff','Viewer'),('south','other','Owner');
 CREATE TABLE team_visible_customers(org TEXT,actor TEXT,customer_id TEXT,role TEXT);
 INSERT INTO team_visible_customers VALUES('north','owner','customer-a','Owner'),('north','owner','customer-b','Owner'),('north','staff','customer-b','Viewer'),('south','other','customer-c','Owner');
 CREATE TABLE operations_control(id INTEGER,write_hold INTEGER,database_frozen INTEGER);INSERT INTO operations_control VALUES(1,0,0);`;
 let schema=fs.readFileSync(new URL('../../../deployment/proposals/organization-ai/schema.sql',import.meta.url),'utf8');
 if(personal){setup+=`CREATE TABLE inventory_customers(id TEXT,user_id TEXT); INSERT INTO inventory_customers VALUES('private-a','owner'),('private-b','staff');`;schema+=fs.readFileSync(new URL('../../../deployment/proposals/personal-ai/schema.sql',import.meta.url),'utf8');}
 store.exec(setup+schema);
 const db={prepare(query){const s=store.prepare(query);const bind=args=>({bind:(...values)=>bind(values),
  first:()=>s.get(...args)||null,all:()=>({results:s.all(...args)}),run:()=>s.columns().length?{results:s.all(...args)}:{meta:{changes:Number(s.run(...args).changes)}}});return bind([]);},
  async batch(statements){store.exec('BEGIN');try{const result=statements.map(s=>s.run());store.exec('COMMIT');return result;}catch(e){store.exec('ROLLBACK');throw e;}}};
 const env={DB:db,CVEHARBOR_AI_PERSONAL_ENABLED:personal?'true':'false',CVEHARBOR_AI_ACCOUNTING_ENABLED:'true',CVEHARBOR_AI_ENABLED:'true',CVEHARBOR_AI_PLATFORM_OWNER_EMAIL:'admin@example.test',
  CVEHARBOR_AZURE_OPENAI_ENDPOINT:'https://cvie-prod.openai.azure.com/',CVEHARBOR_AZURE_OPENAI_DEPLOYMENT:'gpt-5.4-mini',
  CVEHARBOR_AZURE_OPENAI_TENANT_ID:'11111111-1111-4111-8111-111111111111',CVEHARBOR_AZURE_OPENAI_CLIENT_ID:'22222222-2222-4222-8222-222222222222',CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET:'fictional'};
 store.exec("INSERT INTO ai_organizations VALUES('north',1),('south',1)");
 return {store,db,env,setup,schema};
}
export const user=id=>({id,email:id+'@example.test'});
export const question=(request_key='fictional-request-00001',customer='customer-a')=>({request_key,customer,question:'Fictional PHP system: what evidence should an administrator verify?'});
export function provider({failAuth=false,failInference=false,usage,model,hook}={}){
 const calls=[];
 const fetcher=async(url,options)=>{
  calls.push({url,options});
  if(url.includes('login.microsoftonline.com'))return Response.json(failAuth?{}:{access_token:'fictional-token',token_type:'Bearer',expires_in:3600});
  if(hook)await hook();
  if(failInference)throw Error('Fictional timeout');
  return Response.json({model:model||'gpt-5.4-mini-2026-03-17',usage:usage||{prompt_tokens:88,completion_tokens:172,total_tokens:260},choices:[{message:{content:'Verify the fictional package provenance.'},finish_reason:'stop'}]});
 };return {calls,fetcher};
}
