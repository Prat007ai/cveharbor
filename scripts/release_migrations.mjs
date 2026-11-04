// Native D1 forward migrations only; historical initialization remains separately guarded.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {createHash} from 'node:crypto';
export function forwardMigrations(root=process.cwd()){
 const dir=path.join(root,'release/migrations');if(!fs.existsSync(dir))return [];const files=fs.readdirSync(dir).filter(n=>n.endsWith('.sql')).sort();let prior=0;
 return files.map(name=>{assert.match(name,/^\d{4,}_[a-z0-9_]+\.sql$/);const n=Number(name.split('_')[0]);assert.ok(n>prior,'Unique increasing migration numbers required');prior=n;
  const sql=fs.readFileSync(path.join(dir,name),'utf8');
  // Conservative review gate. Maintenance/destructive SQL never enters the routine lane.
  assert.ok(!/\b(?:DROP|DELETE|UPDATE|INSERT|REPLACE|ATTACH|DETACH|VACUUM|PRAGMA|REINDEX|ANALYZE)\b|\bALTER\s+TABLE\s+\S+\s+(?!ADD\b)/i.test(sql),'Destructive/data-transform migration needs separate review');
  return {name,sql,sha256:createHash('sha256').update(sql).digest('hex')};});
}
export function migrationConfig({production=false,account,root=process.cwd()}){
 assert.match(account||'',/^[a-f0-9]{32}$/);
 if(production)assert.notEqual(account,'9706b4d98ad72884e67fd1eb875c8a61');else assert.equal(account,'9706b4d98ad72884e67fd1eb875c8a61');
 return {name:production?'cveharbor-accounts':'cveharbor-accounts-staging',account_id:account,
  d1_databases:[{binding:'DB',database_name:production?'cveharbor-accounts':'cveharbor-accounts-staging',database_id:production?'46710e51-7ca4-4571-b89c-921b9969de0b':'fac61562-fc31-426d-8032-550aba63b7f6',migrations_dir:path.join(root,'release/migrations'),migrations_table:'d1_migrations'}]};
}
