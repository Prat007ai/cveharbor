// Use the documented per-migration rollback contract, not generic REST batch semantics.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';
import {TARGET} from '../target.mjs';import {resourceManifest} from './inventory.mjs';
import {output} from './customer-candidate-artifact.mjs';import {migrationName,journalTable} from './customer-candidate-schema.mjs';
export function applyCandidateMigration(env,statements,profile,runner=spawnSync){
 assert.equal(env.CF_STAGING_ACCOUNT_ID,TARGET.account);assert.equal(env.CF_STAGING_D1_DATABASE_ID,resourceManifest().permanent_database.uuid);
 assert.match(profile.migration_sha256,/^[a-f0-9]{64}$/);assert.ok(statements.length>0);
 fs.mkdirSync(output,{recursive:true});const dir=fs.mkdtempSync(path.join(output,'migration-'));
 try{
  const migrations=path.join(dir,'sql');fs.mkdirSync(migrations);
  const file=path.join(migrations,migrationName(profile));
  fs.writeFileSync(file,statements.map(s=>s.sql.trim().replace(/;\s*$/,'')+';').join('\n')+'\n',{flag:'wx'});
  const config={account_id:TARGET.account,d1_databases:[{binding:'DB',database_name:TARGET.database,database_id:resourceManifest().permanent_database.uuid,migrations_dir:migrations,migrations_table:journalTable}]};
  const configPath=path.join(dir,'wrangler.json');fs.writeFileSync(configPath,JSON.stringify(config));assert.deepEqual(fs.readdirSync(migrations),[migrationName(profile)]);
  const result=runner('npx',['--yes','wrangler@4.156.0','d1','migrations','apply',TARGET.database,'--remote','--config',configPath],{cwd:dir,encoding:'utf8',timeout:180000,maxBuffer:4*1024*1024,env:{PATH:env.PATH,CI:'true',CLOUDFLARE_ACCOUNT_ID:TARGET.account,CLOUDFLARE_API_TOKEN:env.CF_STAGING_API_TOKEN,CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV:'false',WRANGLER_SEND_METRICS:'false',XDG_CONFIG_HOME:path.join(dir,'wrangler-state'),...Object.fromEntries(['HTTPS_PROXY','HTTP_PROXY','NODE_EXTRA_CA_CERTS'].filter(k=>env[k]).map(k=>[k,env[k]]))}});
  // Never infer rollback from the process exit code; query schema and both receipts separately.
  assert.ok(!result.error&&result.status===0,'Migration outcome requires read-only reconciliation');
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
}
