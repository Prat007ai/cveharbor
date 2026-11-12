import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
import {createHash} from 'node:crypto';
import {canonical, schemaSQL, PRODUCTION_DB} from './production_schema_baseline.mjs';
import {d1Client} from './cloudflare_d1.mjs';
import {holdStatus, guardSQL} from './recovery_control.mjs';
import {verifyService} from './production_service_health.mjs';

const account='aa99b9b15e0492302e4f6484b8d27bc2';
const schema=process.env.CUSTOMER_SCHEMA||'managed';
if(schema==='server-network'){await import('./server_network_schema.mjs');process.exit(0);}
if(schema==='organization-ai'){await import('./organization_ai_schema.mjs');process.exit(0);}
if(schema==='workspace-history'){await import('./workspace_history_schema.mjs');process.exit(0);}
assert.ok(['managed','manual','firewall','team'].includes(schema));
const team=schema==='team';
const firewall=schema==='firewall';
const manual=schema==='manual';
const identity=manual?'manual-backend-identity.txt':'backend-identity.txt';
const release=fs.readFileSync(team?'release/firewall-backend-identity.txt':firewall?'release/intelligence-baseline/backend-identity.txt':'release/customer-investigation/'+identity,'utf8').trim();
const sql=fs.readFileSync(team?'deployment/proposals/organization-team-access/schema.sql':firewall?'deployment/proposals/firewall-digest/schema.sql':'deployment/proposals/customer-remediation/'+(manual?'manual-scope.sql':'schema.sql'),'utf8').replaceAll('\r\n','\n');
assert.equal(createHash('sha256').update(sql).digest('hex'),team?'757e529ac34c7b0b6486e95cefaf22c4563103cac6e570f7f3d446c0384d965f':firewall?'e3bf15dee948cba0273a2d98046fc92862752051612a9b85da89af53d761ad27':manual?'8bc72fce5ddb0ca44df71cdbd39abeacae8eae6af19f04a9a39112cb5d76f338':'4cb409cd1ad836c3e71394e3f054168d99b7896817421d92d795d71235a8977a');
const tables=team?['team_organizations','team_members','team_last_login','team_audit']:firewall?['firewall_subscribers','firewall_digest_deliveries']:manual?['remediation_manual_scopes']:['remediation_customer_scopes','remediation_customer_ticket_history'];
const dependencies=new Set(team?['operations_control','users','sessions','inventory_customers','inventory_environments','inventory_assets','remediations','remediation_customer_scopes','remediation_finding_links','customer_finding_statuses']:firewall?['operations_control']:manual?['remediations']:['users','remediations','inventory_customers','inventory_environments','remediation_finding_links','remediation_retired_records']);
const guards=tables.flatMap(table=>['insert','update','delete'].map(op=>guardSQL(table,op)+';')).join('\n');
// D1 already enforces foreign keys. Only the pinned DDL and recovery triggers are sent.
const ddl=sql.slice(sql.indexOf('CREATE TABLE '))+(team?'':'\n'+guards);
const local=new DatabaseSync(':memory:');
const baseline=JSON.parse(fs.readFileSync('release/baseline.json','utf8'));
for(const entry of baseline.application_schema_files)local.exec(fs.readFileSync(entry.path,'utf8'));
if(team)local.exec(fs.readFileSync('deployment/proposals/customer-remediation/schema.sql','utf8'));
if(firewall||team)local.exec(fs.readFileSync('account-backend/migrations/0032_recovery_control.sql','utf8'));
const original=local.prepare(schemaSQL).all();
const dependent=rows=>canonical(rows.filter(r=>r.type==='table'&&dependencies.has(r.name)));
assert.equal(dependent(original).length,dependencies.size,'Every prerequisite must be present in the rehearsal.');
const originalNames=new Set(original.map(r=>r.name));
const writes=()=>local.prepare('SELECT total_changes() n').get().n;
const before=writes();
local.exec(ddl);
assert.equal(writes(),before);
const added=local.prepare(schemaSQL).all().filter(r=>!originalNames.has(r.name));
assert.equal(added.filter(r=>r.type==='table').length,tables.length);
assert.equal(added.filter(r=>r.type==='index').length,team?2:manual?0:1);
assert.equal(added.filter(r=>r.type==='trigger').length,team?17:firewall?6:manual?4:15);
if(team)assert.equal(added.filter(r=>r.type==='view').length,2);
const names=new Set(added.map(r=>r.name));
local.close();

async function apply(){
  assert.equal(process.env.GITHUB_REF,'refs/heads/main');
  assert.equal(process.env.CLOUDFLARE_ACCOUNT_ID,account);
  assert.equal(PRODUCTION_DB,baseline.production_database_id);
  const db=d1Client({database:PRODUCTION_DB,readOnly:false});
  assert.equal((await db.metadata()).uuid,PRODUCTION_DB);
  const state=await holdStatus(db);
  assert.equal(state.write_hold,0);
  assert.equal(state.database_frozen,0);
  assert.equal(state.guards_complete,true);
  await verifyService({expectedRelease:release,readinessOnly:true});
  const readSchema=async()=>(await db.prepare(schemaSQL).all()).results;
  const live=await readSchema();
  assert.deepEqual(dependent(live),dependent(original),'Unexpected prerequisite table definition.');
  const subset=rows=>rows.filter(r=>names.has(r.name));
  const found=subset(live);
  if(found.length){
    assert.deepEqual(canonical(found),canonical(added),'Partial or incompatible customer schema: review before retrying.');
  }else{
    assert.equal((await db.prepare('SELECT count(*) n FROM pragma_foreign_key_check').first()).n,0);
    const res=await fetch('https://api.cloudflare.com/client/v4/accounts/'+account+'/d1/database/'+PRODUCTION_DB+'/time_travel/bookmark',{headers:{Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN},redirect:'error',signal:AbortSignal.timeout(20000)});
    assert.ok(res.ok&&(await res.json()).result?.bookmark,'D1 recovery bookmark unavailable.');
    // Repeat the admission check inside the D1 transaction. SQLite integer
    // overflow aborts the transaction if a concurrent recovery hold intervened.
    const admission="SELECT CASE WHEN EXISTS (SELECT 1 FROM operations_control WHERE id=1 AND write_hold=0 AND database_frozen=0 AND revision=?) THEN 1 ELSE abs(-9223372036854775808) END";
    await db.batch([db.prepare(admission).bind(state.revision),db.prepare(ddl)]);
    const after=await readSchema();
    assert.deepEqual(canonical(subset(after)),canonical(added));
    assert.deepEqual(canonical(after.filter(r=>!names.has(r.name))),canonical(live));
  }
  assert.equal((await db.prepare('SELECT count(*) n FROM pragma_foreign_key_check').first()).n,0);
  assert.equal((await holdStatus(db)).guards_complete,true);
  await verifyService({expectedRelease:release});
  if(team){
    const missing=await db.prepare('SELECT count(*) n FROM (SELECT user_id,max(created_at) latest FROM sessions GROUP BY user_id) s LEFT JOIN team_last_login l ON l.user_id=s.user_id WHERE l.signed_at IS NULL OR l.signed_at<s.latest').first();
    assert.equal(missing.n,0,'Last sign-in migration incomplete');
    await db.prepare('SELECT * FROM team_scoped_records LIMIT 0').all();
  }
  console.log('Verified '+schema+' storage, indexes, guards, foreign keys and live service.');
}
if(process.argv[2]==='--apply')await apply();
else {assert.equal(process.argv[2],'--rehearse');console.log('Verified additive customer schema and recovery guards in SQLite. Existing records untouched.');}
