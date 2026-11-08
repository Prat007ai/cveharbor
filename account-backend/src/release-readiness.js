import {recoveryTablesSQL,recoveryGuardSQL,leaseGuardSQL,normalizedDDL} from './recovery-schema.js';
import {installedIntegrityChecks} from './release-integrity-checks.js';
import {releaseIdentity} from './release-build.js';
import {recoveryState} from './recovery-control.js';
export const integrityGuards=['validate_finding_write','finding_link_identity','finding_link_immutable','retired_remediation_read_only','preserve_remediation_history','preserve_asset_finding_history','linked_finding_status_insert','linked_finding_status_update'];
export async function recoveryCoverage(DB){
 const tables=(await DB.prepare(recoveryTablesSQL).all()).results;
 const triggers=(await DB.prepare("SELECT name,sql FROM sqlite_master WHERE type='trigger'").all()).results;
 const matches=(name,sql)=>triggers.some(t=>t.name===name&&normalizedDDL(t.sql)===normalizedDDL(sql));
 return tables.every(t=>['insert','update','delete'].every(op=>matches('recovery_hold_'+t.name+'_'+op,recoveryGuardSQL(t.name,op))))&&matches('recovery_hold_new_lease',leaseGuardSQL);

}
export async function releaseReadiness(env){
 let ready=false,held=true,schemaReady=false;
 try{
  const state=await recoveryState({...env,RECOVERY_CONTROL_REQUIRED:'true'});
  const names=(await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='trigger'").all()).results.map(r=>r.name);
  const contexts=await env.DB.prepare('SELECT COUNT(*) n FROM remediation_finding_write_context').first();
  held=!!state.write_hold;
  schemaReady=integrityGuards.every(n=>names.includes(n))&&contexts.n===0&&await recoveryCoverage(env.DB);
  if(schemaReady)for(const sql of Object.values(await installedIntegrityChecks(env.DB)))if(Number((await env.DB.prepare(sql).first()).n)!==0)schemaReady=false;
  ready=!held&&schemaReady;
 }catch{}
 return new Response(JSON.stringify({ready,held,schema_ready:schemaReady,release:releaseIdentity,schema:'phase1-integrity-recovery-v1'}),{status:ready?200:503,headers:{'Content-Type':'application/json','Cache-Control':'no-store'}});
}
