// SELECT-only release audit. Report aggregate counts, never customer names/emails/tokens.
import assert from 'node:assert/strict';
import {integrityChecks} from '../account-backend/src/release-integrity-checks.js';
export {integrityChecks};
export async function verifyIntegrity(DB,{preflight=false}={}){
 const counts={};for(const [name,sql] of Object.entries(integrityChecks))counts[name]=Number((await DB.prepare(sql).first()).n);
 if(!preflight){
  const guardNames=['validate_finding_write','finding_link_identity','finding_link_immutable','retired_remediation_read_only','preserve_remediation_history','preserve_asset_finding_history','linked_finding_status_insert','linked_finding_status_update'];
  const found=await DB.prepare("SELECT name FROM sqlite_master WHERE type='trigger'").all();assert.ok(guardNames.every(n=>found.results.some(x=>x.name===n)),'Phase 1 integrity guards missing');
  counts.unfinished_write_contexts=Number((await DB.prepare('SELECT COUNT(*) n FROM remediation_finding_write_context').first()).n);
 }
 return {ok:Object.values(counts).every(n=>n===0),read_only:true,counts};
}
if(process.argv[1]&&new URL(import.meta.url).pathname===process.argv[1]){
 const {d1Client}=await import('./cloudflare_d1.mjs');const DB=d1Client({readOnly:true});
 const result=await verifyIntegrity(DB,{preflight:process.argv.includes('--preflight')});console.log(JSON.stringify({...result,queries:DB.queries,rows_written:0}));if(!result.ok)process.exitCode=1;
}
