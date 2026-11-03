// SELECT-only release audit. Report aggregate counts, never customer names/emails/tokens.
import fs from 'node:fs';import assert from 'node:assert/strict';
export const integrityChecks={
 duplicate_findings:`SELECT COUNT(*) n FROM (SELECT user_id,asset_id,cve_id FROM remediation_finding_links GROUP BY user_id,asset_id,cve_id HAVING COUNT(*)>1)`,
 invalid_links:`SELECT COUNT(*) n FROM remediation_finding_links l LEFT JOIN remediations r ON r.user_id=l.user_id AND r.cve_id=l.record_id LEFT JOIN inventory_assets a ON a.user_id=l.user_id AND a.id=l.asset_id LEFT JOIN inventory_environments e ON e.user_id=a.user_id AND e.id=a.environment_id LEFT JOIN inventory_customers c ON c.user_id=e.user_id AND c.id=e.customer_id WHERE r.cve_id IS NULL OR c.id IS NULL OR l.record_id NOT IN(l.cve_id,l.cve_id||'~'||upper(l.asset_id)) OR l.asset_id!=lower(l.asset_id) OR l.cve_id!=upper(l.cve_id)`,
 status_drift:`SELECT COUNT(*) n FROM remediation_finding_links l JOIN remediations r ON r.user_id=l.user_id AND r.cve_id=l.record_id LEFT JOIN customer_finding_statuses s ON s.user_id=l.user_id AND s.asset_id=l.asset_id AND s.cve_id=l.cve_id WHERE COALESCE(s.status,'Needs Review')!=CASE r.status WHEN 'Open' THEN 'Needs Review' WHEN 'Investigating' THEN 'Fix in Progress' WHEN 'Remediated' THEN 'Fixed/Patched' ELSE r.status END`,
 detached_asset_records:`SELECT COUNT(*) n FROM remediations r WHERE instr(r.cve_id,'~')>0 AND NOT EXISTS(SELECT 1 FROM remediation_finding_links l WHERE l.user_id=r.user_id AND l.record_id=r.cve_id) AND NOT EXISTS(SELECT 1 FROM remediation_retired_records t WHERE t.user_id=r.user_id AND t.record_id=r.cve_id)`,
 invalid_retirements:`SELECT COUNT(*) n FROM remediation_retired_records t LEFT JOIN remediations r ON r.user_id=t.user_id AND r.cve_id=t.canonical_id WHERE r.cve_id IS NULL OR EXISTS(SELECT 1 FROM remediation_finding_links l WHERE l.user_id=t.user_id AND l.record_id=t.record_id) OR EXISTS(SELECT 1 FROM remediation_retired_records x WHERE x.user_id=t.user_id AND x.record_id=t.canonical_id)`,
 orphan_status_history:`SELECT COUNT(*) n FROM remediation_status_changes s LEFT JOIN remediations r ON r.user_id=s.user_id AND r.cve_id=s.cve_id WHERE r.cve_id IS NULL`,
 orphan_assignments:`SELECT COUNT(*) n FROM remediation_assignment_requests a LEFT JOIN remediations r ON r.user_id=a.user_id AND r.cve_id=a.cve_id WHERE r.cve_id IS NULL`,
 orphan_notifications:`SELECT COUNT(*) n FROM remediation_status_notifications n LEFT JOIN remediation_status_changes s ON s.id=n.change_id WHERE s.id IS NULL`
};
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
 const config=fs.readFileSync(new URL('../account-backend/wrangler.toml',import.meta.url),'utf8'),database=config.match(/database_id\s*=\s*"([a-f0-9-]+)"/)[1];
 const account=process.env.CLOUDFLARE_ACCOUNT_ID,token=process.env.CLOUDFLARE_API_TOKEN;assert.ok(account&&token,'Configured Cloudflare release credentials required');let queries=0;
 const DB={prepare(sql){assert.match(sql,/^SELECT\b/);return {async all(){queries++;const r=await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/d1/database/${database}/query`,{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({sql,params:[]})});const d=await r.json();assert.ok(r.ok&&d.success&&d.result?.[0]?.success,'Read-only integrity query failed');assert.equal(d.result[0].meta?.rows_written||0,0);return {results:d.result[0].results};},async first(){return (await this.all()).results[0]||null;}};}};
 const result=await verifyIntegrity(DB,{preflight:process.argv.includes('--preflight')});console.log(JSON.stringify({...result,queries,rows_written:0}));if(!result.ok)process.exitCode=1;
}
