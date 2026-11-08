import {integrityChecks} from './release-integrity-checks.js';

// A scoped investigation can belong to an inventory asset, a managed customer,
// or an explicitly named customer. Inspect only scope tables installed on this DB.
export async function installedIntegrityChecks(DB) {
 const tables=(await DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('remediation_customer_scopes','remediation_manual_scopes')").all()).results;
 const checks={...integrityChecks};
 for (const {name} of tables) {
  if (!['remediation_customer_scopes','remediation_manual_scopes'].includes(name)) continue;
  const pair='s.user_id=r.user_id AND s.record_id=r.cve_id';
  checks.detached_asset_records+=' AND NOT EXISTS(SELECT 1 FROM '+name+' s WHERE '+pair+" AND s.cve_id=substr(r.cve_id,1,instr(r.cve_id,'~')-1))";
  const managed=name==='remediation_customer_scopes';
  const inconsistent=managed?`NOT EXISTS(SELECT 1 FROM inventory_customers c WHERE c.id=s.customer_id AND c.user_id=s.user_id)
   OR (s.environment_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM inventory_environments e WHERE e.id=s.environment_id AND e.customer_id=s.customer_id AND e.user_id=s.user_id))`:
   "s.customer_name='' OR substr(s.customer_key,1,7)!='manual:'";
  checks['invalid_'+name]=`SELECT COUNT(*) n FROM ${name} s LEFT JOIN remediations r ON ${pair}
   WHERE r.cve_id IS NULL OR (s.record_id!=s.cve_id AND substr(s.record_id,1,length(s.cve_id)+1)!=s.cve_id||'~')
   OR EXISTS(SELECT 1 FROM remediation_finding_links l WHERE l.record_id=s.record_id AND l.user_id=s.user_id)
   OR EXISTS(SELECT 1 FROM remediation_retired_records t WHERE t.record_id=s.record_id AND t.user_id=s.user_id)
   OR ${inconsistent}`;
 }
 if(tables.length===2) checks.conflicting_customer_scopes='SELECT COUNT(*) n FROM remediation_customer_scopes c JOIN remediation_manual_scopes m ON c.user_id=m.user_id AND c.record_id=m.record_id';
 return checks;
}
