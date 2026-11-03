// Legacy keys remain CVE IDs. Asset-linked work uses a separate, deterministic key.
export const publicCve=key=>String(key||'').split('~')[0];
export function recordKey(value){const id=String(value||'').trim().toUpperCase();return /^CVE-\d{4}-\d{4,}(?:~[A-F0-9-]{36})?$/.test(id)&&publicCve(id).length<=28?id:null;}
export const workStatus=status=>({'Needs Review':'Open','Fix in Progress':'Investigating','Fixed/Patched':'Remediated'}[status]||status);
export const findingStatus=status=>({Open:'Needs Review',Investigating:'Fix in Progress',Remediated:'Fixed/Patched'}[status]||status);
export async function linkedReady(env){try{await env.DB.prepare('SELECT record_id FROM remediation_finding_links LIMIT 1').first();return true;}catch{return false;}}
export const scopeSQL=`SELECT l.record_id,l.cve_id,l.asset_id,a.name AS asset_name,a.technology,a.version,e.id AS environment_id,e.name AS environment_name,c.id AS customer_id,c.name AS customer_name FROM remediation_finding_links l JOIN inventory_assets a ON a.id=l.asset_id AND a.user_id=l.user_id JOIN inventory_environments e ON e.id=a.environment_id AND e.user_id=a.user_id JOIN inventory_customers c ON c.id=e.customer_id AND c.user_id=e.user_id WHERE l.user_id=?`;
export async function recordScope(env,userId,key){if(!await linkedReady(env))return null;return env.DB.prepare(scopeSQL+' AND l.record_id=?').bind(userId,key).first();}
export const scopeLabel=scope=>scope?[scope.customer_name,scope.environment_name,scope.asset_name,scope.technology,scope.version].filter(Boolean).join(' · '):'';
