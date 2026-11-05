// Schema-only, in-memory impact inventory. Never connects to a live database.
import fs from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
import assert from 'node:assert/strict';
const baseline=JSON.parse(fs.readFileSync('release/baseline.json'));
const db=new DatabaseSync(':memory:');
try {
 for(const entry of baseline.application_schema_files)db.exec(fs.readFileSync(entry.path,'utf8'));
 const objects=db.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY type,name").all();
 assert.equal(objects.length,143);
 const tables=objects.filter(x=>x.type==='table').map(x=>x.name);
 const edges=tables.flatMap(table=>db.prepare('PRAGMA foreign_key_list("'+table+'")').all().map(f=>({child:table,parent:f.table,from:f.from,to:f.to,on_delete:f.on_delete})));
 const descendants=new Set(['remediations']);let changed=true;
 while(changed){changed=false;for(const e of edges)if(descendants.has(e.parent)&&!descendants.has(e.child)){descendants.add(e.child);changed=true;}}
 for(const name of ['users','sessions','login_challenges','user_totp','inventory_customers','inventory_environments','inventory_assets','customer_finding_statuses','customer_finding_tickets','customer_finding_ticket_history'])assert.ok(!descendants.has(name),name);
 const report={schema_only:true,live_records_examined:false,reset_recommended:false,baseline_objects:objects.length,
 root_record_key:['user_id','cve_id'],
 cascade_tables:[...descendants].sort(),cascade_edges:edges.filter(e=>descendants.has(e.parent)),
 remediation_tables_without_root_cascade:tables.filter(t=>t.startsWith('remediation_')&&!descendants.has(t)).sort(),
 delete_triggers:objects.filter(o=>o.type==='trigger'&&/\bDELETE\b/i.test(o.sql)).map(o=>({name:o.name,table:o.tbl_name,sql:o.sql})),
 future_candidate_tables:['remediation_customer_scopes','remediation_customer_ticket_history']};
 fs.mkdirSync('work',{recursive:true});fs.writeFileSync('work/customer-remediation-impact.json',JSON.stringify(report,null,2)+'\n');
 console.log(JSON.stringify({cascade_tables:report.cascade_tables,non_cascade:report.remediation_tables_without_root_cascade,delete_triggers:report.delete_triggers.map(t=>t.name)},null,2));
}finally{db.close();}
