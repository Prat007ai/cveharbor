import fs from 'node:fs';
import {assignmentFixture,fixtureCve} from './assignment-db.mjs';
export const assetOne='11111111-1111-4111-8111-111111111111',assetTwo='22222222-2222-4222-8222-222222222222',assetOther='33333333-3333-4333-8333-333333333333';
export async function unifiedFixture(){
 const f=await assignmentFixture();for(const file of ['inventory-schema.sql','finding-status-schema.sql','finding-ticket-schema.sql','finding-ticket-history-schema.sql','migrations/0026_remediation_workflow.sql','migrations/0027_assignment_progress.sql','migrations/0028_unified_findings.sql'])f.DB.sql.exec(fs.readFileSync(new URL('../../'+file,import.meta.url),'utf8'));
 Object.assign(f.env,{REMEDIATION_WORKFLOW_ENABLED:'true',ASSIGNMENT_PROGRESS_ENABLED:'true',ASSIGNMENT_FYI_ENABLED:'true',ASSIGNMENT_CONFIRM_ORIGIN:'https://confirm.cveharbor.com'});
 for(const [asset,user,customer,environment,name] of [[assetOne,'a','Customer North','Production','Web Server 01'],[assetTwo,'a','Customer South','Staging','Web Server 02'],[assetOther,'b','Private Other','Production','Private Asset']]){
  f.DB.sql.prepare('INSERT INTO inventory_customers(id,user_id,name) VALUES(?,?,?)').run('c-'+asset,user,customer);
  f.DB.sql.prepare('INSERT INTO inventory_environments(id,user_id,customer_id,name) VALUES(?,?,?,?)').run('e-'+asset,user,'c-'+asset,environment);
  f.DB.sql.prepare("INSERT INTO inventory_assets(id,user_id,environment_id,name,asset_type,technology,version) VALUES(?,?,?,?,'Server','Review service','1.0')").run(asset,user,'e-'+asset,name);
 }
 f.DB.sql.prepare('INSERT INTO customer_finding_statuses(user_id,asset_id,cve_id,status,notes) VALUES(?,?,?,?,?)').run('a',assetOne,fixtureCve,'Fix in Progress','Existing finding notes');
 f.DB.sql.prepare('INSERT INTO customer_finding_ticket_history(user_id,asset_id,cve_id,ticket_number) VALUES(?,?,?,?)').run('a',assetOne,fixtureCve,'SEC-248');
 return f;
}
