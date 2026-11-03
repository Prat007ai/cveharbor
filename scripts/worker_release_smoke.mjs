import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
import {inventoryOnly,catalogueOnly,monitorCodeOnly,workspaceCodeOnly,remediationCodeOnly,acknowledgementRelease} from './worker_release_mode.mjs';
import {verifyHistory} from './verify_software_history_d1.mjs';
const inventory='account-backend/src/inventory.js';
assert.equal(inventoryOnly([inventory,'customer-security.js']),true);
for(const path of ['account-backend/src/cvie.js','account-backend/wrangler.toml','account-backend/migrations/0021_cvie_audit_refresh.sql','scripts/verify_cvie_d1.mjs'])assert.equal(inventoryOnly([inventory,path]),false,path);
assert.equal(inventoryOnly(['customer-security.js']),false);
const sql=new DatabaseSync(':memory:');
try{
 sql.exec('CREATE TABLE users(id TEXT PRIMARY KEY)');
 sql.exec(fs.readFileSync(new URL('../account-backend/inventory-schema.sql',import.meta.url),'utf8'));
 sql.exec(fs.readFileSync(new URL('../account-backend/software-upgrade-history-schema.sql',import.meta.url),'utf8'));
 const DB={prepare(query){
  assert.match(query,/^SELECT\b/);
  assert.doesNotMatch(query,/FROM inventory_(customers|environments|assets)\b/);
  const make=params=>({bind:(...args)=>make(args),async all(){return {results:sql.prepare(query).all(...params)}},async first(){return sql.prepare(query).get(...params)||null}});
  return make([]);
 }};
 assert.equal((await verifyHistory(DB)).ok,true);
 sql.exec('DROP TRIGGER inventory_software_version_changed');
 await assert.rejects(()=>verifyHistory(DB),/setup is missing/);
 sql.exec("CREATE TRIGGER inventory_software_version_changed AFTER UPDATE ON inventory_assets BEGIN SELECT 1; END");
 await assert.rejects(()=>verifyHistory(DB),/definition differs/);
 console.log('PASS: inventory-only release classification and SELECT-only schema/reader preflight');
}finally{sql.close()}

assert.equal(catalogueOnly(['account-backend/src/catalogue-selection.js','account-backend/src/cvie.js']),true);
assert.equal(catalogueOnly(['account-backend/src/catalogue-selection.js','account-backend/migrations/0022_cvie_shared_scans.sql']),false);


assert.equal(monitorCodeOnly(['account-backend/src/monitoring.js','account-backend/src/index.js','account-backend/migrations/0023_lifecycle_monitoring.sql','index.html']),true);
assert.equal(monitorCodeOnly(['account-backend/src/monitoring.js','account-backend/src/cvie.js']),false);
assert.equal(monitorCodeOnly(['account-backend/src/index.js']),false);

assert.equal(monitorCodeOnly(['account-backend/src/index.js','account-backend/src/monitor-approved-test.js','account-backend/tests/monitor-approved-test.test.mjs']),true);
assert.equal(catalogueOnly(['account-backend/src/product-identity.js','account-backend/src/cvie.js','account-backend/tests/product-chooser.test.mjs']),true);
assert.equal(catalogueOnly(['account-backend/tests/product-chooser.test.mjs','account-backend/wrangler.toml']),false);

assert.equal(monitorCodeOnly(['account-backend/src/lifecycle.js','account-backend/src/monitor-directory.js','account-backend/tests/monitor-directory.test.mjs','account-backend/tests/lifecycle.test.mjs','data/lifecycle-products.json']),true);

const workspace='account-backend/src/workspace-summary.js';
assert.equal(workspaceCodeOnly([workspace,'account-backend/src/index.js','account-backend/tests/workspace-summary.test.mjs','workspace/index.html']),true);
for(const path of ['account-backend/src/cvie.js','account-backend/wrangler.toml','account-backend/migrations/0023_lifecycle_monitoring.sql','scripts/bootstrap_cvie_shared.mjs'])assert.equal(workspaceCodeOnly([workspace,path]),false,path);
assert.equal(workspaceCodeOnly(['account-backend/src/index.js']),false);

const remediation='account-backend/src/remediation.js';
assert.equal(remediationCodeOnly([remediation,'account-backend/tests/remediation.test.mjs','index.html','operations.js','remediation.css']),true);
for(const path of ['account-backend/src/cvie.js','account-backend/src/index.js','account-backend/wrangler.toml','account-backend/migrations/0019_cvie.sql','scripts/bootstrap_cvie_shared.mjs','scripts/verify_cvie_d1.mjs'])assert.equal(remediationCodeOnly([remediation,path]),false,path);
assert.equal(remediationCodeOnly(['operations.js','remediation.css']),false);
console.log('PASS: remediation release skips maintenance only for isolated record-handler changes');

const ackFiles=['account-backend/src/assignment-acknowledgement.js','account-backend/src/index.js','account-backend/src/remediation.js','account-backend/wrangler.toml','account-backend/migrations/0024_assignment_acknowledgements.sql'];
assert.equal(acknowledgementRelease(ackFiles),true);
for(const file of ['account-backend/src/cvie.js','account-backend/migrations/0019_cvie.sql','scripts/bootstrap_cvie_shared.mjs'])assert.equal(acknowledgementRelease([...ackFiles,file]),false);
assert.equal(acknowledgementRelease(ackFiles.filter(f=>!f.endsWith('0024_assignment_acknowledgements.sql'))),false);
console.log('PASS: acknowledgement release permits only its approved additive migration');

const {fyiRelease}=await import('./worker_release_mode.mjs');
assert.equal(fyiRelease(['account-backend/src/assignment-fyi.js','account-backend/migrations/0025_assignment_fyi.sql','account-backend/src/index.js']),true);
assert.equal(fyiRelease(['account-backend/src/assignment-fyi.js','account-backend/src/cvie.js']),false);
assert.equal(fyiRelease(['account-backend/src/assignment-fyi.js','scripts/bootstrap_cvie_shared.mjs']),false);
console.log('PASS: FYI release is restricted to its own additive migration and notification code');

const {remediationWorkflowRelease}=await import('./worker_release_mode.mjs');
const workflowFiles=['account-backend/src/remediation-workflow.js','account-backend/src/confirmation-host.js','account-backend/migrations/0026_remediation_workflow.sql','account-backend/wrangler.toml'];
assert.equal(remediationWorkflowRelease(workflowFiles),true);
assert.equal(remediationWorkflowRelease([...workflowFiles,'account-backend/src/cvie.js']),false);
assert.equal(remediationWorkflowRelease([...workflowFiles,'scripts/bootstrap_cvie_shared.mjs']),false);
assert.equal(remediationWorkflowRelease(workflowFiles.filter(x=>!x.endsWith('.sql'))),false);

const {assignmentProgressRelease}=await import('./worker_release_mode.mjs');
const progressFiles=['account-backend/src/assignment-progress.js','account-backend/src/index.js','account-backend/migrations/0027_assignment_progress.sql','account-backend/wrangler.toml'];
assert.equal(assignmentProgressRelease(progressFiles),true);
for(const file of ['account-backend/src/cvie.js','account-backend/migrations/0026_remediation_workflow.sql','scripts/bootstrap_cvie_shared.mjs','scripts/verify_cvie_d1.mjs'])assert.equal(assignmentProgressRelease([...progressFiles,file]),false);
assert.equal(assignmentProgressRelease(progressFiles.filter(f=>!f.endsWith('.sql'))),false);
console.log('PASS: assignment progress release applies only migration 0027 and skips unrelated maintenance');

const {assignmentProgressCodeOnly}=await import('./worker_release_mode.mjs');
const managerFiles=['account-backend/src/assignment-progress-mail.js','account-backend/src/assignment-progress.js','account-backend/src/assignment-progress-page.js','account-backend/src/assignment-template.js','account-backend/tests/assignment-progress.test.mjs'];
assert.equal(assignmentProgressCodeOnly(managerFiles),true);
for(const file of ['account-backend/migrations/0027_assignment_progress.sql','account-backend/wrangler.toml','account-backend/src/index.js','scripts/bootstrap_cvie_shared.mjs'])assert.equal(assignmentProgressCodeOnly([...managerFiles,file]),false);
console.log('PASS: manager reminder release deploys notification code without migrations or unrelated maintenance');

const {unifiedFindingsRelease}=await import('./worker_release_mode.mjs');
const unifiedFiles=['account-backend/src/finding-remediation.js','account-backend/src/remediation-identity.js','account-backend/migrations/0028_unified_findings.sql','account-backend/tests/unified-findings.test.mjs'];
assert.equal(unifiedFindingsRelease(unifiedFiles),true);
for(const f of ['account-backend/wrangler.toml','account-backend/src/cvie.js','scripts/bootstrap_cvie_shared.mjs'])assert.equal(unifiedFindingsRelease([...unifiedFiles,f]),false);
assert.equal(unifiedFindingsRelease(unifiedFiles.filter(f=>!f.endsWith('.sql'))),false);

const {findingLinksRelease}=await import('./worker_release_mode.mjs');
const linksFiles=['account-backend/src/finding-assignment-links.js','account-backend/src/remediation.js','account-backend/migrations/0029_finding_assignment_links.sql','account-backend/tests/finding-assignment-links.test.mjs'];
assert.equal(findingLinksRelease(linksFiles),true);
for(const f of ['account-backend/wrangler.toml','account-backend/src/cvie.js','scripts/bootstrap_cvie_shared.mjs','account-backend/migrations/0028_unified_findings.sql'])assert.equal(findingLinksRelease([...linksFiles,f]),false);
assert.equal(findingLinksRelease(linksFiles.filter(f=>!f.endsWith('.sql'))),false);
console.log('PASS: assignment link release applies only migration 0029 and does not run unrelated maintenance');

const {statusMailRelease}=await import('./worker_release_mode.mjs');
const statusMailFiles=['account-backend/src/status-update-mail.js','account-backend/src/assignment-progress.js','account-backend/migrations/0030_status_update_notifications.sql','account-backend/tests/status-update-mail.test.mjs'];
assert.equal(statusMailRelease(statusMailFiles),true);
for(const f of ['account-backend/wrangler.toml','account-backend/src/cvie.js','scripts/bootstrap_cvie_shared.mjs','account-backend/migrations/0029_finding_assignment_links.sql'])assert.equal(statusMailRelease([...statusMailFiles,f]),false);
assert.equal(statusMailRelease(statusMailFiles.filter(f=>!f.endsWith('.sql'))),false);
console.log('PASS: status notification release applies only migration 0030 and skips unrelated maintenance');

const {statusMailRepair}=await import('./worker_release_mode.mjs');
const repairFiles=['account-backend/src/finding-assignment-links.js','account-backend/src/status-update-mail.js','account-backend/tests/status-mail-repair.test.mjs'];
assert.equal(statusMailRepair(repairFiles),true);
for(const f of ['account-backend/wrangler.toml','account-backend/src/cvie.js','scripts/bootstrap_cvie_shared.mjs','account-backend/migrations/0030_status_update_notifications.sql'])assert.equal(statusMailRepair([...repairFiles,f]),false);
console.log('PASS: status linking repair is code-only with no migrations or unrelated maintenance');
