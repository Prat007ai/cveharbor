import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
export function inventoryOnly(files){
 const allowed=new Set(['account-backend/src/inventory.js','account-backend/tests/inventory-history.test.mjs','account-backend/software-upgrade-history-schema.sql']);
 const backend=files.filter(f=>f.startsWith('account-backend/'));
 if(files.some(f=>f.startsWith('scripts/verify_cvie')))return false;
 return backend.includes('account-backend/src/inventory.js')&&backend.every(f=>allowed.has(f));
}
export function catalogueOnly(files){
 const allowed=new Set(['account-backend/src/catalogue-selection.js','account-backend/src/product-identity.js','account-backend/tests/product-chooser.test.mjs','account-backend/src/cvie.js','account-backend/src/cvie-records.js','account-backend/src/shared-scopes.js','account-backend/src/index.js','account-backend/tests/catalogue-scope.test.mjs']);
 return (files.includes('account-backend/src/catalogue-selection.js')||files.includes('account-backend/tests/product-chooser.test.mjs'))&&files.filter(f=>f.startsWith('account-backend/')).every(f=>allowed.has(f))&&!files.some(f=>f.startsWith('scripts/bootstrap_cvie')||f.startsWith('scripts/verify_cvie'));
}
export function monitorCodeOnly(files){
 const allowed=new Set(['account-backend/src/index.js','account-backend/src/lifecycle.js','account-backend/src/monitoring.js','account-backend/src/monitor-directory.js','account-backend/tests/monitor-directory.test.mjs','account-backend/tests/lifecycle.test.mjs','account-backend/src/monitor-engine.js','account-backend/src/monitor-mail.js','account-backend/src/monitor-approved-test.js','account-backend/tests/monitor-approved-test.test.mjs','account-backend/src/monitor-sources.js','account-backend/tests/product-monitoring.test.mjs','account-backend/migrations/0023_lifecycle_monitoring.sql']);
 const backend=files.filter(f=>f.startsWith('account-backend/'));
 return backend.some(f=>f.includes('/monitor'))&&backend.every(f=>allowed.has(f));
}
export function workspaceCodeOnly(files){
 const allowed=new Set(['account-backend/src/workspace-summary.js','account-backend/src/index.js','account-backend/tests/workspace-summary.test.mjs']);
 return files.includes('account-backend/src/workspace-summary.js')&&files.filter(f=>f.startsWith('account-backend/')).every(f=>allowed.has(f))&&!files.some(f=>f.startsWith('scripts/bootstrap_cvie')||f.startsWith('scripts/verify_cvie'));
}
export function remediationCodeOnly(files){
 const allowed=new Set(['account-backend/src/remediation.js','account-backend/tests/remediation.test.mjs']);
 return files.includes('account-backend/src/remediation.js')&&files.filter(f=>f.startsWith('account-backend/')).every(f=>allowed.has(f))&&!files.some(f=>f.startsWith('scripts/bootstrap_cvie')||f.startsWith('scripts/verify_cvie'));
}
export function acknowledgementRelease(files){
 const allowed=new Set(['account-backend/src/index.js','account-backend/src/remediation.js','account-backend/src/assignment-acknowledgement.js','account-backend/src/assignment-template.js','account-backend/tests/assignment-acknowledgement.test.mjs','account-backend/tests/helpers/assignment-db.mjs','account-backend/tests/remediation.test.mjs','account-backend/wrangler.toml','account-backend/migrations/0024_assignment_acknowledgements.sql']);
 return files.includes('account-backend/src/assignment-acknowledgement.js')&&files.includes('account-backend/migrations/0024_assignment_acknowledgements.sql')&&files.filter(f=>f.startsWith('account-backend/')).every(f=>allowed.has(f))&&!files.some(f=>f.startsWith('scripts/bootstrap_cvie')||f.startsWith('scripts/verify_cvie'));
}
export function fyiRelease(files){
 const allowed=new Set(['account-backend/src/index.js','account-backend/src/remediation.js','account-backend/src/assignment-acknowledgement.js','account-backend/src/assignment-fyi.js','account-backend/tests/assignment-fyi.test.mjs','account-backend/tests/helpers/assignment-db.mjs','account-backend/wrangler.toml','account-backend/migrations/0025_assignment_fyi.sql']);
 return files.includes('account-backend/src/assignment-fyi.js')&&files.filter(f=>f.startsWith('account-backend/')).every(f=>allowed.has(f))&&!files.some(f=>f.startsWith('scripts/bootstrap_cvie')||f.startsWith('scripts/verify_cvie'));
}
export function remediationWorkflowRelease(files){
 const allowed=new Set(['index.js','remediation.js','remediation-workflow.js','confirmation-host.js','assignment-acknowledgement.js','assignment-template.js','assignment-fyi.js'].map(f=>'account-backend/src/'+f).concat(['account-backend/tests/assignment-acknowledgement.test.mjs','account-backend/tests/remediation-workflow.test.mjs','account-backend/wrangler.toml','account-backend/migrations/0026_remediation_workflow.sql']));
 return files.includes('account-backend/src/remediation-workflow.js')&&files.includes('account-backend/migrations/0026_remediation_workflow.sql')&&files.filter(f=>f.startsWith('account-backend/')).every(f=>allowed.has(f))&&!files.some(f=>f.startsWith('scripts/bootstrap_cvie')||f.startsWith('scripts/verify_cvie'));
}
export function assignmentProgressRelease(files){
 const allowed=new Set(['assignment-progress.js','assignment-progress-common.js','assignment-progress-mail.js','assignment-progress-page.js','assignment-acknowledgement.js','assignment-template.js','index.js','remediation.js'].map(f=>'account-backend/src/'+f).concat(['account-backend/tests/assignment-progress.test.mjs','account-backend/wrangler.toml','account-backend/migrations/0027_assignment_progress.sql']));
 return files.includes('account-backend/src/assignment-progress.js')&&files.includes('account-backend/migrations/0027_assignment_progress.sql')&&files.filter(f=>f.startsWith('account-backend/')).every(f=>allowed.has(f))&&!files.some(f=>f.startsWith('scripts/bootstrap_cvie')||f.startsWith('scripts/verify_cvie'));
}
export function assignmentProgressCodeOnly(files){
 const allowed=new Set(['assignment-progress-mail.js','assignment-progress.js','assignment-progress-page.js','assignment-template.js'].map(f=>'account-backend/src/'+f).concat(['account-backend/tests/assignment-progress.test.mjs']));
 return files.includes('account-backend/src/assignment-progress-mail.js')&&files.filter(f=>f.startsWith('account-backend/')).every(f=>allowed.has(f))&&!files.some(f=>f.startsWith('scripts/bootstrap_cvie')||f.startsWith('scripts/verify_cvie'));
}
export function unifiedFindingsRelease(files){
 const allowed=new Set(['index.js','remediation.js','remediation-identity.js','finding-remediation.js','finding-status.js','assignment-acknowledgement.js','assignment-fyi.js','assignment-progress.js','assignment-progress-mail.js','assignment-progress-page.js'].map(f=>'account-backend/src/'+f).concat(['account-backend/migrations/0028_unified_findings.sql','account-backend/tests/unified-findings.test.mjs','account-backend/tests/helpers/unified-db.mjs']));
 return files.includes('account-backend/migrations/0028_unified_findings.sql')&&files.includes('account-backend/src/finding-remediation.js')&&files.filter(f=>f.startsWith('account-backend/')).every(f=>allowed.has(f))&&!files.some(f=>f.startsWith('scripts/bootstrap_cvie')||f.startsWith('scripts/verify_cvie'));
}
export function findingLinksRelease(files){
 const allowed=new Set(['index.js','remediation.js','remediation-identity.js','finding-remediation.js','finding-assignment-links.js','assignment-acknowledgement.js'].map(f=>'account-backend/src/'+f).concat(['account-backend/migrations/0029_finding_assignment_links.sql','account-backend/tests/finding-assignment-links.test.mjs']));
 return files.includes('account-backend/migrations/0029_finding_assignment_links.sql')&&files.includes('account-backend/src/finding-assignment-links.js')&&files.filter(f=>f.startsWith('account-backend/')).every(f=>allowed.has(f))&&!files.some(f=>f.startsWith('scripts/bootstrap_cvie')||f.startsWith('scripts/verify_cvie'));
}
export function statusMailRelease(files){
 const allowed=new Set(['index.js','assignment-progress.js','finding-remediation.js','status-update-mail.js'].map(f=>'account-backend/src/'+f).concat(['account-backend/migrations/0030_status_update_notifications.sql','account-backend/tests/status-update-mail.test.mjs']));
 return files.includes('account-backend/migrations/0030_status_update_notifications.sql')&&files.includes('account-backend/src/status-update-mail.js')&&files.filter(f=>f.startsWith('account-backend/')).every(f=>allowed.has(f))&&!files.some(f=>f.startsWith('scripts/bootstrap_cvie')||f.startsWith('scripts/verify_cvie'));
}
export function statusMailRepair(files){
 const allowed=new Set(['finding-assignment-links.js','status-update-mail.js'].map(f=>'account-backend/src/'+f).concat(['account-backend/tests/finding-assignment-links.test.mjs','account-backend/tests/status-mail-repair.test.mjs']));
 return files.includes('account-backend/src/finding-assignment-links.js')&&files.includes('account-backend/src/status-update-mail.js')&&files.filter(f=>f.startsWith('account-backend/')).every(f=>allowed.has(f))&&!files.some(f=>f.startsWith('scripts/bootstrap_cvie')||f.startsWith('scripts/verify_cvie'));
}
export function remediationIntegrityRelease(files){
 const allowed=new Set(['assignment-acknowledgement.js','finding-assignment-links.js','finding-remediation.js','index.js','inventory.js','remediation.js','remediation-integrity.js','workspace-summary.js','recovery-control.js','release-readiness.js','release-build.js','release-integrity-checks.js','recovery-schema.js'].map(f=>'account-backend/src/'+f).concat(['account-backend/migrations/0031_remediation_integrity.sql','account-backend/tests/remediation-integrity.test.mjs','account-backend/tests/finding-status.test.mjs','account-backend/tests/workspace-summary.test.mjs','account-backend/tests/recovery-control.test.mjs','account-backend/tests/remediation.test.mjs','account-backend/migrations/0032_recovery_control.sql','account-backend/wrangler.toml']));
 return files.includes('account-backend/migrations/0031_remediation_integrity.sql')&&files.includes('account-backend/src/remediation-integrity.js')&&files.filter(f=>f.startsWith('account-backend/')).every(f=>allowed.has(f))&&!files.some(f=>f.startsWith('scripts/bootstrap_cvie')||f.startsWith('scripts/verify_cvie'));
}
export function manualRelease(mode='code-only'){
 if(!['code-only','recovery-code-only','phase1-integrity','cvie-maintenance'].includes(mode))throw Error('Unknown manual release mode');
 return {integrity:mode==='phase1-integrity',maintenance:mode==='cvie-maintenance',codeOnly:['code-only','recovery-code-only'].includes(mode),recovery:mode==='recovery-code-only'};
}
if(process.argv[1]&&new URL(import.meta.url).pathname===process.argv[1]){
 let codeOnly=false,catalogue=false,monitorOnly=false,workspaceOnly=false,remediationOnly=false,ackRelease=false,fyi=false,workflow=false,progress=false,progressCode=false,unified=false,findingLinks=false,statusMail=false,mailRepair=false,integrity=false;
 let manual={integrity:false,maintenance:false,codeOnly:false};
 if(process.env.GITHUB_EVENT_NAME==='workflow_dispatch'){manual=manualRelease(process.env.WORKER_RELEASE_MODE||'code-only');integrity=manual.integrity;}
 if(process.env.GITHUB_EVENT_NAME==='push'){
  const {before,after}=JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH,'utf8'));
  if(/^[a-f0-9]{40}$/.test(before||'')&&/^[a-f0-9]{40}$/.test(after||'')&&!/^0+$/.test(before)){
   const files=execFileSync('git',['diff','--name-only',before,after],{encoding:'utf8'}).trim().split('\n');
   integrity=remediationIntegrityRelease(files);mailRepair=statusMailRepair(files);statusMail=statusMailRelease(files);findingLinks=findingLinksRelease(files);unified=unifiedFindingsRelease(files);codeOnly=inventoryOnly(files);catalogue=catalogueOnly(files);monitorOnly=monitorCodeOnly(files);workspaceOnly=workspaceCodeOnly(files);remediationOnly=remediationCodeOnly(files);ackRelease=acknowledgementRelease(files);fyi=fyiRelease(files);workflow=remediationWorkflowRelease(files);progress=assignmentProgressRelease(files);progressCode=assignmentProgressCodeOnly(files);
   const recognized=codeOnly||catalogue||monitorOnly||workspaceOnly||remediationOnly||ackRelease||fyi||workflow||progress||progressCode||unified||findingLinks||statusMail||mailRepair||integrity;
   if(!recognized&&files.some(f=>f.startsWith('account-backend/')&&f.endsWith('.sql')))throw Error('Unclassified schema change: choose a reviewed explicit release; no maintenance or deployment was run');
   manual.codeOnly=!recognized;
  }
 }
 fs.appendFileSync(process.env.GITHUB_OUTPUT,'recovery_code_only='+!!manual.recovery+'\n');
 fs.appendFileSync(process.env.GITHUB_OUTPUT,'safe_code_only='+manual.codeOnly+'\n');
 fs.appendFileSync(process.env.GITHUB_OUTPUT,'remediation_integrity='+integrity+'\n');
 fs.appendFileSync(process.env.GITHUB_OUTPUT,'status_mail_repair='+mailRepair+'\n');
 fs.appendFileSync(process.env.GITHUB_OUTPUT,'status_mail='+statusMail+'\n');
 fs.appendFileSync(process.env.GITHUB_OUTPUT,'finding_links='+findingLinks+'\n');
 fs.appendFileSync(process.env.GITHUB_OUTPUT,'unified_findings='+unified+'\n');
 fs.appendFileSync(process.env.GITHUB_OUTPUT,'assignment_progress_code_only='+progressCode+'\n');
 fs.appendFileSync(process.env.GITHUB_OUTPUT,'assignment_progress='+progress+'\n');
 fs.appendFileSync(process.env.GITHUB_OUTPUT,'remediation_workflow='+workflow+'\n');
 fs.appendFileSync(process.env.GITHUB_OUTPUT,'fyi_release='+fyi+'\n');
 fs.appendFileSync(process.env.GITHUB_OUTPUT,'inventory_only='+codeOnly+'\n');
 fs.appendFileSync(process.env.GITHUB_OUTPUT,'catalogue_only='+catalogue+'\nmonitor_code_only='+monitorOnly+'\nworkspace_only='+workspaceOnly+'\nremediation_only='+remediationOnly+'\nacknowledgement_release='+ackRelease+'\nmaintenance='+manual.maintenance+'\n');
 console.log(integrity?'Phase 1 integrity: read-only preflight, recovery point, migration 0031 only; no automatic linking or historical email replay.':mailRepair?'Status mail linking repair: code deployment and SELECT-only checks; no migrations or automatic linking.':statusMail?'Status notification release: recovery point, migration 0030 and SELECT-only probes. No historical notification replay.':findingLinks?'Finding assignment link release: recovery point, additive migration 0029 and read-only probes; no automatic record linking.':unified?'Unified findings release: recovery point, additive migration 0028 and scoped verification only.':progressCode?'Assignment progress code-only release: SELECT-only schema checks and Worker deployment; no migrations or unrelated maintenance.':progress?'Assignment progress release: only migration 0027, verified reviewer updates and bounded inactivity reminders.':workflow?'Remediation workflow release: migration 0026 and compatible writer, no DNS changes or email sends.':fyi?'Assignment FYI release: apply only additive migration 0025, verify private boundaries; preserve existing records and schedules.':ackRelease?'Approved assignment acknowledgement release: apply only additive migration 0024; no CVIE maintenance, customer updates or email sends.':remediationOnly?'Remediation code-only release: no migrations, rescans, secrets or activation changes.':workspaceOnly?'Workspace read-only release: Worker code and SELECT-only probes; no migrations, rescans, secrets or activation changes.':monitorOnly?'Product monitoring code-only release: no migrations, infrastructure changes, secrets or delivery activation.':catalogue?'Catalogue release: SELECT-only checks, code deployment; no migration, cache reset or bulk rescan.':codeOnly?'Inventory-only release: read-only history preflight, Worker code deployment; no CVIE maintenance.':manual.maintenance?'Explicit CVIE maintenance release selected.':'Safe code-only release: no migrations or unrelated maintenance.');
}

