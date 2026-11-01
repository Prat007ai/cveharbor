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
 const allowed=new Set(['account-backend/src/index.js','account-backend/src/lifecycle.js','account-backend/src/monitoring.js','account-backend/src/monitor-engine.js','account-backend/src/monitor-mail.js','account-backend/src/monitor-approved-test.js','account-backend/tests/monitor-approved-test.test.mjs','account-backend/src/monitor-sources.js','account-backend/tests/product-monitoring.test.mjs','account-backend/migrations/0023_lifecycle_monitoring.sql']);
 const backend=files.filter(f=>f.startsWith('account-backend/'));
 return backend.some(f=>f.includes('/monitor'))&&backend.every(f=>allowed.has(f));
}
if(process.argv[1]&&new URL(import.meta.url).pathname===process.argv[1]){
 let codeOnly=false,catalogue=false,monitorOnly=false;
 if(process.env.GITHUB_EVENT_NAME==='push'){
  const {before,after}=JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH,'utf8'));
  if(/^[a-f0-9]{40}$/.test(before||'')&&/^[a-f0-9]{40}$/.test(after||'')&&!/^0+$/.test(before)){
   const files=execFileSync('git',['diff','--name-only',before,after],{encoding:'utf8'}).trim().split('\n');
   codeOnly=inventoryOnly(files);catalogue=catalogueOnly(files);monitorOnly=monitorCodeOnly(files);
  }
 }
 fs.appendFileSync(process.env.GITHUB_OUTPUT,'inventory_only='+codeOnly+'\n');
 fs.appendFileSync(process.env.GITHUB_OUTPUT,'catalogue_only='+catalogue+'\nmonitor_code_only='+monitorOnly+'\nmaintenance='+!(codeOnly||catalogue||monitorOnly)+'\n');
 console.log(monitorOnly?'Product monitoring code-only release: no migrations, infrastructure changes, secrets or delivery activation.':catalogue?'Catalogue release: SELECT-only checks, code deployment; no migration, cache reset or bulk rescan.':codeOnly?'Inventory-only release: read-only history preflight, Worker code deployment; no CVIE maintenance.':'Existing CVIE release path retained.');
}

