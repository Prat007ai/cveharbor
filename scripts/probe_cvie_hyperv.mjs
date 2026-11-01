// Actual CVIE scan in disposable SQLite, with public NVD/CNA/KEV evidence only.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {DB} from '../account-backend/tests/helpers/d1.mjs';
import {subscribeProducts,runCvieStep,cvieRoute,monthsAgo} from '../account-backend/src/cvie.js';
import {hyperVHosts,hyperVStatement} from '../account-backend/src/hyperv.js';
import {ingestDisclosures,refreshEvidence} from '../account-backend/src/cvie-evidence.js';
import {combinedPage} from '../account-backend/src/cvie-records.js';
const env={DB:new DB(),NVD_API_KEY:process.env.NVD_API_KEY};
const report={checked_at:new Date().toISOString(),ok:false,operation:'Microsoft Windows Hyper-V host selection and 12-month scan in a disposable account/database; no production writes'};
try{
 await subscribeProducts(env,'a',[{name:'HyperV'}]);await runCvieStep(env);
 const product=await env.DB.prepare('SELECT * FROM cvie_products').first();
 assert.equal(product.status,'needs_identity');
 const host=hyperVHosts().find(h=>h.label.includes('Server 2022'));
 assert.ok(JSON.parse(product.candidates_json).some(h=>h.cpe===host.cpe));
 await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie/products/'+product.id+'/identity',{method:'PUT'}),env,{id:'a'},null,{cpe:host.cpe});
 // The directory probe immediately before this script also uses the shared provider.
 await new Promise(resolve=>setTimeout(resolve,6700));
 for(let i=0;i<30;i++){
  const result=await runCvieStep(env);
  if(result.retrying)throw Error('NVD did not complete the component scan; saved retry state needs review');
  if(result.complete){report.pages_checked=i+1;break;}
  await new Promise(resolve=>setTimeout(resolve,env.NVD_API_KEY?1100:6700));
 }
 const completed=await env.DB.prepare('SELECT * FROM cvie_products').first();
 assert.equal(completed.status,'ready');
 const rows=(await env.DB.prepare('SELECT record_json FROM cvie_advisories ORDER BY published DESC').all()).results.map(r=>JSON.parse(r.record_json));
 assert.ok(rows.length>0,'real Hyper-V advisories must be found');
 assert.ok(rows.every(r=>hyperVStatement(r)&&r.cvie_identities[0].cpe===host.cpe));
 for(const r of rows.slice(0,2))await env.DB.prepare('INSERT INTO cvie_disclosure_queue(cve_id,revision,priority) VALUES(?,?,0)').bind(r.id,'').run();
 const ingested=await ingestDisclosures(env,fetch,Date.now(),2);assert.equal(ingested.failed,0);assert.equal(ingested.processed,2);
 // Query the real KEV catalogue, preserving all original timestamps.
 const kev=await refreshEvidence(env);assert.equal(kev.ok,true);
 const page=await combinedPage(env,'a',new Date(monthsAgo(Date.now(),12)).toISOString());
 assert.ok(page.advisories.every(r=>hyperVStatement(r)));
 const reconciled=page.advisories.filter(r=>r.provenance.some(p=>p.source==='nvd')&&r.provenance.some(p=>p.source==='cve_program'));
 assert.ok(reconciled.length>=2,'Microsoft original disclosures must reconcile with the selected Windows host');
 report.ok=true;report.host=host;report.status=completed.status;
 report.history_count=rows.length;report.recent_count=rows.filter(r=>Date.parse(r.published)>=monthsAgo(Date.now(),3)).length;
 report.cna_and_nvd_combined=reconciled.map(r=>r.id);report.cisa_kev_checked=true;
 report.sample=page.advisories.slice(0,3);
}catch(error){report.error=error.message;}
fs.writeFileSync('data/cvie-hyperv-check.json',JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({...report,sample:undefined}));
