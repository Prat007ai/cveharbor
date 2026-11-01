// Actual CVIE + real NVD, using a disposable local SQLite database. No deployment.
import fs from 'node:fs';
import {DB} from '../account-backend/tests/helpers/d1.mjs';
import {subscribeProducts,runCvieStep,monthsAgo} from '../account-backend/src/cvie.js';
import {refreshEvidence,ingestDisclosures} from '../account-backend/src/cvie-evidence.js';
import {combinedPage,sourceHealth} from '../account-backend/src/cvie-records.js';
const env={DB:new DB(),NVD_API_KEY:process.env.NVD_API_KEY};
const report={checked_at:new Date().toISOString(),provider:'NVD',engine:'CVIE',operation:'isolated database backfill; no production writes',ok:false};
try{
 await subscribeProducts(env,'a',[{name:'Apache Tomcat'}]);
 for(let page=0;page<30;page++){
  const result=await runCvieStep(env);
  if(result.retrying)throw Error('Live source could not complete; automatic retry is scheduled');
  if(result.complete){report.ok=true;report.pages_checked=page+1;break;}
  await new Promise(resolve=>setTimeout(resolve,env.NVD_API_KEY?1100:6700));
 }
 const product=await env.DB.prepare('SELECT * FROM cvie_products').first();
 report.status=product.status;report.cpe=product.cpe;
 report.advisories=(await env.DB.prepare('SELECT record_json FROM cvie_advisories ORDER BY published DESC').all()).results.map(row=>JSON.parse(row.record_json));
 report.history_count=report.advisories.length;
 report.recent_count=report.advisories.filter(a=>Date.parse(a.published)>=monthsAgo(Date.now(),3)).length;
 if(product.error)report.error=product.error;
 const feeds=[await refreshEvidence(env),await refreshEvidence(env)];
 if(feeds.some(feed=>!feed.ok))throw Error('One authoritative evidence feed failed; inspect the source status report');
 // Verify one overlapping record and one older known-exploited Tomcat record.
 const ids=[report.advisories[0]?.id,'CVE-2025-24813'].filter(Boolean);
 for(const id of ids)await env.DB.prepare(`INSERT INTO cvie_disclosure_queue(cve_id,revision,priority) VALUES(?,'',-1)
  ON CONFLICT(cve_id) DO UPDATE SET priority=-1,next_attempt_at=0`).bind(id).run();
 const ingested=await ingestDisclosures(env,fetch,Date.now(),2);if(ingested.failed||ingested.processed!==ids.length)throw Error('Original CNA record verification failed');
 const page=await combinedPage(env,'a',new Date(monthsAgo(Date.now(),12)).toISOString());
 report.advisories=page.advisories;report.evidence=await sourceHealth(env);
 report.old_exploitation_retained=page.advisories.some(r=>r.retained_exploited&&r.provenance.some(p=>p.source==='cisa_kev'));
 report.cna_and_nvd_combined=page.advisories.some(r=>r.provenance.some(p=>p.source==='nvd')&&r.provenance.some(p=>p.source==='cve_program'));
 if(!report.old_exploitation_retained||!report.cna_and_nvd_combined)throw Error('Expected cross-source evidence was not reconciled');
 report.operation='isolated NVD + original CNA + CISA KEV integration; no production writes';
}catch(e){report.ok=false;report.error=e.message;report.evidence=await sourceHealth(env).catch(()=>({ready:false}));}
fs.writeFileSync('data/cvie-provider-check.json',JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({...report,advisories:undefined}));
