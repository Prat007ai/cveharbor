// Real sources + real CVIE in disposable SQLite; no production writes.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {DB} from '../account-backend/tests/helpers/d1.mjs';
import {subscribeProducts,runCvieStep,monthsAgo} from '../account-backend/src/cvie.js';
import {dotnetProfile} from '../account-backend/src/dotnet.js';
import {combinedPage} from '../account-backend/src/cvie-records.js';
import {ingestDisclosures,refreshEvidence} from '../account-backend/src/cvie-evidence.js';
const env={DB:new DB(),NVD_API_KEY:process.env.NVD_API_KEY},q=(sql,...args)=>env.DB.prepare(sql).bind(...args);
const report={checked_at:new Date().toISOString(),ok:false,operation:'Real Microsoft modern .NET history and awaiting-analysis disclosure verification in a disposable account/database; no production writes',requests:[]};
try{
 await subscribeProducts(env,'a',[{name:'.NET Core'}]);
 await new Promise(resolve=>setTimeout(resolve,6700));
 let done=false;
 for(let i=0;i<100;i++){
  const result=await runCvieStep(env,async(url,options)=>{
   const u=new URL(url),response=await fetch(url,options),copy=response.clone();
   const data=await copy.json();report.requests.push({family:u.searchParams.get('virtualMatchString'),keyword:u.searchParams.get('keywordSearch'),startIndex:data.startIndex,totalResults:data.totalResults,status:response.status});return response;
  });
  if(result.retrying)throw Error('A source check failed; recent/full history was not reported complete');
  if(result.complete){done=true;break;}
  await new Promise(resolve=>setTimeout(resolve,env.NVD_API_KEY?1100:6700));
 }
 assert.ok(done,'all source windows must finish');
 const product=await q('SELECT * FROM cvie_products').first();assert.equal(product.status,'ready');
 report.profile=dotnetProfile(product);report.nvd_records=(await q('SELECT COUNT(*) AS n FROM cvie_advisories').first()).n;
 // These real Microsoft records currently await NVD CPE analysis. They must be
 // discovered automatically; inserting hardcoded IDs would hide that failure.
 const ids=['CVE-2026-114148','CVE-2026-70161','CVE-2026-109468'];
 for(const id of ids){
  assert.ok(await q('SELECT cve_id FROM cvie_disclosure_queue WHERE cve_id=?',id).first(),'discovery must find '+id);
  await q('UPDATE cvie_disclosure_queue SET priority=-1 WHERE cve_id=?',id).run();
 }
 const result=await ingestDisclosures(env,fetch,Date.now(),3);assert.equal(result.failed,0);assert.equal(result.processed,3);
 const kev=await refreshEvidence(env);assert.equal(kev.ok,true);
 let after='',records=[];
 do{const page=await combinedPage(env,'a',new Date(monthsAgo(Date.now(),12)).toISOString(),after);records.push(...page.advisories);after=page.next||'';}while(after);
 for(const id of ids.slice(0,2))assert.ok(records.some(r=>r.id===id&&r.provenance.some(p=>p.source==='cve_program')),'original Microsoft evidence must display '+id);
 assert.ok(!records.some(r=>r.id===ids[2]),'a Visual Studio / CBOR package finding must not become a Core runtime finding solely from its title');
 assert.ok(!records.some(r=>r.affected_cpes.some(m=>m.criteria?.includes(':.net_framework:'))));
 report.ok=true;report.status=product.status;report.history_count=records.length;
 report.recent_count=records.filter(r=>Date.parse(r.published)>=monthsAgo(Date.now(),3)).length;
 report.original_disclosures_without_nvd=ids.slice(0,2);report.excluded_non_runtime_finding=ids[2];report.cisa_kev_checked=true;
 report.advisories=records;
 report.pending_original_disclosures=(await q('SELECT COUNT(*) AS n FROM cvie_disclosure_queue').first()).n;
}catch(error){report.error=error.message;}
fs.writeFileSync('data/cvie-dotnet-check.json',JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({...report,advisories:undefined,requests:report.requests.length}));
