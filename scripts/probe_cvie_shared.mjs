// A real NVD page with two isolated synthetic accounts; no production identities.
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {DB} from '../account-backend/tests/helpers/d1.mjs';
import {subscribeProducts,runCvieStep,cvieRoute} from '../account-backend/src/cvie.js';
import {combinedPage} from '../account-backend/src/cvie-records.js';
const env={DB:new DB(),CVIE_SHARED_SCANS_ENABLED:'true',NVD_API_KEY:process.env.NVD_API_KEY||''};
const cpe='cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*';
const report={checked_at:new Date().toISOString(),synthetic_accounts:true,checks:[]};let requests=0;
try{
 await subscribeProducts(env,'a',[{name:'Fixture alias A',cpe}]);
 for(let attempt=0;attempt<3;attempt++){
  const result=await runCvieStep(env,async(url,options)=>{assert.equal(new URL(url).hostname,'services.nvd.nist.gov');requests++;return fetch(url,options);},Date.now());
  if(!result.retrying)break;
  if(attempt<2){await new Promise(r=>setTimeout(r,6500));await env.DB.prepare('UPDATE cvie_provider_budget SET next_request_at=0').run();await env.DB.prepare('UPDATE cvie_shared_scopes SET next_attempt_at=0').run();}
 }
 const before=await env.DB.prepare('SELECT * FROM cvie_shared_scopes').first();
 assert.ok(before.last_success_at,'NVD must return a successful source page');
 const a=await combinedPage(env,'a',new Date(Date.now()-93*86400000).toISOString());assert.ok(a.advisories.length,'Expected recent verified Tomcat advisories');
 await subscribeProducts(env,'b',[{name:'Fixture alias B',cpe}]);
 assert.deepEqual(await env.DB.prepare('SELECT * FROM cvie_shared_scopes').first(),before,'a new subscriber preserves the shared cursor and schedule');
 const b=await combinedPage(env,'b',new Date(Date.now()-93*86400000).toISOString());assert.deepEqual(b.advisories.map(r=>r.id),a.advisories.map(r=>r.id));
 assert.ok(b.advisories.every(r=>r.categories[0]==='Fixture alias B'));
 const state=await (await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie'),env,{id:'b'})).json();assert.equal(state.products[0].progress.windows_complete,1);
 report.ok=true;report.provider_requests=requests;report.shared_jobs=(await env.DB.prepare('SELECT COUNT(*) AS n FROM cvie_shared_scopes').first()).n;
 report.private_advisory_copies=(await env.DB.prepare('SELECT COUNT(*) AS n FROM cvie_advisories').first()).n;
 report.public_cve_ids=b.advisories.map(r=>r.id);report.checks=['real NVD affected-family page','one shared job','same evidence for two synthetic accounts','private aliases applied only on read','existing history position reused without provider requests for the second account'];
}catch(error){report.ok=false;report.error=error.message;}
await writeFile(new URL('../data/cvie-shared-check.json',import.meta.url),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify(report));if(!report.ok)process.exitCode=1;
