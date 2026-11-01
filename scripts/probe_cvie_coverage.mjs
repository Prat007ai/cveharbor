// Same scanner, multiple real products, disposable account/SQLite only.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {DB} from '../account-backend/tests/helpers/d1.mjs';
import {subscribeProducts,runCvieStep,monthsAgo} from '../account-backend/src/cvie.js';
import {combinedPage} from '../account-backend/src/cvie-records.js';
import {ingestDisclosures} from '../account-backend/src/cvie-evidence.js';
import {coveragePlan,coverageSummary,catalogueKind,catalogueNames} from '../account-backend/src/product-coverage.js';
import {knownIdentity} from '../account-backend/src/product-identity.js';
const env={DB:new DB(),NVD_API_KEY:process.env.NVD_API_KEY},q=(sql,...args)=>env.DB.prepare(sql).bind(...args);
const report={checked_at:new Date().toISOString(),ok:false,scope:'Same generic CVIE scan and original-disclosure verification for Apache Tomcat, PHP and WordPress; disposable database; no production writes',products:[]};
// Always retain the structural review even if a provider check later fails.
const categories=JSON.parse(fs.readFileSync('data/demo-advisories.json','utf8')).categories;
const audit={checked_at:report.checked_at,scope:'Coverage semantics for every public catalogue category; this does not assert that every member product has been exhaustively mapped',categories:categories.map(c=>{
 const plan=coveragePlan({name:c.name,cpe:knownIdentity(c.name)?.cpe||''});return {name:c.name,description:c.description,kind:catalogueKind(c.name),requires_exact_members:catalogueKind(c.name)==='collection',verified_families:plan.families,notes:plan.notes};
})};
fs.writeFileSync('data/cvie-catalogue-coverage.json',JSON.stringify(audit,null,2)+'\n');
const lines=['# CVIE catalogue coverage review','',audit.scope+'.','', '| Category | Coverage type | Required next step |','| --- | --- | --- |',...audit.categories.map(c=>'| '+c.name+' | '+c.kind.replaceAll('_',' ')+' | '+(c.requires_exact_members?'Confirm exact member products; one CPE does not cover the whole category':c.kind==='host_component'?'Choose the Windows host':c.kind==='reviewed_group'?'Use the reviewed family set; verify deployment conditions':'Confirm the exact source product identity')+' |')];
fs.writeFileSync('docs/cvie-catalogue-coverage.md',lines.join('\n')+'\n');
try{
 await subscribeProducts(env,'a',[{name:'Apache Tomcat'},{name:'PHP'},{name:'WordPress'}]);
 for(let request=0;request<80;request++){
  const result=await runCvieStep(env);if(result.retrying)throw Error('A real source check failed; incomplete history was not reported complete');
  if(!(await q('SELECT COUNT(*) AS pending FROM cvie_products WHERE recent_complete_at IS NULL').first()).pending){report.requests=request+1;break;}
  await new Promise(resolve=>setTimeout(resolve,env.NVD_API_KEY?1100:6700));
 }
 const products=(await q('SELECT * FROM cvie_products ORDER BY name').all()).results;
 for(const p of products){
  assert.ok(p.recent_complete_at,p.name+' recent work must include discovery, not only one CPE request');
  const record=await q('SELECT cve_id FROM cvie_advisories WHERE product_id=? AND published>=? ORDER BY published DESC LIMIT 1',p.id,new Date(monthsAgo(Date.now(),3)).toISOString()).first();
  assert.ok(record,p.name+' must have real recent results');
  await q("INSERT INTO cvie_disclosure_queue(cve_id,revision,priority) VALUES(?,'',-1) ON CONFLICT(cve_id) DO UPDATE SET priority=-1,next_attempt_at=0",record.cve_id).run();
  const ingested=await ingestDisclosures(env,fetch,Date.now(),1);assert.equal(ingested.failed,0);assert.equal(ingested.processed,1);
  const page=await combinedPage(env,'a',new Date(monthsAgo(Date.now(),3)).toISOString(),'',p.id);
  assert.ok(page.advisories.some(r=>r.id===record.cve_id&&r.provenance.some(p=>p.source==='cve_program')),p.name+' must reconcile the original affected-product record');
  report.products.push({name:p.name,coverage:coverageSummary(p),recent_count:page.advisories.length,verified_original:record.cve_id});
 }
 assert.deepEqual(categories.map(c=>c.name).sort(),[...catalogueNames].sort());
 report.catalogue_categories=audit.categories.length;report.collections_requiring_members=audit.categories.filter(c=>c.requires_exact_members).length;report.ok=true;
}catch(error){report.error=error.message;}
fs.writeFileSync('data/cvie-coverage-check.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
