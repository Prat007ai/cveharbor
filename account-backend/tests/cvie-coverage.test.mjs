import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DB} from './helpers/d1.mjs';
import {repairAccountCoverage,subscribeProducts,syncAccountProducts,runCvieStep,cvieRoute,normalizeNvd} from '../src/cvie.js';
import {ingestDisclosures} from '../src/cvie-evidence.js';
import {combinedPage} from '../src/cvie-records.js';
import {coveragePlan,coverageSummary,catalogueNames,catalogueKind,sourceWorkTypes,DISCOVERY_PAGES} from '../src/product-coverage.js';
const NOW=Date.parse('2026-11-01T16:00:00Z'),env=()=>({DB:new DB()}),q=(e,sql,...args)=>e.DB.prepare(sql).bind(...args);
const check=(name,fn)=>test(name,async t=>{t.mock.timers.enable({apis:['Date'],now:NOW});await fn(t);});
const p={name:'Apache Tomcat',cpe:'cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*'};
const state=(e,user='a')=>cvieRoute(new Request('https://api.cveharbor.com/v1/cvie'),e,{id:user}).then(r=>r.json());
const empty=()=>Response.json({startIndex:0,totalResults:0,vulnerabilities:[]});
check('navigation syncs and status reads preserve saved cursors, results and provider budget without writes',async()=>{
 const e=env();
 await q(e,'INSERT INTO user_technology_catalogue VALUES(?,?,0)','a',JSON.stringify({products:[{name:'Apache Tomcat'}]})).run();
 await syncAccountProducts(e,'a');await runCvieStep(e,empty,NOW);
 const before=await q(e,"SELECT * FROM cvie_products WHERE user_id='a'").first();
 await q(e,'INSERT INTO cvie_advisories VALUES(?,?,?,?,?)',before.id,'CVE-2026-19999','2026-10-15T00:00:00Z',JSON.stringify({id:'CVE-2026-19999',published:'2026-10-15T00:00:00Z',summary:'Retained source fixture'}),'saved').run();
 const saved=JSON.stringify(await q(e,"SELECT * FROM cvie_products WHERE user_id='a'").first());
 const budget=JSON.stringify(await q(e,'SELECT * FROM cvie_provider_budget').first());
 let mutations=0,scheduled=0;
 const prepare=e.DB.prepare.bind(e.DB);
 e.DB.prepare=sql=>{if(/^(INSERT|UPDATE|DELETE)/i.test(sql.trim()))mutations++;return prepare(sql);};
 const ctx={waitUntil(){scheduled++;}};
 for(let visit=0;visit<3;visit++){
  const sync=await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie/sync',{method:'POST'}),e,{id:'a'},ctx);
  assert.equal(sync.status,200);assert.equal((await sync.json()).status,'unchanged');
  const response=await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie'),e,{id:'a'},ctx);
  assert.equal(response.status,200);assert.equal((await response.json()).products[0].progress.windows_complete,1);
 }
 assert.equal(mutations,0,'unchanged navigation has no D1 mutation statements');
 assert.equal(scheduled,0,'reading pages never schedules provider requests');
 assert.equal(JSON.stringify(await q(e,"SELECT * FROM cvie_products WHERE user_id='a'").first()),saved);
 assert.equal(JSON.stringify(await q(e,'SELECT * FROM cvie_provider_budget').first()),budget);
 assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_advisories').first()).total,1);
});
check('replaying every stored .NET Core member never restarts an unchanged reviewed product scope',async()=>{
 const e=env(),families=coveragePlan({name:'.NET Core'}).families;
 for(const member of families){
  await q(e,'INSERT INTO user_technology_catalogue VALUES(?,?,0) ON CONFLICT(user_id) DO UPDATE SET preferences_json=excluded.preferences_json','a',JSON.stringify({products:[{name:'.NET Core',cpe:member}]})).run();
  await syncAccountProducts(e,'a');
  await runCvieStep(e,empty,NOW);await runCvieStep(e,empty,NOW+7000);
  const before=await q(e,"SELECT * FROM cvie_products WHERE user_id='a'").first();
  for(let visit=0;visit<3;visit++){
   const sync=await syncAccountProducts(e,'a');assert.equal(sync.changed,false);
   await state(e);
   assert.deepEqual(await q(e,"SELECT * FROM cvie_products WHERE user_id='a'").first(),before);
  }
 }
});
function cna(id,name='Apache Tomcat 10.1',vendor='Apache Software Foundation',version='10.1.0'){
 return {dataType:'CVE_RECORD',dataVersion:'5.1',cveMetadata:{cveId:id,state:'PUBLISHED',datePublished:'2026-10-15T00:00:00Z',dateUpdated:'2026-10-20T00:00:00Z'},containers:{cna:{title:'Coverage fixture',descriptions:[{lang:'en',value:'Structured source evidence fixture.'}],affected:[{vendor,product:name,defaultStatus:'unaffected',versions:[{version,lessThan:version+'.9',versionType:'semver',status:'affected'}]}]}}};
}
async function store(e,raw){await q(e,'INSERT INTO cvie_disclosure_queue(cve_id,revision,priority) VALUES(?,?,0) ON CONFLICT(cve_id) DO UPDATE SET next_attempt_at=0',raw.cveMetadata.cveId,'').run();await ingestDisclosures(e,()=>Response.json(raw),NOW);}
check('every catalogue entry has an explicit scope classification; broad categories cannot masquerade as one complete product',()=>{
 const categories=JSON.parse(fs.readFileSync(new URL('../../data/demo-advisories.json',import.meta.url),'utf8')).categories;
 assert.deepEqual([...catalogueNames].sort(),categories.map(c=>c.name).sort());
 for(const name of catalogueNames){
  const plan=coveragePlan({name});assert.ok(['collection','product','reviewed_group','host_component'].includes(catalogueKind(name)));
  if(catalogueKind(name)==='collection'){
   assert.equal(plan.type,'unresolved',name);
   const selected=coverageSummary({name,cpe:p.cpe,cursor_json:'{}'});assert.equal(selected.kind,'selected_member',name);assert.equal(selected.limited,true,name);
  }
 }
});
check('the same source-work contract applies to known, custom, group and component identities',()=>{
 for(const product of [p,{name:'PHP',cpe:'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*'},{name:'Example Product',vendor:'Example',cpe:'cpe:2.3:a:example:example_product:*:*:*:*:*:*:*:*'},{name:'.NET Core',cpe:'cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*'},{name:'HyperV',cpe:'cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*'}]){
  const plan=coveragePlan(product),types=sourceWorkTypes(plan);
  assert.equal(types.filter(t=>t.cpe).length,plan.families.length);assert.ok(types.some(t=>t.disclosures));
  assert.ok(plan.signature);assert.ok(coverageSummary({...product,cursor_json:'{}'}).identities.length);
 }
});
check('a custom product gets candidate discovery and waits for original vendor/product evidence',async()=>{
 const e=env(),product={name:'Example Product',vendor:'Example',cpe:'cpe:2.3:a:example:example_product:*:*:*:*:*:*:*:*'};
 await subscribeProducts(e,'a',[product]);await runCvieStep(e,empty,NOW);
 const raw={id:'CVE-2026-12345',published:'2026-10-15T00:00:00Z',vulnStatus:'Awaiting Analysis',descriptions:[{lang:'en',value:'Name search candidate only.'}]};
 await runCvieStep(e,url=>{assert.ok(new URL(url).searchParams.has('keywordSearch'));return Response.json({startIndex:0,totalResults:1,vulnerabilities:[{cve:raw}]});},NOW+7000);
 assert.equal((await combinedPage(e,'a','2026-08-01T00:00:00Z')).advisories.length,0);
 await store(e,cna(raw.id,'Example Product 2.0','Example','2.0.0'));
 assert.equal((await combinedPage(e,'a','2026-08-01T00:00:00Z')).advisories.length,1);
 assert.equal((await combinedPage(e,'b','2026-08-01T00:00:00Z')).advisories.length,0);
});
check('release suffix matching requires the same vendor, exact label boundary and supporting version evidence',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:p.name}]);
 for(const [id,name,vendor,version] of [['CVE-2026-12341','Apache Tomcat 10.1','Apache Software Foundation','10.1.0'],['CVE-2026-12342','Apache Tomcat Connector 10.1','Apache Software Foundation','10.1.0'],['CVE-2026-12343','Apache Tomcat 10.1','Other Vendor','10.1.0'],['CVE-2026-12344','Apache Tomcat 2022','Apache Software Foundation','10.1.0']])await store(e,cna(id,name,vendor,version));
 assert.deepEqual((await combinedPage(e,'a','2026-08-01T00:00:00Z')).advisories.map(r=>r.id),['CVE-2026-12341']);
});
check('old completed single-family jobs are requeued once without deleting their saved evidence',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:p.name}]);await subscribeProducts(e,'b',[{name:p.name}]);
 const saved=await q(e,"SELECT id FROM cvie_products WHERE user_id='a'").first();
 await q(e,'INSERT INTO cvie_advisories VALUES(?,?,?,?,?)',saved.id,'CVE-2026-19999','2026-10-15T00:00:00Z',JSON.stringify({id:'CVE-2026-19999',published:'2026-10-15T00:00:00Z',summary:'Saved verified source fixture',cvie_identities:[{name:p.name,cpe:p.cpe}]}),'previous').run();
 await q(e,"UPDATE cvie_products SET status='ready',last_success_at=?,recent_complete_at=?,history_complete_at=?",NOW,NOW,NOW).run();
 await repairAccountCoverage(e,'a');const s=await state(e);assert.equal(s.products[0].status,'queued');assert.equal(s.products[0].recent_complete_at,null);assert.ok(s.products[0].coverage.discovery_terms.length);
 assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_advisories').first()).total,1);
 assert.equal((await q(e,"SELECT status FROM cvie_products WHERE user_id='b'").first()).status,'ready');
 await q(e,"UPDATE cvie_products SET status='ready' WHERE user_id='a'").run();await state(e);assert.equal((await q(e,"SELECT status FROM cvie_products WHERE user_id='a'").first()).status,'ready');
});
check('directory search continues across pages and filters explicit vendors before accepting an exact product',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Example Product',vendor:'Example'}]);
 const cpe='cpe:2.3:a:example:example_product:*:*:*:*:*:*:*:*';
 await runCvieStep(e,url=>{assert.equal(new URL(url).searchParams.get('startIndex'),'0');return Response.json({startIndex:0,totalResults:2,products:[{cpe:{cpeName:cpe.replace(':example:',':other:')}}]});},NOW);
 assert.equal((await q(e,'SELECT cpe FROM cvie_products').first()).cpe,'');
 await runCvieStep(e,url=>{assert.equal(new URL(url).searchParams.get('startIndex'),'1');return Response.json({startIndex:1,totalResults:2,products:[{cpe:{cpeName:cpe}}]});},NOW+7000);
 assert.equal((await q(e,'SELECT cpe FROM cvie_products').first()).cpe,cpe);
});
check('one unrelated directory result and one broad-category member both require human identity confirmation',async()=>{
 for(const name of ['My Product','Linux']){
  const e=env();await subscribeProducts(e,'a',[{name}]);
  await runCvieStep(e,()=>Response.json({startIndex:0,totalResults:1,products:[{cpe:{cpeName:p.cpe}}]}),NOW);
  const row=await q(e,'SELECT * FROM cvie_products').first();assert.equal(row.cpe,'');assert.equal(row.status,'needs_identity');
 }
});
check('bounded keyword discovery is labelled partial and never truncates structured affected-family history',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:p.name}]);await runCvieStep(e,empty,NOW);
 for(let i=0;i<DISCOVERY_PAGES;i++)await runCvieStep(e,url=>{
  const index=Number(new URL(url).searchParams.get('startIndex'));
  return Response.json({startIndex:index,totalResults:1000,vulnerabilities:[{cve:{id:'CVE-2026-'+(20000+index),published:'2026-10-15T00:00:00Z',vulnStatus:'Awaiting Analysis'}}]});
 },NOW+(i+1)*7000);
 const product=await q(e,'SELECT * FROM cvie_products').first(),cursor=JSON.parse(product.cursor_json);
 assert.equal(cursor.discovery_limited,true);assert.ok(product.recent_complete_at);assert.equal(cursor.position,2);
 assert.equal(coverageSummary(product).limited,true);
});
check('conflicting vendor metadata is explicitly flagged rather than presented as complete coverage',()=>{
 const summary=coverageSummary({...p,vendor:'Other Vendor',cursor_json:'{}'});assert.equal(summary.kind,'identity_conflict');assert.equal(summary.limited,true);assert.match(summary.notes[0],/conflicts/);
});
check('a stale response cannot overwrite restarted coverage even if both leases have the same timestamp',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:p.name}]);let nextGeneration;
 await runCvieStep(e,async()=>{
  await q(e,"UPDATE cvie_products SET lease_until=0,cursor_json='{}',status='queued'").run();
  await q(e,'UPDATE cvie_provider_budget SET next_request_at=0').run();
  await runCvieStep(e,empty,NOW);
  nextGeneration=JSON.parse((await q(e,'SELECT cursor_json FROM cvie_products').first()).cursor_json).generation;
  return Response.json({startIndex:0,totalResults:1,vulnerabilities:[{cve:{id:'CVE-2026-12345',published:'2026-10-15T00:00:00Z',configurations:[{nodes:[{cpeMatch:[{criteria:p.cpe,vulnerable:true}]}]}]}}]});
 },NOW);
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_advisories').first()).n,0);
 assert.equal(JSON.parse((await q(e,'SELECT cursor_json FROM cvie_products').first()).cursor_json).generation,nextGeneration);
});
