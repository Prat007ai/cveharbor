import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DB} from './helpers/d1.mjs';
import {subscribeProducts,runCvieStep,cvieRoute,normalizeNvd,loadCvieDigest} from '../src/cvie.js';
import {ingestDisclosures,productFamilies} from '../src/cvie-evidence.js';
import {combinedPage,combinedCounts,mergeDigestEvidence} from '../src/cvie-records.js';
import {dotnetProfile,DOTNET_PROFILE,DOTNET_FAMILY} from '../src/dotnet.js';
const NOW=Date.parse('2026-11-01T16:00:00Z'),cutoff='2026-08-01T00:00:00Z',env=()=>({DB:new DB()});
const q=(e,sql,...args)=>e.DB.prepare(sql).bind(...args),first=e=>q(e,'SELECT * FROM cvie_products ORDER BY user_id').first();
const check=(name,fn)=>test(name,async t=>{t.mock.timers.enable({apis:['Date'],now:NOW});await fn(t);});
const product={name:'.NET Core',cpe:'cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*'},profile=dotnetProfile(product);
const state=(e,user='a')=>cvieRoute(new Request('https://api.cveharbor.com/v1/cvie'),e,{id:user}).then(r=>r.json());
function nvd(id='CVE-2026-12345',families=[profile.families[0]]){
 return {id,published:'2026-10-15T00:00:00Z',lastModified:'2026-10-20T00:00:00Z',vulnStatus:'Analyzed',descriptions:[{lang:'en',value:'.NET regression fixture.'}],
  configurations:[{nodes:[{cpeMatch:families.map(criteria=>({criteria,vulnerable:true,versionStartIncluding:'8.0.0',versionEndExcluding:'8.0.22'}))}]}]};
}
function cna(id='CVE-2026-12345',name='.NET 10.0 runtime',vendor='Microsoft'){
 return {dataType:'CVE_RECORD',dataVersion:'5.1',cveMetadata:{cveId:id,state:'PUBLISHED',datePublished:'2026-10-15T00:00:00Z',dateUpdated:'2026-10-20T00:00:00Z'},
  containers:{cna:{title:'.NET regression fixture',descriptions:[{lang:'en',value:'.NET source fixture; deployment conditions must be checked.'}],affected:[{vendor,product:name,defaultStatus:'unaffected',versions:[{version:'10.0.0',lessThan:'10.0.402',versionType:'custom',status:'affected'}]}]}}};
}
async function store(e,raw){
 await q(e,'INSERT INTO cvie_disclosure_queue(cve_id,revision,priority) VALUES(?,?,0) ON CONFLICT(cve_id) DO UPDATE SET next_attempt_at=0',raw.cveMetadata.cveId,'').run();
 return ingestDisclosures(e,async()=>Response.json(raw),NOW);
}
const empty=()=>Response.json({startIndex:0,totalResults:0,vulnerabilities:[]});
check('the .NET Core category includes verified Microsoft modern runtime families, excluding Framework and explicit foreign identities',()=>{
 for(const name of ['.NET Core','Microsoft .NET Core','dotnet core'])assert.equal(dotnetProfile({name})?.key,DOTNET_PROFILE);
 assert.equal(dotnetProfile({...product,vendor:'Other Vendor'}),null);
 assert.equal(dotnetProfile({...product,cpe:product.cpe.replace(':.net:',':.net_framework:')}),null);
 assert.equal(dotnetProfile({name:'.NET Framework'}),null);assert.equal(dotnetProfile({name:'Entity Framework Core'}),null);
 const report=JSON.parse(fs.readFileSync(new URL('../../data/cvie-dotnet-directory-check.json',import.meta.url),'utf8'));
 const verified=new Set(report.directories.flatMap(d=>d.families.map(f=>f.family)));
 for(const cpe of profile.families)assert.ok(verified.has(cpe.split(':').slice(0,5).join(':')),cpe);
 assert.ok(productFamilies(product).includes(DOTNET_FAMILY));
});
check('a completed legacy-only scan is requeued once, preserves saved evidence and stays account-private',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'.NET Core'}]);await subscribeProducts(e,'b',[{name:'.NET Core'}]);
 const p=await first(e),legacy=profile.families.find(x=>x.split(':')[4]==='.net_core');
 await q(e,"UPDATE cvie_products SET cpe=?,status='ready',recent_complete_at=?,history_complete_at=?,last_success_at=?",legacy,NOW,NOW,NOW).run();
 const r=normalizeNvd(nvd(),product);await q(e,'INSERT INTO cvie_advisories VALUES(?,?,?,?,?)',p.id,r.id,r.published,JSON.stringify(r),'old').run();
 const s=await state(e);assert.equal(s.products[0].status,'queued');assert.equal(s.products[0].recent_complete_at,null);assert.match(s.products[0].identity_label,/ASP.NET Core/);
 assert.equal((await q(e,"SELECT status FROM cvie_products WHERE user_id='b'").first()).status,'ready');
 assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_advisories').first()).total,1,'existing verified results remain while coverage expands');
 await q(e,"UPDATE cvie_products SET status='ready' WHERE user_id='a'").run();await state(e);
 assert.equal((await first(e)).status,'ready','polling never repeatedly resets a prepared profile');
});
check('recent history is complete only after every family and disclosure-discovery window finishes',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'.NET Core'}]);await runCvieStep(e,empty,NOW);let calls=0;
 for(let i=1;i<=30;i++){
  await runCvieStep(e,async url=>{
   const u=new URL(url),virtual=u.searchParams.get('virtualMatchString');
   if(virtual)assert.ok(profile.families.includes(virtual));else{assert.ok(['.NET','ASP.NET Core'].includes(u.searchParams.get('keywordSearch')));assert.ok(u.searchParams.has('keywordExactMatch'));}
   calls++;return empty();
  },NOW+i*7000);
  const p=await first(e);
  if(i<6)assert.equal(p.recent_complete_at,null);
  if(i===6){assert.ok(p.recent_complete_at);assert.equal(p.history_complete_at,null);}
 }
 const p=await first(e);assert.equal(calls,30);assert.equal(p.status,'ready');assert.equal(JSON.parse(p.cursor_json).profile,DOTNET_PROFILE);
 assert.ok(p.history_complete_at);
});
check('modern .NET, ASP.NET Core and legacy Core CVEs normalize while Framework and third-party keyword matches are excluded',()=>{
 for(const cpe of profile.families)assert.ok(normalizeNvd(nvd(undefined,[cpe]),product));
 assert.equal(normalizeNvd(nvd(undefined,[product.cpe.replace(':.net:',':.net_framework:')]),product),null);
 assert.equal(normalizeNvd(nvd(undefined,[product.cpe.replace(':microsoft:.net:',':example:dotnet_library:')]),product),null);
 const r=normalizeNvd(nvd(undefined,profile.families.slice(0,2)),product);assert.equal(r.affected_cpes.length,2);assert.equal(r.cvie_identities.length,2);
});
check('CVE overlaps between .NET runtime families are stored once with all relevant affected ranges',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'.NET Core'}]);await runCvieStep(e,empty,NOW);
 const record=nvd(undefined,profile.families.slice(0,2));
 for(let i=1;i<=2;i++)await runCvieStep(e,()=>Response.json({startIndex:0,totalResults:1,vulnerabilities:[{cve:record}]}),NOW+i*7000);
 const rows=await q(e,'SELECT record_json FROM cvie_advisories').all();assert.equal(rows.results.length,1);
 assert.equal(JSON.parse(rows.results[0].record_json).affected_cpes.length,2);
});
check('an awaiting-analysis CVE is discovered, then displayed only after Microsoft affected-product verification',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'.NET Core'}]);await runCvieStep(e,empty,NOW);
 for(let i=1;i<=4;i++)await runCvieStep(e,empty,NOW+i*7000);
 const raw=nvd();delete raw.configurations;raw.vulnStatus='Awaiting Analysis';
 await runCvieStep(e,()=>Response.json({startIndex:0,totalResults:1,vulnerabilities:[{cve:raw}]}),NOW+35000);
 assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_disclosure_queue').first()).total,1);
 assert.equal((await combinedPage(e,'a',cutoff)).advisories.length,0,'a name search alone is never a vulnerability match');
 await ingestDisclosures(e,()=>Response.json(cna()),NOW+36000);
 const page=await combinedPage(e,'a',cutoff);assert.equal(page.advisories.length,1);assert.equal(page.advisories[0].provenance[0].source,'cve_program');
 assert.ok(page.advisories[0].affected.includes('.NET 10.0 runtime'),'the original affected product is retained rather than relabelled as all Core versions');
 assert.ok(page.advisories[0].affected_cpes.every(r=>r.comparison_unsupported),'group-level vendor conditions never become a guessed installed-version exclusion');
});
check('existing Microsoft disclosure labels work across versions/platforms without reindexing or NVD CPE analysis',async()=>{
 for(const label of ['.NET 8.0 installed on Linux','.NET 9.0 installed on Windows','.NET 10.0 runtime','.NET 11.0 installed on Mac OS','ASP.NET Core runtime and targeting-pack Linux tarballs (Microsoft-published)','.NET source-build Linux tarballs (all archive types)','.NET Core 3.1','.NET Core SDK 2.2']){
  const e=env();await store(e,cna(undefined,label));await subscribeProducts(e,'a',[{name:'.NET Core'}]);
  assert.equal((await combinedPage(e,'a',cutoff)).advisories.length,1,label);
 }
});
check('Microsoft Framework, unrelated NuGet products, Visual Studio and other vendors cannot become Core runtime matches',async()=>{
 for(const [label,vendor] of [['.NET Framework 4.8','Microsoft'],['Microsoft Visual Studio 2022 version 17.14','Microsoft'],['ASP.NET Core OData','Microsoft'],['System.Formats.Cbor','Microsoft'],['.NET 8.0 runtime','Other Vendor'],['Entity Framework Core','Microsoft']]){
  const e=env();await subscribeProducts(e,'a',[{name:'.NET Core'}]);await store(e,cna(undefined,label,vendor));
  assert.equal((await combinedPage(e,'a',cutoff)).advisories.length,0,label);
 }
});
check('a failed additional family leaves recent coverage incomplete and retains already saved results',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'.NET Core'}]);await runCvieStep(e,empty,NOW);
 await runCvieStep(e,()=>Response.json({startIndex:0,totalResults:1,vulnerabilities:[{cve:nvd()}]}),NOW+7000);
 await runCvieStep(e,()=>new Response('Unavailable',{status:503}),NOW+14000);
 const p=await first(e);assert.equal(p.status,'retrying');assert.equal(p.recent_complete_at,null);
 assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_advisories').first()).total,1);
});
check('Core results and counts remain account-owned and the shared category cannot bypass Microsoft identity checks',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'.NET Core'}]);await store(e,cna());
 assert.equal((await combinedPage(e,'b',cutoff)).advisories.length,0);
 assert.equal((await combinedCounts(e,'a',cutoff,'2025-11-01T00:00:00Z'))[0].recent_count,1);
 const digest=await loadCvieDigest(e,'a',NOW);assert.deepEqual(digest.component_products,['.NET Core']);
 const merged=mergeDigestEvidence([{id:'CVE-2026-88888',categories:['.NET Core','Other']}],[],[],[],digest.component_products);
 assert.deepEqual(merged[0].categories,['Other']);
});
check('a concurrent explicit vendor edit cannot be overwritten by coverage repair',async t=>{
 const e=env();await subscribeProducts(e,'a',[{name:'.NET Core'}]);
 const original=e.DB.prepare.bind(e.DB);let edited=false;
 t.mock.method(e.DB,'prepare',sql=>{
  if(!edited&&sql.startsWith('UPDATE cvie_products SET cpe=(SELECT')){
   edited=true;e.DB.sql.exec("UPDATE cvie_products SET vendor='Other Vendor',cpe='',cursor_json='{}'");
  }
  return original(sql);
 });
 await state(e);const p=await first(e);assert.equal(p.vendor,'Other Vendor');assert.equal(p.cpe,'');assert.equal(p.cursor_json,'{}');
});
