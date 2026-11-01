import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {DB} from './helpers/d1.mjs';
import {subscribeProducts,runCvieStep,cvieRoute,normalizeNvd,loadCvieDigest} from '../src/cvie.js';
import {ingestDisclosures,refreshEvidence,readDeltaLog,normalizeDisclosure} from '../src/cvie-evidence.js';
import {combinedPage,combinedCounts,cnaRanges,mergeDigestEvidence,reconcileRecord} from '../src/cvie-records.js';
import {selectDigest} from '../src/digest.js';
import {knownIdentity} from '../src/product-identity.js';
import {simplifyCve} from '../src/cve-lookup.js';
const NOW=Date.parse('2026-11-01T12:00:00Z'),DAY=86400000,id='CVE-2026-12345',cpe=knownIdentity('Apache Tomcat').cpe;
const q=(e,sql,...args)=>e.DB.prepare(sql).bind(...args),env=()=>({DB:new DB()});
const check=(name,fn)=>test(name,async t=>{t.mock.timers.enable({apis:['Date'],now:NOW});await fn(t);});
function disclosure(date='2026-10-20T00:00:00Z'){
 return {dataType:'CVE_RECORD',dataVersion:'5.1',cveMetadata:{cveId:id,state:'PUBLISHED',datePublished:'2026-10-15T00:00:00Z',dateUpdated:date},containers:{cna:{title:'Audit fixture',descriptions:[{lang:'en',value:'Synthetic regression fixture.'}],affected:[{vendor:'Apache Software Foundation',product:'Tomcat',defaultStatus:'unaffected',versions:[{version:'10.1.0',lessThan:'10.1.30',status:'affected',versionType:'semver'}]}]}}};
}
async function store(e,raw,revision=raw.cveMetadata.dateUpdated){
 await q(e,`INSERT INTO cvie_disclosure_queue(cve_id,revision,priority) VALUES(?,?,0) ON CONFLICT(cve_id) DO UPDATE SET revision=excluded.revision,next_attempt_at=0,lease_until=0`,id,revision?new Date(revision).toISOString():'').run();
 return ingestDisclosures(e,async()=>Response.json(raw),NOW);
}
function nvd(){return {id,published:'2026-10-15T00:00:00Z',lastModified:'2026-10-20T00:00:00Z',vulnStatus:'Analyzed',descriptions:[{lang:'en',value:'NVD fixture'}],configurations:[{nodes:[{cpeMatch:[{criteria:cpe,vulnerable:true,versionEndExcluding:'10.1.30'}]}]}]};}
const kev=(cveID=id)=>({cveID,vendorProject:'Apache',product:'Tomcat',dateAdded:'2026-10-30'});
const catalogue=(date,records=[kev()])=>({dateReleased:date,count:records.length,vulnerabilities:records});
check('older CNA responses cannot downgrade a newer record or its affected-product index',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);await store(e,disclosure('2026-10-30T00:00:00Z'));
 const stale=disclosure();stale.containers.cna.affected[0].product='Unrelated Product';
 await store(e,stale,'2026-10-31T00:00:00Z');
 assert.equal((await q(e,'SELECT updated_at FROM cvie_disclosures').first()).updated_at,'2026-10-30T00:00:00.000Z');
 assert.equal((await combinedPage(e,'a','2026-08-01T00:00:00Z')).advisories.length,1);
});
check('a stale published response cannot resurrect an already rejected CVE',async()=>{
 const e=env(),rejected=disclosure('2026-10-30T00:00:00Z');rejected.cveMetadata.state='REJECTED';
 await store(e,rejected);await store(e,disclosure(),'2026-10-31T00:00:00Z');
 assert.equal((await q(e,'SELECT state FROM cvie_disclosures').first()).state,'REJECTED');
});
check('a backwards CVE change feed is rejected rather than moving the checkpoint backwards',async()=>{
 const row={fetchTime:new Date(NOW-1000).toISOString(),numberOfChanges:0,new:[],updated:[],error:[]};
 await assert.rejects(()=>readDeltaLog(Response.json([row]),NOW,NOW));
});
check('a backwards CISA publisher snapshot cannot replace the newer saved catalogue',async()=>{
 const e=env();await refreshEvidence(e,async()=>Response.json(catalogue(new Date(NOW).toISOString())),NOW);
 await q(e,"UPDATE cvie_sources SET next_attempt_at=0 WHERE id='cisa_kev'").run();await q(e,"UPDATE cvie_sources SET next_attempt_at=? WHERE id='cve_program'",NOW+DAY).run();
 const result=await refreshEvidence(e,async()=>Response.json(catalogue(new Date(NOW-DAY).toISOString(),[kev('CVE-2026-99999')])),NOW+1000);
 assert.equal(result.ok,false);assert.equal((await q(e,'SELECT cve_id FROM cvie_kev').first()).cve_id,id);
});
check('an explicitly unknown CNA version is retained for review instead of treated as unaffected',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);const raw=disclosure();raw.containers.cna.affected[0].versions[0].status='unknown';await store(e,raw);
 const page=await combinedPage(e,'a','2026-08-01T00:00:00Z');assert.equal(page.advisories.length,1);
 assert.equal(page.advisories[0].affected_cpes[0].comparison_unsupported,true);
});
check('custom vendor version ordering is not used to exclude an installed version',()=>{
 const window={};vm.runInNewContext(fs.readFileSync(new URL('../../inventory-matching.js',import.meta.url),'utf8'),{window});
 const affected=[{defaultStatus:'unaffected',versions:[{version:'1.0',lessThan:'3.0',status:'affected',versionType:'custom'}]}];
 assert.equal(window.CVEHARBOR_INVENTORY_MATCH.cvieVersionAssessment('5.0',cnaRanges(affected,cpe,'Apache Tomcat')),'unknown');
});
check('missing CVSS values never become a numeric zero or a low-severity finding',()=>{
 const raw=nvd();raw.metrics={cvssMetricV31:[{cvssData:{baseScore:null}}]};assert.equal(normalizeNvd(raw,{name:'Apache Tomcat',cpe}).cvss,null);
 const cna=disclosure();cna.containers.cna.metrics=[{cvssV3_1:{baseScore:'',baseSeverity:'LOW'}}];assert.equal(simplifyCve(cna,'fixture').severity,'unrated');
});
check('a vendor correction restarts unresolved product identification and is not overwritten by inventory sync',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Example Product',vendor:'Wrong Vendor'}]);
 await q(e,"UPDATE cvie_products SET status='needs_identity',candidates_json='[]'").run();
 await subscribeProducts(e,'a',[{name:'Example Product',vendor:'Correct Vendor'}]);
 const p=await q(e,'SELECT * FROM cvie_products').first();assert.equal(p.vendor,'Correct Vendor');assert.equal(p.status,'queued');
 await subscribeProducts(e,'a',[{name:'Example Product'}],'inventory');assert.equal((await q(e,'SELECT vendor FROM cvie_products').first()).vendor,'Correct Vendor');
});
check('a conflicting explicit vendor cannot silently inherit a known product CPE',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat',vendor:'Unrelated Vendor'}]);
 assert.equal((await q(e,'SELECT cpe FROM cvie_products').first()).cpe,'');
});
check('malformed NVD entries do not advance scan progress or create a false zero-result completion',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);
 await runCvieStep(e,async()=>Response.json({startIndex:0,totalResults:1,vulnerabilities:[{}]}),NOW);
 const p=await q(e,'SELECT * FROM cvie_products').first();assert.equal(p.status,'retrying');assert.equal(p.recent_complete_at,null);
});
check('large product histories do not monopolize the shared scan queue',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'},{name:'PHP'}]);const seen=[];
 const fetcher=async url=>{seen.push(new URL(url).searchParams.get('virtualMatchString'));return Response.json({startIndex:0,totalResults:100,vulnerabilities:[{cve:nvd()}]});};
 await runCvieStep(e,fetcher,NOW);await runCvieStep(e,fetcher,NOW+7000);assert.equal(new Set(seen).size,2);
});
check('product-specific unaffected corrections are delivered to clients and suppress matching legacy digest categories',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);const raw=disclosure();raw.containers.cna.affected[0].versions=[];await store(e,raw);
 const response=await(await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie'),e,{id:'a'})).json();
 assert.deepEqual(response.excluded_product_cves,[{id,product:'Apache Tomcat'}]);
 const merged=mergeDigestEvidence([{id,categories:['Apache Tomcat','PHP']}],[],[],response.excluded_product_cves);
 assert.deepEqual(merged[0].categories,['PHP']);assert.deepEqual(merged[0].cvie_excluded_products,['Apache Tomcat']);
});
check('punctuation collisions do not become exact CNA product matches or false product counts',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'AB',vendor:'Apache'}]);const raw=disclosure();raw.containers.cna.affected[0].product='A.B';await store(e,raw);
 assert.equal((await combinedPage(e,'a','2026-08-01T00:00:00Z')).advisories.length,0);
 assert.equal((await combinedCounts(e,'a','2026-08-01','2025-11-01')).length,0);
});
check('an arbitrary display name cannot override an explicitly selected CPE product',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Unrelated Product',vendor:'Apache',cpe}]);const raw=disclosure();raw.containers.cna.affected[0].product='Unrelated Product';await store(e,raw);
 assert.equal((await combinedPage(e,'a','2026-08-01T00:00:00Z')).advisories.length,0);
});
check('legacy PHP correction tables cannot override a newer structured CVIE version range',()=>{
 const window={};vm.runInNewContext(fs.readFileSync(new URL('../../inventory-matching.js',import.meta.url),'utf8'),{window});
 const php=knownIdentity('PHP').cpe,record={id:'CVE-2026-109618',source_type:'cvie_combined',cvie_products:['PHP'],cvie_identities:[{name:'PHP',cpe:php}],affected_cpes:[{criteria:php,versionStartIncluding:'8.2.35',versionEndExcluding:'8.2.40'}]};
 assert.equal(window.CVEHARBOR_INVENTORY_MATCH.candidate({id:'asset',technology:'PHP',version:'8.2.36'},record)?.level,'version_review');
});
check('legacy category-correction tables cannot suppress an exact CVIE product alert',()=>{
 const record={id:'CVE-2026-111497',source_type:'cvie_combined',categories:['Verified Product'],severity:'high',published:'2026-10-30',updated:'2026-10-30'};
 assert.equal(selectDigest([record],['Verified Product'],'high',new Map(),NOW).items.length,1);
});
check('large low-severity histories cannot crowd a recent critical advisory out of a digest',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);const p=await q(e,'SELECT * FROM cvie_products').first();
 const insert=e.DB.sql.prepare('INSERT INTO cvie_advisories VALUES(?,?,?,?,?)');
 for(let i=0;i<1050;i++){
  const record=normalizeNvd({...nvd(),id:'CVE-2026-'+(20000+i)},{name:p.name,cpe});record.severity='low';record.cvss=2;
  insert.run(p.id,record.id,record.published,JSON.stringify(record),'fixture');
 }
 const urgent=normalizeNvd({...nvd(),id:'CVE-2026-99999'},{name:p.name,cpe});urgent.severity='critical';urgent.cvss=9.8;
 insert.run(p.id,urgent.id,urgent.published,JSON.stringify(urgent),'fixture');
 const result=await loadCvieDigest(e,'a',NOW,['Apache Tomcat']);assert.deepEqual(result.records.map(r=>r.id),[urgent.id]);assert.equal(result.coverageLimited,false);
});
check('digest candidates merge product associations before applying their bounded result limit',async()=>{
 const e=env();await subscribeProducts(e,'a',Array.from({length:120},(_,i)=>({name:'Product '+i,cpe})));
 const products=(await q(e,'SELECT * FROM cvie_products').all()).results;
 const insert=e.DB.sql.prepare('INSERT INTO cvie_advisories VALUES(?,?,?,?,?)');
 for(const p of products){const record=normalizeNvd(nvd(),{name:p.name,cpe});record.severity='critical';record.cvss=9.8;insert.run(p.id,id,record.published,JSON.stringify(record),'fixture');}
 const result=await loadCvieDigest(e,'a',NOW);assert.equal(result.records.length,1);assert.equal(result.records[0].categories.length,120);assert.equal(result.coverageLimited,false);
});
check('new NVD analysis remains alertable when its original CNA disclosure is older',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);const p=await q(e,'SELECT * FROM cvie_products').first();
 const raw=disclosure('2026-06-01T00:00:00Z');raw.cveMetadata.datePublished='2026-06-01T00:00:00Z';await store(e,raw);
 const record=normalizeNvd({...nvd(),published:'2026-06-01T00:00:00Z'},{name:p.name,cpe});record.severity='critical';record.cvss=9.8;
 e.DB.sql.prepare('INSERT INTO cvie_advisories VALUES(?,?,?,?,?)').run(p.id,id,record.published,JSON.stringify(record),'fixture');
 const result=await loadCvieDigest(e,'a',NOW,['Apache Tomcat']);assert.equal(result.records.length,1);
 assert.equal(selectDigest(result.records,['Apache Tomcat'],'critical',new Map(),NOW).items.length,1);
});
check('the original CNA score takes precedence over newer-version ADP enrichment',()=>{
 const raw=disclosure();raw.containers.cna.metrics=[{cvssV3_1:{baseScore:7.5}}];raw.containers.adp=[{metrics:[{cvssV4_0:{baseScore:10}}]}];
 const normalized=normalizeDisclosure(raw);assert.equal(normalized.base.cvss,7.5);assert.equal(normalized.base.cvss_provider,'CVE Program / CNA');
 raw.containers.cna.metrics=[];const fallback=normalizeDisclosure(raw);assert.equal(fallback.base.cvss,10);assert.equal(fallback.base.cvss_provider,'CVE Program / ADP');
});
check('NVD primary scores and valid fallback metrics are chosen without hiding severity',()=>{
 const raw=nvd();raw.metrics={cvssMetricV31:[{type:'Secondary',cvssData:{baseScore:5}},{type:'Primary',cvssData:{baseScore:9.8}}]};
 assert.equal(normalizeNvd(raw,{name:'Apache Tomcat',cpe}).severity,'critical');
 raw.metrics.cvssMetricV40=[{type:'Primary',cvssData:{baseScore:null}}];assert.equal(normalizeNvd(raw,{name:'Apache Tomcat',cpe}).cvss,9.8);
});
check('a disclosure-feed outage is visible on individual evidence, not just the source panel',()=>{
 const original=normalizeDisclosure(disclosure());
 const record=reconcileRecord(null,original.base,disclosure().containers.cna.affected,{name:'Apache Tomcat',cpe},null,
  {cna_checked_at:NOW,cve_program:{last_success_at:NOW,status:'unavailable'},cisa_kev:{last_success_at:NOW,status:'ok'}},NOW,'2026-08-01');
 assert.equal(record.disclosure_verification_stale,true);assert.match(record.evidence_status,/Original disclosure feed/);
});
check('unknown defaults and explicit version exceptions cannot become confident exclusions or matches',()=>{
 const window={};vm.runInNewContext(fs.readFileSync(new URL('../../inventory-matching.js',import.meta.url),'utf8'),{window});
 const row={defaultStatus:'unknown',versions:[{version:'1.0',lessThan:'3.0',status:'affected',versionType:'semver'}]};
 assert.equal(window.CVEHARBOR_INVENTORY_MATCH.cvieVersionAssessment('5.0',cnaRanges([row],cpe,'Apache Tomcat')),'unknown');
 row.defaultStatus='unaffected';row.versions.push({version:'2.0',status:'unaffected'});
 assert.equal(window.CVEHARBOR_INVENTORY_MATCH.cvieVersionAssessment('2.0',cnaRanges([row],cpe,'Apache Tomcat')),'unknown');
});
check('invalid or future CISA listing dates retain the last verified catalogue',async()=>{
 for(const date of ['2026-02-30','2026-11-02']){
  const e=env();await refreshEvidence(e,async()=>Response.json(catalogue(new Date(NOW).toISOString())),NOW);
  await q(e,"UPDATE cvie_sources SET next_attempt_at=0 WHERE id='cisa_kev'").run();await q(e,"UPDATE cvie_sources SET next_attempt_at=? WHERE id='cve_program'",NOW+DAY).run();
  const result=await refreshEvidence(e,async()=>Response.json(catalogue(new Date(NOW).toISOString(),[{...kev(),dateAdded:date}])),NOW+1000);
  assert.equal(result.ok,false);assert.equal((await q(e,'SELECT date_added FROM cvie_kev').first()).date_added,'2026-10-30');
 }
});
check('a contradictory severity label cannot hide a critical numeric CVSS score',()=>{
 const raw=disclosure();raw.containers.cna.metrics=[{cvssV3_1:{baseScore:9.8,baseSeverity:'LOW'}}];
 const record=normalizeDisclosure(raw).base;assert.equal(record.severity,'critical');assert.equal(record.cvss_label_conflict,true);
});
check('a new disclosure revision gets a fresh retry budget instead of inheriting an old failure backoff',async()=>{
 const e=env();await q(e,"INSERT INTO cvie_disclosure_queue(cve_id,revision,priority,attempts,next_attempt_at,error) VALUES(?,?,1,9,?,'Old provider error')",id,'2026-10-15T00:00:00Z',NOW+DAY).run();
 await q(e,"UPDATE cvie_sources SET next_attempt_at=? WHERE id='cisa_kev'",NOW+DAY).run();
 const feed=[{fetchTime:new Date(NOW).toISOString(),numberOfChanges:1,new:[],updated:[{cveId:id,dateUpdated:new Date(NOW-3600000).toISOString()}],error:[]}];
 const result=await refreshEvidence(e,async()=>Response.json(feed),NOW);assert.equal(result.ok,true);
 const queued=await q(e,'SELECT * FROM cvie_disclosure_queue').first();assert.equal(queued.attempts,0);assert.equal(queued.next_attempt_at,0);assert.equal(queued.error,'');
});
check('validated CPE input is stored canonically rather than silently missing mixed-case product matches',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat',cpe:cpe.replace(':apache:tomcat:',':Apache:Tomcat:')}]);
 assert.equal((await q(e,'SELECT cpe FROM cvie_products').first()).cpe,cpe);
 await runCvieStep(e,async()=>Response.json({startIndex:0,totalResults:1,vulnerabilities:[{cve:nvd()}]}),NOW);
 assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_advisories').first()).total,1);
});
check('large advisory responses paginate without omissions and retain account/product isolation',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'},{name:'Internal Runtime',cpe}]);await subscribeProducts(e,'b',[{name:'Apache Tomcat'}]);
 const owned=(await q(e,"SELECT * FROM cvie_products WHERE user_id='a'").all()).results;
 const insert=e.DB.sql.prepare('INSERT INTO cvie_advisories VALUES(?,?,?,?,?)');
 for(const p of owned)for(let i=0;i<250;i++){
  const record=normalizeNvd({...nvd(),id:'CVE-2026-'+(30000+i)},{name:p.name,cpe});insert.run(p.id,record.id,record.published,JSON.stringify(record),'fixture');
 }
 let after='',all=[],pages=0;
 do{const response=await(await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie/advisories?months=3'+(after?'&after='+encodeURIComponent(after):'')),e,{id:'a'})).json();
  assert.equal(response.account_id,'a');all.push(...response.advisories);after=response.next||'';pages++;assert.ok(pages<=5);
 }while(after);
 assert.equal(all.length,500);assert.equal(new Set(all.map(r=>r.cvie_products[0]+'/'+r.id)).size,500);
 const other=await(await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie/advisories?months=3&product='+owned[0].id),e,{id:'b'})).json();assert.equal(other.advisories.length,0);
});
check('an expired scan lease can recover without a late original response overwriting its result',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);let release;
 const pending=runCvieStep(e,()=>new Promise(resolve=>{release=()=>resolve(Response.json({startIndex:0,totalResults:1,vulnerabilities:[{cve:nvd()}]}));}),NOW);
 for(let i=0;!release&&i<20;i++)await Promise.resolve();assert.ok(release);
 const fresh=nvd();fresh.metrics={cvssMetricV31:[{type:'Primary',cvssData:{baseScore:9.8}}]};
 await runCvieStep(e,async()=>Response.json({startIndex:0,totalResults:1,vulnerabilities:[{cve:fresh}]}),NOW+130000);
 release();await pending;
 assert.equal(JSON.parse((await q(e,'SELECT record_json FROM cvie_advisories').first()).record_json).cvss,9.8);
 assert.equal((await q(e,'SELECT last_success_at FROM cvie_products').first()).last_success_at,NOW+130000);
});
check('release cache refresh preserves evidence/customer data, fences old work and only runs once',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);
 const raw=disclosure();raw.containers.cna.affected[0].versions[0].status='unknown';await store(e,raw);
 await q(e,"UPDATE cvie_disclosure_products SET applicability='unaffected'").run();
 const record=normalizeNvd(nvd(),{name:'Apache Tomcat',cpe}),p=await q(e,'SELECT * FROM cvie_products').first();
 e.DB.sql.prepare('INSERT INTO cvie_advisories VALUES(?,?,?,?,?)').run(p.id,id,record.published,JSON.stringify(record),'previous');
 e.DB.sql.exec("INSERT INTO inventory_assets VALUES('a','Apache Tomcat')");
 await q(e,"UPDATE cvie_products SET status='scanning',lease_until=?,cursor_json='{}'",NOW+120000).run();
 await q(e,'INSERT INTO cvie_disclosure_queue(cve_id,revision,priority,lease_until) VALUES(?,?,1,?)',id,'2026-10-31T00:00:00.000Z',NOW+120000).run();
 const sql=fs.readFileSync(new URL('../migrations/0021_cvie_audit_refresh.sql',import.meta.url),'utf8');e.DB.sql.exec(sql);
 assert.equal((await q(e,'SELECT applicability FROM cvie_disclosure_products').first()).applicability,'affected');
 const queued=await q(e,'SELECT * FROM cvie_disclosure_queue').first();assert.equal(queued.lease_until,0);assert.equal(queued.revision,'2026-10-31T00:00:00.000Z');
 assert.equal((await q(e,'SELECT status FROM cvie_products').first()).status,'queued');
 assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_advisories').first()).total,1);
 assert.equal((await q(e,'SELECT COUNT(*) AS total FROM inventory_assets').first()).total,1);
 await q(e,'DELETE FROM cvie_disclosure_queue').run();await q(e,"UPDATE cvie_products SET status='ready',next_attempt_at=?",NOW+DAY).run();
 e.DB.sql.exec(sql);assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_disclosure_queue').first()).total,0);
 assert.equal((await q(e,'SELECT status FROM cvie_products').first()).status,'ready');
 assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_maintenance').first()).total,1);
});
