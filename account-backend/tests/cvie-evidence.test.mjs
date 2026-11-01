import test from 'node:test';
import assert from 'node:assert/strict';
import {DB} from './helpers/d1.mjs';
import {subscribeProducts,cvieRoute,runCvieStep} from '../src/cvie.js';
import {knownIdentity} from '../src/product-identity.js';
import {readDeltaLog,refreshEvidence,ingestDisclosures,normalizeDisclosure,productFamilies,queueRelevantKev} from '../src/cvie-evidence.js';
import {sourceHealth,combinedPage,combinedCounts,reconcileRecord,mergeDigestEvidence} from '../src/cvie-records.js';
import {selectDigest,revisionOf} from '../src/digest.js';
const NOW=Date.parse('2026-11-01T12:00:00Z'),DAY=86400000;
const cpe=knownIdentity('Apache Tomcat').cpe,id='CVE-2026-12345';
const env=()=>({DB:new DB()}),q=(e,sql,...args)=>e.DB.prepare(sql).bind(...args);
const check=(name,fn)=>test(name,async t=>{t.mock.timers.enable({apis:['Date'],now:NOW});await fn(t);});
function cna(cveId=id,published='2026-10-15T00:00:00Z',product='Tomcat',vendor='Apache Software Foundation'){
 return {dataType:'CVE_RECORD',dataVersion:'5.1',cveMetadata:{cveId,state:'PUBLISHED',datePublished:published,dateUpdated:published},
  containers:{cna:{providerMetadata:{shortName:'apache'},title:'Fixture vendor advisory',descriptions:[{lang:'en',value:'Original fixture disclosure, independently of NVD analysis.'}],
   affected:[{vendor,product,defaultStatus:'unaffected',versions:[{version:'10.1.0',lessThan:'10.1.30',status:'affected',versionType:'semver'}]}],
   metrics:[{cvssV3_1:{baseScore:7.5,baseSeverity:'HIGH',version:'3.1'}}],references:[{url:'https://tomcat.apache.org/security-10.html'}]}}};
}
function kev(cveId=id){return {cveID:cveId,vendorProject:'Apache',product:'Tomcat',vulnerabilityName:'Fixture KEV entry',dateAdded:'2026-10-30',shortDescription:'Confirmed exploitation evidence fixture.',requiredAction:'Apply vendor mitigations.',dueDate:'2026-11-20',knownRansomwareCampaignUse:'Unknown'};}
const catalogue=items=>({dateReleased:new Date(NOW).toISOString(),count:items.length,vulnerabilities:items});
async function seedQueue(e,cveId=id,revision=''){
 await q(e,'INSERT INTO cvie_disclosure_queue(cve_id,revision,priority) VALUES(?,?,0)',cveId,revision).run();
}
async function storeCna(e,raw=cna()){
 await seedQueue(e,raw.cveMetadata.cveId);await ingestDisclosures(e,async()=>Response.json(raw),NOW);
}
async function storeNvd(e,score=9.8){
 const raw={id,published:'2026-10-15T00:00:00Z',lastModified:'2026-10-16T00:00:00Z',vulnStatus:'Analyzed',descriptions:[{lang:'en',value:'NVD fixture summary'}],
  metrics:{cvssMetricV31:[{cvssData:{baseScore:score}}]},configurations:[{nodes:[{cpeMatch:[{criteria:cpe,vulnerable:true,versionEndExcluding:'10.1.29'}]}]}]};
 await runCvieStep(e,async()=>Response.json({startIndex:0,totalResults:1,vulnerabilities:[{cve:raw}]}),NOW);
}
check('the direct CNA disclosure appears before NVD has analyzed the CVE',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);await storeCna(e);
 const page=await combinedPage(e,'a','2026-08-01T00:00:00Z');assert.equal(page.advisories.length,1);
 assert.equal(page.advisories[0].summary,cna().containers.cna.descriptions[0].value);
 assert.equal(page.advisories[0].provenance[0].source,'cve_program');
 assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_advisories').first()).total,0,'no NVD row is needed');
});
check('all three sources merge into one CVE and score differences are explicit',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);await storeNvd(e);await storeCna(e);
 await refreshEvidence(e,async()=>Response.json(catalogue([kev()])),NOW);
 const page=await combinedPage(e,'a','2026-08-01T00:00:00Z');assert.equal(page.advisories.length,1);
 const record=page.advisories[0];assert.equal(record.cvss,7.5);assert.equal(record.known_exploited,true);
 assert.deepEqual(record.provenance.map(x=>x.source),['nvd','cve_program','cisa_kev']);
 assert.ok(record.source_conflicts.length);assert.equal(record.kev_added,'2026-10-30');
 assert.equal(record.published,'2026-10-15T00:00:00.000Z','fetching evidence does not change disclosure dates');
});
check('older confirmed-exploited CVEs survive both history filters without falsifying their age',async()=>{
 const e=env(),old='CVE-2019-12345';await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);
 await refreshEvidence(e,async()=>Response.json(catalogue([kev(old)])),NOW);
 await ingestDisclosures(e,async()=>Response.json(cna(old,'2019-01-01T00:00:00Z')),NOW);
 const page=await combinedPage(e,'a','2026-08-01T00:00:00Z');assert.equal(page.advisories.length,1);
 assert.equal(page.advisories[0].retained_exploited,true);assert.equal(page.advisories[0].published,'2019-01-01T00:00:00.000Z');
 assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_disclosure_queue').first()).total,0,'KEV dateAdded is not mistaken for a required CNA revision');
 const counts=await combinedCounts(e,'a','2026-08-01T00:00:00Z','2025-11-01T00:00:00Z');
 assert.equal(counts[0].recent_count,0);assert.equal(counts[0].older_kev_recent_count,1);
});
check('structured vendor and product identity prevent misleading description-only matches',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);
 await storeCna(e,cna(id,'2026-10-15T00:00:00Z','Tomcat','Unrelated Vendor'));
 assert.equal((await combinedPage(e,'a','2026-08-01T00:00:00Z')).advisories.length,0);
});
check('a precise vendor/product CNA match can work before a product has an NVD CPE',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'New Product',vendor:'Example Vendor'}]);
 await storeCna(e,cna(id,'2026-10-15T00:00:00Z','New Product','Example Vendor'));
 const page=await combinedPage(e,'a','2026-08-01T00:00:00Z');assert.equal(page.advisories.length,1);
 assert.equal(page.advisories[0].cvie_products[0],'New Product');
});
check('a source outage retains the last catalogue and never publishes a successful check time',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);
 await refreshEvidence(e,async()=>Response.json(catalogue([kev()])),NOW);
 await q(e,"UPDATE cvie_sources SET next_attempt_at=0 WHERE id='cisa_kev'").run();
 await q(e,"UPDATE cvie_sources SET next_attempt_at=? WHERE id='cve_program'",NOW+DAY).run();
 await refreshEvidence(e,async()=>new Response('Unavailable',{status:503}),NOW+1000);
 const row=await q(e,"SELECT * FROM cvie_sources WHERE id='cisa_kev'").first();assert.equal(row.last_success_at,NOW);assert.equal(row.status,'unavailable');
 assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_kev').first()).total,1);
 assert.equal((await sourceHealth(e,NOW+1000)).sources.find(x=>x.id==='cisa_kev').status,'unavailable');
});
check('an empty or incomplete CISA catalogue cannot erase saved exploitation evidence',async()=>{
 const e=env();await refreshEvidence(e,async()=>Response.json(catalogue([kev()])),NOW);
 await q(e,"UPDATE cvie_sources SET next_attempt_at=0 WHERE id='cisa_kev'").run();await q(e,"UPDATE cvie_sources SET next_attempt_at=? WHERE id='cve_program'",NOW+DAY).run();
 const result=await refreshEvidence(e,async()=>Response.json(catalogue([])),NOW+1000);assert.equal(result.ok,false);
 assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_kev').first()).total,1);
});
check('a failed original-record fetch is retried and does not erase a prior good disclosure',async()=>{
 const e=env();await storeCna(e);await seedQueue(e,id,'2026-10-31T00:00:00Z');
 const result=await ingestDisclosures(e,async()=>new Response('Unavailable',{status:503}),NOW);
 assert.equal(result.failed,1);assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_disclosures').first()).total,1);
 assert.equal((await q(e,'SELECT attempts FROM cvie_disclosure_queue').first()).attempts,1);
});
check('provider Retry-After pauses record requests globally instead of hammering other CVE IDs',async()=>{
 const e=env();await seedQueue(e);let calls=0;
 await ingestDisclosures(e,async()=>{calls++;return new Response('Rate limited',{status:429,headers:{'Retry-After':'3600'}});},NOW);
 const first=calls;await seedQueue(e,'CVE-2026-12346');
 const retry=await ingestDisclosures(e,async()=>{calls++;return Response.json(cna());},NOW+60000);
 assert.equal(retry.waiting,true);assert.equal(calls,first);
 assert.equal((await q(e,"SELECT record_retry_at FROM cvie_sources WHERE id='cve_program'").first()).record_retry_at,NOW+3600000);
});
check('a rejected CVE is removed even when a stale NVD record still contains it',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);await storeNvd(e);
 const raw=cna();raw.cveMetadata.state='REJECTED';raw.containers.cna={rejectedReasons:[{lang:'en',value:'Withdrawn fixture'}]};await storeCna(e,raw);
 assert.equal((await combinedPage(e,'a','2026-08-01T00:00:00Z')).advisories.length,0);
 const state=await(await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie'),e,{id:'a'})).json();
 assert.equal(state.products[0].recent_count,0);assert.deepEqual(state.withdrawn_ids,[id]);
});
check('an explicit CNA unaffected-product correction suppresses a stale NVD product match',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);await storeNvd(e);
 const raw=cna();raw.containers.cna.affected[0].versions=[];await storeCna(e,raw);
 assert.equal((await combinedPage(e,'a','2026-08-01T00:00:00Z')).advisories.length,0);
});
check('public disclosure caches never bypass account-scoped product selection',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);await storeCna(e);
 assert.equal((await combinedPage(e,'b','2026-08-01T00:00:00Z')).advisories.length,0);
});
check('streamed change logs handle chunk boundaries and stop at the checkpoint',async()=>{
 const row=(time,ids)=>({fetchTime:new Date(time).toISOString(),numberOfChanges:ids.length,new:ids.map(cveId=>({cveId,dateUpdated:new Date(time).toISOString(),githubLink:'https://untrusted.invalid/ignored'})),updated:[],error:[]});
 const text=JSON.stringify([row(NOW,[id]),row(NOW-60000,['CVE-2026-12346']),row(NOW-120000,[])]);
 const bytes=new TextEncoder().encode(text);let pos=0;
 const response=new Response(new ReadableStream({pull(controller){if(pos>=bytes.length){controller.close();return;}controller.enqueue(bytes.slice(pos,pos+=7));}}));
 const result=await readDeltaLog(response,NOW-90000,NOW);assert.equal(result.entries.length,2);assert.equal(result.newest,NOW);
});
check('truncated, unordered or publisher-error change logs do not advance the checkpoint',async()=>{
 await assert.rejects(()=>readDeltaLog(new Response('[{"fetchTime":'),NOW-60000,NOW));
 const row=time=>({fetchTime:new Date(time).toISOString(),numberOfChanges:0,new:[],updated:[],error:[]});
 await assert.rejects(()=>readDeltaLog(Response.json([row(NOW-1000),row(NOW)]),NOW-60000,NOW));
 await assert.rejects(()=>readDeltaLog(Response.json([{...row(NOW),error:['publisher failure']}]),NOW-60000,NOW));
});
check('a changed record arriving during ingestion remains queued for the newer revision',async()=>{
 const e=env();await seedQueue(e,id,'2026-10-15T00:00:00.000Z');
 await ingestDisclosures(e,async()=>{await q(e,'UPDATE cvie_disclosure_queue SET revision=? WHERE cve_id=?','2026-10-31T00:00:00.000Z',id).run();return Response.json(cna());},NOW);
 assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_disclosure_queue').first()).total,1);
});
check('newly confirmed exploitation can trigger one alert for an older, unrated CVE',async()=>{
 const record={id:'CVE-2019-12345',source_type:'cvie_combined',categories:['Apache Tomcat'],severity:'unrated',published:'2019-01-01',updated:'2019-01-02',known_exploited:true,kev_added:'2026-10-30'};
 const first=selectDigest([record],['Apache Tomcat'],'critical',new Map(),NOW);assert.equal(first.items.length,1);
 const second=selectDigest([record],['Apache Tomcat'],'critical',new Map([[record.id,revisionOf(record)]]),NOW);assert.equal(second.items.length,0);
});
check('alerts prefer reconciled scores and remove withdrawn CVEs from an older public snapshot',async()=>{
 const old={id,updated:'2026-10-20',severity:'critical',known_exploited:true,categories:['Apache Tomcat']};
 const current={...old,severity:'high',known_exploited:false,kev_verified_at:NOW,source_type:'cvie_combined'};
 const records=mergeDigestEvidence([old],[current]);assert.equal(records.length,1);assert.equal(records[0].severity,'high');assert.equal(records[0].known_exploited,false);
 assert.equal(mergeDigestEvidence([old],[],[id]).length,0);
});
