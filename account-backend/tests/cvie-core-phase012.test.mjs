import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DB} from './helpers/d1.mjs';
import {searchRegistry,registryIdentity,resolveRegistry} from '../src/product-registry.js';
import {subscribeProducts,cvieRoute} from '../src/cvie.js';
import {immediateEvidence,evidencePageSql} from '../src/cvie-onboarding.js';
import {refreshEvidence} from '../src/cvie-evidence.js';
import {observeCvie} from '../src/cvie-metrics.js';
function env(){const DBi=new DB();for(const file of ['0028_cvie_source_efficiency.sql','0029_cvie_identity_registry.sql'])DBi.sql.exec(fs.readFileSync(new URL('../migrations/'+file,import.meta.url),'utf8'));return {DB:DBi,CVIE_REGISTRY_ENABLED:'true',CVIE_FAST_EVIDENCE_ENABLED:'true',CVIE_SHARED_SCANS_ENABLED:'true'};}
const q=(e,sql,...args)=>e.DB.prepare(sql).bind(...args);
async function fixture(e,identity='php',n=1){const p=registryIdentity(identity),now=new Date().toISOString();for(let i=0;i<n;i++){const id='CVE-2026-'+(10000+i);await q(e,'INSERT INTO cvie_disclosures VALUES(?,?,?,?,?,?)',id,'PUBLISHED',now,now,JSON.stringify({id,published:now,updated:now,title:'Public test disclosure',cvss:7.5,severity:'high',sources:[]}),Date.now()).run();await q(e,'INSERT INTO cvie_disclosure_products VALUES(?,?,?,?)',id,'cpe:'+p.cpe,'affected',JSON.stringify([{vendor:p.vendor,product:p.name,defaultStatus:'unaffected',versions:[{version:'1',lessThan:'9',versionType:'semver',status:'affected'}]}])).run();}}
const product=async(e,user='a')=>q(e,'SELECT * FROM cvie_products WHERE user_id=?',user).first();
test('reviewed exact identities, ambiguity, typos and context do not collapse components',()=>{
 for(const name of ['Microsoft .NET Framework','.NET Runtime','ASP.NET Core','.NET Core SDK','WordPress Core','PHP','Python','Windows Server 2022','SQL Server','MySQL','MariaDB','Ubuntu','Debian'])assert.equal(searchRegistry({q:name}).status,'resolved',name);
 for(const name of ['.NET','SQL','Linux'])assert.equal(searchRegistry({q:name}).status,'ambiguous',name);
 assert.equal(searchRegistry({q:'WordPress plugin'}).identity,null);
 const typo=searchRegistry({q:'Durpal CMS'});assert.equal(typo.identity,null);assert.equal(typo.candidates[0].id,'drupal');
 assert.equal(searchRegistry({q:'PHP',vendor:'Other Vendor'}).identity,null);
 assert.equal(searchRegistry({q:'Python',ecosystem:'npm'}).identity,null);
 assert.equal(searchRegistry({scheme:'wordpress-slug',identifier:'woocommerce'}).identity.kind,'package');
 assert.notEqual(resolveRegistry({name:'.NET Runtime'}).id,resolveRegistry({name:'.NET Framework'}).id);
});
test('unresolved products remain private, not covered, and repeated saves write no rows',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Durpal CMS'},{name:'SQL'},{name:'Private Tool'}]);
 const rows=(await q(e,'SELECT * FROM cvie_products').all()).results;assert.ok(rows.every(p=>p.status==='needs_identity'&&!p.cpe));
 assert.equal((await q(e,"SELECT COUNT(*) AS n FROM cvie_identity_aliases WHERE alias='private tool'").first()).n,0);
 const before=e.DB.sql.prepare('SELECT total_changes() AS n').get().n;
 await subscribeProducts(e,'a',[{name:'Durpal CMS'},{name:'SQL'},{name:'Private Tool'}]);
 assert.equal(e.DB.sql.prepare('SELECT total_changes() AS n').get().n,before);
 assert.equal((await immediateEvidence(e,'a',rows[0].id)).coverage,'identity_required');
});
test('stored CNA evidence is immediate, bounded, read-only and account-authorized',async()=>{
 const e=env();await fixture(e,'php',120);await subscribeProducts(e,'a',[{name:'PHP'}]);const p=await product(e);
 const before=e.DB.sql.prepare('SELECT total_changes() AS n').get().n;
 const page=await immediateEvidence(e,'a',p.id);assert.equal(page.advisories.length,100);assert.ok(page.next);assert.equal(page.coverage,'indexed_partial');
 assert.equal((await immediateEvidence(e,'a',p.id,{after:page.next})).advisories.length,20);
 assert.equal((await immediateEvidence(e,'b',p.id)).not_found,true);
 assert.equal(e.DB.sql.prepare('SELECT total_changes() AS n').get().n,before);
 assert.ok(page.advisories.every(r=>r.applicability==='requires_version_review'&&r.cna_affected.length));
 const plan=e.DB.sql.prepare('EXPLAIN QUERY PLAN '+evidencePageSql).all('php','2026-01-01T00:00:00Z','~','~',101).map(r=>r.detail).join('\n');
 assert.match(plan,/SEARCH cvie_identity_evidence USING INDEX/);assert.doesNotMatch(plan,/SCAN (cvie_disclosures|cvie_shared_advisories|cvie_kev)/);
});
test('rejection, corrected unaffected statements and feed outage cannot present stale affected evidence',async()=>{
 const e=env();await fixture(e);await subscribeProducts(e,'a',[{name:'PHP'}]);const p=await product(e);
 await q(e,"UPDATE cvie_disclosures SET state='REJECTED'").run();assert.equal((await immediateEvidence(e,'a',p.id)).advisories.length,0);
 await q(e,"UPDATE cvie_disclosures SET state='PUBLISHED'").run();await q(e,'DELETE FROM cvie_disclosure_products').run();
 await q(e,'INSERT INTO cvie_disclosure_products VALUES(?,?,?,?)','CVE-2026-10000','cpe:'+p.cpe,'unaffected',JSON.stringify([{defaultStatus:'unaffected',versions:[{version:'1',status:'unaffected'}]}])).run();
 assert.equal((await immediateEvidence(e,'a',p.id)).advisories.length,0);
 await q(e,'DELETE FROM cvie_disclosure_products').run();assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_identity_evidence').first()).n,0);
});
test('50 concurrent accounts reuse one shared discovery scope; same-account retry is idempotent',async()=>{
 const e=env();for(let i=0;i<50;i++)e.DB.sql.prepare('INSERT INTO users VALUES(?,?)').run('u'+i,'synthetic');
 const batch=e.DB.batch.bind(e.DB);let tail=Promise.resolve();e.DB.batch=stmts=>{const result=tail.then(()=>batch(stmts));tail=result.catch(()=>{});return result;};
 await Promise.all(Array.from({length:50},(_,i)=>subscribeProducts(e,'u'+i,[{name:'PHP'}])));
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_shared_scopes').first()).n,1);
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_product_scopes WHERE scope_id IS NOT NULL').first()).n,50);
 await Promise.all(Array.from({length:5},()=>subscribeProducts(e,'a',[{name:'PHP'}])));
 assert.equal((await q(e,"SELECT COUNT(*) AS n FROM cvie_subscriptions WHERE user_id='a'").first()).n,1);
 const before=e.DB.sql.prepare('SELECT total_changes() AS n').get().n;await subscribeProducts(e,'a',[{name:'PHP'}]);assert.equal(e.DB.sql.prepare('SELECT total_changes() AS n').get().n,before);
});
test('GET directory, progress and status never repair or write legacy jobs',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'PHP'}]);await q(e,"UPDATE cvie_products SET cursor_json='{}',status='ready'").run();
 const before=e.DB.sql.prepare('SELECT total_changes() AS n').get().n;
 for(const path of ['/directory?q=PHH','/progress',''])assert.equal((await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie'+path),e,{id:'a'})).status,200);
 assert.equal(e.DB.sql.prepare('SELECT total_changes() AS n').get().n,before);
});
test('KEV unchanged catalogue is not rewritten; same-date corrections/removals are authoritative; failures retain rows',async()=>{
 const e=env(),now=Date.now(),entry=(id,product='PHP')=>({cveID:id,dateAdded:'2026-01-01',vendorProject:'PHP',product});let items=[entry('CVE-2026-10000'),entry('CVE-2026-10001')];
 const fetcher=async()=>Response.json({dateReleased:new Date(now).toISOString(),count:items.length,vulnerabilities:items});
 const refresh=async(f=fetcher)=>{await q(e,"UPDATE cvie_sources SET next_attempt_at=? WHERE id='cve_program'",now+1e9).run();await q(e,"UPDATE cvie_sources SET next_attempt_at=0 WHERE id='cisa_kev'").run();return refreshEvidence(e,f,now);};
 assert.equal((await refresh()).ok,true);
 const saved=(await q(e,'SELECT * FROM cvie_kev ORDER BY cve_id').all()).results;const before=e.DB.sql.prepare('SELECT total_changes() AS n').get().n;
 assert.equal((await refresh()).ok,true);assert.deepEqual((await q(e,'SELECT * FROM cvie_kev ORDER BY cve_id').all()).results,saved);
 assert.equal(e.DB.sql.prepare('SELECT total_changes() AS n').get().n-before,4,'two test setup writes and two source status writes only');
 items=[entry('CVE-2026-10000','Corrected PHP')];assert.equal((await refresh()).ok,true);assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_kev').first()).n,1);assert.equal((await q(e,'SELECT product FROM cvie_kev').first()).product,'Corrected PHP');
 assert.equal((await refresh(async()=>new Response('',{status:503}))).ok,false);assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_kev').first()).n,1);
});
test('operation telemetry reports real metadata or unknown, never SQL, bindings or private errors',async()=>{
 let metric;const fake={prepare:()=>({bind(){return this;},all:async()=>({results:[],meta:{rows_read:4,rows_written:0,duration:2}})})};
 await observeCvie({DB:fake,CVIE_METRICS_ENABLED:'true',CVIE_METRIC_SINK:m=>metric=m},'directory',e=>e.DB.prepare('private sql').bind('private customer').all());assert.equal(metric.rows_read,4);assert.equal(metric.rows_written,0);assert.doesNotMatch(JSON.stringify(metric),/private/);
 await observeCvie({...env(),CVIE_METRICS_ENABLED:'true',CVIE_METRIC_SINK:m=>metric=m},'status',e=>e.DB.prepare('SELECT 1').all());assert.equal(metric.rows_read,null);assert.equal(metric.metadata_complete,false);
});

test('additive migration backfill resumes bounded checkpoints and code rollback preserves customer rows',async()=>{
 const e=env();await fixture(e,'php',7);await subscribeProducts(e,'a',[{name:'PHP'}]);const p=await product(e);
 const before=JSON.stringify((await q(e,'SELECT * FROM cvie_products').all()).results);
 await q(e,'DELETE FROM cvie_identity_evidence').run();
 const {backfillEvidenceIndex}=await import('../src/cvie-index-maintenance.js');
 assert.deepEqual(await backfillEvidenceIndex(e,'cna',3),{complete:false,processed:3});
 assert.equal((await immediateEvidence(e,'a',p.id)).advisories.length,3);
 await backfillEvidenceIndex(e,'cna',3);assert.deepEqual(await backfillEvidenceIndex(e,'cna',3),{complete:true,processed:1});
 assert.equal((await immediateEvidence(e,'a',p.id)).advisories.length,7);
 const changes=e.DB.sql.prepare('SELECT total_changes() AS n').get().n;
 await backfillEvidenceIndex(e,'cna',3);assert.equal(e.DB.sql.prepare('SELECT total_changes() AS n').get().n,changes);
 assert.equal(JSON.stringify((await q(e,'SELECT * FROM cvie_products').all()).results),before);
 const response=await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie'),{...e,CVIE_REGISTRY_ENABLED:'false',CVIE_FAST_EVIDENCE_ENABLED:'false'},{id:'a'});assert.equal(response.status,200);
});

test('recent indexed evidence is not buried behind old history; older KEV remains visible and removal restores the date filter',async()=>{
 const e=env();await fixture(e,'php',120);await subscribeProducts(e,'a',[{name:'PHP'}]);const p=await product(e);
 await q(e,"UPDATE cvie_disclosures SET published='2020-01-01T00:00:00Z',record_json=json_set(record_json,'$.published','2020-01-01T00:00:00Z') WHERE cve_id<'CVE-2026-10119'").run();
 let page=await immediateEvidence(e,'a',p.id,{months:3});assert.deepEqual(page.advisories.map(r=>r.id),['CVE-2026-10119']);assert.equal(page.next,null);
 const kev={cveID:'CVE-2026-10000',dateAdded:'2026-01-01',vendorProject:'PHP',product:'PHP'};
 await q(e,"UPDATE cvie_sources SET last_success_at=?,status='ok' WHERE id='cisa_kev'",Date.now()).run();
 await q(e,'INSERT INTO cvie_kev VALUES(?,?,?,?,?,?)',kev.cveID,kev.dateAdded,'PHP','PHP',JSON.stringify(kev),Date.now()).run();
 page=await immediateEvidence(e,'a',p.id,{months:3});assert.equal(page.advisories[0].id,kev.cveID);assert.equal(page.advisories[0].known_exploited,true);
 await q(e,'DELETE FROM cvie_kev WHERE cve_id=?',kev.cveID).run();assert.equal((await immediateEvidence(e,'a',p.id,{months:3})).advisories.length,1);
});

test('all requested product families retain version uncertainty, no plugin-to-core leakage and no vendor override',async()=>{
 for(const identity of ['microsoft-dotnet-framework','microsoft-dotnet-runtime','microsoft-aspnet-core','wordpress-core','php','python','microsoft-windows-server-2022','microsoft-sql-server','oracle-mysql','mariadb','ubuntu','debian']){
  const e=env(),p=registryIdentity(identity);await fixture(e,identity);await subscribeProducts(e,'a',[{name:p.name}]);
  const result=await immediateEvidence(e,'a',(await product(e)).id);assert.equal(result.advisories.length,1,identity);assert.equal(result.advisories[0].applicability,'requires_version_review');
  if(['debian','vendor','pep440'].includes(p.version_scheme))assert.ok(result.advisories[0].affected_cpes.every(c=>c.comparison_unsupported));
 }
 const e=env();await fixture(e,'wordpress-core');await subscribeProducts(e,'a',[{name:'WordPress Plugin: Private Plugin'}]);assert.equal((await immediateEvidence(e,'a',(await product(e)).id)).advisories.length,0);
});

test('identical original disclosure retry acknowledges the queue without rewriting CVE or family assertions',async()=>{
 const e=env(),{ingestDisclosures}=await import('../src/cvie-evidence.js'),id='CVE-2026-23456',date='2026-10-01T00:00:00Z';
 const raw={dataType:'CVE_RECORD',dataVersion:'5.1',cveMetadata:{cveId:id,state:'PUBLISHED',datePublished:date,dateUpdated:date},containers:{cna:{title:'Fixture',descriptions:[{lang:'en',value:'Public fixture'}],affected:[{vendor:'php',product:'php',defaultStatus:'unaffected',versions:[{version:'8',lessThan:'9',status:'affected',versionType:'semver'}]}],references:[]}}};
 const ingest=async now=>{await q(e,'INSERT INTO cvie_disclosure_queue(cve_id,revision) VALUES(?,?)',id,new Date(date).toISOString()).run();return ingestDisclosures(e,async()=>Response.json(raw),now);};
 assert.equal((await ingest(Date.now())).processed,1);
 e.DB.sql.exec('CREATE TABLE mutation_probe(n INTEGER); INSERT INTO mutation_probe VALUES(0); CREATE TRIGGER probe_disclosure AFTER UPDATE ON cvie_disclosures BEGIN UPDATE mutation_probe SET n=n+1; END; CREATE TRIGGER probe_family AFTER UPDATE ON cvie_disclosure_products BEGIN UPDATE mutation_probe SET n=n+1; END; CREATE TRIGGER probe_family_delete AFTER DELETE ON cvie_disclosure_products BEGIN UPDATE mutation_probe SET n=n+1; END;');
 assert.equal((await ingest(Date.now()+1000)).processed,1);assert.equal((await q(e,'SELECT n FROM mutation_probe').first()).n,0);
 raw.containers.cna.affected[0].versions[0].lessThan='8.5';assert.equal((await ingest(Date.now()+2000)).processed,1);
 assert.match((await q(e,'SELECT cna_affected_json FROM cvie_identity_evidence WHERE identity_id=?','php').first()).cna_affected_json,/8.5/);
});

test('verified long-tail identity primes existing public CNA evidence, resumes locally and shares one index job',async()=>{
 const e=env(),cpe='cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*',now=new Date().toISOString();
 await q(e,'INSERT INTO cvie_disclosures VALUES(?,?,?,?,?,?)','CVE-2026-34567','PUBLISHED',now,now,JSON.stringify({id:'CVE-2026-34567',published:now,updated:now,cvss:null,sources:[]}),Date.now()).run();
 await q(e,'INSERT INTO cvie_disclosure_products VALUES(?,?,?,?)','CVE-2026-34567','name:acme:widget','affected',JSON.stringify([{vendor:'acme',product:'widget',defaultStatus:'affected',versions:[]}])).run();
 const {registerVerifiedCpe}=await import('../src/product-registry.js');
 const identity=await registerVerifiedCpe(e,cpe);assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_identity_evidence WHERE identity_id=?',identity.id).first()).n,1);
 await subscribeProducts(e,'a',[{name:identity.name,cpe}]);await subscribeProducts(e,'b',[{name:identity.name,cpe}]);
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_identity_index_jobs').first()).n,1);
 assert.equal((await immediateEvidence(e,'a',(await product(e)).id)).advisories.length,1);
 const {runIdentityIndexWork}=await import('../src/cvie-index-maintenance.js');await runIdentityIndexWork(e,identity.id,Date.now()+120000);assert.equal((await q(e,'SELECT complete FROM cvie_identity_index_jobs').first()).complete,1);
});

test('telemetry wrappers retain public-status cache sharing, invalidation and failure recovery',async()=>{
 const {publicSourceStatus,invalidatePublicSourceStatus}=await import('../src/public-source-status-cache.js');const raw={},a={DB:{},CVIE_UNWRAPPED_DB:raw},b={DB:{},CVIE_UNWRAPPED_DB:raw};let reads=0;
 const load=()=>{reads++;return {ready:true};};await publicSourceStatus(a,1000,load);await publicSourceStatus(b,1001,load);assert.equal(reads,1);
 invalidatePublicSourceStatus(b);await assert.rejects(()=>publicSourceStatus(a,1002,()=>{throw Error('Public source unavailable');}));await publicSourceStatus(b,1003,load);assert.equal(reads,2);
});
test('a stale source selection cannot fetch again after another worker advances its schedule',async()=>{
 const e=env(),now=Date.now(),prepare=e.DB.prepare.bind(e.DB);let fetched=0;
 e.DB.prepare=sql=>{if(sql.startsWith('UPDATE cvie_sources SET last_attempt_at'))e.DB.sql.prepare("UPDATE cvie_sources SET next_attempt_at=? WHERE id='cisa_kev'").run(now+1e6);return prepare(sql);};
 assert.equal((await refreshEvidence(e,async()=>{fetched++;throw Error('Unexpected provider call');},now)).busy,true);assert.equal(fetched,0);
});
