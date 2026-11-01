import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DB} from './helpers/d1.mjs';
import {subscribeProducts,runCvieStep,cvieRoute,normalizeNvd,loadCvieDigest} from '../src/cvie.js';
import {combinedPage} from '../src/cvie-records.js';
import {sharedDescriptor,reconcileSharedScopes,seedSharedHistory} from '../src/shared-scopes.js';
import {coveragePlan,coverageMetadata} from '../src/product-coverage.js';
const NOW=Date.parse('2026-11-01T18:00:00Z'),CPE='cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*';
const env=()=>({DB:new DB(),CVIE_SHARED_SCANS_ENABLED:'true'}),q=(e,sql,...a)=>e.DB.prepare(sql).bind(...a);
const product=name=>({name,cpe:CPE});
const check=(name,fn)=>test(name,async t=>{t.mock.timers.enable({apis:['Date'],now:NOW});await fn(t);});
const state=(e,id='a',path='/v1/cvie')=>cvieRoute(new Request('https://api.cveharbor.com'+path),e,{id}).then(r=>r.json());
const empty=()=>Response.json({startIndex:0,totalResults:0,vulnerabilities:[]});
const raw=(id='CVE-2026-12345')=>({id,published:'2026-10-15T00:00:00Z',lastModified:'2026-10-20T00:00:00Z',vulnStatus:'Analyzed',
 descriptions:[{lang:'en',value:'Public Apache Tomcat advisory fixture.'}],metrics:{cvssMetricV31:[{cvssData:{baseScore:8.1}}]},
 configurations:[{nodes:[{cpeMatch:[{vulnerable:true,criteria:CPE,versionStartIncluding:'10.1.0',versionEndExcluding:'10.1.99'}]}]}]});
const one=()=>Response.json({startIndex:0,totalResults:1,vulnerabilities:[{cve:raw()}]});
async function finish(e){for(let i=0;i<20;i++){const r=await runCvieStep(e,i===0?one:empty,NOW+i*7000);if(r.complete)return;}throw Error('Shared fixture did not complete');}
check('one hundred accounts share one source job and public advisory copy, with private aliases preserved only in responses',async()=>{
 const e=env();
 for(let i=0;i<100;i++){const id='tenant-'+i;await q(e,'INSERT INTO users VALUES(?,?)',id,id+'@example.test').run();await subscribeProducts(e,id,[product('Private stack '+i)]);}
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_shared_scopes').first()).n,1);
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_product_scopes').first()).n,100);
 let calls=0;await runCvieStep(e,()=>{calls++;return one();},NOW,'tenant-0');assert.equal(calls,1);
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_shared_advisories').first()).n,1);
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_advisories').first()).n,0,'new records are not copied into every account');
 for(const i of [0,1,99]){
  const page=await combinedPage(e,'tenant-'+i,'2026-08-01T00:00:00Z');assert.equal(page.advisories.length,1);
  assert.deepEqual(page.advisories[0].categories,['Private stack '+i]);assert.ok(page.advisories[0].cvie_identities.every(p=>p.name==='Private stack '+i));
  assert.equal((await state(e,'tenant-'+i)).products[0].progress.windows_complete,1);
 }
 const publicData=JSON.stringify((await q(e,'SELECT * FROM cvie_shared_scopes').all()).results)+JSON.stringify((await q(e,'SELECT * FROM cvie_shared_advisories').all()).results);
 assert.doesNotMatch(publicData,/Private stack|tenant-/);
 assert.equal((await combinedPage(e,'a','2026-08-01T00:00:00Z')).advisories.length,0);
});
check('new subscribers reuse completed history without resetting its cursor, due time or provider budget',async()=>{
 const e=env();await subscribeProducts(e,'a',[product('First private alias')]);await finish(e);
 const before=await q(e,'SELECT * FROM cvie_shared_scopes').first(),budget=await q(e,'SELECT * FROM cvie_provider_budget').first();
 await subscribeProducts(e,'b',[product('Second private alias')]);
 assert.deepEqual(await q(e,'SELECT * FROM cvie_shared_scopes').first(),before);
 assert.deepEqual(await q(e,'SELECT * FROM cvie_provider_budget').first(),budget);
 let calls=0;await runCvieStep(e,()=>{calls++;return empty();},NOW+150000,'b');assert.equal(calls,0);
 const b=await state(e,'b');assert.equal(b.products[0].status,'ready');assert.equal(b.products[0].recent_count,1);
 const digest=await loadCvieDigest(e,'b',NOW+150000);assert.equal(digest.records[0].id,raw().id);assert.deepEqual(digest.records[0].categories,['Second private alias']);
});
check('scope identity includes affected family, modern .NET group and Hyper-V component filtering',async()=>{
 const host='cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*';
 assert.notEqual((await sharedDescriptor({name:'HyperV',cpe:host})).id,(await sharedDescriptor({name:'Windows Server 2022',cpe:host})).id);
 assert.equal((await sharedDescriptor({name:'.NET Core',cpe:'cpe:2.3:a:microsoft:.net_core:*:*:*:*:*:*:*:*'})).id,(await sharedDescriptor({name:'Microsoft .NET Core',cpe:'cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*'})).id);
 assert.equal((await sharedDescriptor(product('My custom name'))).id,(await sharedDescriptor(product('Apache Tomcat'))).id);
 assert.equal(await sharedDescriptor({name:'Unresolved private technology',vendor:'Example'}),null);
 assert.equal(await sharedDescriptor({...product('Conflicting vendor'),vendor:'Other vendor'}),null);
});
check('parallel subscribers cannot fetch the same page twice and changing one identity does not cancel another customer scan',async()=>{
 const e=env();await subscribeProducts(e,'a',[product('Stack')]);await subscribeProducts(e,'b',[product('Stack')]);let calls=0,release;
 const running=runCvieStep(e,async()=>{calls++;await new Promise(r=>{release=r;});return one();},NOW,'a');
 while(!release)await new Promise(r=>setImmediate(r));
 await runCvieStep(e,()=>{calls++;return one();},NOW,'b');assert.equal(calls,1);
 await subscribeProducts(e,'a',[{name:'Stack',cpe:'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*'}]);release();await running;
 assert.equal((await combinedPage(e,'a','2026-08-01T00:00:00Z')).advisories.length,0);
 assert.equal((await combinedPage(e,'b','2026-08-01T00:00:00Z')).advisories.length,1);
});
check('legacy history is sanitized, imported in resumable pages and never deleted from the original account cache',async()=>{
 const e=env();e.CVIE_SHARED_SCANS_ENABLED='false';await subscribeProducts(e,'a',[product('Customer secret stack')]);
 const p=await q(e,'SELECT * FROM cvie_products').first(),plan=coveragePlan(p);
 await q(e,"UPDATE cvie_products SET status='ready',cursor_json=?,last_success_at=?,recent_complete_at=?,history_complete_at=?,next_attempt_at=?",JSON.stringify(coverageMetadata(plan)),NOW,NOW,NOW,NOW+21600000).run();
 for(let i=0;i<150;i++){const r=normalizeNvd(raw('CVE-2026-'+(10000+i)),p);await q(e,'INSERT INTO cvie_advisories VALUES(?,?,?,?,?)',p.id,r.id,r.published,JSON.stringify(r),'old-account-generation').run();}
 e.CVIE_SHARED_SCANS_ENABLED='true';await reconcileSharedScopes(e);
 let scope=await q(e,'SELECT * FROM cvie_shared_scopes').first();assert.equal(scope.seed_state,'pending');
 const first=await seedSharedHistory(e,scope,normalizeNvd,NOW);assert.equal(first.seeded,100);assert.equal(first.seed_complete,false);
 scope=await q(e,'SELECT * FROM cvie_shared_scopes').first();const last=await seedSharedHistory(e,scope,normalizeNvd,NOW+1);assert.equal(last.seed_complete,true);
 assert.equal((await q(e,'SELECT * FROM cvie_shared_scopes').first()).status,'ready');
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_shared_advisories').first()).n,150);
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_advisories').first()).n,150);
 assert.doesNotMatch(JSON.stringify((await q(e,'SELECT * FROM cvie_shared_advisories').all()).results),/Customer secret|old-account-generation/);
 await subscribeProducts(e,'b',[product('Other customer name')]);
 const page=await combinedPage(e,'b','2026-08-01T00:00:00Z');assert.equal(page.advisories.length,100);assert.ok(page.next);
});
check('unresolved product searches stay private and a resolved identity attaches to an existing public job',async()=>{
 const e=env();await subscribeProducts(e,'a',[product('Apache Tomcat')]);await subscribeProducts(e,'b',[{name:'Tomcat'}]);
 // Tomcat is a known exact alias and is resolved before any directory search.
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_shared_scopes').first()).n,1);
 await subscribeProducts(e,'b',[{name:'Internal new technology',vendor:'Example'}]);
 assert.equal((await q(e,"SELECT COUNT(*) AS n FROM cvie_product_scopes WHERE scope_id IS NULL").first()).n,1);
 assert.doesNotMatch(JSON.stringify((await q(e,'SELECT * FROM cvie_shared_scopes').all()).results),/Internal new/);
});
check('unverified custom CPEs remain private until an authoritative directory response confirms the family',async()=>{
 const e=env(),cpe='cpe:2.3:a:example:public_tool:*:*:*:*:*:*:*:*';
 await subscribeProducts(e,'a',[{name:'Secret label A',cpe}]);await subscribeProducts(e,'b',[{name:'Secret label B',cpe}]);
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_shared_scopes').first()).n,0);
 let requests=0;
 await runCvieStep(e,url=>{assert.ok(new URL(url).pathname.includes('/cpes/'));requests++;return Response.json({totalResults:1,startIndex:0,products:[{cpe:{cpeName:cpe}}]});},NOW,'a');
 assert.equal(requests,1);assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_shared_scopes').first()).n,1);
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_product_scopes WHERE scope_id IS NOT NULL').first()).n,2,'confirmed public scopes adopt other waiting private subscriptions without another provider request');
 assert.doesNotMatch(JSON.stringify((await q(e,'SELECT * FROM cvie_shared_scopes').all()).results),/Secret label/);
});
check('an unfinished source scan keeps its exact saved position when its public history is adopted',async()=>{
 const e=env();e.CVIE_SHARED_SCANS_ENABLED='false';await subscribeProducts(e,'a',[product('Private partial stack')]);await runCvieStep(e,one,NOW);
 const old=await q(e,'SELECT * FROM cvie_products').first(),position=JSON.parse(old.cursor_json).position;
 e.CVIE_SHARED_SCANS_ENABLED='true';await reconcileSharedScopes(e,null,NOW+1);
 const scope=await q(e,'SELECT * FROM cvie_shared_scopes').first();await seedSharedHistory(e,scope,normalizeNvd,NOW+1);
 const current=await q(e,'SELECT * FROM cvie_shared_scopes').first();assert.equal(JSON.parse(current.cursor_json).position,position);
 assert.equal(current.status,'scanning');let calls=0;
 await runCvieStep(e,url=>{calls++;assert.ok(new URL(url).searchParams.has('keywordSearch'),'resume the next discovery window, not the first CPE history window');return empty();},NOW+7000);
 assert.equal(calls,1);assert.equal((await state(e)).products[0].progress.windows_complete,position+1);
});
check('removing an account or its subscription does not remove shared evidence used by another account',async()=>{
 const e=env();await subscribeProducts(e,'a',[product('A')]);await subscribeProducts(e,'b',[product('B')]);await runCvieStep(e,one,NOW);
 await q(e,"DELETE FROM users WHERE id='a'").run();
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_shared_advisories').first()).n,1);
 assert.equal((await combinedPage(e,'b','2026-08-01T00:00:00Z')).advisories.length,1);
 await subscribeProducts(e,'b',[]);let requests=0;const result=await runCvieStep(e,()=>{requests++;return one();},NOW+7000);
 assert.equal(result.idle,true);assert.equal(requests,0,'unwatched public scopes do not keep scanning');
});
check('a fresh shared refresh keeps saved results until completion, then applies cleanup for every subscriber',async()=>{
 const e=env();await subscribeProducts(e,'a',[product('A')]);await subscribeProducts(e,'b',[product('B')]);await finish(e);
 let complete=false;
 for(let i=0;i<20;i++){
  const result=await runCvieStep(e,()=>i===0?Response.json({startIndex:0,totalResults:1,vulnerabilities:[{cve:raw('CVE-2026-12346')}] }):empty(),NOW+7*3600000+i*7000);
  if(i===0)assert.equal((await combinedPage(e,'b','2026-08-01T00:00:00Z')).advisories.length,2,'the old verified cache survives an unfinished refresh');
  if(result.complete){complete=true;break;}
 }
 assert.ok(complete);
 for(const id of ['a','b'])assert.deepEqual((await combinedPage(e,id,'2026-08-01T00:00:00Z')).advisories.map(r=>r.id),['CVE-2026-12346']);
 await q(e,'INSERT INTO cvie_disclosures VALUES(?,?,?,?,?,?)','CVE-2026-12346','REJECTED',null,'2026-11-01T00:00:00Z','{}',NOW).run();
 for(const id of ['a','b'])assert.equal((await combinedPage(e,id,'2026-08-01T00:00:00Z')).advisories.length,0,'original source withdrawals override shared NVD evidence');
});
check('a missing migration donor cannot leave an incomplete public import marked complete',async()=>{
 const e=env();e.CVIE_SHARED_SCANS_ENABLED='false';await subscribeProducts(e,'a',[product('Private donor')]);await runCvieStep(e,one,NOW);
 e.CVIE_SHARED_SCANS_ENABLED='true';await reconcileSharedScopes(e,null,NOW+1);await subscribeProducts(e,'b',[product('B')]);
 await q(e,"DELETE FROM users WHERE id='a'").run();
 await seedSharedHistory(e,await q(e,'SELECT * FROM cvie_shared_scopes').first(),normalizeNvd,NOW+1);
 const scope=await q(e,'SELECT * FROM cvie_shared_scopes').first();assert.equal(scope.seed_state,'complete');assert.equal(scope.status,'queued');assert.equal(scope.history_complete_at,null);
});
check('bulk subscription links use set operations rather than a database write per customer/product',async()=>{
 const e=env();e.DB.executions=0;await subscribeProducts(e,'a',Array.from({length:500},(_,i)=>product('Stack '+i)),'inventory');
 assert.ok(e.DB.executions<=50,'shared bulk registration fits the existing invocation query budget');
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_shared_scopes').first()).n,1);
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_product_scopes').first()).n,500);
});

async function migrationFixture(count=150){
 const e=env();e.CVIE_SHARED_SCANS_ENABLED='false';await subscribeProducts(e,'a',[product('Private migration donor')]);
 const p=await q(e,'SELECT * FROM cvie_products').first();
 await q(e,"UPDATE cvie_products SET status='ready',cursor_json=?,last_success_at=?,recent_complete_at=?,history_complete_at=?,next_attempt_at=? WHERE id=?",JSON.stringify({...coverageMetadata(coveragePlan(p)),generation:'donor-generation'}),NOW,NOW,NOW,NOW+21600000,p.id).run();
 for(let i=0;i<count;i++){const record=normalizeNvd(raw('CVE-2026-'+(20000+i)),p);await q(e,'INSERT INTO cvie_advisories VALUES(?,?,?,?,?)',p.id,record.id,record.published,JSON.stringify(record),'donor-generation').run();}
 e.CVIE_SHARED_SCANS_ENABLED='true';await reconcileSharedScopes(e,null,NOW+1);
 return {e,p,scope:await q(e,'SELECT * FROM cvie_shared_scopes').first()};
}
check('a donor refresh between import pages discards inherited completion and schedules a full public scan',async()=>{
 const {e,p,scope}=await migrationFixture();
 assert.equal((await seedSharedHistory(e,scope,normalizeNvd,NOW+1)).seed_complete,false);
 await q(e,"UPDATE cvie_products SET cursor_json=json_set(cursor_json,'$.generation','replacement-generation') WHERE id=?",p.id).run();
 await seedSharedHistory(e,await q(e,'SELECT * FROM cvie_shared_scopes').first(),normalizeNvd,NOW+2);
 const current=await q(e,'SELECT * FROM cvie_shared_scopes').first();
 assert.equal(current.seed_state,'complete');assert.equal(current.status,'queued');assert.equal(current.history_complete_at,null);assert.equal(current.recent_complete_at,null);assert.equal(current.last_success_at,null);assert.equal(current.next_attempt_at,0);
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_advisories').first()).n,150);
});
check('a donor refresh during the final page cannot commit inherited completion',async()=>{
 const {e,p,scope}=await migrationFixture(1),batch=e.DB.batch.bind(e.DB);
 e.DB.batch=async statements=>{
  await q(e,"UPDATE cvie_products SET cursor_json=json_set(cursor_json,'$.generation','replacement-generation') WHERE id=?",p.id).run();
  return batch(statements);
 };
 await seedSharedHistory(e,scope,normalizeNvd,NOW+1);
 const current=await q(e,'SELECT * FROM cvie_shared_scopes').first();assert.equal(current.status,'queued');assert.equal(current.history_complete_at,null);assert.equal(current.last_success_at,null);
});
check('an interrupted import rolls back its page and resumes without missing or duplicating evidence',async()=>{
 const {e,scope}=await migrationFixture(),batch=e.DB.batch.bind(e.DB);
 e.DB.batch=statements=>batch([...statements,q(e,"INSERT INTO users VALUES('a','duplicate@example.test')")]);
 await assert.rejects(seedSharedHistory(e,scope,normalizeNvd,NOW+1));
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_shared_advisories').first()).n,0);
 assert.equal((await q(e,'SELECT after_cve FROM cvie_shared_seeds').first()).after_cve,'');
 e.DB.batch=batch;
 assert.equal((await seedSharedHistory(e,scope,normalizeNvd,NOW+2)).busy,true);
 await seedSharedHistory(e,scope,normalizeNvd,NOW+120002);
 await seedSharedHistory(e,await q(e,'SELECT * FROM cvie_shared_scopes').first(),normalizeNvd,NOW+120003);
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_shared_advisories').first()).n,150);
 assert.equal((await q(e,'SELECT * FROM cvie_shared_scopes').first()).status,'ready');
});
check('a replaced import lease blocks stale evidence writes and cursor completion',async()=>{
 const {e,scope}=await migrationFixture(1),batch=e.DB.batch.bind(e.DB);
 e.DB.batch=async statements=>{
  await q(e,"UPDATE cvie_shared_scopes SET cursor_json=json_set(cursor_json,'$.active_scan','new-owner'),lease_until=? WHERE id=?",NOW+240000,scope.id).run();
  return batch(statements);
 };
 await seedSharedHistory(e,scope,normalizeNvd,NOW+1);
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_shared_advisories').first()).n,0);
 const current=await q(e,'SELECT * FROM cvie_shared_scopes').first();assert.equal(current.seed_state,'pending');assert.equal(JSON.parse(current.cursor_json).active_scan,'new-owner');
 assert.equal((await q(e,'SELECT after_cve FROM cvie_shared_seeds').first()).after_cve,'');
});
check('retrying the additive schema preserves shared evidence and private bridges',async()=>{
 const {e,scope}=await migrationFixture(1);await seedSharedHistory(e,scope,normalizeNvd,NOW+1);
 const before={scopes:(await q(e,'SELECT * FROM cvie_shared_scopes').all()).results,links:(await q(e,'SELECT * FROM cvie_product_scopes').all()).results,records:(await q(e,'SELECT * FROM cvie_shared_advisories').all()).results};
 e.DB.sql.exec(fs.readFileSync(new URL('../migrations/0022_cvie_shared_scans.sql',import.meta.url),'utf8'));
 assert.deepEqual({scopes:(await q(e,'SELECT * FROM cvie_shared_scopes').all()).results,links:(await q(e,'SELECT * FROM cvie_product_scopes').all()).results,records:(await q(e,'SELECT * FROM cvie_shared_advisories').all()).results},before);
 assert.deepEqual(e.DB.sql.prepare('PRAGMA foreign_key_check').all(),[]);
});
for(const mutation of ['malformed record','changed identity'])check('migration recovers safely from '+mutation,async()=>{
 const {e,p,scope}=await migrationFixture(1);
 if(mutation==='malformed record')await q(e,"UPDATE cvie_advisories SET record_json='invalid json' WHERE product_id=?",p.id).run();
 else await q(e,"UPDATE cvie_products SET name='Changed private label' WHERE id=?",p.id).run();
 await seedSharedHistory(e,scope,normalizeNvd,NOW+1);
 const current=await q(e,'SELECT * FROM cvie_shared_scopes').first();assert.equal(current.status,'queued');assert.equal(current.last_success_at,null);assert.equal(current.history_complete_at,null);
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_advisories').first()).n,1);
 assert.equal((await q(e,'SELECT COUNT(*) AS n FROM cvie_shared_advisories').first()).n,0);
});

