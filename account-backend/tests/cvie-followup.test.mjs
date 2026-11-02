import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DB} from './helpers/d1.mjs';
import {subscribeProducts,cvieRoute} from '../src/cvie.js';
import {immediateEvidence,bindProductIdentities} from '../src/cvie-onboarding.js';
import {publicKevCatalogue,invalidateKevCatalogue,KEV_CATALOGUE_TTL,refreshEvidence} from '../src/cvie-evidence.js';
import {searchRegistry} from '../src/product-registry.js';
const env=()=>{const DBi=new DB();for(const f of ['0028_cvie_source_efficiency.sql','0029_cvie_identity_registry.sql'])DBi.sql.exec(fs.readFileSync(new URL('../migrations/'+f,import.meta.url),'utf8'));return {DB:DBi,CVIE_SHARED_SCANS_ENABLED:'true',CVIE_REGISTRY_ENABLED:'true',CVIE_FAST_EVIDENCE_ENABLED:'true'};};
const q=(e,sql,...args)=>e.DB.prepare(sql).bind(...args);
const kev={cveID:'CVE-2026-12345',dateAdded:'2026-01-01',vendorProject:'PHP',product:'PHP'};
const addKev=e=>q(e,'INSERT INTO cvie_kev VALUES(?,?,?,?,?,?)',kev.cveID,kev.dateAdded,'PHP','PHP',JSON.stringify(kev),0).run();
async function addDisclosure(e,id='CVE-2026-12345',state='PUBLISHED',affected=[{vendor:'php',product:'php',versions:[{version:'1',lessThan:'9',status:'affected'}]}]){
 const date=new Date().toISOString();await q(e,'INSERT INTO cvie_disclosures VALUES(?,?,?,?,?,?)',id,state,date,date,JSON.stringify({id,published:date,updated:date,cvss:7,severity:'high',sources:[]}),Date.now()).run();
 await q(e,'INSERT INTO cvie_disclosure_products VALUES(?,?,?,?)',id,'cpe:cpe:2.3:a:php:php:*:*:*:*:*:*:*:*','affected',JSON.stringify(affected)).run();return date;
}
test('public KEV cache coalesces concurrent reads, expires, isolates bindings and retries failures',async()=>{
 const e=env();await addKev(e);const prepare=e.DB.prepare.bind(e.DB);let reads=0,fail=false;
 e.DB.prepare=sql=>{if(sql==='SELECT record_json FROM cvie_kev'){reads++;if(fail)throw Error('Fixture failure');}return prepare(sql);};
 await Promise.all(Array.from({length:50},()=>publicKevCatalogue(e,100)));assert.equal(reads,1);
 await publicKevCatalogue({...e,DB:{},CVIE_UNWRAPPED_DB:e.DB},101);assert.equal(reads,1);
 assert.deepEqual(await publicKevCatalogue(env(),101),[]);
 await publicKevCatalogue(e,100+KEV_CATALOGUE_TTL);assert.equal(reads,2);
 invalidateKevCatalogue(e);fail=true;await assert.rejects(publicKevCatalogue(e,200));fail=false;
 assert.equal((await publicKevCatalogue(e,201))[0].cveID,kev.cveID);assert.equal(reads,4);
});
test('successful authoritative KEV replacement invalidates the cached public catalogue',async()=>{
 const e=env();await addKev(e);assert.equal((await publicKevCatalogue(e)).length,1);
 const now=Date.now();await q(e,"UPDATE cvie_sources SET next_attempt_at=? WHERE id='cve_program'",now+1e6).run();
 const next={...kev,cveID:'CVE-2026-54321'};
 assert.equal((await refreshEvidence(e,async()=>Response.json({dateReleased:new Date(now).toISOString(),count:1,vulnerabilities:[next]}),now)).ok,true);
 assert.deepEqual((await publicKevCatalogue(e)).map(x=>x.cveID),[next.cveID]);
});
test('product/subscription batch remains atomic when a statement fails after insertion',async()=>{
 const e=env(),batch=e.DB.batch.bind(e.DB);let calls=0;
 e.DB.batch=stmts=>batch(++calls===2?[...stmts,q(e,"INSERT INTO users VALUES('a','duplicate')")]:stmts);
 await assert.rejects(subscribeProducts(e,'a',[{name:'PHP'}]));
 assert.equal((await q(e,'SELECT COUNT(*) n FROM cvie_products').first()).n,0);
 assert.equal((await q(e,'SELECT COUNT(*) n FROM cvie_subscriptions').first()).n,0);
});
test('private identity bindings are reused and shared cleanup leaves unrelated account leases intact',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'PHP'}]);await subscribeProducts(e,'b',[{name:'Python'}]);
 await q(e,"UPDATE cvie_products SET lease_until=123 WHERE user_id='b'").run();
 const before=e.DB.sql.prepare('SELECT total_changes() n').get().n;await bindProductIdentities(e,'a');assert.equal(e.DB.sql.prepare('SELECT total_changes() n').get().n,before);
 await subscribeProducts(e,'a',[{name:'PHP'},{name:'Python'}]);assert.equal((await q(e,"SELECT lease_until FROM cvie_products WHERE user_id='b'").first()).lease_until,123);
});
test('initial association stores its correct page key without a second projection update',async()=>{
 const e=env();e.DB.sql.exec('CREATE TABLE projection_updates(n INTEGER); INSERT INTO projection_updates VALUES(0); CREATE TRIGGER count_projection_update AFTER UPDATE ON cvie_identity_evidence BEGIN UPDATE projection_updates SET n=n+1; END;');
 const date=await addDisclosure(e);assert.equal((await q(e,'SELECT sort_date FROM cvie_identity_evidence').first()).sort_date,date);
 assert.equal((await q(e,'SELECT n FROM projection_updates').first()).n,0);
 await q(e,"UPDATE cvie_disclosures SET state='REJECTED' WHERE cve_id=?",kev.cveID).run();assert.equal((await q(e,'SELECT sort_date FROM cvie_identity_evidence').first()).sort_date,'');
 await q(e,"UPDATE cvie_disclosures SET state='PUBLISHED' WHERE cve_id=?",kev.cveID).run();assert.equal((await q(e,'SELECT sort_date FROM cvie_identity_evidence').first()).sort_date,date);
 const plan=e.DB.sql.prepare("EXPLAIN QUERY PLAN SELECT cve_id FROM cvie_disclosures WHERE state='REJECTED'").all();assert.ok(plan.some(p=>p.detail.includes('cvie_disclosure_state')));
});
test('feature rollback preserves private data/checkpoints, maintains projection on new source data and never revives rejected CVEs',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'PHP'}]);await q(e,"UPDATE cvie_sources SET checkpoint=123,status='ok' WHERE id='cve_program'").run();
 await q(e,"INSERT INTO user_technology_catalogue VALUES('a',?,0)",JSON.stringify({defaults:['PHP'],products:[]})).run();
 const snapshots=()=>JSON.stringify(['cvie_products','cvie_subscriptions','cvie_product_scopes','user_technology_catalogue','cvie_sources'].map(t=>e.DB.sql.prepare('SELECT * FROM '+t).all()));
 const before=snapshots(),off={...e,CVIE_REGISTRY_ENABLED:'false',CVIE_FAST_EVIDENCE_ENABLED:'false',CVIE_METRICS_ENABLED:'false'};
 const date=await addDisclosure(off);await addDisclosure(off,'CVE-2026-54321','REJECTED');
 const p=await q(e,"SELECT id FROM cvie_products WHERE user_id='a'").first();
 assert.deepEqual(await immediateEvidence(off,'a',p.id),{enabled:false});
 assert.equal((await q(e,"SELECT sort_date FROM cvie_identity_evidence WHERE cve_id=?",kev.cveID).first()).sort_date,date);
 const response=await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie'),off,{id:'a'});assert.equal(response.status,200);assert.equal(snapshots(),before);
 const page=await immediateEvidence(e,'a',p.id);assert.deepEqual(page.advisories.map(x=>x.id),[kev.cveID]);assert.equal(page.coverage,'indexed_partial');assert.equal(page.advisories[0].applicability,'requires_version_review');
});
test('unknown identities, vendor conflicts and spelling suggestions do not create speculative shared history jobs',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Durpal CMS'},{name:'PHP',vendor:'Microsoft'},{name:'SQL'},{name:'Private Tool'}]);
 assert.equal((await q(e,'SELECT COUNT(*) n FROM cvie_shared_scopes').first()).n,0);
 for(const p of (await q(e,'SELECT * FROM cvie_products').all()).results){assert.equal(p.status,'needs_identity');assert.equal((await immediateEvidence(e,'a',p.id)).coverage,'identity_required');}
 assert.equal(searchRegistry({q:'Durpal CMS'}).identity,null);assert.equal(searchRegistry({q:'Durpal CMS'}).candidates[0].id,'drupal');
});

test('authenticated save and stored CVEs finish while the first external discovery is still pending',async t=>{
 const {default:worker}=await import('../src/index.js');const e=env();await addDisclosure(e);
 const token='a'.repeat(64),hash=Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token))).toString('hex');
 await q(e,"INSERT INTO user_totp VALUES('a',1)").run();await q(e,'INSERT INTO sessions VALUES(?,?,?,?)','fixture','a',hash,Math.floor(Date.now()/1000)+3600).run();
 const background=[];let requested=false,release;const pending=new Promise(resolve=>release=resolve);
 t.mock.method(globalThis,'fetch',()=>{requested=true;return pending;});
 const request=(method,path,data)=>new Request('https://api.cveharbor.com'+path,{method,headers:{Origin:'https://cveharbor.com',Cookie:'cvh_session='+token,'Content-Type':'application/json'},...(data?{body:JSON.stringify(data)}:{})});
 try{
  const saved=await worker.fetch(request('PUT','/v1/technology-catalogue',{defaults:['PHP'],products:[]}),e,{waitUntil(p){background.push(p)}});assert.equal(saved.status,200);assert.equal((await saved.json()).cvie.ready,true);
  const p=await q(e,"SELECT id FROM cvie_products WHERE user_id='a'").first();
  const response=await worker.fetch(request('GET','/v1/cvie/products/'+p.id+'/evidence'),e,{}),result=await response.json();
  assert.deepEqual(result.advisories.map(x=>x.id),[kev.cveID]);assert.equal(result.advisories[0].applicability,'requires_version_review');
  for(let i=0;i<20&&!requested;i++)await new Promise(r=>setTimeout(r,1));assert.equal(requested,true);
 }finally{release(new Response('Synthetic provider outage',{status:503}));await Promise.all(background);}
});

test('a stale hydration selection cannot reclaim an advanced or completed checkpoint',async()=>{
 const {runIdentityIndexWork}=await import('../src/cvie-index-maintenance.js');const e=env();
 await q(e,"INSERT INTO cvie_identity_index_jobs(identity_id) VALUES('php')").run();const prepare=e.DB.prepare.bind(e.DB);
 e.DB.prepare=sql=>{if(sql.startsWith('UPDATE cvie_identity_index_jobs SET lease_until'))e.DB.sql.prepare("UPDATE cvie_identity_index_jobs SET cursor_json=?,complete=1,next_attempt_at=123 WHERE identity_id='php'").run('{"phase":"cna","after":"CVE-2026-99999"}');return prepare(sql);};
 assert.equal((await runIdentityIndexWork(e,'php',Date.now(),true)).busy,true);
 const job=await q(e,"SELECT * FROM cvie_identity_index_jobs WHERE identity_id='php'").first();assert.equal(job.complete,1);assert.equal(JSON.parse(job.cursor_json).after,'CVE-2026-99999');assert.equal(job.lease_token,'');
});

test('verified KEV matches do not invalidate source status when the queue is unchanged',async()=>{
 const {publicSourceStatus}=await import('../src/public-source-status-cache.js'),{queueRelevantKev}=await import('../src/cvie-evidence.js');
 const e=env();await addKev(e);await addDisclosure(e);let loads=0;const load=async()=>({checks:++loads});
 await publicSourceStatus(e,100,load);await queueRelevantKev(e,[{name:'PHP',cpe:'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*'}]);
 assert.equal((await publicSourceStatus(e,101,load)).checks,1);
 assert.equal((await q(e,'SELECT COUNT(*) n FROM cvie_disclosure_queue').first()).n,0);
});
