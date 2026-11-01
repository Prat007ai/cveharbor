import test from 'node:test';
import assert from 'node:assert/strict';
import {DB} from './helpers/d1.mjs';
import {cvieReady,subscribeProducts,syncAccountProducts,runCvieStep,cvieRoute,normalizeNvd,monthsAgo,scanWindows,loadCvieDigest} from '../src/cvie.js';
import {knownIdentity,productCpe,logoFor} from '../src/product-identity.js';
import worker from '../src/index.js';

const NOW=Date.parse('2026-11-01T12:00:00Z'),DAY=86400000;
const env=()=>({DB:new DB()}),rows=(e,sql,...args)=>e.DB.prepare(sql).bind(...args).all().then(x=>x.results);
const first=e=>e.DB.prepare('SELECT * FROM cvie_products ORDER BY id LIMIT 1').first();
const cpe=knownIdentity('Apache Tomcat').cpe;
function cve(id='CVE-2026-12345',date='2026-09-01T00:00:00.000Z'){
 return {id,published:date,lastModified:date,vulnStatus:'Analyzed',descriptions:[{lang:'en',value:'Fixture advisory for product identity and version range tests.'}],
  metrics:{cvssMetricV31:[{cvssData:{baseScore:8.1,baseSeverity:'HIGH'}}]},
  configurations:[{nodes:[{operator:'OR',cpeMatch:[{vulnerable:true,criteria:cpe,versionStartIncluding:'10.1.0',versionEndExcluding:'10.1.30'}]}]}],
  references:[{url:'https://tomcat.apache.org/security.html',tags:['Vendor Advisory']},{url:'javascript:alert(1)'}]};
}
function provider(records=[],pageSize=50){
 return async url=>{
  const u=new URL(url),start=Date.parse(u.searchParams.get('pubStartDate')),end=Date.parse(u.searchParams.get('pubEndDate')),index=Number(u.searchParams.get('startIndex'));
  assert.equal(u.origin,'https://services.nvd.nist.gov');assert.ok(end-start<=120*DAY);
  const matching=records.filter(x=>Date.parse(x.published)>=start&&Date.parse(x.published)<=end);
  return Response.json({startIndex:index,totalResults:matching.length,vulnerabilities:matching.slice(index,index+pageSize).map(x=>({cve:x}))});
 };
}
async function complete(e,fetcher,now=NOW){for(let i=0;i<30;i++){const result=await runCvieStep(e,fetcher,now+i*7000);if(result.complete)return;}throw Error('Scan did not complete');}
test('three and twelve month calendar boundaries include leap years and short months',()=>{
 assert.equal(new Date(monthsAgo(Date.parse('2024-05-31T12:00:00Z'),3)).toISOString(),'2024-02-29T12:00:00.000Z');
 const windows=scanWindows(NOW);assert.equal(windows[0].end,NOW);assert.equal(windows.at(-1).start,monthsAgo(NOW,12));
 for(let i=1;i<windows.length;i++)assert.equal(windows[i].end,windows[i-1].start-1);
});
test('known identities and registered logos are safe; unknown names do not become invented CPEs',()=>{
 assert.match(cpe,/:apache:tomcat:/);assert.equal(knownIdentity('An invented product'),null);
 assert.equal(productCpe('https://internal.example/'),null);assert.equal(productCpe(cpe.replace(':*:',':10.1:')),null);
 assert.equal(logoFor('Grafana'),'grafana');assert.equal(logoFor('An invented product'),'');assert.equal(logoFor('Apache Tomcat'),'apachetomcat');
});
test('normalization requires vulnerable affected-product CPE evidence and excludes rejected CVEs',()=>{
 const product={name:'Apache Tomcat',cpe};
 const result=normalizeNvd(cve(),product);assert.equal(result.cvss,8.1);assert.equal(result.severity,'high');assert.equal(result.known_exploited,false);
 assert.equal(result.sources.length,2);assert.deepEqual(result.cvie_identities,[{name:'Apache Tomcat',cpe}]);
 assert.equal(normalizeNvd({...cve(),configurations:[]},product),null);
 assert.equal(normalizeNvd({...cve(),vulnStatus:'Rejected'},product),null);
 const other=cve();other.configurations[0].nodes[0].cpeMatch[0].vulnerable=false;assert.equal(normalizeNvd(other,product),null);
});
test('subscription changes are private, idempotent, and inventory/catalogue share one job per product',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'},{name:' apache tomcat '}]);
 await subscribeProducts(e,'a',[{name:'Apache Tomcat'}],'inventory');
 assert.equal((await rows(e,'SELECT * FROM cvie_products')).length,1);
 await subscribeProducts(e,'b',[{name:'Apache Tomcat'}]);assert.equal((await rows(e,'SELECT * FROM cvie_products')).length,2);
 await subscribeProducts(e,'a',[]);assert.equal((await rows(e,"SELECT * FROM cvie_subscriptions WHERE user_id='a'")).length,1);
});
test('legacy assets and watchlists are registered without modifying customer inventory',async()=>{
 const e=env();e.DB.sql.exec(`INSERT INTO inventory_assets VALUES('a','Apache Tomcat');INSERT INTO user_stack VALUES('a','PHP');INSERT INTO user_technology_catalogue VALUES('a','{"products":[{"name":"PostgreSQL"}]}',0);`);
 await syncAccountProducts(e,'a');assert.equal((await rows(e,'SELECT * FROM cvie_products')).length,3);
 assert.equal((await rows(e,'SELECT * FROM inventory_assets')).length,1);
});
test('history scans prioritize three months, resume pagination, and only finish after every window',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);
 const records=[cve(),cve('CVE-2026-12346'),cve('CVE-2026-12347','2026-02-01T00:00:00Z')],fetcher=provider(records,1);
 await runCvieStep(e,fetcher,NOW);
 let p=await first(e);assert.equal(p.status,'scanning');assert.equal(p.recent_complete_at,null);assert.equal(JSON.parse(p.cursor_json).windows[0].index,1);
 await runCvieStep(e,fetcher,NOW+7000);p=await first(e);assert.ok(p.recent_complete_at);assert.equal(p.history_complete_at,null);
 await complete(e,fetcher,NOW+14000);p=await first(e);assert.equal(p.status,'ready');assert.ok(p.history_complete_at);
 assert.equal((await rows(e,'SELECT * FROM cvie_advisories')).length,3);
});
test('a full fifty-record NVD page is saved transactionally and the next page is not skipped',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);
 const fetcher=provider(Array.from({length:51},(_,i)=>cve('CVE-2026-'+(20000+i))));
 await runCvieStep(e,fetcher,NOW);assert.equal((await rows(e,'SELECT * FROM cvie_advisories')).length,50);
 await runCvieStep(e,fetcher,NOW+7000);assert.equal((await rows(e,'SELECT * FROM cvie_advisories')).length,51);
 assert.ok((await first(e)).recent_complete_at);
});
test('an in-flight response cannot contaminate a corrected product identity',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);
 const newCpe=cpe.replace(':tomcat:',':http_server:');
 await runCvieStep(e,async url=>{
  await subscribeProducts(e,'a',[{name:'Apache Tomcat',cpe:newCpe}]);
  return provider([cve()])(url);
 },NOW);
 assert.equal((await first(e)).cpe,newCpe);assert.equal((await first(e)).status,'queued');
 assert.equal((await rows(e,'SELECT * FROM cvie_advisories')).length,0);
});
test('empty completed checks differ from failed checks, and failures preserve the last successful results',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);await complete(e,provider());
 let p=await first(e);assert.equal(p.status,'ready');assert.ok(p.history_complete_at);
 await runCvieStep(e,async()=>new Response('Unavailable',{status:503}),NOW+7*3600000);
 p=await first(e);assert.equal(p.status,'retrying');assert.ok(p.history_complete_at);assert.match(p.error,/unavailable/);
});
test('rate limits back off globally and never claim a failed source window was checked',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);
 await runCvieStep(e,async()=>new Response('Slow down',{status:429,headers:{'Retry-After':'120'}}),NOW);
 const p=await first(e);assert.equal(p.last_success_at,null);assert.equal(p.recent_complete_at,null);assert.ok(p.next_attempt_at>=NOW+120000);
 let calls=0;await runCvieStep(e,async()=>{calls++;return Response.json({});},NOW+7000);assert.equal(calls,0);
});
test('parallel workers cannot consume two NVD requests in the same provider slot',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'},{name:'PHP'}]);let calls=0;
 const fetcher=async url=>{calls++;return provider()(url);};
 await Promise.all([runCvieStep(e,fetcher,NOW),runCvieStep(e,fetcher,NOW)]);assert.equal(calls,1);
});
test('ambiguous directory responses require an account-owned exact selection',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Example product'}]);
 const cpe2=cpe.replace(':tomcat:',':http_server:');
 await runCvieStep(e,async()=>Response.json({totalResults:2,products:[{cpe:{cpeName:cpe}},{cpe:{cpeName:cpe2}}]}),NOW);
 const p=await first(e);assert.equal(p.status,'needs_identity');assert.equal(p.cpe,'');
 const req=new Request('https://api.cveharbor.com/v1/cvie/products/'+p.id+'/identity',{method:'PUT'});
 await assert.rejects(()=>cvieRoute(req,e,{id:'b'},null,{cpe}),error=>error.status===404);
 await assert.rejects(()=>cvieRoute(req,e,{id:'a'},null,{cpe:cpe.replace(':apache:',':other:')}),error=>error.status===400);
 assert.equal((await cvieRoute(req,e,{id:'a'},null,{cpe})).status,202);
});
test('partial product-directory results are not treated as a unique identity',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Example product'}]);
 await runCvieStep(e,async()=>Response.json({totalResults:1000,products:[{cpe:{cpeName:cpe}}]}),NOW);
 assert.equal((await first(e)).status,'needs_identity');
});
test('advisory routes enforce account ownership and the selected calendar horizon',async t=>{
 t.mock.timers.enable({apis:['Date'],now:NOW});
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);await complete(e,provider([cve(),cve('CVE-2026-12346','2026-02-01T00:00:00Z')]));
 const req=n=>new Request('https://api.cveharbor.com/v1/cvie/advisories?months='+n);
 assert.equal((await (await cvieRoute(req(3),e,{id:'a'})).json()).advisories.length,1);
 assert.equal((await (await cvieRoute(req(12),e,{id:'a'})).json()).advisories.length,2);
 assert.equal((await (await cvieRoute(req(12),e,{id:'b'})).json()).advisories.length,0);
 await assert.rejects(()=>cvieRoute(req(99),e,{id:'a'}),error=>error.status===400);
});
test('the real authenticated catalogue save queues CVIE immediately without waiting for hourly collection',async t=>{
 const e=env(),token='a'.repeat(64),digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token));
 const hash=[...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,'0')).join('');
 e.DB.sql.prepare('INSERT INTO sessions VALUES(?,?,?,?)').run('session','a',hash,Math.floor(Date.now()/1000)+3600);
 e.DB.sql.exec("INSERT INTO user_totp VALUES('a',1)");
 t.mock.method(globalThis,'fetch',provider());const pending=[];
 const request=new Request('https://api.cveharbor.com/v1/technology-catalogue',{method:'PUT',
  headers:{Origin:'https://cveharbor.com',Cookie:'cvh_session='+token,'Content-Type':'application/json'},
  body:JSON.stringify({defaults:[],products:[{name:'Apache Tomcat',version:'10.1.20'}]})});
 const response=await worker.fetch(request,e,{waitUntil:p=>pending.push(p)});
 assert.equal(response.status,200);assert.equal((await response.json()).cvie.ready,true);
 await Promise.all(pending);assert.equal((await first(e)).name,'Apache Tomcat');
 assert.equal((await rows(e,'SELECT * FROM inventory_assets')).length,0,'catalogue save never creates customer inventory');
});
test('email intelligence is account scoped and flags unfinished product coverage',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'Apache Tomcat'}]);
 await runCvieStep(e,provider([cve('CVE-2026-55555','2026-10-25T00:00:00Z')]),NOW);
 const a=await loadCvieDigest(e,'a',NOW),b=await loadCvieDigest(e,'b',NOW);
 assert.equal(a.records.length,1);assert.equal(a.degraded,true);assert.equal(b.records.length,0);
});
test('CVIE data is not exposed before the existing account login check',async()=>{
 const result=await worker.fetch(new Request('https://api.cveharbor.com/v1/cvie'),env(),{});assert.equal(result.status,401);
});
test('a missing additive migration reports setup required rather than breaking existing accounts',async()=>{
 const e={DB:{prepare(){throw Error('no such table')}}};assert.equal(await cvieReady(e),false);
 assert.equal((await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie'),e,{id:'a'})).status,503);
 assert.equal((await subscribeProducts(e,'a',[{name:'Apache Tomcat'}])).ready,false);
});
