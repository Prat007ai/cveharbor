import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DB} from './helpers/d1.mjs';
import {subscribeProducts,runCvieStep,cvieRoute,normalizeNvd,loadCvieDigest} from '../src/cvie.js';
import {ingestDisclosures} from '../src/cvie-evidence.js';
import {combinedPage,combinedCounts} from '../src/cvie-records.js';
import {isHyperV,hyperVHosts,hyperVHost,hyperVStatement} from '../src/hyperv.js';
const NOW=Date.parse('2026-11-01T12:00:00Z'),cutoff='2026-08-01T00:00:00Z';
const host=hyperVHosts().find(x=>x.label.includes('Server 2022')).cpe;
const q=(e,sql,...args)=>e.DB.prepare(sql).bind(...args),env=()=>({DB:new DB()});
const check=(name,fn)=>test(name,async t=>{t.mock.timers.enable({apis:['Date'],now:NOW});await fn(t);});
const state=(e,user='a')=>cvieRoute(new Request('https://api.cveharbor.com/v1/cvie'),e,{id:user}).then(r=>r.json());
async function select(e){
 const p=await q(e,"SELECT * FROM cvie_products WHERE user_id='a' AND name='HyperV'").first();
 return cvieRoute(new Request('https://api.cveharbor.com/v1/cvie/products/'+p.id+'/identity',{method:'PUT'}),e,{id:'a'},null,{cpe:host});
}
function nvd(id='CVE-2026-12345',summary='Windows Hyper-V security advisory fixture.',cpe=host){
 return {id,published:'2026-10-15T00:00:00Z',lastModified:'2026-10-20T00:00:00Z',vulnStatus:'Analyzed',descriptions:[{lang:'en',value:summary}],
  configurations:[{nodes:[{cpeMatch:[{criteria:cpe,vulnerable:true,versionEndExcluding:'10.0.20348.5499'}]}]}]};
}
function cna(id='CVE-2026-12345',title='Windows Hyper-V security advisory fixture.',product='Windows Server 2022',vendor='Microsoft'){
 return {dataType:'CVE_RECORD',dataVersion:'5.1',cveMetadata:{cveId:id,state:'PUBLISHED',datePublished:'2026-10-15T00:00:00Z',dateUpdated:'2026-10-20T00:00:00Z'},
  containers:{cna:{title,descriptions:[{lang:'en',value:title}],affected:[{vendor,product,defaultStatus:'unaffected',versions:[{version:'10.0.20348.0',lessThan:'10.0.20348.5499',versionType:'custom',status:'affected'}]}]}}};
}
async function store(e,raw){
 await q(e,'INSERT INTO cvie_disclosure_queue(cve_id,revision,priority) VALUES(?,?,0)',raw.cveMetadata.cveId,'').run();
 await ingestDisclosures(e,async()=>Response.json(raw),NOW);
}
check('Hyper-V aliases mean Microsoft Windows only; explicitly different vendors are not overridden',()=>{
 for(const name of ['HyperV','Hyper-V','Hyper V','Windows Hyper-V','Microsoft Hyper-V','Microsoft Windows Hyper-V'])assert.ok(isHyperV({name}));
 assert.ok(isHyperV({name:'HyperV',vendor:'Microsoft Corporation'}));
 for(const name of ['Hypervisor','HyperView','Citrix Hypervisor','Hyper-V Manager'])assert.equal(isHyperV({name}),false);
 assert.equal(isHyperV({name:'HyperV',vendor:'Citrix'}),false);
});
check('every offered Windows host is evidenced by an actual public NVD Hyper-V record',()=>{
 const report=JSON.parse(fs.readFileSync(new URL('../../data/cvie-hyperv-directory-check.json',import.meta.url),'utf8'));
 const verified=new Set();
 for(const record of report.cves.records){
  if(!hyperVStatement(record))continue;
  for(const config of record.configurations||[])for(const node of config.nodes||[])for(const m of node.cpeMatch||[])if(m.vulnerable)verified.add(m.criteria.split(':').slice(0,5).join(':'));
 }
 for(const h of hyperVHosts())assert.ok(verified.has(h.cpe.split(':').slice(0,5).join(':')),h.label);
 assert.equal(hyperVHost('cpe:2.3:o:citrix:hypervisor:*:*:*:*:*:*:*:*'),undefined);
});
check('new Hyper-V subscriptions ask for the Microsoft host without a broad directory request',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'HyperV'}]);
 await runCvieStep(e,()=>{throw Error('No directory lookup should occur');},NOW);
 const p=(await state(e)).products[0];assert.equal(p.status,'needs_identity');assert.equal(p.cpe,'');
 assert.match(p.error,/Windows host/);assert.match(p.identity_prompt,/Windows host/);
 assert.ok(p.candidates.some(h=>h.label==='Microsoft Windows Server 2022 · Hyper-V'));
 assert.ok(p.candidates.every(h=>h.cpe.startsWith('cpe:2.3:o:microsoft:windows_')));
});
check('opening CVIE repairs old choices once and keeps repairs private to the account',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'HyperV'}]);await subscribeProducts(e,'b',[{name:'HyperV'}]);
 await q(e,"UPDATE cvie_products SET status='needs_identity',candidates_json=?",JSON.stringify([{cpe:'cpe:2.3:o:citrix:hypervisor:*:*:*:*:*:*:*:*',label:'citrix / hypervisor'}])).run();
 await state(e);assert.equal((await q(e,"SELECT candidates_json FROM cvie_products WHERE user_id='b'").first()).candidates_json.includes('citrix'),true);
 const before=e.DB.executions;await state(e);const unchanged=e.DB.executions-before;
 assert.equal((await state(e)).products[0].candidates.some(x=>x.label.includes('citrix')),false);
 assert.ok(unchanged<30,'subsequent polls do not repeatedly reset or rewrite the product');
 assert.equal((await select(e)).status,202);
 const p=(await state(e)).products[0];assert.equal(p.cpe,host);assert.equal(p.status,'queued');assert.match(p.identity_label,/Server 2022/);
});
check('legacy unrelated selections cannot be submitted and invalid cached identities are cleared',async()=>{
 const e=env(),bad='cpe:2.3:o:citrix:hypervisor:*:*:*:*:*:*:*:*';await subscribeProducts(e,'a',[{name:'HyperV'}]);
 await q(e,"UPDATE cvie_products SET status='needs_identity',candidates_json=?",JSON.stringify([{cpe:bad,label:'citrix / hypervisor'}])).run();
 const p=await q(e,'SELECT * FROM cvie_products').first();
 await assert.rejects(()=>cvieRoute(new Request('https://api.cveharbor.com/v1/cvie/products/'+p.id+'/identity',{method:'PUT'}),e,{id:'a'},null,{cpe:bad}),/Windows host/);
 await q(e,"UPDATE cvie_products SET cpe=?,status='ready'",bad).run();
 await q(e,"INSERT INTO cvie_advisories VALUES(?,?,?,?,?)",p.id,'CVE-2026-12345',cutoff,JSON.stringify({id:'CVE-2026-12345',summary:'Wrong product cache'}),'old').run();
 assert.equal((await state(e)).products[0].status,'needs_identity');
 assert.equal((await q(e,'SELECT COUNT(*) AS total FROM cvie_advisories').first()).total,0);
});
check('NVD matching requires both a selected affected host and an explicit Windows Hyper-V statement',()=>{
 const product={name:'HyperV',cpe:host};assert.ok(normalizeNvd(nvd(),product));
 assert.equal(normalizeNvd(nvd(undefined,'Windows kernel advisory fixture.'),product),null);
 assert.equal(normalizeNvd(nvd(undefined,'Linux Hyper-V guest driver advisory fixture.','cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*'),product),null);
 assert.equal(normalizeNvd(nvd(undefined,undefined,host.replace('2022','2025')),product),null);
 assert.equal(normalizeNvd(nvd(),{name:'HyperV',cpe:host.replace(':microsoft:',':citrix:')}),null);
 assert.ok(normalizeNvd(nvd(undefined,'Windows kernel advisory fixture.'),{name:'Windows Server 2022',cpe:host}),'ordinary host scans still include other Windows components');
});
check('Hyper-V history uses the host CPE plus component query for all history windows',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'HyperV',cpe:host}]);let calls=0;
 for(let i=0;i<6;i++)await runCvieStep(e,async url=>{
  const u=new URL(url);assert.equal(u.searchParams.get('virtualMatchString'),host);assert.equal(u.searchParams.get('keywordSearch'),'Windows Hyper-V');assert.ok(u.searchParams.has('keywordExactMatch'));
  calls++;return Response.json({startIndex:0,totalResults:0,vulnerabilities:[]});
 },NOW+i*7000);
 assert.equal(calls,5);assert.equal((await state(e)).products[0].status,'ready');
});
check('CNA-only Hyper-V records require the same Windows host and exclude other components/vendors',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'HyperV',cpe:host}]);
 await store(e,cna());await store(e,cna('CVE-2026-12346','Windows kernel advisory fixture.'));
 await store(e,cna('CVE-2026-12347','Windows Hyper-V security advisory fixture.','Windows Server 2025'));
 await store(e,cna('CVE-2026-12348','Windows Hyper-V security advisory fixture.','Windows Server 2022','Other Vendor'));
 await store(e,cna('CVE-2026-12349','Windows Hypervisor security advisory fixture.'));
 assert.deepEqual((await combinedPage(e,'a',cutoff)).advisories.map(r=>r.id),['CVE-2026-12345']);
 assert.equal((await combinedCounts(e,'a',cutoff,'2025-11-01T00:00:00Z'))[0].recent_count,1);
 assert.equal((await combinedPage(e,'b',cutoff)).advisories.length,0);
 assert.deepEqual((await loadCvieDigest(e,'a',NOW)).records.map(r=>r.id),[],'unrated fixtures are not high-severity email items');
});
check('Windows client Version labels and Server Core labels reconcile with their verified host CPEs',async()=>{
 for(const [name,label] of [['windows_11_24h2','Windows 11 Version 24H2'],['windows_server_2022','Windows Server 2022 (Server Core installation)']]){
  const e=env(),cpe=hyperVHosts().find(h=>h.cpe.split(':')[4]===name).cpe;
  await subscribeProducts(e,'a',[{name:'HyperV',cpe}]);await store(e,cna(undefined,undefined,label));
  assert.equal((await combinedPage(e,'a',cutoff)).advisories.length,1,label);
 }
});
check('unresolved Hyper-V cannot inherit Windows disclosures before a host has been selected',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'HyperV',vendor:'Microsoft'}]);await store(e,cna());
 assert.equal((await combinedPage(e,'a',cutoff)).advisories.length,0);
});
check('stale broad Windows caches and a corrected CNA component cannot leak into Hyper-V results',async()=>{
 const e=env();await subscribeProducts(e,'a',[{name:'HyperV',cpe:host},{name:'Windows Server 2022'}]);
 const p=await q(e,"SELECT * FROM cvie_products WHERE name='HyperV'").first();
 for(const [id,summary] of [['CVE-2026-12345','Windows kernel advisory fixture.'],['CVE-2026-12346','Windows Hyper-V security advisory fixture.']]){
  const r=normalizeNvd(nvd(id,summary),{name:'Windows Server 2022',cpe:host});
  await q(e,'INSERT INTO cvie_advisories VALUES(?,?,?,?,?)',p.id,id,r.published,JSON.stringify(r),'legacy').run();
 }
 assert.deepEqual((await combinedPage(e,'a',cutoff,'',p.id)).advisories.map(r=>r.id),['CVE-2026-12346']);
 await store(e,cna('CVE-2026-12346','Windows kernel corrected advisory fixture.'));
 assert.equal((await combinedPage(e,'a',cutoff,'',p.id)).advisories.length,0);
});
