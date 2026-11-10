import test from 'node:test';
import assert from 'node:assert/strict';
import {catalogueNames} from '../../account-backend/src/product-coverage.js';
import {versionResponse,validVersion,windowFor,buildMatch} from '../version-scan.mjs';
import config from '../version-products.json' with {type:'json'};
import releases from '../version-releases.json' with {type:'json'};

test('every card offers concrete products with distinct, well-formed releases across all offered lines',()=>{
  assert.deepEqual(Object.keys(config.cards).sort(),[...catalogueNames].sort());
  for(const ids of Object.values(config.cards))for(const id of ids){
    const p=config.products[id], list=releases[id].versions;
    assert.ok(validVersion(p,p.example),id);
    assert.ok(list.length>0,id);
    if(!p.source.startsWith('distribution:'))assert.equal(list.length,10,id);
    assert.equal(new Set(list.map(x=>x.version)).size,list.length,id);
    for(const r of [...Object.values(releases[id].lines||{}).flat(),...(releases[id].supported||[])]){
      assert.ok(validVersion(p,r.version),id+' '+r.version);
    }
    for(const r of list)assert.ok(validVersion(p,r.version),id+' '+r.version);
    assert.equal(validVersion(p,'2.*'),false);
  }
  assert.equal(validVersion(config.products.sdk,'8.0.12'),false);
  assert.equal(validVersion(config.products.sql,'15.0.1000.1'),false);
});
test('3 and 12 calendar months have contiguous nonoverlapping NVD windows, including month ends',()=>{
  const anchor=new Date('2024-05-31T23:59:59.999Z');
  const windows=[0,1,2,3].map(q=>windowFor(anchor,q));
  assert.equal(windows[0].start,'2024-02-29T23:59:59.999Z');
  assert.equal(windows[3].start,'2023-05-31T23:59:59.999Z');
  for(let i=1;i<4;i++)assert.equal(Date.parse(windows[i].end)+1,Date.parse(windows[i-1].start));
});
test('Microsoft build ranges require the correct branch, product, and vendor',()=>{
  const affected=[{vendor:'Microsoft',product:'Windows Server 2022',versions:[{status:'affected',versionType:'custom',version:'10.0.20348.0',lessThan:'10.0.20348.3000'}]}];
  assert.match(buildMatch('server','20348.1200',affected),/Vendor affected/);
  assert.match(buildMatch('server','20348.3000',affected),/lead/);
  assert.match(buildMatch('server','17763.1200',affected),/lead/);
});
test('OSV receives only the selected public package/version and respects disclosure date and withdrawal',async t=>{
  const anchor=new Date(),day=anchor.toISOString().slice(0,10);
  const old=new Date(anchor);old.setUTCMonth(old.getUTCMonth()-6);
  t.mock.method(globalThis,'fetch',async(url,opts)=>{
    assert.equal(url,'https://api.osv.dev/v1/query');
    assert.equal(opts.redirect,'manual');
    assert.deepEqual(JSON.parse(opts.body),{package:{ecosystem:'npm',name:'react'},version:'19.0.0'});
    return Response.json({vulns:[{id:'GHSA-example',published:old.toISOString()},{id:'GHSA-withdrawn',published:day,withdrawn:day}]});
  });
  for(const [months,expected] of [[3,0],[12,1]]){
    const r=await versionResponse(new Request('https://example.test/v1/version-picker/scan?'+new URLSearchParams({cursor:'source:',product:'react',version:'19.0.0',day,months})),{});
    assert.equal(r.status,200);assert.equal((await r.json()).rows.length,expected);
  }
});

test('SQL branches validate their own build, and distributions query their published OS identity',async t=>{
  assert.equal(config.cards['SQL Server'].length,6);
  assert.ok(config.cards.Linux.includes('ubuntu')&&config.cards.Linux.includes('debian')&&config.cards.Linux.includes('linux'));
  for(const id of config.cards['SQL Server']){
    for(const other of config.cards['SQL Server'])assert.equal(validVersion(config.products[id],releases[other].versions[0].version),id===other);
  }
  const fetched=[];
  t.mock.method(globalThis,'fetch',async url=>{
    fetched.push(url.searchParams.get('cpeName'));
    return Response.json({vulnerabilities:[],startIndex:0,totalResults:0});
  });
  const day=new Date().toISOString().slice(0,10);
  for(const [product,version] of [['ubuntu','22.04.5'],['debian','13.7'],['sles','15.7']]){
    const res=await versionResponse(new Request('https://example.test/v1/version-picker/scan?'+new URLSearchParams({cursor:'source:',product,version,day,months:3})),{});
    assert.equal(res.status,200);
  }
  assert.deepEqual(fetched,['o:canonical:ubuntu_linux:22.04:*','o:debian:debian_linux:13:*','o:suse:sles:15:sp7'].map(v=>'cpe:2.3:'+v+':*:*:*:*:*:*'));
});

test('vendor scans distinguish SQL servicing branches and Noble package notices from installed exposure', async()=>{
  const today=new Date().toISOString(), month=today.slice(0,7), digest='a'.repeat(64), snapshot='b'.repeat(64);
  const day=today.slice(0,10);
  async function scan(product,version,rows){
    const key=product==='ubuntu'?'ubuntu-noble':product;
    const directory={product:key,from:'2020-01-01',checked:today,snapshot,months:{[month]:digest}};
    const bucket={get:async path=>({json:async()=>path.endsWith('current.json')?directory:rows})};
    const res=await versionResponse(new Request('https://example.test/v1/version-picker/scan?'+new URLSearchParams({product,version,day,months:3})),{INTELLIGENCE_BUCKET:bucket});
    assert.equal(res.status,200);
    return (await res.json()).rows[0];
  }
  const sql=[{id:'CVE-2099-9999',published:today,fixes:[{branch:'CU32',build:'15.0.4500.2',kb:'5128494'},{branch:'GDR',build:'15.0.2200.2',kb:'5128495'}]}];
  for(const [version,label] of [['15.0.4490.9',/predates the CU32/],['15.0.4500.2',/included.*CU32/],['15.0.2200.2',/included.*GDR/],['15.0.1000.9',/verify servicing/]]){
    assert.match((await scan('sql2019',version,sql)).evidence,label);
  }
  const row=await scan('ubuntu','24.04.5',[{id:'USN-9008-1',published:today,packages:{libnfs:'5.0.2-1ubuntu0.24.04.2'},
    binaries:{libnfs14:'5.0.2-1ubuntu0.24.04.2'},cves:['CVE-2026-108985']}]);
  assert.match(row.affected,/CVE-2026-108985/);assert.match(row.remediation,/libnfs14/);assert.match(row.evidence,/verify installed packages/);
  const res=await versionResponse(new Request('https://example.test/v1/version-picker/scan?product=sql2019&version=15.0.4500.2&months=3&day='+day),{});
  assert.equal(res.status,503);
});

test('published history and installed-version evidence are separate and both remain accessible',async t=>{
  const {scopes,label}=await import('../catalogue-history.mjs');
  assert.deepEqual(scopes('alpine-linux','3.24.4'),['alpine-linux@3.24']);
  assert.deepEqual(scopes('debian','13.7'),['debian@13']);
  assert.deepEqual(scopes('rhel','10.2'),['rhel@10','rhel@10.2']);
  const row={id:'CVE-2099-12345',ranges:[['10.0.26100.0','10.0.26100.8000',false]],evidence:'Product advisory'};
  assert.match(label(row,'server','26100.6000').evidence,/affected range/);
  assert.equal(label(row,'server','20348.1000').evidence,row.evidence);
  assert.equal(label(row,'server','26100.8000').evidence,row.evidence);
  const today=new Date().toISOString(),day=today.slice(0,10),hash='a'.repeat(64);
  const bucket={get:async path=>({json:async()=>path.endsWith('/current.json')?
    {audited:['react'],products:{react:[[day,day,hash]]},checked:today,from:'2020-01-01',snapshot:hash}:
    [{id:'CVE-2099-12345',published:today,evidence:'Package advisory'}]})};
  t.mock.method(globalThis,'fetch',async()=>Response.json({vulns:[]}));
  const url='https://example.test/v1/version-picker/scan?product=react&version=19.0.0&months=3&day='+day;
  const first=await (await versionResponse(new Request(url),{INTELLIGENCE_BUCKET:bucket})).json();
  assert.equal(first.rows[0].id,'CVE-2099-12345');assert.equal(first.next,'source:');
  const second=await (await versionResponse(new Request(url+'&cursor=source:'),{INTELLIGENCE_BUCKET:bucket})).json();
  assert.deepEqual(second.rows,[]);assert.equal(second.next,null);
  assert.equal((await versionResponse(new Request(url),{})).status,503);
});

test('bundled advisories use the exact installed archive and stay separate from direct findings', async()=>{
  const {cataloguePage}=await import('../catalogue-history.mjs');
  const now=new Date().toISOString(),day=now.slice(0,10),hash='c'.repeat(64);
  const index={audited:['npm'],snapshot:hash,from:'2020-01-01',checked:now,
    products:{'npm@12.2.2~components':[[day,day,hash]]}};
  const row={id:'CVE-2099-34567',published:now,scope:'bundled'};
  const bucket={get:async path=>({json:async()=>path.endsWith('/current.json')?index:[row]})};
  const range={start:day+'T00:00:00Z',end:day+'T23:59:59.999Z'};
  const matched=await cataloguePage(bucket,'npm','12.2.2',range,'');
  assert.deepEqual(matched.rows,[]);assert.deepEqual(matched.componentRows,[row]);
  const unknown=await cataloguePage(bucket,'npm','12.2.3',range,'');
  assert.deepEqual(unknown.componentRows,[]);assert.match(unknown.coverage,/not been verified/);
});

test('scan coverage distinguishes a completed public query, a restricted source and an unreadable source',async t=>{
  const day=new Date().toISOString().slice(0,10);
  let payload={},status=200;
  t.mock.method(globalThis,'fetch',async()=>Response.json(payload,{status}));
  function scan(id){
    const params=new URLSearchParams({product:id,version:config.products[id].example,day,months:'3',cursor:'source:'});
    return versionResponse(new Request('https://example.test/v1/version-picker/scan?'+params),{});
  }
  const clean=await (await scan('ts')).json();
  assert.deepEqual(clean.rows,[]);assert.deepEqual(clean.coverageGaps,[]);
  payload={vulnerabilities:[],totalResults:0,startIndex:0};
  for(const id of ['esxi','forti','rhel','sles','veeam','sql2014','sql2016']){
    const page=await (await scan(id)).json();
    assert.deepEqual(page.rows,[],id);assert.ok(page.coverageGaps[0],id);
  }
  for(const invalid of [{error:'Authentication required'},{vulns:[{id:'GHSA-example'}]},{vulns:'missing'},[]]){
    payload=invalid;assert.equal((await scan('ts')).status,503);
  }
  status=403;
  for(const id of ['ts','linux'])assert.equal((await scan(id)).status,503);
});

test('missing distribution and component evidence is scoped to the selected release',async()=>{
  const {cataloguePage}=await import('../catalogue-history.mjs');
  const now=new Date().toISOString(),range={start:now,end:now};
  const index={checked:now,from:'2020-01-01',snapshot:'a'.repeat(64),audited:['debian','npm','react'],
    products:{'debian@13':[],'npm@11.0.0~components':[]}};
  const bucket={get:async()=>({json:async()=>index})};
  async function gaps(id,v){return (await cataloguePage(bucket,id,v,range,'')).coverageGaps;}
  assert.deepEqual(await gaps('debian','13'),[]);
  assert.match((await gaps('debian','77'))[0],/unverified/);
  assert.deepEqual(await gaps('npm','11.0.0'),[]);
  assert.match((await gaps('npm','1.0.0'))[0],/dependencies/);
  assert.match((await gaps('react','19.0.0'))[0],/component/);
});
