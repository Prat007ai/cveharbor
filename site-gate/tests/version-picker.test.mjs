import test from 'node:test';
import assert from 'node:assert/strict';
import {catalogueNames} from '../../account-backend/src/product-coverage.js';
import {versionResponse,validVersion,windowFor,buildMatch} from '../version-scan.mjs';
import config from '../version-products.json' with {type:'json'};
import releases from '../version-releases.json' with {type:'json'};

test('every card offers concrete products with ten distinct, well-formed releases',()=>{
  assert.deepEqual(Object.keys(config.cards).sort(),[...catalogueNames].sort());
  for(const ids of Object.values(config.cards))for(const id of ids){
    const p=config.products[id], list=releases[id].versions;
    assert.ok(validVersion(p,p.example),id);
    assert.equal(new Set(list.map(x=>x.version)).size,10,id);
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
    const r=await versionResponse(new Request('https://example.test/v1/version-picker/scan?'+new URLSearchParams({product:'react',version:'19.0.0',day,months})),{});
    assert.equal(r.status,200);assert.equal((await r.json()).rows.length,expected);
  }
});
