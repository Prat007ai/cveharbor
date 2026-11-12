import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {DB} from './helpers/d1.mjs';
import {knownIdentity,dotnetInventoryIdentity,identityCandidates} from '../src/product-identity.js';
import {subscribeProducts,syncAccountProducts,repairAccountCoverage,cvieRoute,normalizeNvd} from '../src/cvie.js';
const cpe=name=>'cpe:2.3:a:microsoft:'+name+':*:*:*:*:*:*:*:*';
const aliases=[['.NET Runtime','.net'],['.NET Desktop Runtime','.net'],['ASP.NET Core Runtime','asp.net_core'],['.NET SDK','.net_core_sdk'],['.NET Framework','.net_framework'],['.NET Core Runtime','.net_core']];
const row=(e,user='a')=>e.DB.sql.prepare('SELECT * FROM cvie_products WHERE user_id=?').get(user);
const route=(e,id,user='a',method='POST')=>cvieRoute(new Request('https://api.cveharbor.com/v1/cvie/products/'+id+'/identity-options?scope=inventory',{method}),e,{id:user});
async function legacy(e,user='a',name='.NET Runtime',origin='inventory'){
 await subscribeProducts(e,user,[{name}],origin);
 const p=row(e,user);
 e.DB.sql.prepare("UPDATE cvie_products SET cpe='',status='needs_identity',candidates_json=?,cursor_json=?,error='Choose exact product',lease_until=999 WHERE id=?").run(
  JSON.stringify([{cpe:'cpe:2.3:a:businessobjects:crystal_reports_.net_runtime:*:*:*:*:*:*:*:*',label:'Crystal Reports'}]),
  JSON.stringify({directory_query:name,directory_complete:true}),p.id);
 return row(e,user);
}
test('collector aliases use separate Microsoft product families without enabling the held registry',async()=>{
 const e={DB:new DB()};
 for(const [name,family] of aliases){
  assert.equal(dotnetInventoryIdentity(name)?.cpe,cpe(family));
  assert.equal(knownIdentity('Microsoft '+name,'Microsoft Corporation')?.cpe,cpe(family));
  assert.equal(knownIdentity(name,'Other Vendor'),null);
 }
 await subscribeProducts(e,'a',aliases.map(([name])=>({name})),'inventory');
 const products=e.DB.sql.prepare('SELECT name,cpe FROM cvie_products ORDER BY name').all();
 assert.equal(products.length,aliases.length);
 for(const p of products)assert.equal(p.cpe,cpe(aliases.find(([name])=>name===p.name)[1]));
 for(const name of ['.NET','Crystal Reports .NET Runtime','StarTeam SDK Runtime for .NET','Entity Framework Core','ASP.NET Core OData','.NET Runtime Helper'])assert.equal(dotnetInventoryIdentity(name),null,name);
});
test('runtime suggestions exclude the screenshot false positives, Framework, SDK and deprecated identities',()=>{
 const products=['.net','.net_framework','.net_core_sdk','asp.net_core'].map(name=>({cpe:{cpeName:cpe(name)}}));
 products.push({cpe:{cpeName:'cpe:2.3:a:borland:starteam_sdk_runtime_for_.net:*:*:*:*:*:*:*:*'}},{cpe:{cpeName:'cpe:2.3:a:businessobjects:crystal_reports_.net_runtime:*:*:*:*:*:*:*:*'}});
 assert.deepEqual(identityCandidates({products},{name:'.NET Runtime'}).map(p=>p.cpe),[cpe('.net')]);
 assert.deepEqual(identityCandidates({products:[{cpe:{cpeName:cpe('.net'),deprecated:true}}]},{name:'.NET Runtime'}),[]);
});
test('refresh repairs existing unresolved rows once, clears stale suggestions and retains every installed version',async()=>{
 const e={DB:new DB(),CVIE_SHARED_SCANS_ENABLED:'true'};
 e.DB.sql.exec('ALTER TABLE inventory_assets ADD COLUMN version TEXT');
 e.DB.sql.prepare('INSERT INTO inventory_assets VALUES(?,?,?)').run('a','.NET Runtime','8.0.1');
 e.DB.sql.prepare('INSERT INTO inventory_assets VALUES(?,?,?)').run('a','.NET Runtime','8.0.2');
 await legacy(e);await legacy(e,'b');
 const untouched=row(e,'b');
 await syncAccountProducts(e,'a','inventory');
 const repaired=row(e);assert.equal(repaired.cpe,cpe('.net'));assert.equal(repaired.status,'queued');assert.equal(repaired.candidates_json,'[]');assert.equal(repaired.error,'');assert.equal(repaired.lease_until,0);
 assert.deepEqual(row(e,'b'),untouched,'another account is never repaired implicitly');
 assert.deepEqual(e.DB.sql.prepare('SELECT version FROM inventory_assets ORDER BY version').all().map(r=>r.version),['8.0.1','8.0.2']);
 assert.ok(e.DB.sql.prepare('SELECT scope_id FROM cvie_product_scopes WHERE product_id=?').get(repaired.id).scope_id);
 assert.equal(await repairAccountCoverage(e,'a','inventory'),false,'repair is idempotent');
});
test('the already-open chooser repairs on retry, respects ownership/scope and does not perform an AI request',async()=>{
 const e={DB:new DB(),CVIE_SHARED_SCANS_ENABLED:'true'},p=await legacy(e);
 await assert.rejects(()=>route(e,p.id,'b'),/Product not found/);
 assert.equal((await (await route(e,p.id,'a','GET')).json()).cpe,'','GET does not mutate');
 const state=await (await route(e,p.id)).json();assert.equal(state.cpe,cpe('.net'));assert.deepEqual(state.candidates,[]);assert.equal(state.directory_complete,false);
 await subscribeProducts(e,'a',[],'inventory');await assert.rejects(()=>route(e,p.id),/Product not found/);
});
test('repair preserves explicit selections, foreign vendors and out-of-scope subscriptions',async()=>{
 const e={DB:new DB()};await legacy(e,'a');
 const selected=cpe('.net_core');e.DB.sql.prepare('UPDATE cvie_products SET cpe=?').run(selected);
 assert.equal(await repairAccountCoverage(e,'a','inventory'),false);assert.equal(row(e).cpe,selected);
 e.DB.sql.exec("UPDATE cvie_products SET cpe='',vendor='Other Vendor'");
 assert.equal(await repairAccountCoverage(e,'a','inventory'),false);assert.equal(row(e).cpe,'');
 e.DB.sql.exec("UPDATE cvie_products SET vendor=''");
 assert.equal(await repairAccountCoverage(e,'a','catalogue'),false);assert.equal(row(e).cpe,'');
});
test('a concurrent identity selection wins over repair',async t=>{
 const e={DB:new DB()};await legacy(e);
 const prepare=e.DB.prepare.bind(e.DB);let raced=false;
 t.mock.method(e.DB,'prepare',sql=>{
  if(!raced&&sql.startsWith('UPDATE cvie_products SET\n  cpe=')){
   raced=true;e.DB.sql.prepare('UPDATE cvie_products SET cpe=?').run(cpe('.net_core'));
  }
  return prepare(sql);
 });
 assert.equal(await repairAccountCoverage(e,'a','inventory'),false);assert.ok(raced);assert.equal(row(e).cpe,cpe('.net_core'));
});
test('runtime evidence accepts Microsoft runtime ranges without relabelling Framework or SDK CVEs',()=>{
 const product={name:'.NET Runtime',cpe:knownIdentity('.NET Runtime').cpe};
 const nvd=family=>({id:'CVE-2026-99999',published:'2026-10-01T00:00:00Z',descriptions:[{lang:'en',value:'Fictional mapping test'}],configurations:[{nodes:[{cpeMatch:[{criteria:cpe(family),vulnerable:true,versionStartIncluding:'8.0.0',versionEndExcluding:'8.0.2'}]}]}]});
 const record=normalizeNvd(nvd('.net'),product);assert.ok(record);assert.equal(record.affected_cpes[0].versionEndExcluding,'8.0.2');
 const context={window:{}};vm.runInNewContext(fs.readFileSync(new URL('../../inventory-matching.js',import.meta.url),'utf8'),context);
 const candidate=context.window.CVEHARBOR_INVENTORY_MATCH.candidate;
 assert.equal(candidate({id:'fictional-1',technology:'.NET Runtime',version:'8.0.1'},record)?.level,'version_review');
 assert.equal(candidate({id:'fictional-2',technology:'.NET Runtime',version:'8.0.2'},record),null);
 assert.equal(candidate({id:'fictional-3',technology:'.NET Runtime',version:''},record)?.level,'category');
 assert.equal(normalizeNvd(nvd('.net_framework'),product),null);assert.equal(normalizeNvd(nvd('.net_core_sdk'),product),null);
 const sdk={name:'.NET SDK',cpe:knownIdentity('.NET SDK').cpe};assert.equal(normalizeNvd(nvd('.net'),sdk),null,'SDK versions are never compared as runtime versions');
});
