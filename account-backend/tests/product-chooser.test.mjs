import test from 'node:test';
import assert from 'node:assert/strict';
import {DB} from './helpers/d1.mjs';
import {subscribeProducts,runCvieStep,cvieRoute,runIdentityLookup} from '../src/cvie.js';
import {directorySearch,identityCandidates} from '../src/product-identity.js';
const cpe=name=>'cpe:2.3:o:microsoft:'+name+':*:*:*:*:*:*:*:*';
test('Windows Server uses directory labels and filters non-server results without hardcoding releases',()=>{
 assert.equal(directorySearch({name:'Windows Server OS'}),'Microsoft Windows Server');
 assert.equal(directorySearch({name:'Maria DB'}),'MariaDB');
 const data={products:[...['windows_server_2025','windows_server_2012_r2','windows_11','exchange_server'].map(name=>({cpe:{cpeName:cpe(name)}})),{cpe:{cpeName:cpe('windows_server_2019'),deprecated:true}}]};
 assert.deepEqual(identityCandidates(data,{name:'Windows Server OS'}).map(x=>x.cpe),[cpe('windows_server_2012_r2'),cpe('windows_server_2025')]);
});
test('options pagination, approved identity persistence and ownership',async()=>{
 const env={DB:new DB(),CVIE_SHARED_SCANS_ENABLED:'true'};
 await subscribeProducts(env,'a',[{name:'Windows Server OS'}]);
 const p=env.DB.sql.prepare("SELECT * FROM cvie_products WHERE user_id='a'").get();
 env.DB.sql.prepare("UPDATE cvie_products SET status='needs_identity' WHERE id=?").run(p.id);
 const route=(path,method='POST',data={},id='a')=>cvieRoute(new Request('https://api.cveharbor.com/v1/cvie/products/'+p.id+'/'+path+'?scope=catalogue',{method}),env,{id},undefined,data);
 await assert.rejects(()=>route('identity-options','POST',{},'b'),/Product not found/);
 assert.equal((await route('identity-options')).status,202);
 const before=env.DB.sql.prepare('SELECT total_changes() n').get().n;
 await route('identity-options');assert.equal(env.DB.sql.prepare('SELECT total_changes() n').get().n,before);
 let calls=0;
 const fetcher=async url=>{const u=new URL(url);assert.equal(u.searchParams.get('keywordSearch'),'Microsoft Windows Server');calls++;return Response.json({startIndex:calls-1,totalResults:2,products:[{cpe:{cpeName:cpe(calls===1?'windows_server_2022':'windows_server_2025')}}]})};
 await runCvieStep(env,fetcher,Date.now(),'a','catalogue');
 const state=await (await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie?scope=catalogue'),env,{id:'a'})).json();
 assert.equal(state.products[0].candidates.length,1);assert.equal(state.products[0].directory_complete,false);
 env.DB.sql.exec('UPDATE cvie_provider_budget SET next_request_at=0');
 await runCvieStep(env,fetcher,Date.now()+10000,'a','catalogue');
 const complete=env.DB.sql.prepare('SELECT * FROM cvie_products WHERE id=?').get(p.id);
 assert.equal(JSON.parse(complete.candidates_json).length,2);assert.equal(JSON.parse(complete.cursor_json).directory_complete,true);
 await assert.rejects(()=>route('identity','PUT',{cpe:cpe('windows_11')}),/Select an identity/);
 await route('identity','PUT',{cpe:cpe('windows_server_2025')});
 await subscribeProducts(env,'a',[{name:'Windows Server OS'}]);
 assert.equal(env.DB.sql.prepare('SELECT cpe FROM cvie_products WHERE id=?').get(p.id).cpe,cpe('windows_server_2025'));
 await subscribeProducts(env,'a',[]);await assert.rejects(()=>route('identity-options'),/Product not found/);
});

test('on-demand lookup finishes up to three pages without running other products or CVE history',async()=>{
 const env={DB:new DB(),CVIE_SHARED_SCANS_ENABLED:'true'};
 await subscribeProducts(env,'a',[{name:'WordPress'},{name:'Windows Server OS'}]);
 const p=env.DB.sql.prepare("SELECT id FROM cvie_products WHERE name='Windows Server OS'").get();
 let calls=0;
 await runIdentityLookup(env,'a','catalogue',p.id,async url=>{
  const u=new URL(url);assert.ok(u.pathname.includes('/cpes/'));assert.equal(u.searchParams.get('keywordSearch'),'Microsoft Windows Server');
  return Response.json({startIndex:calls++,totalResults:3,products:[{cpe:{cpeName:cpe('windows_server_'+(2022+calls))}}]});
 },async()=>{env.DB.sql.exec('UPDATE cvie_provider_budget SET next_request_at=0')});
 assert.equal(calls,3);assert.equal(env.DB.sql.prepare("SELECT last_attempt_at FROM cvie_products WHERE name='WordPress'").get().last_attempt_at,null);
});
