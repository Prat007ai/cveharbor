import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const context=vm.createContext({TextEncoder,URL});context.window=context;
for(const f of ['inventory-matching.js','inventory-assessment.js'])vm.runInContext(fs.readFileSync(new URL('../'+f,import.meta.url),'utf8'),context);
const engine=context.CVEHARBOR_INVENTORY_MATCH;
const row=(product,version,lessThan,extra={})=>({vendor:'Microsoft',product,versions:[{version,lessThan,status:'affected',versionType:'custom'}],...extra});
const record=rows=>({id:'CVE-2023-38180',source_type:'cvie_combined',cvie_products:['.NET Runtime','.NET Desktop Runtime','ASP.NET Core Runtime','.NET SDK'],affected:'.NET Desktop Runtime: >= 6.0.0, < 6.0.21',cna_affected:rows,sources:[{url:'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38180'}]});
const asset=(version,technology='.NET Runtime')=>({id:'a',technology,version});
const candidate=(version,rows,technology)=>engine.candidate(asset(version,technology),record(rows));
test('custom Microsoft numeric ranges compare every branch and exclude patched/future runtimes',()=>{
 const rows=[row('.NET 6.0','6.0.0','6.0.21'),row('.NET 7.0','7.0.0','7.0.10')];
 for(const v of ['3.1.32','6.0.21','7.0.10','7.0.14','8.0.2','10.0.3'])assert.equal(candidate(v,rows),null,v);
 for(const v of ['6.0.20','7.0.9'])assert.equal(candidate(v,rows)?.level,'version_review');
 assert.equal(candidate('7.0.9',rows,'.NET Desktop Runtime')?.level,'version_review');
 assert.equal(candidate('',rows)?.level,'category');
});
test('ASP.NET and SDK evidence cannot be relabelled as a .NET runtime',()=>{
 const rows=[row('ASP.NET Core 8.0','8.0.0','8.0.32'),row('.NET SDK 8.0','8.0.100','8.0.428')];
 assert.equal(candidate('8.0.2',rows),null);
 assert.equal(candidate('8.0.2',rows,'ASP.NET Core Runtime')?.level,'version_review');
 assert.equal(candidate('8.0.201',rows,'.NET SDK')?.level,'version_review');
 assert.equal(candidate('8.0.428',rows,'.NET SDK'),null);
});
test('ambiguous SDK-style product labels never confirm runtime patch applicability',()=>{
 assert.equal(candidate('8.0.2',[row('.NET 8.0 installed on Windows','8.0.0','8.0.428')])?.level,'category');
 assert.equal(candidate('7.0.14',[row('.NET 8.0 installed on Windows','8.0.0','8.0.428')]),null);
});
test('prerelease and complex ranges do not contaminate a different branch',()=>{
 const rows=[row('.NET 8.0 runtime','8.0.0','8.0.34'),row('.NET 11.0 runtime','11.0.0-preview.1','11.0.0')];
 assert.equal(candidate('7.0.14',rows),null);
 assert.equal(candidate('8.0.2',rows)?.level,'version_review');
 assert.equal(candidate('11.0.0',rows)?.level,'category');
 assert.equal(candidate('8.0.2',[row('.NET 8.0','8.0.0','8.0.34',{versions:[{version:'8.0.0',lessThan:'8.0.34',status:'affected',changes:[{}]}]})])?.level,'category');
});
test('OS context is isolated by hostname and environment and included in the cache key',()=>{
 const r=record([row('.NET 8.0 installed on Linux','8.0.0','8.0.34')]);
 const app={...asset('8.0.2'),name:'DEMO',environment_id:'prod'};
 const windows={id:'os',name:'DEMO',environment_id:'prod',technology:'Windows Server',version:'10.0.20348.1'};
 const records=[r];assert.equal(engine.evaluate([app,windows],records).total,0);
 assert.equal(engine.evaluate([app],records).total,1,'unknown OS cannot reuse Windows exclusion');
 assert.equal(engine.evaluate([app,{...windows,environment_id:'qa'}],records).total,1);
});
test('uncertain CNA evidence stays reviewable, and Foundation/Framework need servicing evidence',()=>{
 const r=record([row('.NET 8.0','8.0.0','8.0.2')]);r.verification_pending=true;
 assert.equal(engine.candidate(asset('8.0.5'),r)?.level,'category');
 const framework={...record([]),affected:'.NET Framework: >= 4.8.0, < 4.8.4811.0'};
 const f=engine.candidate(asset('4.8','.NET Framework'),framework);assert.equal(f.level,'category');assert.match(f.comparison_detail,/Release registry value/);
});
test('legacy Server SAC labels are distinct from Server 2022',()=>{
 const r={id:'CVE-2019-0797',affected:'Windows Server: 2012; 2016 (Core installation); version 1709 (Core Installation); version 1803 (Core Installation); 2019',sources:[{url:'https://msrc.microsoft.com/'}]};
 assert.equal(engine.candidate(asset('10.0.20348.5761','Windows Server'),r),null);
 assert.ok(engine.candidate(asset('version 1803','Windows Server'),r));
});
test('combining monitored components preserves every original CNA product row',()=>{
 const src=fs.readFileSync(new URL('../cvie.js',import.meta.url),'utf8');
 const mergeSource=src.slice(src.indexOf('function merge(base=[]){'),src.indexOf('function clearPrivate'));
 const runtime=row('.NET 7.0','7.0.0','7.0.10'),aspnet=row('ASP.NET Core 2.1','2.1.0','2.1.40');
 const sandbox=vm.createContext({products:[],records:[{id:'CVE-2023-38180',cna_affected:[runtime]},{id:'CVE-2023-38180',cna_affected:[aspnet]}],withdrawn:new Set(),excluded:[],normalize:x=>String(x).toLowerCase()});
 vm.runInContext(mergeSource+';this.result=merge();',sandbox);
 assert.equal(sandbox.result.length,1);assert.equal(sandbox.result[0].cna_affected.length,2);
 assert.equal(engine.candidate(asset('7.0.14'),{...record([]),...sandbox.result[0]}),null);
});
