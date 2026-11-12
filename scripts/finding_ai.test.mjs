import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const context=vm.createContext({TextEncoder,URL});context.window=context;
for(const name of ['inventory-matching.js','inventory-assessment.js','finding-ai.js'])vm.runInContext(fs.readFileSync(new URL('../'+name,import.meta.url),'utf8'),context);
test('Windows Server release exclusions apply before broad product fallback',()=>{
 const asset={id:'a',technology:'Windows Server',version:'10.0.20348.5761'},record={id:'CVE-2019-0708',categories:['Windows'],affected:'Windows Server 2008 R2; Windows Server 2008',sources:[{url:'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708'}]};
 const engine=context.CVEHARBOR_INVENTORY_MATCH;
 for(const affected of [record.affected,'Windows Server: 2008 R2 for x64-based Systems Service Pack 1 (Core installation); 2008 for x64-based Systems Service Pack 2'])assert.equal(engine.candidate(asset,{...record,affected}),null);
 for(const version of ['10.0.14393.1','10.0.17763.1','10.0.20348.5761','10.0.26100.1','Windows Server 2022','2022'])assert.equal(engine.candidate({...asset,version},record),null);
 for(const version of ['6.0.6002.1','6.1.7601.1','2008','2008 R2','unknown','10.0.99999.1',''])assert.ok(engine.candidate({...asset,version},record),version);
 for(const affected of ['Windows Server: 2008 R2; 2022','Windows Server 2022','Windows Server 2008 and later','Windows Server 2008 through 2025','Windows Server 2008; Windows Server','Windows Server 2008; 2028','Windows Server 2008;','Windows Server 2008; ...','Windows Server 2008 except 2022','Windows Server 2008'+ ' '.repeat(4000)+'; Windows Server 2022'])assert.ok(engine.candidate(asset,{...record,affected}),affected);
 assert.ok(engine.candidate(asset,{...record,verification_pending:true}));
 assert.ok(engine.candidate(asset,{...record,cna_affected:[{product:'Windows Server',versions:[{status:'affected',version:'2008'},{status:'affected',version:'2022'}]}]}));
 for(const row of [{defaultStatus:'affected'},{versions:[{status:'affected',version:'*'}]},{versions:[{status:'affected',version:'2008',lessThan:'2025'}]}])assert.ok(engine.candidate(asset,{...record,cna_affected:[row]}));
 assert.equal(engine.candidate(asset,{...record,cna_affected:[{product:'Windows Server',versions:[{status:'affected',version:'2008 R2 for x64-based Systems Service Pack 1 (Core installation)'}]}]}),null);
 assert.ok(engine.candidate(asset,{...record,affected_cpes:[{criteria:'cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*'}]}));
 assert.equal(engine.candidate({...asset,version:'2012 R2'},{...record,affected:'Windows Server 2012'}),null);
 assert.ok(engine.candidate({...asset,version:'2012 R2'},{...record,affected:'Windows Server 2012 R2'}));
 const result=engine.evaluate([asset,{...asset,id:'legacy',version:'2008 R2'}],[record]);assert.equal(result.total,1);assert.equal(result.items[0].asset_id,'legacy');
 const changed=engine.evaluate([{...asset,version:'2008 R2'}],[record]);assert.equal(changed.total,1,'changing inventory recomputes applicability');
});

test('finding prompt keeps the admitted byte bound and excludes private labels and unsafe sources',()=>{
 const finding={id:'CVE-2026-12345',technology:'PHP',version:'8.4.1',asset:{name:'PRIVATE-HOST',notes:'PRIVATE-NOTES'},evidence:'💡'.repeat(3000),comparison_detail:'🧪'.repeat(3000)};
 const advisory={affected:'🧪'.repeat(3000),summary:'🧪'.repeat(3000),remediation:'🧪'.repeat(3000),sources:[{url:'javascript:alert(1)'},{url:'https://user:secret@example.test/'},{url:'https://example.test/vendor',label:'Vendor'}]};
 const result=context.CVEHARBOR_FINDING_AI.question(finding,advisory);assert.ok(Buffer.byteLength(result)<=6000);assert.doesNotMatch(result,/PRIVATE-HOST|PRIVATE-NOTES|javascript|secret/);assert.match(result,/https:\/\/example.test\/vendor/);assert.match(result,/Temporary mitigation/);
});
