import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const context=vm.createContext({TextEncoder,URL});context.window=context;
for(const name of ['inventory-matching.js','inventory-assessment.js','finding-ai.js'])vm.runInContext(fs.readFileSync(new URL('../'+name,import.meta.url),'utf8'),context);
test('Windows Server build mismatch is explained without asserting patch applicability',()=>{
 const asset={id:'a',technology:'Windows Server',version:'10.0.20348.5761'},record={id:'CVE-2019-0708',affected:'Windows Server 2008 R2; Windows Server 2008',sources:[{url:'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708'}]};
 const finding=context.CVEHARBOR_INVENTORY_MATCH.candidate(asset,record);assert.match(finding.comparison_detail,/Version family mismatch/);assert.match(finding.comparison_detail,/Windows Server 2022/);assert.equal(finding.level,'category');
 const grouped=context.CVEHARBOR_INVENTORY_MATCH.candidate(asset,{...record,affected:'Windows Server: 2008 R2 for x64-based Systems Service Pack 1 (Core installation); 2008 for x64-based Systems Service Pack 2'});assert.match(grouped.comparison_detail,/Version family mismatch/);assert.match(grouped.comparison_detail,/Windows Server 2022/);
 const mixed=context.CVEHARBOR_INVENTORY_MATCH.candidate(asset,{...record,affected:'Windows Server: 2008 R2; 2022'});assert.doesNotMatch(mixed.comparison_detail,/mismatch/);
 const same=context.CVEHARBOR_INVENTORY_MATCH.candidate(asset,{...record,affected:'Windows Server 2022'});assert.doesNotMatch(same.comparison_detail,/mismatch/);
 const unknown=context.CVEHARBOR_INVENTORY_MATCH.candidate({...asset,version:'unknown'},record);assert.doesNotMatch(unknown.comparison_detail,/mismatch/);
});
test('finding prompt keeps the admitted byte bound and excludes private labels and unsafe sources',()=>{
 const finding={id:'CVE-2026-12345',technology:'PHP',version:'8.4.1',asset:{name:'PRIVATE-HOST',notes:'PRIVATE-NOTES'},evidence:'💡'.repeat(3000),comparison_detail:'🧪'.repeat(3000)};
 const advisory={affected:'🧪'.repeat(3000),summary:'🧪'.repeat(3000),remediation:'🧪'.repeat(3000),sources:[{url:'javascript:alert(1)'},{url:'https://user:secret@example.test/'},{url:'https://example.test/vendor',label:'Vendor'}]};
 const result=context.CVEHARBOR_FINDING_AI.question(finding,advisory);assert.ok(Buffer.byteLength(result)<=6000);assert.doesNotMatch(result,/PRIVATE-HOST|PRIVATE-NOTES|javascript|secret/);assert.match(result,/https:\/\/example.test\/vendor/);assert.match(result,/Temporary mitigation/);
});
