import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const context=vm.createContext({URL,TextEncoder});context.window=context;
for(const file of ['inventory-matching.js','inventory-assessment.js','finding-ai.js'])vm.runInContext(fs.readFileSync(new URL('../'+file,import.meta.url),'utf8'),context);
const engine=context.CVEHARBOR_INVENTORY_MATCH;
const asset=(technology,version='2.1.0')=>({id:'test',technology,version});
const record=(technology,extra={})=>({id:'CVE-2026-12345',source_type:'cvie_nvd',cvie_products:[technology],affected:technology+' before 2.2.0',severity:'critical',sources:[{url:'https://example.test/vendor'}],affected_cpes:[{criteria:'cpe:2.3:a:fixture:product:*:*:*:*:*:*:*:*',cvie_product_key:technology,versionStartIncluding:'2.0.0',versionEndExcluding:'2.2.0'}],...extra});

for(const product of ['PHP','WordPress','WordPress Plugin: Autoptimize','MySQL','MariaDB','SQL Server','Python','FortiOS','Docker','Kubernetes','OpenSSL','Apache HTTP Server','NGINX','Progress Sitefinity']){
 test(product+': structured ranges, fixed boundary, unknown version and pending evidence',()=>{
  const source=record(product);
  assert.equal(engine.candidate(asset(product),source)?.applicability_status,'affected_version');
  assert.equal(engine.candidate(asset(product,'2.2.0'),source),null,'fallback must not resurrect an explicit exclusion');
  assert.equal(engine.candidate(asset(product,'unknown'),source)?.applicability_status,'needs_verification');
  for(const field of ['verification_pending','disclosure_verification_stale']){
   for(const version of ['2.1.0','2.2.0'])assert.equal(engine.candidate(asset(product,version),{...source,[field]:true})?.applicability_status,'needs_verification');
  }
 });
}
test('Windows, IIS and Framework versions do not establish servicing state',()=>{
 for(const product of ['Windows','Windows Server','IIS','.NET Framework']){
  const finding=engine.candidate(asset(product,'4.8'),record(product));
  assert.equal(finding?.applicability_status,'needs_verification');assert.match(finding.verification_required,/security updates/);
 }
});
test('compound text must not lend another component or branch its range',()=>{
 for(const affected of ['MySQL with OpenSSL before 3.0.0','MySQL 2.0 and 3.0 before 3.1.0','MySQL before 2.2.0 only when a plugin is enabled']){
  const finding=engine.candidate(asset('MySQL','9.0'),{...record('MySQL'),source_type:'advisory',categories:['MySQL'],affected});
  assert.equal(finding?.applicability_status,'needs_verification',affected);
 }
 assert.equal(engine.candidate(asset('MySQL'),{...record('MySQL'),source_type:'advisory',categories:['MySQL']})?.applicability_status,'affected_version');
});
test('distribution release is not a package version and package revisions remain unverified',()=>{
 for(const product of ['Debian','Ubuntu'])assert.equal(engine.candidate(asset(product,'12'),record(product)),null);
 assert.equal(engine.candidate(asset('OpenSSL','3.0.11-1~deb12u2'),record('OpenSSL'))?.applicability_status,'needs_verification');
});
test('CPE not-applicable, contradictory bounds and unsupported versions are not cleared',()=>{
 const range=record('OpenSSL').affected_cpes[0];
 for(const change of [{criteria:'cpe:2.3:a:fixture:product:-:*:*:*:*:*:*:*'},{versionStartIncluding:'3.0.0'},{comparison_unsupported:true},{vulnerable:false}])assert.equal(engine.cvieVersionAssessment('2.1.0',[{...range,...change}]),'unknown');
 assert.equal(engine.cvieVersionAssessment('2.2.0',[range,{...range,versionStartIncluding:'2.2.0',versionEndExcluding:'2.3.0'}]),'within');
});
test('mixed affected and unaffected CNA exceptions cannot assert a version match',()=>{
 const source=record('.NET Runtime',{cna_affected:[{vendor:'Microsoft',product:'.NET 8.0',versions:[{version:'8.0.0',lessThan:'8.0.10',status:'affected'},{version:'8.0.2',status:'unaffected'}]}]});
 assert.equal(engine.candidate(asset('.NET Runtime','8.0.2'),source)?.applicability_status,'needs_verification');
});
test('source freshness changes are reflected in replacement snapshots and summaries',()=>{
 const source=record('OpenSSL'),a=asset('OpenSSL');
 const first=engine.evaluate([a],[source]);assert.equal(engine.summarize(first.items).affected_version,1);
 const second=engine.evaluate([a],[{...source,verification_pending:true}]);assert.equal(engine.summarize(second.items).needs_verification,1);
 assert.equal(engine.evaluate([{...a,version:'2.2.0'}],[source]).total,0);
});
test('remediation choices never promote applicability and AI must verify first',()=>{
 for(const status of ['Fixed/Patched','Not Applicable','Accepted Risk','Applicability verified']){
  const finding={...asset('OpenSSL'),id:'CVE-2026-12345',level:'category',status};
  assert.equal(engine.applicability(finding).code,'needs_verification');
  const prompt=context.CVEHARBOR_FINDING_AI.question(finding,record('OpenSSL'));
  assert.match(prompt,/Needs verification means provide verification steps first/);assert.match(prompt,/Never upgrade a finding/);
 }
});
