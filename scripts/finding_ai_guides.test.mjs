import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const finding={id:'CVE-2026-12345',technology:'.NET Desktop Runtime',version:'10.0.3',level:'version_review',name:'PRIVATE-HOST',notes:'PRIVATE-NOTES'};
const page='https://github.com/dotnet/runtime/security/advisories/GHSA-p3jp-9v83-76w9';
const advisory={affected:'.NET 10.0',sources:[{url:'https://fortiguard.example/advisory',label:'Unrelated'}, {url:page,label:'Microsoft'}]};
const row=(version,name='Microsoft.NETCore.App.Runtime.win-x64')=>({package:{ecosystem:'nuget',name},vulnerable_version_range:'>= '+version.split('.').slice(0,2).join('.')+'.0, < '+version,patched_versions:version});
const vendor=()=>({cve_id:finding.id,ghsa_id:'GHSA-p3jp-9v83-76w9',html_url:page,published_at:'2026-01-01',updated_at:'2026-01-02',withdrawn_at:null,vulnerabilities:[row('8.0.33'),row('10.0.14'),row('10.0.14','Microsoft.NETCore.App.Runtime.linux-x64')],description:'## Executive summary\nBrotli is a runtime dependency; exposure requires untrusted decompression.\n## Mitigations\nAvoid processing untrusted input until updated.\n## How do I fix the issue?\nInstall the matching update. Rebuild self-contained applications.\n## Other Information\nDo not include unrelated prose.'});
function runtime(fetcher){const c=vm.createContext({TextEncoder,TextDecoder,URL,AbortController,setTimeout,clearTimeout,fetch:fetcher});c.window=c;for(const file of ['inventory-matching.js','inventory-assessment.js','finding-ai.js'])vm.runInContext(fs.readFileSync(new URL('../'+file,import.meta.url),'utf8'),c);return c.CVEHARBOR_FINDING_AI;}
test('vendor evidence selects installed branch and keeps Windows package identity',async()=>{
 const calls=[];const ai=runtime(async(url,options)=>{calls.push({url,options});return Response.json(vendor());});
 const guide=await ai.enrich(finding,advisory),question=ai.question(finding,advisory,guide),e=JSON.parse(question.split('Evidence JSON:\n')[1]);
 assert.equal(calls.length,1);assert.equal(calls[0].options.credentials,'omit');assert.equal(calls[0].options.referrerPolicy,'no-referrer');assert.equal(calls[0].options.redirect,'error');assert.doesNotMatch(calls[0].url,/PRIVATE|10\.0\.3/);
 assert.equal(e.sources[0].url,page);assert.doesNotMatch(JSON.stringify(e.sources),/fortiguard/);
 assert.deepEqual(e.remediation_evidence.fixed_packages,[{package:'Microsoft.NETCore.App.Runtime.win-x64',affected:'>= 10.0.0, < 10.0.14',fixed:'10.0.14'}]);
 assert.match(question,/dotnet --list-runtimes/);assert.match(question,/Desktop Runtime includes/);assert.match(question,/self-contained/);assert.doesNotMatch(question,/PRIVATE-HOST|PRIVATE-NOTES|Other Information/);assert.ok(Buffer.byteLength(question)<6000);
 await ai.enrich(finding,advisory);assert.equal(calls.length,1,'public evidence is cached without customer data');
 const sdk=await ai.enrich({...finding,technology:'.NET SDK',version:'10.0.100'},advisory);assert.equal(sdk.facts.fixed_packages.length,0,'runtime patch versions are not SDK targets');
});
test('CNA lookup uses correct public bucket and discovers reviewed vendor only',async()=>{
 const calls=[],ai=runtime(async(url)=>{calls.push(url);return Response.json(url.includes('raw.githubusercontent')?{cveMetadata:{cveId:finding.id,state:'PUBLISHED'},containers:{cna:{references:[{url:page}],solutions:[{lang:'en',value:'Apply vendor release.'}]}}}:vendor());});
 const guide=await ai.enrich(finding,{sources:[]});assert.match(calls[0],/2026\/12xxx\/CVE-2026-12345.json$/);assert.equal(calls.length,2);assert.equal(guide.sources[0].url,page);
 for(const url of ['https://github.com.evil.test/dotnet/runtime/security/advisories/GHSA-p3jp-9v83-76w9',page+'?secret=x',page.replace('/dotnet/','/untrusted/'),'https://localhost/private'])assert.equal(ai.vendorLink(url,finding),null);
 assert.equal(ai.vendorLink(page,{technology:'PHP'}),null);
});
test('failed, oversized, withdrawn and mismatched evidence cannot supply a patch',async()=>{
 for(const response of [()=>{throw Error('offline');},()=>new Response('x',{status:429}),()=>Response.json({...vendor(),cve_id:'CVE-2026-99999'}),()=>Response.json({...vendor(),withdrawn_at:'2026-02-01'}),()=>Response.json({...vendor(),published_at:null}),()=>new Response('x'.repeat(524289)),()=>new Response('{}',{headers:{'content-length':'524289'}})]){
  const ai=runtime(async()=>response()),guide=await ai.enrich(finding,advisory);assert.equal(guide.facts.fixed_packages,undefined);assert.match(guide.facts.evidence_status,/unavailable/);assert.match(guide.facts.product_runbook,/dotnet --info/);
 }
});
test('generic CNA solutions and workarounds preserve source attribution',async()=>{
 const ai=runtime(async()=>Response.json({cveMetadata:{cveId:finding.id,state:'PUBLISHED'},containers:{cna:{solutions:[{lang:'en',value:'Install fictional 4.2.1.'}],workarounds:[{lang:'en',value:'Disable the affected optional feature.'}]}}}));
 const guide=await ai.enrich({...finding,technology:'ExampleProduct'}, {sources:[]});assert.equal(guide.facts.solutions,'Install fictional 4.2.1.');assert.equal(guide.facts.workarounds,'Disable the affected optional feature.');assert.match(guide.sources[0].url,/CVEProject/);
});
test('large multibyte evidence remains admitted with a matched fixed version and sources',async()=>{
 const data=vendor();data.description='## How do I fix the issue?\n'+'🧪'.repeat(5000)+'\n## Executive summary\n'+'🧪'.repeat(5000)+'\n## Mitigations\n'+'🧪'.repeat(5000);
 const ai=runtime(async()=>Response.json(data)),guide=await ai.enrich(finding,advisory);
 const question=ai.question({...finding,evidence:'🧪'.repeat(3000),comparison_detail:'🧪'.repeat(3000)},{...advisory,affected:'🧪'.repeat(3000),summary:'🧪'.repeat(3000),remediation:'🧪'.repeat(3000)},guide);
 assert.ok(Buffer.byteLength(question)<=6000);assert.match(question,/10\.0\.14/);assert.match(question,/Microsoft security advisory/);
});
