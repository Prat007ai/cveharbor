import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const ctx=vm.createContext({URL,TextEncoder});ctx.window=ctx;
for(const f of ['inventory-matching.js','inventory-assessment.js'])vm.runInContext(fs.readFileSync(new URL('../'+f,import.meta.url),'utf8'),ctx);
const engine=ctx.CVEHARBOR_INVENTORY_MATCH,asset={technology:'Google Chrome',version:'130.0.0'};
const ready={name:asset.technology,cpe:'cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*',status:'ready',recent_complete_at:1,history_complete_at:1,stale:false};
test('every product has an explicit state; incomplete checks never claim no applicable matches',()=>{
 const status=(p,opts,a=asset)=>engine.productAssessment(a,p,opts).code;
 assert.equal(status(undefined),'unregistered');assert.equal(status(ready,{available:false}),'unavailable');
 assert.equal(status({...ready,cpe:'',status:'needs_identity'}),'unmapped');assert.equal(status({...ready,cpe:'',status:'queued'}),'resolving');
 for(const code of ['queued','scanning','retrying'])assert.equal(status({...ready,status:code}),code);
 assert.equal(status({...ready,stale:true}),'stale');assert.equal(status(ready,{limited:true}),'partial');
 assert.equal(status({...ready,coverage:{limited:true}}),'partial');assert.equal(status({...ready,recent_complete_at:null}),'pending');
 assert.equal(status(ready,{count:2}),'candidates');assert.equal(status(ready),'no_match');
 for(const version of ['', 'Unknown','Version unknown'])assert.equal(status(ready,{}, {...asset,version}),'version_missing');
});
test('Windows-agent products do not match explicitly mobile-only affected CPEs',()=>{
 const name='Microsoft OneDrive',a={id:'test',agent_device_id:'device',name:'TEST01',environment_id:'env',technology:name,version:'1.0'};
 const source={id:'CVE-2026-12345',source_type:'cvie_nvd',cvie_products:[name],cvie_identities:[{name,cpe:'cpe:2.3:a:microsoft:onedrive:*:*:*:*:*:*:*:*'}],affected_cpes:[{criteria:'cpe:2.3:a:microsoft:onedrive:*:*:*:*:*:android:*:*',versionEndExcluding:'2.0'}],severity:'high'};
 assert.equal(engine.evaluate([a],[source]).items.length,0);
 assert.equal(engine.evaluate([{...a,agent_device_id:null}],[source]).items.length,1,'unknown platform retains uncertainty');
});
test('Python interpreter assessment uses the explicit runtime release rather than the MSI package build',()=>{
 const name='Python 3.12.10 Core Interpreter (64-bit)',a={id:'test',technology:name,version:'3.12.10150.0'};
 const source={id:'CVE-2026-12345',source_type:'cvie_nvd',cvie_products:[name],affected_cpes:[{criteria:'cpe:2.3:a:python:python:*:*:*:*:*:*:*:*',cvie_product_key:name,versionStartIncluding:'3.12.0',versionEndExcluding:'3.12.11'}],severity:'high'};
 assert.equal(engine.structuredAssessment(a,source),'within');
 assert.equal(engine.structuredAssessment({...a,technology:'Python 3.12.11 Core Interpreter (64-bit)'},{...source,cvie_products:['Python 3.12.11 Core Interpreter (64-bit)'],affected_cpes:[{...source.affected_cpes[0],cvie_product_key:'Python 3.12.11 Core Interpreter (64-bit)'}]}),'outside');
 assert.equal(a.version,'3.12.10150.0','collected evidence remains unchanged');
});
