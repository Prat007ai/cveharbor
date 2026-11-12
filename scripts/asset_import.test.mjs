import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const context=vm.createContext({TextEncoder,URL});context.window=context;
for(const f of ['asset-import.js','inventory-matching.js','inventory-assessment.js'])vm.runInContext(fs.readFileSync(f,'utf8'),context);
const {parse,key}=context.CVEHARBOR_ASSET_IMPORT,match=context.CVEHARBOR_INVENTORY_MATCH;
const head='Asset Name,Asset Type,Technology,Version,Notes\r\n';
test('network CSV retains multiple adapters, preserves legacy import and rejects conflicting snapshots',()=>{
 const network={version:1,collected_at:'2026-01-01T00:00:00Z',adapters:[{id:'lan',name:'LAN',status:'Up',addresses:[{ip:'192.0.2.10',prefix:24,state:'Preferred'},{ip:'2001:db8::10',prefix:64,state:'Preferred'}]},{id:'backup',name:'Backup',status:'Disconnected',addresses:[]}],suggested:{adapter_id:'lan',ip:'192.0.2.10'}};
 const row=(n,version='1')=>'DEMO,Server,Product,'+version+',,"'+JSON.stringify(n).replaceAll('"','""')+'"\r\n';
 const header=head.trim()+',Server Network\r\n';const parsed=parse(header+row(network)+row(network,'2'));
 assert.equal(parsed.entries.length,2);assert.equal(parsed.networks.length,1);assert.equal(parsed.networks[0].snapshot.adapters.length,2);
 assert.throws(()=>parse(header+row(network)+row({...network,collected_at:'2026-01-02T00:00:00Z'},'2')),/Conflicting/);
 assert.throws(()=>parse(header+row({...network,suggested:{adapter_id:'lan',ip:'invalid'}})),/Invalid/);
});
test('UTF8 BOM, quotes, versions, missing version and exact duplicate handling',()=>{
 const result=parse('\uFEFF'+head+'DEMO,Server,.NET Runtime,8.0.1,"Publisher: Example, Inc"\r\nDEMO,Server,.NET Runtime,8.0.2,\r\nDEMO,Server,.NET Runtime,8.0.1,duplicate\r\nDEMO,Server,Unknown,,Review\r\n');
 assert.equal(result.entries.length,3);assert.equal(result.duplicates,1);assert.equal(result.warnings.length,1);
 assert.notEqual(key(result.entries[0]),key(result.entries[1]));assert.equal(result.entries[0].notes,'Publisher: Example, Inc');
});
test('malformed or unsafe files reject before any writes',()=>{
 for(const csv of ['wrong\n',head,head+'x,Server,Product,1,"unterminated',head+'x,Server,"Product"junk,1,n',head+'x,wrong,Product,1,n',head+'=cmd,Server,Product,1,n',head+'x,Server,Product,1,"two\nlines"',head+Array(201).fill('x,Server,Product,1,n').join('\n'),head+'x,Server,'+'X'.repeat(132000)+',1,n'])assert.throws(()=>parse(csv));
 assert.equal(parse(head+"'=cmd,Server,Product,1,n").entries.length,1);
});
const advisory=(product,extra={})=>({id:'CVE-2026-12345',categories:['Windows','.NET Core'],title:'Fictional advisory',affected:product+' before 9.0.0',sources:[{url:'https://example.test/advisory',label:'Fictional source'}],...extra});
test('Windows and Framework builds do not produce false version conclusions',()=>{
 for(const technology of ['Windows Server','.NET Framework','IIS']){
  const a={id:'a',technology,version:'10.0.20348.1'};
  const r=advisory(technology==='IIS'?'Microsoft IIS':technology);
  assert.equal(match.candidate(a,r).level,'category');
 }
});
test('product identities, sources, exclusions and legacy safeguards',()=>{
 const runtime={id:'a',technology:'.NET Runtime',version:'8.0.1'};
 assert.equal(match.candidate(runtime,advisory('.NET Framework')),null);
 assert.equal(match.candidate(runtime,advisory('.NET Runtime')).level,'category');
 assert.equal(match.candidate(runtime,advisory('.NET Runtime',{status:'rejected'})),null);
 assert.equal(match.candidate(runtime,advisory('.NET Runtime',{sources:[{url:'javascript:alert(1)'}]})),null);
 assert.equal(match.candidate(runtime,advisory('.NET Runtime',{cvie_excluded_products:['.NET Runtime']})),null);
 assert.equal(match.candidate({id:'x',technology:'WordPress',version:'6.0'},advisory('WordPress plugin Foo',{categories:['WordPress / Plugins']})),null);
 assert.equal(match.candidate({id:'x',technology:'Acme Tool',version:'1'},advisory('Acme Toolbox')),null);
});
test('distinct installed versions produce distinct potential findings',()=>{
 const a=[{id:'one',technology:'.NET Runtime',version:'8.0.1'},{id:'two',technology:'.NET Runtime',version:'8.0.2'}];
 const r=match.evaluate(a,[advisory('.NET Runtime'),advisory('.NET Runtime')]);assert.equal(r.total,2);
 assert.equal(match.evaluate(a,[advisory('.NET Runtime')],1).limited,true);
});
