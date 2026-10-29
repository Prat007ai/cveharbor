import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizePluginLookup,pluginAdvisoryRoute} from '../src/plugin-advisories.js';
const slug='wp-file-manager';
test('matches confirmed slug and numeric affected version without inventing safety',()=>{
 const x=normalizePluginLookup(slug,'8.0.1',{error:0,updated:123,data:{slug,vulnerabilities:[
  {cve:'CVE-2026-12345',title:'File Manager test issue',operator:'lt',version:'8.0.2',severity:'high',url:'https://example.org/advisory'},
  {cve:'CVE-2026-12346',operator:'lt',version:'7.9.0'}]}});
 assert.equal(x.status,'checked');assert.equal(x.findings.length,1);
 assert.equal(x.findings[0].id,'CVE-2026-12345');
 assert.equal(x.findings[0].level,'version_review');
});
test('rejects unverified slug and unknown versions rather than claiming a clean scan',()=>{
 assert.equal(normalizePluginLookup(slug,'8.0.1',{error:0,data:{slug:'wrong',vulnerabilities:[]}}).status,'unverified');
 const x=normalizePluginLookup(slug,'unverified',{error:0,data:{slug,vulnerabilities:[{cve:'CVE-2026-12345',operator:'lt',version:'8.0.2'}]}});
 assert.equal(x.findings[0].level,'category');
});
test('authenticated request verifies ownership and fetches fixed public origin only',async()=>{
 const asset='11111111-1111-4111-8111-111111111111';
 const env={DB:{prepare(){return {bind(){return {first:async()=>({id:asset,technology:'WordPress Plugin: WP File Manager',version:'8.0.1'})}}}}}};
 let fetched='';
 const req=new Request('https://api.cveharbor.com/v1/plugin-advisories?asset_id='+asset+'&slug=wp-file-manager');
 const response=await pluginAdvisoryRoute(req,env,{id:'u1'},async url=>{fetched=url;return {ok:true,text:async()=>JSON.stringify({error:0,data:{slug,vulnerabilities:[]}})}});
 assert.match(fetched,/^https:\/\/www\.wpvulnerability\.net\/plugin\/wp-file-manager\/$/);
 assert.equal((await response.json()).status,'checked');
});

test('recognizes endpoint scoped responses without a redundant slug',()=>{
 const body={error:0,updated:123,data:{vulnerabilities:[
  {cve:'CVE-2026-98765',title:'Test plugin flaw',operator:'lt',version:'8.0.2'}]}};
 const result=normalizePluginLookup(slug,'8.0.1',body);
 assert.equal(result.status,'checked');
 assert.equal(result.findings[0].id,'CVE-2026-98765');
 assert.equal(normalizePluginLookup(slug,'8.0.1',{error:0,data:{vulnerabilities:[]}}).status,'checked');
});
test('explicit wrong slug and unrecognized payload remain unverified',()=>{
 assert.equal(normalizePluginLookup(slug,'8.0.1',{error:0,data:{slug:'unrelated',vulnerabilities:[]}}).status,'unverified');
 assert.equal(normalizePluginLookup(slug,'8.0.1',{error:0,data:{}}).status,'unverified');
 assert.equal(normalizePluginLookup(slug,'8.0.1',{error:1,data:null}).status,'unverified');
});

test('empty successful API data does not become a parsing failure',()=>{
 for(const data of [[],null,{}]){
  const result=normalizePluginLookup(slug,'8.0.1',{error:0,data});
  assert.equal(result.status,'checked');
  assert.deepEqual(result.findings,[]);
 }
});
test('direct vulnerability arrays and CVE arrays are parsed',()=>{
 const result=normalizePluginLookup(slug,'8.0.1',{error:0,data:[
  {cve:['CVE-2026-99991'],operator:'lt',version:'8.0.2',title:'Example'}
 ]});
 assert.equal(result.status,'checked');
 assert.equal(result.findings[0].id,'CVE-2026-99991');
});
test('other plugin identity is not accepted',()=>{
 const result=normalizePluginLookup(slug,'8.0.1',{error:0,data:[{slug:'other-plugin',vulnerabilities:[]}]});
 assert.equal(result.status,'unverified');
});
