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
