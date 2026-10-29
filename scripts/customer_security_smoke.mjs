import assert from 'node:assert/strict';
import fs from 'node:fs';
import {JSDOM} from 'jsdom';

const html=fs.readFileSync('customer-reports/index.html','utf8');
const dom=new JSDOM(html,{url:'https://cveharbor.com/customer-reports/?customer=c1',runScripts:'outside-only'});
const {window}=dom,doc=window.document;
const sample={
 customers:[{id:'c1',name:'Customer A'},{id:'c2',name:'Customer B'}],
 environments:[{id:'e1',customer_id:'c1',name:'Production',kind:'Production'},
 {id:'e2',customer_id:'c2',name:'Staging',kind:'Staging'}],
 assets:[{id:'a1',environment_id:'e1',name:'WEB01',asset_type:'Server',technology:'PHP',version:'8.4.26'},
 {id:'a2',environment_id:'e2',name:'WEB02',asset_type:'Server',technology:'Python',version:'3.11.1'}]
};
window.CVEHARBOR_DATA={advisories:[{id:'CVE-2026-32101',categories:['PHP'],severity:'critical',
 title:'Test PHP vulnerability',affected:'PHP before 8.4.27',sources:[{url:'https://example.com/cve'}]}]};
window.CVEHARBOR_CATALOG={advisories:[]};
window.CVEHARBOR_INVENTORY_MATCH={evaluate(assets){
 return {items:assets.filter(x=>x.technology==='PHP').map(x=>({id:'CVE-2026-32101',title:'Test PHP vulnerability',
 asset_id:x.id,technology:'PHP',version:x.version,severity:'critical',known_exploited:false,
 level:'version_review',evidence:'Requires verification',source_url:'https://example.com/cve'})),total:assets.filter(x=>x.technology==='PHP').length,limited:false};
}};
const seen=[];
window.fetch=async url=>{
 seen.push(String(url));
 if(String(url).endsWith('/me'))return {ok:true,json:async()=>({authenticated:true,email:'admin@example.com'})};
 if(String(url).endsWith('/inventory/status'))return {ok:true,json:async()=>({ready:true})};
 if(String(url).endsWith('/inventory'))return {ok:true,json:async()=>sample};
 return {ok:false,json:async()=>({error:'Unexpected endpoint'})};
};
window.eval(fs.readFileSync('customer-security.js','utf8'));
await new Promise(resolve=>setTimeout(resolve,20));
assert.equal(doc.querySelector('#customerDashFilter').value,'c1','customer selected using a valid scoped query');
assert.match(doc.querySelector('#customerReportBody').textContent,/Customer A/);
assert.match(doc.querySelector('#customerReportBody').textContent,/CVE-2026-32101/);
assert.doesNotMatch(doc.querySelector('#customerReportBody').textContent,/Customer B|WEB02/,'other customer inventory never appears in report');
assert.equal(doc.querySelector('#customerReportPrint').disabled,false);
assert.ok(seen.every(x=>x.startsWith('https://api.cveharbor.com/v1/')),'only authenticated account API used for private reads');
window.close();
const unauth=new JSDOM(html,{url:'https://cveharbor.com/customer-reports/',runScripts:'outside-only'});
unauth.window.fetch=async()=>({ok:false,status:401,json:async()=>({error:'Sign in required'})});
unauth.window.eval(fs.readFileSync('customer-security.js','utf8'));
await new Promise(resolve=>setTimeout(resolve,20));
assert.equal(unauth.window.document.getElementById('customerDashLogin').hidden,false,'signed out users see login action');
assert.match(unauth.window.document.getElementById('customerDashStatus').textContent,/Sign in required/);
unauth.window.close();
console.log('Customer reports remain scoped to selected customer and include candidate evidence');
