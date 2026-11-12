import assert from 'node:assert/strict';
import fs from 'node:fs';
import {JSDOM,VirtualConsole} from 'jsdom';
import {securityFixture} from './customer_security_fixture.mjs';
const source=name=>fs.readFileSync(name,'utf8');
const tick=()=>new Promise(r=>setTimeout(r,30));
const csv='Asset Name,Asset Type,Technology,Version,Notes\r\nDEMO01,Server,.NET Runtime,8.0.1,Fictional\r\nDEMO01,Server,.NET Runtime,8.0.2,Fictional\r\nDEMO01,Server,.NET Runtime,8.0.2,Duplicate\r\n';
function dom(html='<main></main>',url='https://cveharbor.com/'){
 const d=new JSDOM(html,{url,runScripts:'outside-only',virtualConsole:new VirtualConsole()});
 d.window.TextEncoder=TextEncoder;return d;
}
for(const organization of [false,true]){
 const d=dom(),w=d.window,host=w.document.querySelector('main');w.eval(source('asset-import.js'));
 let scope={customer:'demo',environment:'prod',...(organization?{org:'north'}:{})},saved=[],fail=true;
 w.CVEHARBOR_ASSET_IMPORT.mount(host,{scope:()=>scope,readAssets:async()=>saved,
  saveAsset:async a=>{if(fail&&saved.length===1)throw Error('Fictional network interruption');saved.push({...a,id:'a'+saved.length});}});
 const file=host.querySelector('[type=file]'),check=host.querySelector('[type=checkbox]'),submit=[...host.querySelectorAll('button')].find(x=>x.textContent==='Import and assess vulnerabilities');
 async function upload(text=csv){Object.defineProperty(file,'files',{configurable:true,value:[{name:'demo.csv',size:Buffer.byteLength(text),text:async()=>text}]});await file.onchange();}
 await upload();assert.match(host.textContent,/2 distinct entries; 1 duplicate/);assert.equal(submit.disabled,true);
 check.checked=true;check.onchange();await submit.onclick();assert.equal(saved.length,1);assert.match(host.textContent,/Imported 1; skipped 0.*interruption/);
 fail=false;await upload();check.checked=true;check.onchange();await submit.onclick();assert.equal(saved.length,2);assert.match(host.textContent,/1 entries imported; 1 existing entries skipped/);
 const target=new URL(host.querySelector('a[href^="/customer-dashboard/"]').href);
 assert.equal(target.searchParams.get('org'),organization?'north':null);assert.equal(target.searchParams.get('environment'),'prod');
 await upload();scope={...scope,environment:'another'};check.checked=true;await submit.onclick();assert.equal(saved.length,2);assert.match(host.textContent,/context changed|environment changed/);
 await upload('Asset Name,Asset Type,Technology,Version,Notes\nDEMO01,Server,"<img src=x onerror=alert(1)>",1.0,fictional');assert.equal(host.querySelector('img'),null);assert.match(host.textContent,/<img src=x/);
 await upload('bad,headers\na,b');assert.equal(submit.disabled,true);assert.match(host.textContent,/Headers must be/);d.window.close();
}

// Persisted imported rows are assessed in the personal dashboard, scoped to the URL environment.
const fixture=securityFixture();fixture.inventory.assets.push({id:'dotnet-demo',environment_id:'e1',name:'DEMO01',technology:'.NET Runtime',version:'8.0.1',asset_type:'Server'});
fixture.advisories.push({id:'CVE-2099-12345',title:'Fictional .NET advisory',affected:'.NET Runtime before 8.0.3',severity:'high',sources:[{url:'https://example.test/advisory'}]});
const personal=dom(source('customer-dashboard/index.html'),'https://cveharbor.com/customer-dashboard/?customer=c1&environment=e1');
personal.window.fetch=fixture.request;personal.window.CVEHARBOR_DATA={advisories:fixture.advisories};
for(const name of ['inventory-matching.js','inventory-assessment.js','customer-score.js','advisory-details.js','server-security.js','customer-security.js'])personal.window.eval(source(name));
await tick();assert.match(personal.window.document.getElementById('customerDashboardAssessment').textContent,/3 software entries assessed/);
assert.doesNotMatch(personal.window.document.getElementById('customerDashboardAssessment').textContent,/OTHER01|STAGE01/);
assert.match(personal.window.document.getElementById('customerDashboardCves').textContent,/CVE-2099-12345/);
assert.ok(!fixture.seen.some(x=>/ai\//.test(x.path)));personal.window.close();

// Actual organization rendering module: no personal inventory/CVIE requests, scope revocation clears results.
async function organization(query,role='Viewer'){
 const d=dom(source('customer-dashboard/index.html'),'https://cveharbor.com/customer-dashboard/?org=north&'+query),w=d.window;let revoked=false;const requests=[];
 w.CVEHARBOR_DATA={advisories:fixture.advisories};
 w.fetch=async url=>{requests.push(url);assert.ok(url.includes('/v1/team/'),'organization page made a personal API request');
  const result=revoked?{error:'Access removed'}:url.endsWith('/customers')?{name:'Northstar Demo',customers:[{id:'c1',name:'Demo Customer'}]}:{customer:{name:'Demo Customer',role},environments:[{id:'e1',name:'Demo Production'}],assets:fixture.inventory.assets.filter(a=>a.environment_id==='e1'),remediations:[]};
  return {ok:!revoked,status:revoked?404:200,json:async()=>result};};
 for(const name of ['cvie.js','inventory-matching.js','inventory-assessment.js','server-security.js','customer-security.js'])w.eval(source(name));
 w.eval('(async()=>{'+source('team-ui.js').replaceAll('export ','')+'\n'+source('organization-security.js').replace(/^import .*?;\r?\n/m,'')+'})()');
 await tick();return {d,w,requests,revoke:()=>{revoked=true;w.dispatchEvent(new w.Event('focus'));}};
}
const org=await organization('customer=c1&environment=e1');
assert.match(org.w.document.querySelector('.organization-security').textContent,/CVE-2099-12345/);
assert.equal(org.w.document.querySelector('#customerDashAccess').hidden,true);
assert.doesNotMatch(org.w.document.querySelector('.organization-security').textContent,/OTHER01|STAGE01/);
assert.equal(org.w.document.querySelector('.organization-security [type=file]'),null);
org.revoke();await tick();assert.equal(org.w.document.querySelector('.organization-security').textContent,'');assert.match(org.w.document.getElementById('customerDashStatus').textContent,/Access removed/);org.w.close();
for(const query of ['customer=foreign','customer=c1&environment=foreign']){const x=await organization(query);assert.match(x.w.document.getElementById('customerDashStatus').textContent,/not available/);assert.equal(x.w.document.querySelector('.organization-security').textContent,'');x.w.close();}
console.log('PASS: reviewed imports, partial retries, side-by-side versions, scope changes, safe CSV rendering, persisted dashboard findings, organization isolation/revocation and no AI calls.');
