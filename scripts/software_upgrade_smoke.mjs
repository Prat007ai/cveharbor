import assert from 'node:assert/strict';
import fs from 'node:fs';
import {JSDOM} from 'jsdom';
import {securityFixture} from './customer_security_fixture.mjs';
const f=securityFixture(),core=f.inventory.assets.find(a=>a.id==='a1'),plugin=f.inventory.assets.find(a=>a.id==='a4');
Object.assign(core,{technology:'WordPress',version:'6.6.1'});
const advisory=(id,affected,title)=>({id,affected,title,summary:title,categories:['WordPress / Plugins'],severity:'high',published:'2026-10-01'});
f.advisories.splice(0,f.advisories.length,
 advisory('CVE-2026-70001','WordPress before 6.6.2','WordPress core old range'),
 advisory('CVE-2026-70002','WordPress through 6.7.1','WordPress core still affected'),
 advisory('CVE-2026-70003','Autoptimize before 3.2.0','Autoptimize plugin old range'),
 advisory('CVE-2026-70004','','Autoptimize plugin requires verification'));
const staleCheck={asset_id:'a4',installed_version:'3.1.0',status:'checked',release:{installed_version:'3.1.0',release_status:'verified',update_status:'Update Available'},findings:[{id:'CVE-2026-80001',title:'Saved old plugin check',severity:'high',level:'version_review'}]};
const until=async fn=>{const end=Date.now()+3000;while(!fn()){if(Date.now()>end)throw Error('Upgrade UI did not settle');await new Promise(r=>setTimeout(r,5));}};
async function page(kind){
 const dom=new JSDOM(fs.readFileSync(kind+'/index.html','utf8'),{url:'https://cveharbor.com/'+kind+'/?customer=c1',runScripts:'outside-only'}),w=dom.window;
 w.fetch=async(url,opts)=>new URL(url).pathname==='/v1/plugin-monitor'?{ok:true,json:async()=>({ready:true,checks:[structuredClone(staleCheck)]})}:f.request(url,opts);
 w.alert=message=>{w.lastAlert=message};w.CVEHARBOR_DATA={advisories:f.advisories};
 for(const s of ['inventory-matching.js','customer-score.js','advisory-details.js','customer-security.js'])w.eval(fs.readFileSync(s,'utf8'));
 await until(()=>w.document.querySelector('.customer-vulnerability-table'));
 const select=w.document.getElementById('customerDashEnvironment');select.value='e1';select.dispatchEvent(new w.Event('change'));
 return dom;
}
const report=await page('customer-reports'),dashboard=await page('customer-dashboard');
const text=dom=>dom.window.document.querySelector('.customer-vulnerability-table').textContent;
const refresh=dom=>dom.window.dispatchEvent(new dom.window.Event('focus'));
async function edit(asset,version){return f.request('https://api.cveharbor.com/v1/inventory/assets/'+asset.id,{method:'PUT',body:JSON.stringify({...asset,version})})}
try{
 assert.match(text(report),/70001/);assert.match(text(report),/70003/);assert.match(text(report),/80001/);
 await edit(core,'6.6.2');assert.match(text(report),/70001/,'test response is an independent JSON snapshot');
 refresh(report);refresh(dashboard);
 await until(()=>!text(report).includes('70001')&&!text(dashboard).includes('70001'));
 assert.match(text(report),/70002/,'new version still within another affected range remains visible');
 await edit(plugin,'3.2.0');refresh(report);refresh(dashboard);
 await until(()=>!text(report).includes('70003')&&!text(report).includes('80001')&&!text(dashboard).includes('80001'));
 assert.match(text(report),/70004/,'ambiguous advisory is not silently declared fixed');
 assert.equal(report.window.document.querySelectorAll('.customer-update-indicator').length,0,'stale release does not claim the new version needs updating');
 await until(()=>report.window.document.querySelector('.customer-upgrade-history').textContent.includes('3.2.0'));
 assert.match(report.window.document.querySelector('.customer-upgrade-history').textContent,/6\.6\.1.*6\.6\.2/);
 assert.match(dashboard.window.document.querySelector('.customer-upgrade-history').textContent,/3\.1\.0.*3\.2\.0/);
 assert.equal(report.window.document.querySelectorAll('.customer-upgrade-history input,.customer-upgrade-history select').length,0);
 assert.equal(f.writes.length,2,'refreshing dashboards, reports and history performs no writes');
 // Exports also re-read versions without requiring a focus event.
 await edit(core,'6.8.0');let csv='';const w=report.window;
 w.Blob=class{constructor(parts){csv=parts.join('')}};w.URL.createObjectURL=()=> 'blob:test';w.URL.revokeObjectURL=()=>{};w.HTMLAnchorElement.prototype.click=()=>{};
 w.document.getElementById('customerReportCsv').click();await until(()=>csv.length>0);
 assert.doesNotMatch(csv,/70001|70002|70003|80001/);assert.match(csv,/70004/);
 assert.match(w.document.querySelector('.customer-print-document').textContent,/Software Upgrade History.*6\.6\.2.*6\.8\.0/);
 const env=w.document.getElementById('customerDashEnvironment');env.value='e2';env.dispatchEvent(new w.Event('change'));
 await until(()=>w.document.querySelector('.customer-upgrade-history').textContent.includes('No software version changes'));
 assert.doesNotMatch(w.document.querySelector('.customer-upgrade-history').textContent,/6\.8\.0|3\.2\.0/);
 // Existing structured range comparisons exclude only proven out-of-range versions.
 const matcher=w.CVEHARBOR_INVENTORY_MATCH;
 const range={criteria:'cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*',versionStartIncluding:'6.0',versionEndExcluding:'6.6.2'};
 assert.equal(matcher.cvieVersionAssessment('6.6.1',[range]),'within');assert.equal(matcher.cvieVersionAssessment('6.6.2',[range]),'outside');
 assert.equal(matcher.cvieVersionAssessment('6.7',[range,{...range,versionStartIncluding:'6.7',versionEndExcluding:'6.8'}]),'within');
 assert.equal(matcher.cvieVersionAssessment('6.6.2',[{...range,comparison_unsupported:true}]),'unknown');
 console.log('PASS software upgrades: fresh inventory, WordPress and plugin range exclusions, retained ambiguous/current findings, stale plugin evidence rejected, scoped history, no report writes and fresh exports.');
}finally{report.window.close();dashboard.window.close()}
