// Customer dialogs use synthetic fixtures and never call production services.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {JSDOM} from 'jsdom';
import {securityFixture} from './customer_security_fixture.mjs';
const fixture=securityFixture();
const full='Full description: '+('Detailed PHP vulnerability evidence. '.repeat(30))+'End of full advisory.';
Object.assign(fixture.advisories[0],{summary:full,cvss:9.8,epss:0.1065,epss_as_of:'2026-11-01',status:'Analyzed',remediation:'Install the vendor-fixed PHP release.',action:'Verify package applicability.',kev_added:'2026-10-25',kev_required_action:'Apply vendor mitigation.',provenance:[{source:'nvd',checked_at:'invalid',updated:'2026-10-24'}]});
fixture.advisories[0].sources.push({label:'Unsafe',url:'javascript:alert(1)'});
const settle=()=>new Promise(r=>setTimeout(r,30));
for(const kind of ['customer-dashboard','customer-reports']){
 const dom=new JSDOM(fs.readFileSync(kind+'/index.html','utf8'),{url:'https://cveharbor.com/'+kind+'/?customer=c1',runScripts:'outside-only'});
 const w=dom.window,d=w.document;w.fetch=(url,options)=>new URL(url).pathname==='/v1/plugin-monitor'?Promise.resolve({ok:true,status:200,json:async()=>({ready:true,checks:[{asset_id:'a4',installed_version:'3.1.0',status:'checked',findings:[{id:'CVE-2026-99999',severity:'high',title:'Plugin-only advisory',summary:'Full plugin advisory absent from explorer.',affected:'Autoptimize before 3.1.1',sources:[{label:'Plugin source',url:'https://example.test/plugin'}]}]}]})}):fixture.request(url,options);w.CVEHARBOR_DATA={advisories:fixture.advisories};
 for(const file of ['advisory-details.js','inventory-matching.js','customer-score.js','customer-security.js'])w.eval(fs.readFileSync(file,'utf8'));
 await settle();const env=d.getElementById('customerDashEnvironment');env.value='e1';env.dispatchEvent(new w.Event('change'));await settle();
 const first=d.querySelector('.customer-cve-detail');assert.equal(first.textContent,'CVE-2026-12345');
 const status=d.querySelector('.customer-vulnerability-table .customer-finding-status-select'),ticket=d.querySelector('.customer-vulnerability-table .customer-ticket-input');
 if(status){status.value='Fix in Progress';status.dispatchEvent(new w.Event('change'));ticket.value='UNSAVED-42';ticket.dispatchEvent(new w.Event('input'))}
 const requests=fixture.seen.length,writes=fixture.writes.length;
 first.click();const modal=d.querySelector('.customer-finding-dialog');assert.ok(modal.open);
 assert.ok(modal.textContent.includes(full),'full description is not the clipped table summary');
 for(const value of ['9.8','10.65%','CISA exploitation evidence','Apply vendor mitigation.','PHP before 8.4.2','Install the vendor-fixed PHP release.','WEB01','Fixture Harbor','Production','DEV-10','Affected version detected'])assert.ok(modal.textContent.includes(value),value);
 assert.doesNotMatch(modal.textContent,/STAGE01|OTHER01|Other Customer|UNSAVED-42/);
 assert.equal(modal.querySelectorAll('input,select,.remediation-detail-assign').length,0,'details stay read only');
 assert.equal(modal.querySelectorAll('a[href^="javascript:"]').length,0);
 assert.ok([...modal.querySelectorAll('a')].every(a=>a.target==='_blank'&&a.rel==='noopener noreferrer'));
 assert.equal(fixture.seen.length,requests,'opening details causes no fetch or scan');assert.equal(fixture.writes.length,writes);
 modal.querySelector('.close-dialog').click();assert.equal(d.querySelector('.customer-finding-dialog'),null);
 if(status){assert.equal(status.value,'Fix in Progress');assert.equal(ticket.value,'UNSAVED-42')}
 [...d.querySelectorAll('.customer-cve-detail')].find(b=>b.textContent==='CVE-2026-99999').click();
 const pluginModal=d.querySelector('.customer-finding-dialog');assert.match(pluginModal.textContent,/Full plugin advisory absent from explorer/);assert.match(pluginModal.textContent,/SITE01/);assert.doesNotMatch(pluginModal.textContent,/Reported CVSS/);
 pluginModal.querySelector('.close-dialog').click();
 first.click();env.value='e2';env.dispatchEvent(new w.Event('change'));assert.equal(d.querySelector('.customer-finding-dialog'),null,'scope changes clear private context');
 d.querySelector('.customer-cve-detail').click();assert.match(d.querySelector('.customer-finding-dialog').textContent,/STAGE01/);assert.doesNotMatch(d.querySelector('.customer-finding-dialog').textContent,/WEB01/);
 w.dispatchEvent(new w.CustomEvent('cveharbor:account-state',{detail:{authenticated:false}}));assert.equal(d.querySelector('.customer-finding-dialog'),null,'signout removes private modal content');
 dom.window.close();
}
// Plugin-only records need no copy in the explorer; missing facts remain missing.
const dom=new JSDOM('<main></main>',{runScripts:'outside-only'});dom.window.eval(fs.readFileSync('advisory-details.js','utf8'));
const root=dom.window.document.querySelector('main');
dom.window.CVEHARBOR_ADVISORY_DETAILS.render(root,{id:'CVE-2026-99999',summary:'<img src=x onerror=alert(1)>',severity:'unknown'});
assert.ok(root.textContent.includes('<img src=x onerror=alert(1)>'));assert.equal(root.querySelectorAll('img').length,0);
assert.match(root.textContent,/Not provided by the indexed source/);assert.doesNotMatch(root.textContent,/Reported CVSS|FIRST EPSS/);
dom.window.close();
console.log('PASS: shared CVE details, full source metadata, scoped evidence, drafts, safe references, missing data and no reads/writes');
