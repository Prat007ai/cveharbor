import assert from 'node:assert/strict';
import fs from 'node:fs';
import {JSDOM} from 'jsdom';

// Product-specific matching must not inflate a PHP inventory with unrelated software.
const matchingDom=new JSDOM('<!doctype html><html></html>',{runScripts:'outside-only'});
matchingDom.window.eval(fs.readFileSync('inventory-matching.js','utf8'));
const match=matchingDom.window.CVEHARBOR_INVENTORY_MATCH;
const phpAsset={id:'php',technology:'PHP',version:'8.3.36'};
const coreAsset={id:'wp',technology:'WordPress',version:'6.6.2'};
const pluginAsset={id:'plugin',technology:'WordPress Plugin: WP File Manager',version:'8.0.1'};
const finding=(id,category,description)=>({id,categories:[category],title:description,summary:description,severity:'high'});
assert.equal(match.candidate(phpAsset,finding('CVE-2026-11111','PHP','Linux kernel skb vulnerability')),null);
assert.equal(match.candidate(phpAsset,finding('CVE-2026-11112','PHP','ASP.NET Core Brotli decoder vulnerability')),null);
assert.equal(match.candidate(phpAsset,finding('CVE-2026-11113','PHP','DedeCMS PHP code injection')),null);
assert.equal(match.candidate(phpAsset,finding('CVE-2026-11114','PHP','WordPress plugin WP File Manager vulnerability')),null);
assert.ok(match.candidate(phpAsset,{...finding('CVE-2026-11115','PHP','PHP runtime overflow'),affected:'PHP before 8.3.37'}));
assert.equal(match.candidate(coreAsset,finding('CVE-2026-11116','WordPress / Plugins','WP File Manager plugin vulnerability')),null);
assert.ok(match.candidate(pluginAsset,finding('CVE-2026-11117','WordPress / Plugins','WP File Manager plugin vulnerability')));
assert.equal(match.candidate(pluginAsset,finding('CVE-2026-11118','WordPress / Plugins','Gravity Forms plugin vulnerability')),null);
matchingDom.window.close();

const html=fs.readFileSync('customer-reports/index.html','utf8');
assert.ok(html.includes('customer-security.js?v=score-v1'),'report loads fresh plugin monitoring script');
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
 level:'version_review',evidence:'Version review required',affected:'PHP before 8.4.27',comparison_detail:'Installed 8.4.26 before 8.4.27',summary:'Test  PHP\n vulnerability with   irregular spacing',remediation:'Upgrade to 8.4.27',source_label:'Test advisory',published:'2026-10-24',source_url:'https://example.com/cve'})),total:assets.filter(x=>x.technology==='PHP').length,limited:false};
}};
const seen=[];
const statusWrites=[];
let savedStatus='Needs Review';
window.fetch=async (url,options={})=>{
 seen.push(String(url));
 if(String(url).endsWith('/me'))return {ok:true,json:async()=>({authenticated:true,email:'admin@example.com'})};
 if(String(url).endsWith('/inventory/status'))return {ok:true,json:async()=>({ready:true})};
 if(String(url).endsWith('/inventory'))return {ok:true,json:async()=>sample};
 if(String(url).endsWith('/finding-tickets'))return {ok:true,json:async()=>({ready:true,append_ready:true,tickets:[]})};
 if(String(url).includes('/finding-tickets/')&&options.method==='POST'){statusWrites.push({ticket:JSON.parse(options.body).ticket_number});return {ok:true,json:async()=>({saved:true})}}
 if(String(url).endsWith('/plugin-installation-status'))return {ok:true,json:async()=>({ready:true,statuses:[]})};
 if(String(url).endsWith('/plugin-sources'))return {ok:true,json:async()=>({ready:true,sources:[]})};
 if(String(url).endsWith('/finding-statuses'))return {ok:true,json:async()=>({ready:true,statuses:[]})};
 if(String(url).includes('/finding-statuses/')&&options.method==='PUT'){
  const body=JSON.parse(options.body);statusWrites.push({url:String(url),...body});savedStatus=body.status;
  return {ok:true,json:async()=>({saved:true})};
 }
 return {ok:false,json:async()=>({error:'Unexpected endpoint'})};
};
window.eval(fs.readFileSync('customer-security.js','utf8'));
await new Promise(resolve=>setTimeout(resolve,20));
assert.equal(doc.querySelector('#customerDashFilter').value,'c1','customer selected using a valid scoped query');
assert.match(doc.querySelector('#customerReportBody').textContent,/Customer A/);
assert.match(doc.querySelector('#customerReportBody').textContent,/CVE-2026-32101/);
assert.match(doc.querySelector('#customerReportBody').textContent,/PHP before 8.4.27/);
assert.match(doc.querySelector('#customerReportBody').textContent,/2026-10-24/);
assert.match(doc.querySelector('.customer-report-table:nth-of-type(3)')?.textContent||doc.querySelector('#customerReportBody').textContent,/Test PHP vulnerability with irregular spacing/,'summary whitespace is normalized');
assert.ok(!doc.querySelector('#customerReportBody').textContent.includes('Test  PHP'),'report does not expose repeated whitespace');
assert.match(fs.readFileSync('customer-security.js','utf8'),/f\.published\|\|'Not available',shortSummary\(f\)/,'CSV has explicit missing publication date fallback');
assert.deepEqual([...doc.querySelectorAll('.customer-vulnerability-table thead th')].map(x=>x.textContent.replace(/[▲▼⇅]/g,'').trim()),['CVE','Published','Severity','Software / Asset','Vulnerability summary','Vulnerability Fix Status','DevOps Ticket #']);
for(const key of ['Published','Severity','Software / Asset','Vulnerability Fix Status']){
 const header=[...doc.querySelectorAll('.customer-report-sort')].find(b=>b.textContent.startsWith(key));
 assert.ok(header,'sortable report header exists: '+key);
 header.click();
 assert.equal(doc.querySelector('.customer-vulnerability-table th[aria-sort="ascending"]')?.textContent.includes(key),true);
}
const expectedSections=['Recorded Technology Inventory','Vulnerabilities Requiring Verification','CVE Findings','Advisory Evidence and References'];
for(const label of expectedSections){
 const section=[...doc.querySelectorAll('#customerReportBody details.customer-report-section')].find(el=>el.dataset.section===label);
 assert.ok(section,'report has collapsible section: '+label);
 assert.equal(section.open,false,'section collapsed by default: '+label);
}
assert.ok([...doc.querySelectorAll('#customerReportBody h2')].some(el=>el.textContent==='Executive Summary'),'executive summary stays visible');
let findingsPanel=[...doc.querySelectorAll('#customerReportBody details.customer-report-section')].find(el=>el.dataset.section==='CVE Findings');
findingsPanel.open=true;
findingsPanel.dispatchEvent(new window.Event('toggle'));
await new Promise(resolve=>setTimeout(resolve,5));
doc.querySelector('.customer-report-sort').click();
findingsPanel=[...doc.querySelectorAll('#customerReportBody details.customer-report-section')].find(el=>el.dataset.section==='CVE Findings');
assert.equal(findingsPanel.open,true,'expanded state survives report redraw');
window.dispatchEvent(new window.Event('beforeprint'));
assert.ok([...doc.querySelectorAll('#customerReportBody details.customer-report-section')].every(el=>el.open),'all sections expand for printing');
window.dispatchEvent(new window.Event('afterprint'));
assert.equal([...doc.querySelectorAll('#customerReportBody details.customer-report-section')].find(el=>el.dataset.section==='Recorded Technology Inventory').open,false,'previous collapsed state restored after printing');
assert.equal(doc.querySelectorAll('#customerReportBody .customer-report-finding').length,1);
assert.ok(fs.readFileSync('customer-security.js','utf8').includes('plugin-monitor/refresh-batch'),'report includes authenticated plugin recheck action');
const ticketInput=doc.querySelector('.customer-ticket-input');
assert.ok(ticketInput&&!ticketInput.disabled,'DevOps ticket field is editable');
ticketInput.value='WOODBINE-123';
doc.querySelector('.customer-ticket-save').click();
await new Promise(resolve=>setTimeout(resolve,20));
assert.ok(statusWrites.some(x=>x.ticket==='WOODBINE-123'),'ticket reference saved');
assert.match(doc.querySelector('.customer-ticket-history').textContent,/WOODBINE-123/,'previous ticket preserved as read only');
const second=doc.querySelector('.customer-ticket-input');second.value='WOODBINE-124';doc.querySelector('.customer-ticket-save').click();
await new Promise(resolve=>setTimeout(resolve,20));
assert.deepEqual(statusWrites.filter(x=>x.ticket).map(x=>x.ticket),['WOODBINE-123','WOODBINE-124']);
assert.match(doc.querySelector('.customer-ticket-history').textContent,/WOODBINE-123.*WOODBINE-124/,'multiple immutable tickets displayed');
assert.ok(doc.querySelector('.customer-ticket-save'),'ticket reference action present');
const statusSelect=doc.querySelector('.customer-finding-status-select');
assert.ok(statusSelect&&!statusSelect.disabled,'status is editable when D1 tracking is ready');
assert.deepEqual([...statusSelect.options].map(o=>o.value),['Needs Review','Fix in Progress','Fixed/Patched','Not Applicable','Accepted Risk']);
statusSelect.value='Fixed/Patched';
statusSelect.dispatchEvent(new window.Event('change'));
await new Promise(resolve=>setTimeout(resolve,20));
assert.equal(statusWrites.filter(x=>x.status).length,1,'status saved with an authenticated PUT');
assert.match(statusWrites.find(x=>x.status).url,/\/finding-statuses\/a1\/CVE-2026-32101$/);
assert.equal(statusWrites.find(x=>x.status).status,'Fixed/Patched');
assert.equal(doc.querySelectorAll('.customer-vulnerability-table tbody tr').length,0,'patched finding is filtered from unresolved view');
doc.querySelectorAll('.customer-finding-filter')[0].click();
assert.equal(doc.querySelector('.customer-finding-status-select').value,'Fixed/Patched','status persists in browser after redraw');
assert.doesNotMatch(doc.querySelector('#customerReportBody').textContent,/Customer B|WEB02/,'other customer inventory never appears in report');
assert.equal(doc.querySelector('#customerReportPrint').disabled,false);
const overviewHtml=fs.readFileSync('customer-dashboard/index.html','utf8');
assert.ok(overviewHtml.includes('id="customerAttentionVisual"'));
assert.ok(overviewHtml.includes('id="customerSeverityVisual"'));
assert.ok(overviewHtml.includes('id="customerSoftwareVisual"'));
const overviewDom=new JSDOM(overviewHtml,{url:'https://cveharbor.com/customer-dashboard/?customer=c1',runScripts:'outside-only'});
const ow=overviewDom.window,od=ow.document;
ow.CVEHARBOR_DATA=window.CVEHARBOR_DATA;
ow.CVEHARBOR_CATALOG=window.CVEHARBOR_CATALOG;
ow.CVEHARBOR_INVENTORY_MATCH=window.CVEHARBOR_INVENTORY_MATCH;
ow.CVEHARBOR_LIFECYCLE={cycles:[{slug:'php',cycle:'8.4',eol_date:'2027-12-31'}]};
ow.fetch=window.fetch;
ow.eval(fs.readFileSync('customer-security.js','utf8'));
await new Promise(resolve=>setTimeout(resolve,20));
assert.equal(od.getElementById('customerDashFilter').value,'c1');
assert.match(od.getElementById('customerSeverityVisual').textContent,/Critical candidates/);
assert.equal(od.querySelectorAll('.customer-software-card').length,1,'chosen customer only renders its own software');
od.querySelector('.customer-software-card').click();
assert.match(od.getElementById('customerDashFindings').textContent,/CVE-2026-32101/);
assert.equal(od.querySelectorAll('#customerDashFindings details').length,1);
assert.ok(od.querySelector('#customerDashFindings a[href="https://example.com/cve"]'));
overviewDom.window.close();

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
