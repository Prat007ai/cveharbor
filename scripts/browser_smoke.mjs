// Automated DOM smoke checks for the public dashboard using synthetic advisory data.
// Does not call external feeds or send telemetry.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { JSDOM } from 'jsdom';

const reportHtml=fs.readFileSync('customer-reports/index.html','utf8');
const dashboardHtml=fs.readFileSync('customer-dashboard/index.html','utf8');
assert.ok(reportHtml.includes('customerReportPrint')&&reportHtml.includes('customerReportCsv'),'customer report supports print and CSV');
assert.ok(dashboardHtml.includes('customerDashMetrics')&&dashboardHtml.includes('customerDashFindings'),'multi-customer dashboard has security metrics and candidate findings');
assert.ok(fs.readFileSync('workspace/index.html','utf8').includes('href="/customer-dashboard/"'),'customer dashboard accessible from workspace');
assert.ok(fs.readFileSync('workspace/index.html','utf8').includes('href="/customer-reports/"'),'customer reports accessible from workspace');
const html=fs.readFileSync('index.html','utf8');
assert.match(html,/styles\.css\?v=[a-zA-Z0-9-]+/,'versioned main stylesheet loaded');
assert.ok(fs.readFileSync('styles.css','utf8').includes('width:min(1500px,calc(100% - 32px))'),'compact feed banner width is shared globally');
// Validate every canonical page is actually emitted by the Pages build.
const routes={
 'vulnerabilities':['technology','advisories'],
 'alerts':['securityWorkspace'],
 'threats':['threat-intelligence'],
 'malware':['malware-intelligence'],
 'lifecycle':['lifecycleMonitor'],
 'environments':['inventoryWorkspace'],
 'admin-tools':['operationsCentre'],
 'remediation':['remediationTracker']
};
for(const [route,ids] of Object.entries(routes)){
 const output='public/'+route+'/index.html';
 assert.ok(fs.existsSync(output),'dedicated page exists: '+route);
 const page=fs.readFileSync(output,'utf8');
 assert.ok(page.includes('data-page="'+route+'"'),'page renders its own route: '+route);
 assert.ok(page.includes('src="/app.js?'),'nested page loads the root-level CVE popup application');
 assert.ok(page.includes('src="/data.js"'),'nested page loads public data from site root');
 assert.ok(page.includes('src="/page-router.js'),'route compatibility module loads');
 for(const id of ids)assert.ok(page.includes('id="'+id+'"'),'preserve section/deep-link target '+id);
}
assert.ok(fs.readFileSync('public/index.html','utf8').includes('data-page="home"'),
 'homepage uses compact overview layout');

const script=fs.readFileSync('app.js','utf8');
const catalog=JSON.parse(fs.readFileSync('data/demo-advisories.json','utf8'));
const dom=new JSDOM(html,{url:'https://cveharbor.com/',runScripts:'outside-only',pretendToBeVisual:true});
const {window}=dom;
const {document}=window;
window.Element.prototype.scrollIntoView=function(){};
window.HTMLDialogElement.prototype.close=function(){this.removeAttribute('open');};
const parts=new Intl.DateTimeFormat('en-US',{timeZone:'America/Toronto',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date());
const part=k=>Number(parts.find(x=>x.type===k)?.value);
const localDay=Date.UTC(part('year'),part('month')-1,part('day'));
const day=offset=>new Date(localDay-offset*86400000).toISOString().slice(0,10);
const records=Array.from({length:12},(_,i)=>({
  id:'CVE-2026-'+String(300000+i),
  kind:'cve',
  title:'Sample PHP advisory '+(i+1),
  summary:'Synthetic example for smoke tests',
  severity:i%3===0?'critical':'high',
  categories:['PHP'],
  published:day(i<3?0:(i<5?1:(i<7?2:4))),
  updated:day(0),
  affected:'PHP test fixture',
  remediation:'Update test fixture',
  action:'Review sample',
  sources:[{label:'Example vendor',url:'https://example.com/advisory'}],
  source_type:'github',
  known_exploited:i===4,
  exploitation:i===4?'Confirmed: listed in CISA KEV':'Not confirmed'
}));
const sources=Object.fromEntries(['github','php_upstream','nvd','cisa_kev'].map(name=>[name,{ok:true,last_success:new Date().toISOString()}]));
window.CVEHARBOR_DATA={
  categories:catalog.categories,advisories:records,mode:'live',
  sources,last_checked_at:new Date().toISOString(),
  last_successful_update:new Date().toISOString()
};
window.CVEHARBOR_CATALOG={categories:catalog.categories,advisories:[]};
window.eval(script);
const $=id=>document.getElementById(id);
assert.equal($('statTotal').textContent,'12','total CVE count');
assert.equal(document.querySelectorAll('.technology-panel').length,4,'four platform groups');
assert.equal(document.querySelectorAll('.technology-row').length,38,'all categories visible');
assert.equal(document.querySelectorAll('.focus-action').length,9,'focus panel populated');
assert.match(fs.readFileSync('app.js','utf8'),/FIRST EPSS, 30 day exploitation probability/,'EPSS details supported');
assert.equal(document.querySelectorAll('#chartInsights .chart-insight').length,4,'chart insights populated');
document.querySelector('[data-chart-period="published30"]').click();
assert.equal(document.querySelectorAll('#chartInsights .chart-insight').length,4,'chart insights update with period');
document.querySelector('[data-chart-period="all"]').click();
assert.equal($('heroFeedSummary'),null,'hero feed banner removed');
assert.match($('feedStatus').textContent,/Feeds responding/,'feed status remains in footer');
assert.equal(document.querySelectorAll('.advisory-table thead th').length,6,'no Exploited column');
assert.match(fs.readFileSync('styles.css','utf8'),/\.advisory-table tbody td::before/,'mobile table labels');
assert.doesNotMatch(document.querySelector('.advisory-table thead').textContent,/Exploited/i);

const php=[...document.querySelectorAll('.technology-row')].find(row=>row.querySelector('.technology-row-name')?.textContent==='PHP');
assert.ok(php,'PHP category exists');
assert.match(php.textContent,/Today 3/,'recent publication badge');
php.click();
assert.equal($('technologyFilter').value,'PHP','category filter');
assert.equal($('dateRange').value,'today','click shows newest disclosure day');
assert.equal($('advisoryTableWrap').hidden,false,'list opens');
assert.equal(document.querySelectorAll('#advisoryTableBody tr').length,3,'today records');

$('dateRange').value='all';
$('dateRange').dispatchEvent(new window.Event('change'));
assert.equal(document.querySelectorAll('#advisoryTableBody tr').length,12,'full category archive');
document.querySelector('#advisoryTableBody .table-details').click();
assert.match($('dialogContent').textContent,/Affected software and versions/,'advisory detail populated');
assert.match($('dialogContent').textContent,/Original advisory and source references/,'source links in detail');

$('closeDialog').click();
$('search').value='nonexistent string';
$('search').dispatchEvent(new window.Event('input'));
assert.equal($('noResults').hidden,false,'empty-state shown');
$('clearFilters').click();
assert.equal($('noResults').hidden,true,'filters reset');
document.querySelector('.technology-panel-head').click();
assert.equal($('listContext').textContent.includes('Microsoft & Cloud'),true,'section drilldown');

const threatDom=new JSDOM(html,{url:'https://cveharbor.com/',runScripts:'outside-only'});
const threatWindow=threatDom.window;
const threatDocument=threatWindow.document;
threatWindow.CVEHARBOR_THREATS={
  checked_at:new Date().toISOString(),
  sources:{dshield_scanners:{ok:true,count:1}},
  indicators:[{ip:'8.8.8.8',source:'SANS Internet Storm Center',source_id:'dshield_scanners',
    activity:'Observed scanning and attack sources',source_url:'https://feeds.dshield.org/feeds/topips.txt',observed_at:null}]
};
threatWindow.eval(fs.readFileSync('threats.js','utf8'));
const threatButton=threatDocument.querySelector('.threat-view-details');
assert.ok(threatButton,'threat details button is visible');
assert.equal(threatButton.tagName,'BUTTON','threat source is not an external navigation link');
threatButton.click();
assert.match(threatDocument.getElementById('threatDetailContent').textContent,/8.8.8.8/);
assert.match(threatDocument.getElementById('threatDetailContent').textContent,/Not supplied by this feed/);

const workspaceWindow=new JSDOM(html,{url:'https://cveharbor.com/',runScripts:'outside-only'}).window;
workspaceWindow.CVEHARBOR_DATA=window.CVEHARBOR_DATA;
workspaceWindow.CVEHARBOR_CATALOG=window.CVEHARBOR_CATALOG;
workspaceWindow.eval(fs.readFileSync('workspace.js','utf8'));
const workspaceDocument=workspaceWindow.document;
assert.equal(workspaceDocument.querySelectorAll('.workspace-checkbox').length,38,'all technology choices available');
const phpChoice=[...workspaceDocument.querySelectorAll('.workspace-checkbox')].find(n=>n.textContent==='PHP');
phpChoice.querySelector('input').click();
assert.match(workspaceDocument.getElementById('stackSummary').textContent,/indexed matches/,'stack matches shown');
workspaceDocument.getElementById('securityLookup').value='CVE-2026';
workspaceDocument.getElementById('securityLookup').dispatchEvent(new workspaceWindow.Event('input'));
assert.ok(workspaceDocument.querySelectorAll('#securityLookupResults .workspace-result').length>0,'lookup results visible');
assert.ok(html.includes('id="lifecycleMonitor"'),'full lifecycle monitoring section exists');
assert.ok(html.includes('id="lifecycleSearchStatus"'),'expanded product search status exists');
assert.ok(html.includes('id="lifecycleEmailOptin"')&&html.includes('id="lifecycleInstalled"'),'lifecycle opt-in and installed version controls exist');
assert.ok(html.includes('id="lifecycleWatchQueue"')&&html.includes('id="lifecycleSaveAll"'),'multiple lifecycle watch queue is available');
assert.ok(html.includes('src="/patch-notes.js"'),'vendor release evidence is loaded on lifecycle pages');

assert.ok(html.includes('lifecycle-monitor.js?v=multiwatch-3'),'versioned lifecycle monitor script loads');
const lifecycleDom=new JSDOM(html,{url:'https://cveharbor.com/',runScripts:'outside-only'});
lifecycleDom.window.CVEHARBOR_LIFECYCLE={checked_at:new Date().toISOString(),cycles:[{slug:'php',product:'PHP',cycle:'8.4',eol_date:'2027-12-31',latest:'8.4.27',url:'https://endoflife.date/php'}],errors:[]};
lifecycleDom.window.eval(fs.readFileSync('lifecycle-monitor.js','utf8'));
assert.match(lifecycleDom.window.document.getElementById('lifecycleUserStatus').textContent,/Sign in/);
assert.match(lifecycleDom.window.document.getElementById('lifecyclePublished').textContent,/PHP/);
assert.ok(html.includes('id="lifecycleDetailDialog"'),'on-site product support modal exists');
assert.ok(html.includes('lifecycle-monitor.js?v=multiwatch-3'),'lifecycle popup script cache-busted');
const popup=lifecycleDom.window.document.getElementById('lifecycleDetailDialog');
const first=lifecycleDom.window.document.querySelector('#lifecyclePublished .lifecycle-view-details');
assert.ok(first,'each lifecycle result offers a popup');
lifecycleDom.window.fetch=async()=>({
 ok:true,json:async()=>[{cycle:'8.4',eol:'2027-12-31',support:'2027-01-01',latest:'8.4.27',releaseDate:'2024-11-21'}]
});
first.click();
await new Promise(resolve=>setTimeout(resolve,10));
assert.ok(popup.hasAttribute('open'),'product support details open within CVEHarbor');
assert.match(lifecycleDom.window.document.getElementById('lifecycleDetailBody').textContent,/8.4.27/);
assert.match(lifecycleDom.window.document.getElementById('lifecycleDetailBody').textContent,/2027-12-31/);
assert.ok(lifecycleDom.window.document.querySelector('#lifecycleDetailBody a[href="https://endoflife.date/php"]'),
 'external product source appears at the bottom');
lifecycleDom.window.document.getElementById('lifecycleDetailClose').click();
assert.ok(!popup.hasAttribute('open'),'popup closes');

assert.equal(lifecycleDom.window.document.getElementById('lifecycleWatchSave').disabled,true,'saving watches requires a live account and D1');
const signedOutEvent=new lifecycleDom.window.CustomEvent('cveharbor:account-state',{detail:{authenticated:false}});
lifecycleDom.window.dispatchEvent(signedOutEvent);
assert.equal(lifecycleDom.window.document.getElementById('lifecycleProduct').disabled,false,'signed-out visitors can choose a product');
const queueDom=lifecycleDom.window.document;
queueDom.getElementById('lifecycleProduct').value='php';
queueDom.getElementById('lifecycleProduct').dispatchEvent(new lifecycleDom.window.Event('change',{bubbles:true}));
queueDom.getElementById('lifecycleCycle').value='8.4';
queueDom.getElementById('lifecycleInstalled').value='8.4.26';
queueDom.getElementById('lifecycleWatchQueue').click();
assert.equal(queueDom.getElementById('lifecycleQueueCount').textContent,'1 selected','first technology is queued without account');
queueDom.getElementById('lifecycleWatchQueue').click();
assert.equal(queueDom.getElementById('lifecycleQueueCount').textContent,'1 selected','duplicate product is rejected');
queueDom.getElementById('lifecycleProduct').value='';
queueDom.getElementById('lifecycleCustomName').value='Vendor CMS';
queueDom.getElementById('lifecycleCustomDate').value='2027-10-31';
queueDom.getElementById('lifecycleCustomSource').value='https://example.org/support';
queueDom.getElementById('lifecycleWatchQueue').click();
assert.equal(queueDom.getElementById('lifecycleQueueCount').textContent,'2 selected','custom vendor product joins the list');
assert.equal(queueDom.getElementById('lifecycleSaveAll').disabled,true,'saving queued products requires account and D1');

assert.equal(lifecycleDom.window.document.getElementById('lifecycleCycle').disabled,false,'signed-out visitors can choose a release');
assert.equal(lifecycleDom.window.document.getElementById('lifecycleCustomName').disabled,false,'signed-out visitors can enter custom products');
assert.equal(lifecycleDom.window.document.getElementById('lifecycleLead').disabled,false,'signed-out visitors can explore advance warnings');
assert.equal(lifecycleDom.window.document.getElementById('lifecycleWatchSave').disabled,true,'signed-out visitors cannot save watches');
assert.equal(lifecycleDom.window.document.getElementById('lifecyclePrefsSave').disabled,true,'signed-out visitors cannot save email settings');
lifecycleDom.window.close();
assert.ok(html.includes('id="inventoryWorkspace"'),'customer inventory workspace exists');
assert.ok(html.includes('id="inventoryMatching"'),'customer vulnerability matching section exists');
const matcherDom=new JSDOM(html,{url:'https://cveharbor.com/',runScripts:'outside-only'});
matcherDom.window.eval(fs.readFileSync('inventory-matching.js','utf8'));
const engine=matcherDom.window.CVEHARBOR_INVENTORY_MATCH;
const asset={id:'asset-1',technology:'PHP',version:'8.4.26'};
const advisory={id:'CVE-2026-98765',title:'PHP affected version test',categories:['PHP'],
 severity:'critical',affected:'PHP before 8.4.27',sources:[{url:'https://example.com/security'}]};
assert.equal(engine.candidate(asset,advisory).level,'version_review',
 'numeric version within explicit PHP range is flagged for confirmation');
assert.equal(engine.candidate({...asset,version:'8.4.27'},advisory),null,
 'exactly patched version is excluded only for a clear numeric before range');
assert.equal(engine.candidate({...asset,version:'8.4.26'}, {...advisory,categories:['Fortinet']}),null,
 'unrelated technology category does not become a customer match');
assert.equal(engine.candidate({...asset,version:'unknown'},advisory).level,'category',
 'unknown installed version remains an investigation lead');
assert.equal(engine.candidate(asset,{...advisory,affected:'PHP before 8.4.27 only when optional module enabled'}).level,'category',
 'configuration-dependent advisories never claim verified version exposure');
assert.equal(engine.evaluate([asset],[advisory,advisory]).total,1,
 'duplicate CVE items are not counted twice for the same asset');
const falsePositives=[
 {id:'CVE-2016-10033',title:'PHPMailer command injection',summary:'PHPMailer fails to sanitize user input',categories:['PHP'],affected:'PHPMailer before 5.2.18'},
 {id:'CVE-2023-36844',title:'Juniper Junos OS PHP external variable modification',categories:['PHP','Linux'],affected:'Juniper Junos OS on EX Series'},
 {id:'CVE-2025-68645',title:'Zimbra PHP remote file inclusion',categories:['PHP'],affected:'Zimbra Collaboration Suite'},
 {id:'CVE-2026-41940',title:'cPanel and WHM authentication bypass',categories:['PHP','WordPress / Plugins'],affected:'cPanel WP2'},
 {id:'CVE-2020-17496',title:'vBulletin PHP widget code execution',categories:['PHP'],affected:'vBulletin widget'},
];
for(const v of falsePositives)assert.equal(engine.candidate(asset,v),null,'foreign application excluded from PHP runtime: '+v.id);
const debian={id:'debian',technology:'Debian',version:'12'};
assert.equal(engine.candidate(debian,{id:'CVE-2026-11111',categories:['Linux'],title:'Linux kernel memory issue',affected:'Linux kernel before 6.1'}),null,'generic kernel advisory not matched to Debian OS version');
assert.equal(engine.candidate(debian,{id:'CVE-2026-11112',categories:['Linux'],title:'Debian 12 security update for curl',affected:'Debian 12 curl security issue'}),null,'OS release alone cannot confirm curl package exposure');
assert.equal(engine.candidate(debian,{id:'CVE-2026-11113',categories:['Linux'],title:'Ubuntu kernel security update',affected:'Ubuntu kernel 6.8'}),null,'Ubuntu advisory excluded from Debian');
assert.equal(engine.candidate({...asset,technology:'PHP'}, {...advisory,affected:'PHP before 8.4.27'}).level,'version_review','explicit PHP runtime range stays eligible');
const phpRelease={id:'CVE-2026-109618',title:'PHP runtime request handling RCE',categories:['PHP'],affected:'PHP web request handling',sources:[{url:'https://www.php.net/'}]};
assert.equal(engine.candidate({...asset,version:'8.3.35'},phpRelease)?.level,'version_review','vendor bulletin flags PHP predating fixed release');
assert.equal(engine.candidate({...asset,version:'8.3.36'},phpRelease),null,'vendor bulletin excludes fixed PHP 8.3 release');
assert.equal(engine.candidate({...asset,version:'8.4.26'},phpRelease)?.level,'version_review','vendor bulletin flags older PHP 8.4');
assert.equal(engine.candidate({...asset,version:'8.4.27'},phpRelease),null,'vendor bulletin excludes patched PHP 8.4');
const debianVendor={id:'CVE-2026-11115',title:'Debian 12 security advisory for curl',categories:['Linux'],affected:'Debian 12 curl package before 7.88',sources:[{url:'https://security-tracker.debian.org/tracker/CVE-2026-11115'}]};
const debianFinding=engine.candidate({id:'deb-1',technology:'Debian',version:'12'},debianVendor);
assert.equal(debianFinding,null,'Debian package advisories require explicit installed package inventory');
assert.equal(engine.candidate({id:'wp',technology:'WordPress',version:'6.6.2'},{id:'CVE-2026-41940',categories:['WordPress / Plugins'],title:'cPanel WHM WP2 authentication bypass',affected:'WebPros cPanel WP2 WordPress Squared'}),null,'cPanel WP2 is not WordPress core');
assert.equal(engine.candidate({id:'wp',technology:'WordPress',version:'6.6.2'},{id:'CVE-2026-61992',categories:['WordPress / Plugins'],title:'GEO my WordPress plugin PHP object injection',affected:'GEO my WordPress plugin before 4.5'}),null,'third party WordPress plugin excluded from core');
assert.ok(engine.candidate({id:'wp',technology:'WordPress',version:'6.6.2'},{id:'CVE-2026-60317',categories:['WordPress / Plugins'],title:'WordPress Core SQL injection',affected:'WordPress core before 6.7'}),'explicit WordPress core remains eligible');
matcherDom.window.close();
assert.ok(html.includes('id="inventoryCustomerName"')&&html.includes('id="inventoryEnvironmentName"')&&html.includes('id="inventoryVersion"'),'customer environment and software version input fields exist');
assert.ok(html.includes('id="inventoryAdditionalTechnologies"'),'multiple technology version input exists');
assert.ok(fs.readFileSync('inventory.js','utf8').includes("groupCard.append"),'asset technologies are grouped under the same asset name');
assert.ok(fs.readFileSync('inventory.js','utf8').includes(String.raw`/\.txt$/i`),'TXT filename validation matches actual txt extensions');
assert.ok(fs.readFileSync('inventory.js','utf8').includes(String.raw`/\r?\n/`),'plugin lines split at actual newlines');
assert.ok(fs.readFileSync('inventory.js','utf8').includes("fileInput.type='file'"),'plugin importer has local file browse control');
assert.ok(fs.readFileSync('inventory.js','utf8').includes('file.size>65536'),'plugin upload has a file size limit');
assert.ok(fs.readFileSync('inventory.js','utf8').includes('plugin-sources/'),'plugin source URLs can be saved and verified');
assert.ok(fs.readFileSync('inventory.js','utf8').includes("Technology | Version"),'technology version entry format is validated');

assert.ok(html.includes('inventory.js?v=env-dialog-130'),'public build references account inventory client');
const inventoryDom=new JSDOM(html,{url:'https://cveharbor.com/',runScripts:'outside-only'});
inventoryDom.window.eval(fs.readFileSync('inventory.js','utf8'));
const picker=inventoryDom.window.document.querySelector('.inventory-plugin-import:not(.inventory-bulk-import):not(.inventory-package-import) input[type=file]');
assert.ok(picker,'plugin importer renders the Browse file input');
const pluginFile=new inventoryDom.window.File(['Gravity Forms | 2.9.5\nYoast SEO | 24.7'], 'Woodbine_WordPress_Plugins_Import.txt',{type:'text/plain'});
Object.defineProperty(picker,'files',{configurable:true,value:[pluginFile]});
picker.dispatchEvent(new inventoryDom.window.Event('change'));
await new Promise(resolve=>setTimeout(resolve,35));
const pluginPreview=inventoryDom.window.document.querySelector('.inventory-plugin-import:not(.inventory-bulk-import):not(.inventory-package-import) textarea');
assert.ok(pluginPreview.value.includes('Gravity Forms | 2.9.5'),'local TXT content loads into preview');
assert.ok(pluginPreview.value.includes('Yoast SEO | 24.7'),'multiple plugin lines remain distinct');
assert.match(inventoryDom.window.document.querySelector('.inventory-plugin-import:not(.inventory-bulk-import):not(.inventory-package-import) .inventory-plugin-status').textContent,/Loaded .*2 lines/,'upload acknowledges the selected filename and line count');
assert.match(inventoryDom.window.document.getElementById('inventoryMessage').textContent,/Sign in/,'anonymous inventory is not displayed');
assert.equal(inventoryDom.window.document.getElementById('inventoryCustomerCount').textContent,'0');
inventoryDom.window.close();
// Exercise actual customer and asset Edit controls with a synthetic authenticated inventory.
const editDom=new JSDOM(html,{url:'https://cveharbor.com/',runScripts:'outside-only'});
editDom.window.HTMLElement.prototype.scrollIntoView=function(){};
editDom.window.fetch=async url=>({ok:true,json:async()=>String(url).endsWith('/status')?{ready:true}:String(url).includes('/plugin-sources')?{ready:true,sources:[]}:{
 customers:[{id:'customer-one',name:'Woodbine.com'}],
 environments:[{id:'env-one',customer_id:'customer-one',name:'Production',kind:'Production'}],
 assets:[{id:'asset-one',environment_id:'env-one',name:'Web Servers',asset_type:'WEB',technology:'PHP',version:'8.3.36',notes:'Production Servers'}]
}});
editDom.window.eval(fs.readFileSync('inventory.js','utf8'));
editDom.window.dispatchEvent(new editDom.window.CustomEvent('cveharbor:account-state',{detail:{authenticated:true}}));
await new Promise(resolve=>setTimeout(resolve,70));
assert.ok(editDom.window.document.querySelector('.inventory-customer .inventory-edit-customer'),'saved customer has edit action');
editDom.window.document.querySelector('.inventory-customer .inventory-edit-customer').click();
assert.equal(editDom.window.document.getElementById('inventoryEnvironmentSelect').value,'env-one','customer edit selects its environment');
const assetEdit=[...editDom.window.document.querySelectorAll('.inventory-asset button')].find(b=>b.textContent==='Edit');
assert.ok(assetEdit,'saved asset has Edit button');assetEdit.click();
assert.equal(editDom.window.document.getElementById('inventoryAssetEditId').value,'asset-one','asset Edit selects record ID');
assert.equal(editDom.window.document.getElementById('inventoryVersion').value,'8.3.36','asset Edit populates installed version');
assert.equal(editDom.window.document.getElementById('inventoryStepAsset').hidden,false,'asset editing step is visible');
assert.equal(editDom.window.document.getElementById('inventoryAssetForm').hidden,false,'asset editing form is visible');
editDom.window.close();

assert.ok(html.includes('id="operationsCentre"'),'operations centre exists');
assert.ok(fs.readFileSync('operations.js','utf8').includes('https://api.osv.dev/v1/query'),'version checker uses OSV');
const opsDom=new JSDOM(html,{url:'https://cveharbor.com/',runScripts:'outside-only'});
opsDom.window.CVEHARBOR_DATA=window.CVEHARBOR_DATA;
opsDom.window.CVEHARBOR_CATALOG=window.CVEHARBOR_CATALOG;
opsDom.window.CVEHARBOR_THREATS={indicators:[]};
opsDom.window.eval(fs.readFileSync('operations.js','utf8'));
const opsDoc=opsDom.window.document;
assert.equal(opsDoc.querySelectorAll('#versionEcosystem option').length,8,'package ecosystems available');
opsDoc.getElementById('remediationCve').value='CVE-2026-12345';
opsDoc.getElementById('remediationForm').dispatchEvent(new opsDom.window.Event('submit',{bubbles:true,cancelable:true}));
assert.match(opsDoc.getElementById('remediationCount').textContent,/1 tracked/,'legacy browser records remain available before backend activation');
assert.ok(opsDoc.getElementById('remediationAssignDialog'),'assignment modal exists');
opsDoc.getElementById('remediationAssign').click();
assert.equal(opsDoc.getElementById('remediationAssignCve').value,'CVE-2026-12345');
assert.equal(opsDoc.getElementById('remediationSendAssignment').disabled,true,
  'anonymous visitors cannot send assignment emails');
opsDoc.getElementById('closeRemediationAssign').click();
const legacySnapshot=opsDom.window.localStorage.getItem('cveharbor.remediation.v1');
const cloudRows=[];
const cloudCalls=[];
opsDom.window.confirm=()=>true;
opsDom.window.fetch=async(url,options={})=>{
  const path=new URL(url).pathname,method=options.method||'GET';
  cloudCalls.push({path,method,credentials:options.credentials,body:options.body});
  let data={},status=200;
  if(path==='/v1/remediations/features')data={
    storage:'d1',version:2,assignments_available:true,assignment_email_enabled:true
  };
  else if(path==='/v1/remediations'&&method==='GET')data={remediations:[...cloudRows]};
  else if(path==='/v1/remediations/CVE-2026-12345'&&method==='PUT'){
    const body=JSON.parse(options.body);
    cloudRows.splice(0,cloudRows.length,{id:'CVE-2026-12345',...body,updated:'2026-10-28'});
    data={saved:true,storage:'d1'};
  }else if(path==='/v1/remediations/CVE-2026-12345/assign'&&method==='POST'){
    const payload=JSON.parse(options.body);
    cloudRows[0].assigned_to=payload.email;
    cloudRows[0].assignment_status='sent';
    data={assigned:true,notified:true,message:'Assignment accepted by SMTP2GO.'};
  }else if(path==='/v1/remediations'&&method==='PUT')data={saved:1};
  else {status=404;data={error:'No mock for '+method+' '+path};}
  return {ok:status===200,status,json:async()=>data};
};
opsDom.window.dispatchEvent(new opsDom.window.CustomEvent('cveharbor:account-state',
  {detail:{authenticated:true,email:'security@example.org'}}));
await new Promise(resolve=>setTimeout(resolve,15));
assert.match(opsDoc.getElementById('remediationStorage').textContent,/Cloudflare D1/,
  'authenticated tracker uses Cloudflare D1 as canonical storage');
assert.equal(opsDoc.getElementById('remediationImport').hidden,false,
  'legacy browser records can be imported explicitly without replacement');
opsDoc.getElementById('remediationCve').value='CVE-2026-12345';
opsDoc.getElementById('remediationOwner').value='Cloud owner';
opsDoc.getElementById('remediationForm').dispatchEvent(new opsDom.window.Event('submit',{bubbles:true,cancelable:true}));
await new Promise(resolve=>setTimeout(resolve,15));
assert.equal(cloudRows.length,1,'cloud write made a D1 API request');
assert.match(cloudCalls.find(x=>x.method==='PUT'&&x.path.endsWith('CVE-2026-12345')).credentials,/include/,
  'cloud remediation requests carry the authenticated session');
assert.equal(opsDom.window.localStorage.getItem('cveharbor.remediation.v1'),legacySnapshot,
  'cloud save does not overwrite existing browser records');
opsDoc.getElementById('remediationAssign').click();
assert.equal(opsDoc.getElementById('remediationSendAssignment').disabled,false,
  'a configured, migrated backend enables explicit assignment');
opsDoc.getElementById('remediationAssignEmail').value='engineer@example.org';
opsDoc.getElementById('remediationAssignConfirm').checked=true;
opsDoc.getElementById('remediationAssignForm').dispatchEvent(new opsDom.window.Event('submit',{bubbles:true,cancelable:true}));
await new Promise(resolve=>setTimeout(resolve,0));
assert.equal(opsDoc.getElementById('remediationConfirmDialog').open,true,'branded confirmation opens before sending');
opsDoc.getElementById('remediationConfirmSend').click();
await new Promise(resolve=>setTimeout(resolve,15));
assert.equal(cloudRows[0].assigned_to,'engineer@example.org',
  'assignment API receives the named colleague email');
assert.match(opsDoc.getElementById('remediationAssignMessage').textContent,/Request submitted successfully/,
  'assignment confirmation does not expose provider');
assert.equal(opsDoc.getElementById('remediationSuccessDialog').open,true,'branded success dialog opens');
assert.match(opsDoc.getElementById('remediationRows').textContent,/engineer@example.org/,
  'tracker shows assigned recipient from D1');

assert.equal(opsDoc.querySelectorAll('#firewallDownloads a').length,4,'firewall downloads available');
const threatSection=document.getElementById('threat-intelligence');
const firewallSection=document.getElementById('firewallCentre');
assert.ok(threatSection.querySelector('a[href="#firewallCentre"]'),
  'Threat IP Intelligence links to its single firewall export location');
assert.equal(threatSection.querySelectorAll('a[download]').length,0,
  'Threat IP Intelligence has no duplicate configuration download buttons');
assert.ok(firewallSection.querySelector('#firewallDownloads'),
  'Admin Toolkit remains the single canonical firewall download section');
assert.equal(opsDoc.querySelectorAll('#firewallDownloads a[download]').length,4,
  'all four FortiGate and Sophos exports remain downloadable');


assert.ok(html.includes('id="remediationForm"')&&html.includes('id="firewallCentre"'),'tracker and firewall centre present');
assert.ok(html.includes('id="accountWorkspace"')&&html.includes('id="accountVerify"'),'account section and verification UI present');
assert.ok(html.includes('href="/account/?mode=login"')&&html.includes('href="/account/?mode=register"'),
 'login and registration actions are visible in the global site header');
assert.ok(html.includes('header-auth.js?v=account-navigation-1'),'header auth status is loaded');
const accountHtml=fs.readFileSync('workspace/index.html','utf8');
const workspaceHtml=fs.readFileSync('workspace/index.html','utf8');
assert.match(accountHtml,/accountPageRequest/);
assert.match(accountHtml,/accountPageVerify/);
assert.match(accountHtml,/accountPageLogout/);
assert.ok(workspaceHtml.includes('href="/environments/#inventoryWorkspace"')&&workspaceHtml.includes('href="/lifecycle/#lifecycleMonitor"'),
 'workspace links keep existing feature anchors operational');
const accountPageDom=new JSDOM(accountHtml,{url:'https://cveharbor.com/workspace/?mode=register',runScripts:'outside-only'});
const aw=accountPageDom.window,ad=aw.document;
const authCalls=[];
aw.fetch=async(url,options={})=>{
 authCalls.push({url,options});
 const path=new URL(url).pathname;
 if(path==='/v1/me')return {ok:false,status:401,json:async()=>({error:'Sign in required'})};
 if(path==='/v1/auth/request')return {ok:true,json:async()=>({challenge_id:'challenge-1',salt:'a'.repeat(64)})};
 if(path==='/v1/auth/verify')return {ok:true,json:async()=>({authenticated:true,email:'member@example.org'})};
 if(path==='/v1/auth/logout')return {ok:true,json:async()=>({authenticated:false})};
 return {ok:false,status:404,json:async()=>({error:'Not found'})};
};
aw.eval(fs.readFileSync('account-page.js','utf8'));
assert.match(ad.getElementById('accountFormTitle').textContent,/Create your free/);
await new Promise(resolve=>setTimeout(resolve,0));
ad.getElementById('accountPageEmail').value='member@example.org';
ad.getElementById('accountPageRequest').dispatchEvent(new aw.Event('submit',{bubbles:true,cancelable:true}));
await new Promise(resolve=>setTimeout(resolve,0));
assert.equal(ad.getElementById('accountPageVerify').hidden,false,'requesting a code shows verification form');
ad.getElementById('accountPageCode').value='123456';
ad.getElementById('accountPageVerify').dispatchEvent(new aw.Event('submit',{bubbles:true,cancelable:true}));
await new Promise(resolve=>setTimeout(resolve,0));
assert.equal(ad.getElementById('accountPageSignedIn').hidden,false,'valid email code signs in');
assert.ok(authCalls.every(c=>c.options.credentials==='include'),'account code sends existing secure session cookies');
ad.getElementById('accountPageLogout').click();
await new Promise(resolve=>setTimeout(resolve,0));
assert.equal(ad.getElementById('accountPageSignedIn').hidden,true,'sign out returns to email form');
aw.close();

// The email/account panel contains a source-limited publication chart even before login.
assert.ok(document.getElementById('accountWorkspace').contains(document.getElementById('disclosureTrend')),
  'publication trend fills the account panel without requiring sign in');
assert.ok(html.includes('disclosure-trend.js?v=30day-1'),'trends script is deployed with a versioned path');
assert.ok(html.includes('not the number found or exploited using AI'),
  'the chart does not imply that published CVE totals measure AI attribution');
const trendDom=new JSDOM(html,{url:'https://cveharbor.com/',runScripts:'outside-only'});
const tw=trendDom.window,td=tw.document;
const utcStart=Math.floor(Date.now()/86400000)*86400000;
const utcAgo=n=>new Date(utcStart-n*86400000).toISOString().slice(0,10);
tw.CVEHARBOR_DATA={
  last_successful_update:new Date().toISOString(),
  advisories:[
    {id:'CVE-2026-90001',published:utcAgo(1)},
    {id:'CVE-2026-90002',published:utcAgo(1)},
    {id:'CVE-2026-90002',published:utcAgo(1)}, // duplicate across sources
    {id:'CVE-2026-90003',published:utcAgo(8)},
    {id:'CVE-2026-90004',published:utcAgo(16),updated:utcAgo(1)}, // updated, not new
    {id:'CVE-2026-90005',published:utcAgo(30)}, // first included date
    {id:'CVE-2026-90006',published:utcAgo(31)}, // older, excluded
    {id:'CVE-2026-90007',published:utcAgo(0)}, // partial current day, excluded
    {id:'CVE-2026-90008',published:utcAgo(1),status:'REJECTED'},
    {id:'GHSA-test-test-test',published:utcAgo(1)}
  ]
};
tw.eval(fs.readFileSync('disclosure-trend.js','utf8'));
assert.equal(td.querySelectorAll('#disclosureTrendBars .disclosure-day-button').length,30,
  'the trend contains thirty finished UTC days');
assert.equal(td.getElementById('disclosureTrendTotal').textContent,'5',
  'duplicates, rejected IDs, advisories and today are not counted');
assert.equal(td.getElementById('disclosureTrendAverage').textContent,'0.2',
  'daily average is based on thirty complete days');
assert.equal(td.getElementById('disclosureTrendChange').textContent,'+100%',
  'latest seven complete days compare to the previous seven days');
assert.match(td.getElementById('disclosureTrendCompare').textContent,/2 in the latest 7 days vs 1/);
assert.match(td.getElementById('disclosureTrendSelected').textContent,/2 CVEs published/,
  'the most recent complete day is selected by default');
const dayEight=td.querySelectorAll('#disclosureTrendBars .disclosure-day-button')[22];
dayEight.click();
assert.equal(dayEight.getAttribute('aria-pressed'),'true');
assert.match(td.getElementById('disclosureTrendSelected').textContent,/1 CVE published/,
  'selecting a bar reveals the exact date value');
assert.match(td.getElementById('disclosureTrendNote').textContent,/not a worldwide CVE total/,
  'public feed coverage limits are clear');
assert.equal(td.querySelectorAll('.disclosure-trend-line path').length,1,
  'seven day average line is rendered without an external chart dependency');
const noFeedDom=new JSDOM(html,{url:'https://cveharbor.com/',runScripts:'outside-only'});
noFeedDom.window.eval(fs.readFileSync('disclosure-trend.js','utf8'));
assert.match(noFeedDom.window.document.getElementById('disclosureTrendStatus').textContent,/unavailable/i,
  'the trend never invents data during a feed outage');
trendDom.window.close();noFeedDom.window.close();
assert.ok(fs.readFileSync('accounts.js','utf8').includes('accountDownload'),'account sync frontend installed');

// The watchlist and email preferences must share one unified workspace.
assert.ok(document.getElementById('securityWorkspace').contains(document.getElementById('accountWorkspace')),
  'email account controls live beside the technology watchlist');
assert.ok(html.includes('id="accountSaveStack"') && html.includes('id="accountLoadStack"'),
  'visible cloud alert watchlist save and restore controls');

const makeSignedInWatchlist = async (local,cloud) => {
  const browser=new JSDOM(html,{url:'https://cveharbor.com/',runScripts:'outside-only'});
  const w=browser.window,d=w.document;
  w.CVEHARBOR_DATA=window.CVEHARBOR_DATA;
  w.CVEHARBOR_CATALOG=window.CVEHARBOR_CATALOG;
  w.localStorage.setItem('cveharbor.stack.v1',JSON.stringify(local));
  w.confirm=()=>true;
  let saved=cloud.map(technology=>({technology,product_version:''}));
  const writes=[];
  w.fetch=async (url,opts={})=>{
    const route=new URL(url).pathname;
    const method=opts.method||'GET';
    let data={},status=200;
    if(route==='/v1/me')data={authenticated:true,email:'example@example.com'};
    else if(route==='/v1/alerts'&&method==='GET')data={preferences:{enabled:0,severity:'critical',frequency:'daily'},consented:false,delivery_active:false};
    else if(route==='/v1/stack'&&method==='GET')data={stack:saved};
    else if(route==='/v1/stack'&&method==='PUT'){
      data=JSON.parse(opts.body);writes.push(data.stack.map(x=>x.technology));saved=data.stack;data={saved:saved.length};
    }else if(route==='/v1/alerts/test'&&method==='POST')data={sent:true,message:'Sample accepted'};
    else if(route==='/v1/auth/logout'&&method==='POST')data={authenticated:false};
    else{data={error:'Unexpected route '+route};status=404;}
    return {ok:status<400,status,json:async()=>data};
  };
  w.eval(fs.readFileSync('workspace.js','utf8'));
  w.eval(fs.readFileSync('accounts.js','utf8'));
  await new Promise(resolve=>setTimeout(resolve,70));
  return {w,d,writes};
};
const synced=await makeSignedInWatchlist(['PHP'],['PHP']);
assert.match(synced.d.getElementById('stackSyncHeadline').textContent,/up to date/i);
const addWordpress=[...synced.d.querySelectorAll('#stackTechnologyList .workspace-checkbox')]
  .find(n=>n.textContent==='WordPress / Plugins');
addWordpress.querySelector('input').click();
await new Promise(resolve=>setTimeout(resolve,700));
assert.equal(synced.writes.length,1,'technology change saved to cloud automatically');
assert.deepEqual(synced.writes[0].slice().sort(),['PHP','WordPress / Plugins'].sort());
assert.match(synced.d.getElementById('stackSyncStatus').textContent,/saved to your account/i);
synced.w.close();
const conflict=await makeSignedInWatchlist([],['PHP','WordPress / Plugins']);
assert.equal(conflict.writes.length,0,'new empty browser does not overwrite existing cloud watchlist');
assert.match(conflict.d.getElementById('stackSyncStatus').textContent,/2 saved in your email watchlist/);
conflict.d.getElementById('accountLoadStack').click();
await new Promise(resolve=>setTimeout(resolve,90));
assert.equal(conflict.d.querySelector('#stackTechnologyList input:checked')!==null,true,'load saved cloud watchlist checks technology boxes');
assert.equal(conflict.writes.length,0,'loading cloud selections does not re-upload or erase server data');
conflict.w.close();

// Malware lists show six cards by default, with separate expansion and filters.
const malwareDom=new JSDOM(html,{url:'https://cveharbor.com/',runScripts:'outside-only'});
const malwareWindow=malwareDom.window, malwareDoc=malwareWindow.document;
malwareWindow.CVEHARBOR_MALWARE={
  checked_at:new Date().toISOString(),
  samples:Array.from({length:11},(_,i)=>({
    sha256:String(i+1).padStart(64,'0'),
    family:i===0?'Mirai <img src=x onerror=alert(1)>':i===10?'RedLine':'Mirai',
    type:i===10?'Infostealer':'Botnet',
    first_seen:'2026-10-28 12:00:00',file_type:'elf',
    tags:i===0?['IoT botnet','<script>untrusted tag</script>']:[],
    source_url:i===0?'javascript:alert(1)':'https://bazaar.abuse.ch/'
  })),
  advisories:[],sources:{malwarebazaar:{ok:true}}
};
malwareWindow.eval(fs.readFileSync('malware.js','utf8'));
const familyCards=()=>malwareDoc.querySelectorAll('#malwareFamilyDirectory .malware-entry').length;
const sampleCards=()=>malwareDoc.querySelectorAll('#malwareRows .malware-entry').length;
const familyToggle=malwareDoc.getElementById('malwareShowAllFamilies');
const sampleToggle=malwareDoc.getElementById('malwareShowAllSamples');
assert.ok(malwareDoc.getElementById('malwareDetailDialog'),'malware detail popup exists');
// Both malware sections must use the same on-site detail popup.
assert.ok(html.includes('malware.js?v=family-profiles-3'),
  'new browser asset version prevents reuse of the old external links');
const firstFamilyCard=malwareDoc.querySelector('#malwareFamilyDirectory .malware-entry');
const familyDetailsButton=firstFamilyCard.querySelector('button.malware-detail-trigger');
assert.equal(firstFamilyCard.querySelectorAll('a[href]').length,0,
  'known malware family cards must not navigate directly to Malpedia');
assert.equal(familyDetailsButton?.getAttribute('aria-haspopup'),'dialog',
  'malware family button announces the on-site dialog');
familyDetailsButton.click();
const commonMalwareDialog=malwareDoc.getElementById('malwareDetailDialog');
const commonMalwareContent=malwareDoc.getElementById('malwareDetailContent');
assert.ok(commonMalwareDialog.hasAttribute('open'),'family popup opens without leaving CVEHarbor');
assert.match(commonMalwareContent.textContent,/LockBit/,'family name is visible');
assert.match(commonMalwareContent.textContent,/File encryption and double extortion/,'family behavior is visible');
assert.match(commonMalwareContent.textContent,/Family reference, not a new sample/,
  'the family directory is distinguished from live samples');
assert.match(commonMalwareContent.textContent,/Matching samples in current feed/,
  'family dialog shows the limited live sample count');
const optionalFamilyLink=commonMalwareContent.querySelector('a.malware-detail-source-link');
assert.equal(optionalFamilyLink?.href,'https://malpedia.caad.fkie.fraunhofer.de/details/win.lockbit',
  'LockBit link leads directly to its Malpedia family profile, not the generic home page');
assert.equal(optionalFamilyLink?.target,'_blank','research link is optional');
malwareDoc.getElementById('closeMalwareDetail').click();
assert.ok(!commonMalwareDialog.hasAttribute('open'),'family dialog can be closed');

const firstMalwareCard=malwareDoc.querySelector('#malwareRows .malware-entry');
const sampleDetailsButton=firstMalwareCard.querySelector('.malware-detail-trigger');
assert.equal(sampleDetailsButton?.tagName,'BUTTON','samples open an on-site detail dialog');
assert.equal(sampleDetailsButton?.getAttribute('aria-haspopup'),'dialog','sample trigger advertises dialog');
assert.equal(firstMalwareCard.querySelectorAll('a[href]').length,0,'sample cards no longer navigate away');
sampleDetailsButton.click();
const sampleDialog=malwareDoc.getElementById('malwareDetailDialog');
const sampleContents=malwareDoc.getElementById('malwareDetailContent');
assert.ok(sampleDialog.hasAttribute('open'),'sample detail popup opened');
assert.match(sampleContents.textContent,/SHA256 file hash/,'hash label is visible');
assert.match(sampleContents.textContent,/0000000000000000000000000000000000000000000000000000000000000001/,'full SHA256 shown');
assert.match(sampleContents.textContent,/2026-10-28 12:00:00/,'first shared UTC timestamp is shown');
assert.match(sampleContents.textContent,/Reported classification/,'malware type is shown');
assert.match(sampleContents.textContent,/IoT botnet/,'reported tags are shown');
assert.match(sampleContents.textContent,/Original malware intelligence source/,'source is inside dialog');
assert.match(sampleContents.textContent,/incomplete or inferred/,'classification limitations are visible');
assert.match(sampleContents.textContent,/Mirai <img src=x onerror=alert\(1\)>/,'untrusted text is displayed literally');
assert.equal(sampleContents.querySelector('img'),null,'feed text cannot inject HTML into popup');
assert.equal(sampleContents.querySelector('script'),null,'malware metadata cannot inject script');
const malwareSource=sampleContents.querySelector('a.malware-detail-source-link');
assert.equal(malwareSource?.href,
  'https://bazaar.abuse.ch/sample/0000000000000000000000000000000000000000000000000000000000000001/',
  'source link constructed from trusted MalwareBazaar domain and verified hash');
assert.equal(malwareSource?.target,'_blank','original source link opens separately on request');
assert.ok(malwareSource?.rel.includes('noopener'),'original source does not inherit parent tab access');
malwareDoc.getElementById('closeMalwareDetail').click();
assert.ok(!sampleDialog.hasAttribute('open'),'malware popup closes and returns to the page');
sampleDetailsButton.click();
sampleDialog.click();
assert.ok(!sampleDialog.hasAttribute('open'),'clicking outside the popup closes the dialog');
assert.equal(familyCards(),6,'initial malware family preview is six cards');
assert.equal(sampleCards(),6,'initial malware sample preview is six cards');
assert.equal(familyToggle.hidden,false,'family expansion visible with more than six entries');
assert.equal(sampleToggle.hidden,false,'sample expansion visible with more than six entries');
assert.match(malwareDoc.getElementById('malwareFamilySummary').textContent,/Showing 6 of 26 families/);
assert.match(malwareDoc.getElementById('malwareSampleSummary').textContent,/Showing 6 of 11 samples/);
familyToggle.click();
assert.equal(familyCards(),26,'Show All reveals every reference family');
// Verify every curated family has its own Malpedia research destination,
// including the Gafgyt/Bashlite alias.
const malpediaExpected={
  'LockBit':'win.lockbit','Akira':'win.akira','Qilin':'elf.qilin','Cl0p':'win.clop',
  'Black Basta':'win.blackbasta','RansomHub':'win.ransomhub','PLAY':'win.play',
  'BlackCat / ALPHV':'win.blackcat','Lumma Stealer':'win.lumma',
  'RedLine':'win.redline_stealer','Vidar':'win.vidar','Raccoon Stealer':'win.raccoon',
  'Agent Tesla':'win.agent_tesla','Emotet':'win.emotet','TrickBot':'win.trickbot',
  'Dridex':'win.dridex','Remcos RAT':'win.remcos','AsyncRAT':'win.asyncrat',
  'Quasar RAT':'win.quasar_rat','DarkComet':'win.darkcomet','Mirai':'elf.mirai',
  'Gafgyt':'elf.bashlite','QakBot':'win.qakbot','IcedID':'win.icedid',
  'Bumblebee':'win.bumblebee','Cobalt Strike (misused)':'win.cobalt_strike'
};
for(const [name,profile] of Object.entries(malpediaExpected)){
  const card=[...malwareDoc.querySelectorAll('#malwareFamilyDirectory .malware-entry')]
    .find(node=>node.querySelector('strong')?.textContent===name);
  assert.ok(card,'Family card exists for '+name);
  card.querySelector('button.malware-detail-trigger').click();
  const link=commonMalwareContent.querySelector('a.malware-detail-source-link');
  assert.equal(link?.href,'https://malpedia.caad.fkie.fraunhofer.de/details/'+profile,
    'Family-specific Malpedia link for '+name);
  assert.ok(link?.rel.includes('noopener'),'Family profile uses a safe external link');
  if(name==='Gafgyt')assert.match(commonMalwareContent.textContent,/Bashlite/,
    'Gafgyt alias is disclosed rather than misleading the user');
  malwareDoc.getElementById('closeMalwareDetail').click();
}
assert.equal(sampleCards(),6,'expanding families does not expand samples');
assert.equal(familyToggle.getAttribute('aria-expanded'),'true');
assert.match(familyToggle.textContent,/Show Less/);
sampleToggle.click();
assert.equal(sampleCards(),11,'Show All reveals every matching malware sample');
assert.equal(sampleToggle.getAttribute('aria-expanded'),'true');
sampleToggle.click();familyToggle.click();
assert.equal(sampleCards(),6,'Show Less collapses sample cards');
assert.equal(familyCards(),6,'Show Less collapses reference family cards');
assert.equal(familyToggle.getAttribute('aria-expanded'),'false');
assert.equal(sampleToggle.getAttribute('aria-expanded'),'false');
malwareDoc.getElementById('malwareSearch').value='LockBit';
malwareDoc.getElementById('malwareSearch').dispatchEvent(new malwareWindow.Event('input'));
assert.equal(familyCards(),1,'family search applies before preview limit');
assert.equal(sampleCards(),0,'search filters live sample cards too');
assert.equal(familyToggle.hidden,true,'no Show All button for one family');
assert.equal(sampleToggle.hidden,true,'no Show All button when no matching samples');
malwareDoc.getElementById('malwareSearch').value='';
malwareDoc.getElementById('malwareSearch').dispatchEvent(new malwareWindow.Event('input'));
assert.equal(familyCards(),6,'clearing search restores six card family preview');
assert.equal(sampleCards(),6,'clearing search restores six card sample preview');
malwareDoc.getElementById('malwareType').value='Infostealer';
malwareDoc.getElementById('malwareType').dispatchEvent(new malwareWindow.Event('change'));
assert.equal(sampleCards(),1,'type filters still work for recent samples');
assert.equal(sampleToggle.hidden,true,'filtered list below six has no expansion button');
malwareWindow.close();


// An exact CVE outside the 2,500-record snapshot must use the live official lookup.
const cveDom=new JSDOM(html,{url:'https://cveharbor.com/',runScripts:'outside-only'});
const cveWindow=cveDom.window,cveDocument=cveWindow.document;
cveWindow.CVEHARBOR_DATA=window.CVEHARBOR_DATA;
cveWindow.CVEHARBOR_CATALOG=window.CVEHARBOR_CATALOG;
const remoteRequests=[];
let fallbackStatus=200;
cveWindow.fetch=async (url,options={})=>{
  remoteRequests.push({url,credentials:options.credentials,method:options.method});
  const id=String(url).split('/').pop();
  const data=fallbackStatus===200?{
    id,status:'published',title:'WordPress remote code execution via PostScript upload',
    description:'Requires Imagick and Ghostscript on the server plus a user with upload permissions.',
    affected:['WordPress: before 7.0.4'],severity:'high',cvss:8.8,cvssVersion:'3.0',
    published:'2026-08-17T20:55:33Z',updated:'2026-08-18T15:17:13Z',
    references:[{label:'WordPress release',url:'https://wordpress.org/news/2026/08/wordpress-7-0-4-release/'}],
    source:'CVE Program official GitHub mirror'
  }:{id,status:'not_published',message:'No published record found'};
  return {ok:fallbackStatus===200,status:fallbackStatus,json:async()=>data};
};
cveWindow.eval(fs.readFileSync('workspace.js','utf8'));
const cveInput=cveDocument.getElementById('securityLookup');
const cveOutput=cveDocument.getElementById('securityLookupResults');
cveInput.value='CVE-2026-65640';
cveInput.dispatchEvent(new cveWindow.Event('input'));
assert.match(cveOutput.textContent,/Checking the official CVE Program/);
await new Promise(resolve=>setTimeout(resolve,450));
assert.equal(remoteRequests.length,1,'one fallback lookup sent for exact unindexed CVE');
assert.equal(remoteRequests[0].url,'https://api.cveharbor.com/v1/cve/CVE-2026-65640');
assert.equal(remoteRequests[0].credentials,'omit','do not send account cookies to public lookup');
assert.match(cveOutput.textContent,/WordPress remote code execution/,'live vulnerability title rendered');
assert.match(cveOutput.textContent,/8\.8/,'CVSS score is visible');
assert.match(cveOutput.textContent,/7\.0\.4/,'affected WordPress versions are visible');
assert.ok(cveOutput.querySelector('a[href*="cve.org/CVERecord"]'),'CVE Program link provided');
assert.ok(cveOutput.querySelector('a[href*="nvd.nist.gov"]'),'NVD cross-reference provided');
cveInput.value='WordPress';
cveInput.dispatchEvent(new cveWindow.Event('input'));
assert.equal(remoteRequests.length,1,'partial text search stays local');
fallbackStatus=404;
cveInput.value='CVE-2026-99991234';
cveInput.dispatchEvent(new cveWindow.Event('input'));
await new Promise(resolve=>setTimeout(resolve,450));
assert.match(cveOutput.textContent,/No published record was found/,'missing publication is distinguished from local absence');
cveWindow.close();


// Universal lookup opens indexed advisory details and source links inside CVEHarbor.
const detailDom=new JSDOM(html,{url:'https://cveharbor.com/',runScripts:'outside-only',pretendToBeVisual:true});
const detailWindow=detailDom.window,detailDoc=detailWindow.document;
detailWindow.HTMLDialogElement.prototype.showModal=function(){this.setAttribute('open','');};
detailWindow.HTMLDialogElement.prototype.close=function(){this.removeAttribute('open');};
detailWindow.Element.prototype.scrollIntoView=function(){};
detailWindow.CVEHARBOR_DATA={...window.CVEHARBOR_DATA,advisories:[
  {...records[0],
    summary:'Demonstration description of a PHP vulnerability with prerequisites.',
    affected:'PHP 8.4.20 before a vendor patch',
    remediation:'Apply the fixed vendor package.',
    action:'Check the deployed PHP version.',
    exploitation:'Not confirmed by the source.',
    sources:[
      {label:'Unsafe source',url:'javascript:alert(1)'},
      {label:'Original vendor notice',url:'https://example.com/security/vendor-advisory'}
    ]
  }
]};
detailWindow.CVEHARBOR_CATALOG=window.CVEHARBOR_CATALOG;
detailWindow.eval(fs.readFileSync('app.js','utf8'));
detailWindow.eval(fs.readFileSync('workspace.js','utf8'));
const detailLookup=detailDoc.getElementById('securityLookup');
detailLookup.value='CVE-2026-300000';
detailLookup.dispatchEvent(new detailWindow.Event('input'));
const resultCard=detailDoc.querySelector('#securityLookupResults .workspace-result');
assert.ok(resultCard,'indexed CVE result is visible');
const detailTrigger=resultCard.querySelector('.workspace-detail-trigger');
assert.equal(detailTrigger?.tagName,'BUTTON','indexed sources button opens local dialog instead of external URL');
assert.equal(detailTrigger?.getAttribute('aria-haspopup'),'dialog','button is announced as a dialog trigger');
assert.equal(resultCard.querySelectorAll('a[href]').length,0,'result does not navigate to source directly');
detailTrigger.click();
const detailDialog=detailDoc.getElementById('detailDialog');
const detailBody=detailDoc.getElementById('dialogContent');
assert.ok(detailDialog.hasAttribute('open'),'vulnerability details open in on-site popup');
assert.match(detailBody.textContent,/Demonstration description/,'description is visible in dialog');
assert.match(detailBody.textContent,/PHP 8\.4\.20/,'affected software is visible in dialog');
assert.match(detailBody.textContent,/Apply the fixed vendor package/,'remediation is visible in dialog');
assert.equal(detailBody.querySelector('.remediation-detail-assign')?.textContent,'Assign vulnerability by email',
  'indexed CVE popup exposes assignment workflow');
assert.match(detailBody.textContent,/Suggested next step/,'suggested action is visible in dialog');
assert.match(detailBody.textContent,/Original advisory and source references/,'source links appear inside dialog');
const sourceLinks=[...detailBody.querySelectorAll('.detail-source-links a')];
assert.ok(sourceLinks.some(a=>a.textContent==='Original vendor notice'),'original source link is listed');
assert.ok(sourceLinks.some(a=>a.href.includes('cve.org/CVERecord')),'CVE Program link is listed');
assert.ok(sourceLinks.some(a=>a.href.includes('nvd.nist.gov')),'NVD link is listed');
assert.equal(sourceLinks.some(a=>a.href.startsWith('javascript:')),false,'unsafe external links are not displayed');
assert.ok(sourceLinks.every(a=>a.target==='_blank'&&a.rel.includes('noopener')),'source links open safely');
detailDoc.getElementById('closeDialog').click();
assert.equal(detailDialog.hasAttribute('open'),false,'popup closes with the existing close button');
// My Technology Stack uses the very same details popup.
const selectedPhp=[...detailDoc.querySelectorAll('#stackTechnologyList .workspace-checkbox')]
  .find(n=>n.textContent==='PHP');
selectedPhp.querySelector('input').click();
const stackTrigger=detailDoc.querySelector('#stackAdvisories .workspace-detail-trigger');
assert.ok(stackTrigger,'watchlist advisories also show on-site detail button');
stackTrigger.click();
assert.ok(detailDialog.hasAttribute('open'),'watchlist item opens same popup');
detailWindow.close();

console.log('CVEHarbor browser smoke passed: 38 categories, publication badges, list, details, focus, search and feed status.');

// The public build will supply separate canonical URLs while preserving
// the existing element IDs for all legacy popup / dashboard scripts.
assert.ok(html.includes('page-router.js?v=multipage-1'),'shared page navigation is loaded');
assert.ok(html.includes('href="/vulnerabilities/"'),'advisories have a distinct navigation URL');
assert.ok(html.includes('href="/lifecycle/"'),'lifecycle has a distinct navigation URL');

assert.ok(fs.readFileSync('public/command-center.js','utf8').includes('command-sidebar'),'command center navigation published');
for(const route of ['index.html','account/index.html','workspace/index.html','customer-dashboard/index.html','customer-reports/index.html'])assert.match(fs.readFileSync(route,'utf8'),/\/command-center\.js\?v=[a-zA-Z0-9-]+/,'shared navigation loaded on '+route);
assert.ok(fs.readFileSync('styles.css','utf8').includes('body.command-center-app'),'command center responsive design available');

assert.ok(html.includes('hero-intelligence-network'),'hero contains visible animated security intelligence network');
assert.ok(html.includes('hero-network-movement'),'network animation has moving signals');
assert.ok(fs.readFileSync('command-center.js','utf8').includes('command-sidebar-toggle'),'sidebar can expand and collapse');
assert.ok(fs.readFileSync('styles.css','utf8').includes('prefers-reduced-motion:reduce'),'animation respects reduced motion');

assert.ok(fs.readFileSync('command-center.js','utf8').includes("!body.dataset.page"),'home page receives command center sidebar');
assert.ok(fs.readFileSync('styles.css','utf8').includes('transform:scale(1.36)'),'sidebar icons enlarge on hover');

assert.equal(html.includes('PUBLIC ADVISORY FEEDS'),false,'hero card no longer displays public advisory feeds wording');

assert.ok(html.includes('Find risks faster. Prioritize fixes. Stay protected.'),'hero contains clear security value statement');
assert.equal(html.includes('>REMEDIATE</text>'),false,'network badge overlap label removed');

assert.ok(html.includes('<option>WEB</option>'),'WEB asset type appears in inventory form');
assert.ok(fs.readFileSync('inventory.js','utf8').includes("'Server','WEB','Application'"),'CSV importer accepts WEB asset type');

assert.ok(fs.readFileSync('inventory.js','utf8').includes(String.raw`Version,Notes\\r\\nWEB01`) === false,'CSV template does not emit escaped newline literals');
assert.ok(fs.readFileSync('inventory.js','utf8').includes('Production Web Stack,WEB,PHP'),'CSV template includes shared stack rows');

assert.ok(fs.readFileSync('inventory.js','utf8').includes("const displayName=plugin?asset.technology.slice(pluginPrefix.length):asset.technology"),'inventory uses short plugin labels');

assert.ok(fs.readFileSync('inventory.js','utf8').includes('confirmInventoryRemoval'),'inventory removal uses custom confirmation dialog');

assert.ok(html.includes('id="inventoryStepEnvironment"'),'guided environment stage available');
assert.ok(html.includes('id="inventoryStepAsset"'),'guided asset stage available');
assert.ok(fs.readFileSync('inventory.js','utf8').includes('updateInventorySteps()'),'inventory stages update after loading data');

assert.ok(fs.readFileSync('inventory.js','utf8').includes('inventory-step-collapsed'),'guided setup can collapse completed stages');

assert.ok(fs.readFileSync('inventory.js','utf8').includes("form.hidden=panel.classList.contains('inventory-step-collapsed')"),'completed setup forms are hidden directly');

const bulkSource=fs.readFileSync('inventory.js','utf8');
assert.ok(bulkSource.includes('Production Web Stack,WEB,NGINX'),'CSV sample includes a logical web software stack');
assert.ok(bulkSource.includes('Production Web Stack,WEB,Ubuntu Linux'),'CSV sample includes an OS');

assert.ok(html.includes('id="inventoryCustomerSaved"')&&html.includes('id="inventoryEnvironmentSaved"'),'saved setup details appear in steps');
assert.ok(fs.readFileSync('inventory.js','utf8').includes('setupCustomerId=saved.id'),'new customer selection is retained');

assert.ok(fs.readFileSync('inventory.js','utf8').includes('customerNameField.value=selectedCustomer.name'),'saved customer name restored');
assert.ok(fs.readFileSync('inventory.js','utf8').includes('environmentNameField.value=selectedEnvironment.name'),'saved environment name restored');

const csvGenerator=fs.readFileSync('inventory.js','utf8');
assert.ok(csvGenerator.includes("'Production Web Stack,WEB,PHP,8.4.26,Example only'"),'shared stack CSV sample is published');
assert.ok(csvGenerator.includes("'Production Web Stack,WEB,NGINX,1.26.3,Example only'"),'shared stack contains web server technology');
assert.ok(csvGenerator.includes("'Production Web Stack,WEB,Ubuntu Linux,24.04,Example only'"),'shared stack contains operating system');

assert.ok(fs.readFileSync('inventory.js','utf8').includes("||'WordPress'"),'plugin import defaults asset name');

assert.ok(fs.readFileSync('inventory.js','utf8').includes('importPanel.after(box)'),'plugin source editor follows importer');

assert.ok(fs.readFileSync('inventory.js','utf8').includes('setupCustomerCompletion()'),'customer review step exists');
assert.ok(fs.readFileSync('inventory.js','utf8').includes('has been successfully added to the CVEHarbor Vulnerability Intelligence Portal'),'customer completion success message exists');

assert.ok(fs.readFileSync('inventory.js','utf8').includes('setupPackageImport()'),'Linux package upload is available');
assert.ok(fs.readFileSync('account-backend/src/inventory.js','utf8').includes('/v1/inventory/packages/import'),'account scoped package API exists');

assert.ok(fs.readFileSync('inventory.js','utf8').includes("newCustomerSetup=true"),'new customer setup starts without previous account selection');
assert.ok(fs.readFileSync('inventory.js','utf8').includes('startNewCustomer()'),'new customer action clears prior wizard data');

assert.ok(fs.readFileSync('inventory.js','utf8').includes('packages imported successfully into CVEHarbor.'),'package import uses customer friendly confirmation');

assert.ok(fs.readFileSync('inventory.js','utf8').includes('showSetupError('),'review uses setup validation alerts');

assert.ok(fs.readFileSync('inventory.js','utf8').includes('Edit customer'),'customer edit action exists');

assert.ok(fs.readFileSync('inventory.js','utf8').includes('customerActions.append(editCustomer)'),'customer cards include edit action');
assert.ok(fs.readFileSync('inventory.js','utf8').includes('inventory-edit-customer'),'customer edit action has stable selector');

assert.ok(fs.readFileSync('inventory.js','utf8').includes('customerActions.append(deleteCustomer)'),'customer actions grouped together');

assert.ok(fs.readFileSync('inventory.js','utf8').includes('setupCustomerId=customer.id'),'edit customer selects saved customer inventory');

assert.equal(fs.readFileSync('inventory.js','utf8').includes("window.prompt('Environment name'"),false,'environment editing avoids native browser prompt');
assert.ok(fs.readFileSync('inventory.js','utf8').includes('inventory-record-actions'),'asset and environment actions grouped');

assert.ok(fs.readFileSync('styles.css','utf8').includes('Align customer and nested environment actions'),'customer and environment button alignment style exists');

assert.ok(fs.readFileSync('customer-security.js','utf8').includes("if(needsReview){card.classList.add('customer-software-attention')"),'needs review findings trigger red attention class');

// Account redesign retains passwordless sign-in contract and removes provider disclosure.
const accountMarkup=fs.readFileSync('workspace/index.html','utf8');
assert.ok(accountMarkup.includes('accountPageRequest') && accountMarkup.includes('accountPageVerify'),'account login and verification forms preserved');
assert.ok(accountMarkup.includes('Manage customer environments') && accountMarkup.includes('Generate professional reports'),'workspace benefits visible');
assert.ok(!accountMarkup.includes('Cloudflare') && !accountMarkup.includes('pending Cloudflare backend'),'no provider or deployment disclosure on login');
const stylesheetMatch=accountMarkup.match(/href=["'](\/styles\.css\?v=[a-zA-Z0-9-]+)["']/);
assert.ok(stylesheetMatch,'account page loads a versioned stylesheet');
assert.ok(fs.readFileSync('styles.css','utf8').includes('.account-redesign'),'account stylesheet includes login layout');

const mandatoryMfaWorker=fs.readFileSync('account-backend/src/index.js','utf8');
assert.ok(mandatoryMfaWorker.includes("mfa_enrollment_required:true"),'users without MFA must enroll');
assert.ok(mandatoryMfaWorker.includes("mfa_required:true"),'enrolled users must verify MFA');
assert.ok(mandatoryMfaWorker.includes("JOIN user_totp ON user_totp.user_id=users.id AND user_totp.enabled=1"),'private sessions require completed enrollment');
assert.ok(fs.readFileSync('workspace/index.html','utf8').includes('accountPageRequiredEnroll'),'required enrollment form exists');

assert.ok(accountMarkup.includes('accountPageRequiredQr'),'mandatory authenticator enrollment contains QR target');
assert.ok(accountMarkup.includes('qrcode.min.js'),'workspace QR generation library loaded');
assert.ok(fs.readFileSync('account-page.js','utf8').includes("renderQr('accountPageRequiredQr',data.otpauth_url)"),'QR provisioning uses local authenticator URI');

const recoveryPage=fs.readFileSync('workspace/index.html','utf8');
const recoveryClient=fs.readFileSync('account-page.js','utf8');
const recoveryWorker=fs.readFileSync('account-backend/src/index.js','utf8');
assert.ok(recoveryPage.includes('<ol id="accountPageRequiredRecoveryCodes"'),'initial recovery codes displayed as an ordered list');
assert.ok(recoveryPage.includes('<ol id="accountPageTotpRecoveryCodes"'),'rotated recovery codes displayed as an ordered list');
assert.ok(recoveryClient.includes('showRecoveryCodes('),'recovery code renderer available');
assert.ok(recoveryClient.includes("navigator.clipboard.writeText(code)"),'individual copy includes only the code');
assert.ok(recoveryClient.includes("'/auth/totp/recovery/rotate'"),'rotation requires a separate authenticated request');
assert.ok(recoveryWorker.includes("'/v1/auth/totp/recovery/rotate'"),'Worker implements recovery code rotation');
assert.ok(recoveryWorker.includes("last_counter<? AND enabled=1"),'rotation prevents reuse of an authenticator code');

const workspaceMarkup=fs.readFileSync('workspace/index.html','utf8');
const accountSecurityMarkup=fs.readFileSync('account/index.html','utf8');
const sidebarScript=fs.readFileSync('command-center.js','utf8');
assert.ok(workspaceMarkup.includes('accountPageRequest')&&workspaceMarkup.includes('accountPageRequiredEnroll'),'Workspace includes full email and MFA sign in');
assert.ok(workspaceMarkup.includes('accountPageTotpVerify')&&workspaceMarkup.includes('accountPageTotpRecovery'),'Workspace retains MFA recovery functionality');
assert.ok(workspaceMarkup.includes('workspaceAccess'),'Workspace shows authenticated destinations');
assert.ok(accountSecurityMarkup.includes('account-security-dashboard')&&accountSecurityMarkup.includes('accountSecurityRecoveryStart'),'Account focuses on authenticated profile and security');
assert.ok(sidebarScript.includes("link.dataset.requiresAuth='true'")&&sidebarScript.includes("info?.authenticated"),'protected sidebar requires verified API session');

assert.ok(accountSecurityMarkup.includes('account-security.js?v=account-security-156'),'Account uses independent security controller');
assert.ok(!accountSecurityMarkup.includes('id="accountPageRequest"'),'Account no longer duplicates Workspace sign in');

const authRetryWorker=fs.readFileSync('account-backend/src/index.js','utf8');
const authRetryPage=fs.readFileSync('workspace/index.html','utf8');
const authRetryClient=fs.readFileSync('account-page.js','utf8');
const accountStatusClient=fs.readFileSync('account-security.js','utf8');
assert.ok(authRetryWorker.includes("retry_after:delay")&&authRetryWorker.includes("'Retry-After'"),'rate limit exposes a bounded retry time');
assert.ok(authRetryWorker.includes("created_at+60")&&authRetryWorker.includes("'resend'"),'email resend cooldown enforced by Worker');
assert.ok(authRetryWorker.includes("emailKey,5")&&authRetryWorker.includes("ipKey,12"),'existing hourly email and IP protections remain enabled');
assert.ok(authRetryPage.includes('accountPageRetryMessage')&&authRetryPage.includes('accountPageResend'),'Workspace provides retry text and resend action');
assert.ok(authRetryClient.includes('window.setInterval(update,1000)')&&authRetryClient.includes('cooldown(60)'),'browser exposes a live retry countdown');
assert.ok(accountStatusClient.includes('Your account is signed in, but authenticator settings could not be refreshed'),'Account preserves authenticated profile on temporary MFA status errors');

const workspaceCleanup=fs.readFileSync('workspace/index.html','utf8');
assert.ok(workspaceCleanup.includes('workspace-signed-in-note'),'signed in Workspace welcomes user to tools');
assert.ok(workspaceCleanup.includes('href="/account/" class="account-secondary-button workspace-security-link"'),'Workspace links to Account security controls');
assert.ok(workspaceCleanup.includes('id="accountPageLogout" class="account-secondary-button" hidden'),'sign out no longer appears in Workspace');
assert.ok(workspaceCleanup.includes('aria-label="Authenticator security settings" hidden'),'MFA management is not displayed on Workspace after login');
assert.ok(workspaceCleanup.includes('accountPageRequiredEnroll'),'MFA enrollment stays available during sign in');
const securityDashboard=fs.readFileSync('account/index.html','utf8');
assert.ok(securityDashboard.includes('accountSecurityRecoveryStart')&&securityDashboard.includes('accountSecuritySignOut'),'recovery management and sign out remain in Account');

const assignmentMarkup=fs.readFileSync('index.html','utf8');
const assignmentClient=fs.readFileSync('operations.js','utf8');
assert.ok(assignmentMarkup.includes('id="remediationAssignNotes"'),'assignment has optional reviewer notes');
assert.ok(assignmentMarkup.includes('id="remediationAssignNotesCount"'),'assignment shows notes character count');
assert.ok(assignmentClient.includes("reviewer_notes:$('remediationAssignNotes').value.trim().slice(0,1000)"),'assignment includes bounded notes in request');

const remediationDialogs=fs.readFileSync('index.html','utf8');
const remediationUi=fs.readFileSync('operations.js','utf8');
const remediationStyles=fs.readFileSync('styles.css','utf8');
assert.ok(remediationDialogs.includes('id="remediationConfirmDialog"'),'branded pre-send confirmation exists');
assert.ok(remediationDialogs.includes('id="remediationSuccessDialog"'),'branded success dialog exists');
assert.ok(remediationUi.includes('confirmReviewRequest(cve,email)'),'assignment invokes branded confirmation');
assert.ok(!remediationUi.includes("window.confirm('Send the "),'native browser confirm removed for assignment');
assert.ok(remediationUi.includes("Your request has been submitted to "),'success text contains recipient address');
assert.ok(remediationStyles.includes('#remediationDue::-webkit-calendar-picker-indicator'),'date calendar icon has higher contrast');

const signedInWorkspaceJs=fs.readFileSync('account-page.js','utf8');
const signedInWorkspaceCss=fs.readFileSync('styles.css','utf8');
assert.ok(signedInWorkspaceJs.includes("classList.add('workspace-authenticated')"),'successful login changes Workspace layout');
assert.ok(signedInWorkspaceJs.includes("classList.remove('workspace-authenticated')"),'sign out restores login layout');
assert.ok(signedInWorkspaceCss.includes('workspace-authenticated .account-new-login{display:none!important}'),'signed in login card is hidden');
assert.ok(signedInWorkspaceCss.includes('workspace-authenticated #workspaceAccess{display:block!important}'),'signed in Workspace tools are displayed');

const workspaceDashboardMarkup=fs.readFileSync('workspace/index.html','utf8');
assert.ok(workspaceDashboardMarkup.includes('id="workspaceAccess"')&&workspaceDashboardMarkup.includes('workspace-kpis'),'authenticated Workspace has full dashboard');
assert.ok(workspaceDashboardMarkup.includes('wsRecentRemediation')&&workspaceDashboardMarkup.includes('wsRecentCves'),'dashboard contains remediation and advisory panels');
assert.ok(workspaceDashboardMarkup.includes('wsCriticalHint'),'critical count does not imply unvalidated findings');
assert.ok(workspaceDashboardMarkup.includes('accountPageRequiredEnroll'),'mandatory MFA enrollment retained');
assert.ok(fs.readFileSync('workspace-dashboard.js','utf8').includes("credentials:'include'"),'private dashboard fetches include account session');

const workspaceDataClient=fs.readFileSync('workspace-dashboard.js','utf8');
assert.ok(workspaceDataClient.includes("request('/inventory')"),'Workspace uses the actual account inventory read endpoint');
assert.ok(workspaceDataClient.includes("fetch('/feed-health.json'"),'recent advisory summary uses a published JSON feed');
assert.ok(!workspaceDataClient.includes("fetch('/data.js'"),'empty script is not treated as an advisory feed');
assert.ok(workspaceDataClient.includes("setTimeout(start,0)"),'dashboard loads after login state is rendered');

assert.ok(fs.readFileSync('account-backend/src/index.js','utf8').includes("path==='/v1/website-monitor'?await body(req):{}"),'manual website checks must not JSON parse empty POST requests');

const emailTestPage=fs.readFileSync('website-monitor/index.html','utf8');
const emailTestScript=fs.readFileSync('website-monitor-page.js','utf8');
assert.ok(emailTestPage.includes('id="webRiskEmailTest"')&&emailTestPage.includes('monitor-178'),'warning email test button is published with current script version');
assert.ok(emailTestScript.includes("warningButton.addEventListener('click'")&&emailTestScript.includes('Test warning email failed:'),'warning email test has a working click listener with visible errors');
