// Automated DOM smoke checks for the public dashboard using synthetic advisory data.
// Does not call external feeds or send telemetry.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { JSDOM } from 'jsdom';

const html=fs.readFileSync('index.html','utf8');
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
assert.match($('dialogContent').textContent,/Public sources/,'source links in detail');

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
assert.match(opsDoc.getElementById('remediationCount').textContent,/1 tracked/,'local remediation form saves item');
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
    family:i===10?'RedLine':'Mirai',
    type:i===10?'Infostealer':'Botnet',
    first_seen:'2026-10-28 12:00:00',file_type:'elf',
    tags:[],source_url:'https://bazaar.abuse.ch/'
  })),
  advisories:[],sources:{malwarebazaar:{ok:true}}
};
malwareWindow.eval(fs.readFileSync('malware.js','utf8'));
const familyCards=()=>malwareDoc.querySelectorAll('#malwareFamilyDirectory .malware-entry').length;
const sampleCards=()=>malwareDoc.querySelectorAll('#malwareRows .malware-entry').length;
const familyToggle=malwareDoc.getElementById('malwareShowAllFamilies');
const sampleToggle=malwareDoc.getElementById('malwareShowAllSamples');
assert.equal(familyCards(),6,'initial malware family preview is six cards');
assert.equal(sampleCards(),6,'initial malware sample preview is six cards');
assert.equal(familyToggle.hidden,false,'family expansion visible with more than six entries');
assert.equal(sampleToggle.hidden,false,'sample expansion visible with more than six entries');
assert.match(malwareDoc.getElementById('malwareFamilySummary').textContent,/Showing 6 of 26 families/);
assert.match(malwareDoc.getElementById('malwareSampleSummary').textContent,/Showing 6 of 11 samples/);
familyToggle.click();
assert.equal(familyCards(),26,'Show All reveals every reference family');
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

console.log('CVEHarbor browser smoke passed: 38 categories, publication badges, list, details, focus, search and feed status.');
