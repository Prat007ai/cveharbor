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
assert.equal(document.querySelectorAll('#chartInsights .chart-insight').length,4,'chart insights populated');
document.querySelector('[data-chart-period="published30"]').click();
assert.equal(document.querySelectorAll('#chartInsights .chart-insight').length,4,'chart insights update with period');
document.querySelector('[data-chart-period="all"]').click();
assert.match($('heroFeedPulse').textContent,/4 of 4 sources/,'feed status visible');
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

console.log('CVEHarbor browser smoke passed: 38 categories, publication badges, list, details, focus, search and feed status.');
