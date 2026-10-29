(()=>{
'use strict';
const $=id=>document.getElementById(id);
if(!$('customerDashStatus'))return;
const reporting=!!$('customerReportBody');
let inventory={customers:[],environments:[],assets:[]},records=[];
let pluginFindings=[],pluginChecks={},pluginMonitorRows={};
const pluginSlugOverrides={'yoast seo':'wordpress-seo','wp file manager':'wp-file-manager','wps hide login':'wps-hide-login','autoptimize':'autoptimize','wp mail smtp':'wp-mail-smtp','advanced editor tools':'tinymce-advanced','addtoany share buttons':'add-to-any','events manager':'events-manager','wp store locator':'wp-store-locator','wpbakery page builder':'js_composer'};
const pluginSlug=name=>pluginSlugOverrides[name.toLowerCase()]||name.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
async function refreshPluginFindings(){
 const assets=inventory.assets.filter(a=>a.technology.startsWith('WordPress Plugin: '));
 pluginChecks={};pluginFindings=[];pluginMonitorRows={};
 let stored=null;
 try{stored=await api('plugin-monitor')}catch(_){}
 if(stored?.ready){
  const rows=new Map((stored.checks||[]).map(r=>[r.asset_id,r]));
  pluginMonitorRows=Object.fromEntries(rows);
  for(const asset of assets){
   const check=rows.get(asset.id);
   if(!check||check.installed_version!==asset.version){pluginChecks[asset.id]='pending';continue}
   pluginChecks[asset.id]=check.status||'unavailable';
   if(check.status!=='checked')continue;
   for(const v of check.findings||[])pluginFindings.push({...v,asset_id:asset.id,technology:asset.technology,version:asset.version,
    evidence:v.level==='version_review'?'Version range candidate; confirm vendor applicability.':'Plugin advisory requires version verification.',
    comparison_detail:v.affected||'',source_label:v.sources?.[0]?.label||'WPVulnerability',
    source_url:v.sources?.[0]?.url||''});
  }
 }else{
  for(const a of assets)pluginChecks[a.id]='unavailable';
 }
 if(reporting)drawReport();else drawDashboard();
}

let findingStatusReady=false,findingStatuses=new Map(),findingStatusFilter='Unresolved';
const statusOptions=['Needs Review','Fix in Progress','Fixed/Patched','Not Applicable','Accepted Risk'];
const statusKey=i=>i.asset_id+'|'+i.id;
const statusFor=i=>findingStatuses.get(statusKey(i))||'Needs Review';
const closedStatus=s=>['Fixed/Patched','Not Applicable','Accepted Risk'].includes(s);
async function saveFindingStatus(i,status,select){
 select.disabled=true;
 try{
  const r=await fetch('https://api.cveharbor.com/v1/finding-statuses/'+encodeURIComponent(i.asset_id)+'/'+encodeURIComponent(i.id),{
   method:'PUT',credentials:'include',headers:{'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify({status})});
  if(!r.ok)throw Error((await r.json().catch(()=>({}))).error||'Unable to save status');
  findingStatuses.set(statusKey(i),status);
  drawReport();
 }catch(error){select.value=statusFor(i);window.alert('Could not save vulnerability status: '+error.message)}finally{select.disabled=false}
}

const text=(tag,value,cls)=>{const el=document.createElement(tag);el.textContent=String(value??'');if(cls)el.className=cls;return el};
const api=async path=>{
 const r=await fetch('https://api.cveharbor.com/v1/'+path,{credentials:'include',headers:{Accept:'application/json'}});
 const d=await r.json().catch(()=>({}));if(r.status===401)return {authenticated:false};if(!r.ok){const error=new Error(d.error||'Account service unavailable');error.status=r.status;throw error}return d;
};
function option(select,label,id){const el=text('option',label);el.value=id;select.append(el)}
const advisories=()=>{
 const result=new Map();
 for(const source of [window.CVEHARBOR_DATA?.advisories,window.CVEHARBOR_CATALOG?.advisories])
  for(const record of source||[])if(record?.id&&!result.has(record.id))result.set(record.id,record);
 return [...result.values()];
};
function compute(customerId,environmentId=''){
 const environments=inventory.environments.filter(e=>e.customer_id===customerId&&(!environmentId||e.id===environmentId));
 const ids=new Set(environments.map(e=>e.id));
 const assets=inventory.assets.filter(a=>ids.has(a.environment_id));
 const matched=window.CVEHARBOR_INVENTORY_MATCH.evaluate(assets,records,5000);
 const issues=[...matched.items,...pluginFindings.filter(m=>assets.some(a=>a.id===m.asset_id))].map(m=>({
  ...m,asset:assets.find(a=>a.id===m.asset_id),
  environment:environments.find(e=>e.id===assets.find(a=>a.id===m.asset_id)?.environment_id)
 }));
 const unique=new Set(issues.map(i=>i.id));
 return {environments,assets,issues,total:issues.length,limited:matched.limited,
  unique:unique.size,critical:issues.filter(i=>i.severity.toLowerCase()==='critical').length,
  kev:issues.filter(i=>i.known_exploited).length,
  reviewed:issues.filter(i=>i.level==='version_review').length};
}
function filters(){
 const chosen=$('customerDashFilter').value;
 $('customerDashFilter').replaceChildren();option($('customerDashFilter'),reporting?'Choose a customer':'All customers','');
 for(const c of inventory.customers)option($('customerDashFilter'),c.name,c.id);
 if(inventory.customers.some(c=>c.id===chosen))$('customerDashFilter').value=chosen;
 environments();
}
function environments(){
 const customer=$('customerDashFilter').value,previous=$('customerDashEnvironment').value;
 const select=$('customerDashEnvironment');select.replaceChildren();
 option(select,'All environments','');
 for(const env of inventory.environments.filter(e=>!customer||e.customer_id===customer)){
  const customerName=inventory.customers.find(c=>c.id===env.customer_id)?.name||'Customer';
  option(select,customerName+' / '+env.name+' ('+env.kind+')',env.id);
 }
 if([...select.options].some(x=>x.value===previous))select.value=previous;
}
function metric(label,value){const box=text('div','','customer-dash-metric');box.append(text('strong',value),text('span',label));return box}
function link(url,label){const a=text('a',label,'ops-link');a.href=url;a.target='_blank';a.rel='noopener noreferrer';return a}
const normalize=x=>String(x||'').trim().toLowerCase();
function lifecycleFor(tech,version){
 const aliases={'sql server':'mssqlserver','microsoft sql server':'mssqlserver',
 'windows server':'windows-server','windows':'windows','php':'php','wordpress':'wordpress',
 '.net':'dotnet','mariadb':'mariadb','mysql':'mysql','ubuntu':'ubuntu','debian':'debian','sitefinity':'sitefinity'};
 const slug=aliases[normalize(tech)]||normalize(tech).replace(/\s+/g,'-');
 const rows=(window.CVEHARBOR_LIFECYCLE?.cycles||[]).filter(x=>x.slug===slug);
 if(!rows.length)return {text:'Support status unknown',state:'unknown'};
 const cycle=rows.find(x=>version&&String(version).startsWith(String(x.cycle)))||null;
 if(!cycle)return {text:'Release cycle unverified',state:'unknown'};
 const date=cycle.eol_date;
 if(!/^\d{4}-\d{2}-\d{2}$/.test(String(date||'')))return {text:'Support deadline not published',state:'unknown'};
 const remaining=Math.floor((Date.parse(date+'T00:00:00Z')-Date.now())/86400000);
 return {text:remaining<0?'Published support deadline passed':remaining<=90?'Support ends within 90 days':'Published support date '+date,
  state:remaining<0?'expired':remaining<=90?'warning':'supported'};
}
function visualize(groups,all){
 const attention=$('customerAttentionVisual'),severity=$('customerSeverityVisual'),software=$('customerSoftwareVisual');
 if(!attention||!severity||!software)return;
 attention.replaceChildren();severity.replaceChildren();software.replaceChildren();
 const items=groups.flatMap(x=>x.stats.issues.map(i=>({...i,customer:x.customer})));
 const critical=items.filter(i=>normalize(i.severity)==='critical').length;
 const high=items.filter(i=>normalize(i.severity)==='high').length;
 const other=items.length-critical-high;
 const sev=[['Critical candidates',critical,'critical'],['High candidates',high,'high'],['Other candidates',other,'other']];
 const total=items.length;
 const center=text('div','','customer-donut-center');
 center.append(text('strong',total),text('span','Potential matches'));
 const circle=text('div','','customer-donut');
 const angle=total?Math.round(100*critical/total):0;
 const highPercent=total?Math.round(100*high/total):0;
 circle.style.background='conic-gradient(#ed6b78 0% '+angle+'%, #eebc66 '+angle+'% '+(angle+highPercent)+'%, #5d9baf '+(angle+highPercent)+'% 100%)';
 circle.append(center);severity.append(circle);
 for(const [label,count,kind] of sev){
  const legend=text('div','','customer-chart-legend');
  legend.append(text('span',label),text('strong',count));legend.dataset.kind=kind;severity.append(legend);
 }
 let customerCount=groups.filter(g=>g.stats.total>0).length;
 const note=total?customerCount+' customer'+(customerCount===1?'':'s')+' with potential matches.':'No matches in this limited advisory index.';
 attention.append(text('strong',String(customerCount)+' / '+all.length,'customer-attention-number'),
  text('p',note,'ops-note'));
 const scale=text('div','','customer-attention-track');
 const fill=text('div','','customer-attention-fill');
 fill.style.width=(all.length?Math.round(100*customerCount/all.length):0)+'%';
 scale.append(fill);attention.append(scale);
 attention.append(text('p','Unmatched or unknown product versions are not evidence of safety.','ops-note'));
 const bySoftware=new Map();
 for(const g of groups)for(const asset of g.stats.assets){
  const key=g.customer.id+'|'+asset.environment_id+'|'+asset.name+'|'+asset.technology;
  const findings=g.stats.issues.filter(i=>i.asset_id===asset.id);
  bySoftware.set(key,{customer:g.customer,asset,findings,environment:g.stats.environments.find(e=>e.id===asset.environment_id)});
 }
 for(const item of [...bySoftware.values()].slice(0,100)){
  const {customer,asset,findings,environment}=item;
  const card=text('button','','customer-software-card');
  card.type='button';
  card.append(text('strong',asset.technology),text('span',customer.name+' · '+(environment?.name||'Environment')+' · '+asset.name),
   text('span','Installed '+(asset.version||'version unknown')),
   text('span',findings.length+' potential CVE '+(findings.length===1?'match':'matches'),'customer-software-count'));
  const support=lifecycleFor(asset.technology,asset.version);
  const badge=text('span',support.text,'customer-support-indicator');badge.dataset.state=support.state;card.append(badge);
  const last=(window.CVEHARBOR_PATCH_NOTES?.releases||[]).find(r=>normalize(r.slug)===normalize(asset.technology).replace(/\s+/g,'-'));
  if(last)card.append(text('span','Publisher release: '+last.version+' · Review notes'));
  card.addEventListener('click',()=>{
   $('customerDashFilter').value=customer.id;environments();
   $('customerDashEnvironment').value=environment?.id||'';
   drawDashboard();
   showFindings(customer.id,asset.id);
  });
  software.append(card);
 }
 if(!bySoftware.size)software.append(text('p','No software inventory recorded yet.','ops-note'));
}
function evidenceDetail(i){
 const panel=text('details','','customer-evidence-detail');
 const summary=text('summary',(i.level==='version_review'?'Numeric range candidate':i.level==='outside_range'?'Outside one stated range':'Category match only')+' · View advisory evidence');
 panel.append(summary);
 const add=(name,value)=>{if(value)panel.append(text('p',name+': '+value,'ops-note'))};
 add('Installed software',i.technology+' '+(i.version||'(version unknown)'));
 add('Assessment',i.evidence);
 add('Version comparison',i.comparison_detail);
 add('Advisory description',i.summary||i.title);
 add('Published affected products and versions',i.affected||'Not supplied by this feed');
 add('Vendor remediation guidance',i.remediation||'Not supplied by this feed');
 add('Published',i.published||'Unknown');
 add('Last updated',i.updated||'Unknown');
 if(i.source_url)panel.append(link(i.source_url,i.source_label||'Original advisory'));
 panel.append(text('p','This is advisory evidence, not a scan or confirmed exposure. Check vendor applicability, OS backports, exact packages and enabled features.','ops-note'));
 return panel;
}
function showFindings(customerId,assetId){
 const box=$('customerDashFindings');if(!box)return;
 box.replaceChildren();
 const customer=inventory.customers.find(c=>c.id===customerId);
 for(const i of compute(customerId,$('customerDashEnvironment').value).issues.filter(x=>x.asset_id===assetId)){
  const row=text('article','','ops-result');
  row.append(text('strong',i.id+' · '+i.severity.toUpperCase()),
   text('p',(customer?.name||'Customer')+' / '+(i.environment?.name||'')+' / '+(i.asset?.name||'')),
   text('p',i.evidence,'ops-note'),evidenceDetail(i));
  box.append(row);
 }
 if(!box.children.length)box.append(text('p','No candidate advisories for this entry in the current index.','ops-note'));
 box.scrollIntoView?.({behavior:'smooth',block:'start'});
}
function drawDashboard(){
 const chosen=$('customerDashFilter').value,env=$('customerDashEnvironment').value;
 const customers=inventory.customers.filter(c=>!chosen||c.id===chosen);
 const all=customers.map(c=>({customer:c,stats:compute(c.id,env)}));
 const totals=all.reduce((s,x)=>({environments:s.environments+x.stats.environments.length,
  assets:s.assets+x.stats.assets.length,issues:s.issues+x.stats.total,
  critical:s.critical+x.stats.critical,kev:s.kev+x.stats.kev}),
 {environments:0,assets:0,issues:0,critical:0,kev:0});
 const metrics=$('customerDashMetrics');metrics.replaceChildren(
  metric('Customers',all.length),metric('Environments',totals.environments),
  metric('Technology entries',totals.assets),metric('Potential matches',totals.issues),
  metric('Critical candidates',totals.critical),metric('KEV candidates',totals.kev));
 visualize(all,customers);
 const root=$('customerDashRows');root.replaceChildren();
 for(const {customer,stats} of all){
  const item=text('article','','ops-result');const row=text('div','','ops-result-top');
  row.append(text('strong',customer.name),text('span',stats.environments.length+' environments · '+stats.assets.length+' technologies · '+stats.total+' potential matches'));
  item.append(row);
  const a=text('a','Generate customer report','ops-link');
  a.href='/customer-reports/?customer='+encodeURIComponent(customer.id);
  const overview=text('button','Open customer dashboard','ops-download');overview.type='button';
  overview.addEventListener('click',()=>{$('customerDashFilter').value=customer.id;environments();drawDashboard()});
  item.append(overview,a);root.append(item);
 }
 if(!all.length)root.append(text('p','No customer records yet. Create customers in My Environments.','ops-note'));
 const findings=$('customerDashFindings');findings.replaceChildren();
 const list=all.flatMap(x=>x.stats.issues.map(i=>({...i,customer:x.customer})));
 for(const i of list.slice(0,100)){
  const row=text('article','','ops-result');
  row.append(text('strong',i.id+' · '+i.severity.toUpperCase()+(i.known_exploited?' · CISA KEV':'')),
   text('p',i.customer.name+' / '+i.environment?.name+' / '+i.asset?.name+' / '+i.technology+' '+(i.version||'Version unknown')),
   text('p',i.evidence,'ops-note'),evidenceDetail(i));
  findings.append(row);
 }
 if(!list.length)findings.append(text('p','No matching findings within the available index. This does not prove the assets are secure.','ops-note'));
 $('customerDashCoverage').textContent='Showing up to 100 findings. CVEHarbor matches from a limited indexed feed; product category matches are unverified. One CVE on multiple assets counts as multiple asset findings.';
}
function reportSection(title){return text('h2',title)}
function table(headers,rows){
 const t=text('table','','customer-report-table'),head=text('thead'),hr=text('tr');
 for(const h of headers)hr.append(text('th',h));head.append(hr);t.append(head);
 const body=text('tbody');
 for(const values of rows){const row=text('tr');for(const v of values)row.append(text('td',v));body.append(row)}
 t.append(body);return t;
}
function shortSummary(i){
 const source=String(i.summary||i.title||'').replace(/\s+/g,' ').trim();
 if(!source||source===i.id)return 'Description not available in the indexed advisory.';
 if(source.length<=205)return source;
 const lead=source.slice(0,205);
 const sentence=lead.lastIndexOf('. ');
 if(sentence>70)return lead.slice(0,sentence+1);
 const space=lead.lastIndexOf(' ');
 return lead.slice(0,space>90?space:205)+'…';
}
function findingStatusControls(issues){
 const wrap=text('div','','customer-finding-filters');
 const counts={All:issues.length,Unresolved:issues.filter(i=>!closedStatus(statusFor(i))).length,
  'Fixed/Patched':issues.filter(i=>statusFor(i)==='Fixed/Patched').length,
  'Not Applicable':issues.filter(i=>statusFor(i)==='Not Applicable').length,
  'Accepted Risk':issues.filter(i=>statusFor(i)==='Accepted Risk').length};
 for(const [label,count] of Object.entries(counts)){
  const b=text('button',label+' ('+count+')','customer-finding-filter');b.type='button';
  b.setAttribute('aria-pressed',String(findingStatusFilter===label));
  b.addEventListener('click',()=>{findingStatusFilter=label;drawReport()});wrap.append(b);
 }
 return wrap;
}
function drawReport(){
 const id=$('customerDashFilter').value,env=$('customerDashEnvironment').value;
 const root=$('customerReportBody');root.replaceChildren();
 const customer=inventory.customers.find(c=>c.id===id);
 $('customerReportPrint').disabled=!customer;
 $('customerReportCsv').disabled=!customer;
 if(!customer){root.append(text('p','Select a customer to generate their security review.','ops-note'));return}
 const stats=compute(customer.id,env),date=new Date().toISOString().slice(0,10);
 root.append(text('p','CVEHarbor | Customer Security Review','eyebrow'),text('h2',customer.name),
  text('p','Prepared: '+date+' · Scope: '+(env?(stats.environments[0]?.name||'Selected environment'):'All recorded environments')),
  text('p','This is an automated review of user-entered software inventory and a limited public advisory index. No customer endpoints were scanned. Potential findings must be validated before being treated as confirmed vulnerabilities.','ops-note'));
 root.append(reportSection('Executive Summary'),
 table(['Metric','Count'],[['Environments',stats.environments.length],['Technology entries',stats.assets.length],
  ['Potential asset–CVE matches',stats.total],['Critical candidate matches',stats.critical],
  ['CISA KEV candidate matches',stats.kev],['Preliminary version-range matches',stats.reviewed]]));
 root.append(reportSection('Recorded Technology Inventory'),
 table(['Environment','Asset','Technology','Installed version'],
 stats.assets.map(a=>[stats.environments.find(e=>e.id===a.environment_id)?.name||'',a.name,a.technology,a.version||'Unknown'])));
 root.append(reportSection('Vulnerabilities Requiring Verification'));
 root.append(text('p','Publication dates and descriptions are shown only when supplied by the indexed advisory. Matches are candidates requiring product-specific verification.','ops-note'));
 root.append(text('p',findingStatusReady?'Status changes are saved privately to your account for each asset and CVE.':'Vulnerability status tracking is unavailable until its D1 migration is applied. Existing findings remain visible.','ops-note'));
 const pluginAssets=stats.assets.filter(a=>a.technology.startsWith('WordPress Plugin: '));
 if(pluginAssets.length){
  const checked=pluginAssets.filter(a=>pluginChecks[a.id]==='checked').length;
  const unavailable=pluginAssets.filter(a=>pluginChecks[a.id]==='unavailable'||pluginChecks[a.id]==='unverified').length;
  root.append(text('p','Plugin monitoring: '+checked+' checked, '+unavailable+' unavailable or unverified, '+(pluginAssets.length-checked-unavailable)+' pending. Saved results refresh on a schedule. Unknown coverage does not establish safety.','ops-note'));
 }
 if(pluginAssets.length){
  const monitor=table(['Plugin','Installed version','Last check','Coverage','Potential CVEs'],
   pluginAssets.map(a=>{
    const check=pluginMonitorRows[a.id];
    return [a.technology.slice('WordPress Plugin: '.length),a.version||'Unknown',
     check?.checked_at?new Date(check.checked_at*1000).toISOString().replace('T',' ').slice(0,16)+' UTC':'Not checked',
     pluginChecks[a.id]==='checked'?'Checked':pluginChecks[a.id]==='pending'?'Pending':'Unverified or unavailable',
     check?.status==='checked'?String(check.findings?.length||0):'Unknown'];
   }));
  monitor.classList.add('customer-plugin-monitor-table');root.append(reportSection('WordPress Plugin Monitoring'),monitor);
 }
 root.append(findingStatusControls(stats.issues));
 const filtered=stats.issues.filter(i=>findingStatusFilter==='All'||findingStatusFilter==='Unresolved'&&!closedStatus(statusFor(i))||statusFor(i)===findingStatusFilter);
 const compact=filtered.slice(0,250);
 const findingsTable=table(['CVE','Published','Severity','Software / Asset','Vulnerability summary','Assessment','Vulnerability Fix Status'],
  compact.map(i=>[
   i.id,i.published||'Not available',i.severity,
   i.technology+' '+(i.version||'Unknown')+' · '+(i.asset?.name||'Asset'),
   shortSummary(i),i.level==='version_review'?'Version range candidate':'Category match · Unverified',''
  ]));
 findingsTable.classList.add('customer-vulnerability-table');
 for(const [index,i] of compact.entries()){
  const cell=findingsTable.tBodies[0].rows[index].cells[6];
  const select=text('select','','customer-finding-status-select');
  select.setAttribute('aria-label','Fix status for '+i.id+' on '+(i.asset?.name||'asset'));
  for(const optionValue of statusOptions)option(select,optionValue,optionValue);
  select.value=statusFor(i);select.disabled=!findingStatusReady;
  select.addEventListener('change',()=>void saveFindingStatus(i,select.value,select));
  cell.append(select);
 }
 root.append(findingsTable);
 root.append(reportSection('Advisory Evidence and References'));
 for(const i of compact){
  const block=text('section','','customer-report-finding');
  block.append(text('h3',i.id+' · '+i.technology+' '+(i.version||'Unknown')),
   text('p',shortSummary(i),'customer-finding-summary'),
   text('p','Published: '+(i.published||'Not available')+' · Severity: '+i.severity,'ops-note'),
   text('p','Match assessment: '+(i.evidence||'Requires verification'),'ops-note'));
  if(i.affected)block.append(text('p','Affected software: '+i.affected,'ops-note'));
  if(i.remediation)block.append(text('p','Vendor guidance: '+i.remediation,'ops-note'));
  if(i.source_url)block.append(link(i.source_url,i.source_label||'Original advisory'));
  root.append(block);
 }
 if(filtered.length>250||stats.limited)root.append(text('p','The findings list is limited. Narrow the report by environment for a more complete review.','ops-note'));
 if(!stats.total)root.append(text('p','No matches in the available index. This does not establish absence of vulnerabilities.','ops-note'));
 root.append(reportSection('Recommended Follow-up'),
 text('p','Validate product identity, installed build, affected configurations and the original vendor advisory. Assign verified findings for remediation and retain evidence of patch verification.','ops-note'),
 text('p','Data classification: Customer confidential. Review before sharing. Report generated locally in your browser; CVEHarbor does not publish your inventory.','ops-note'));
}
function csvReport(){
 const id=$('customerDashFilter').value,env=$('customerDashEnvironment').value;
 const customer=inventory.customers.find(c=>c.id===id);if(!customer)return;
 const rows=[['Customer','Environment','Asset','Technology','Installed version','CVE','Severity','CISA KEV','Match classification','Published','Summary','Vulnerability Fix Status','Affected versions','Version comparison','Remediation','Source']];
 for(const f of compute(id,env).issues)
  rows.push([customer.name,f.environment?.name||'',f.asset?.name||'',f.technology,f.version,f.id,f.severity,f.known_exploited?'Yes':'No',f.level,f.published||'Not available',shortSummary(f),statusFor(f),f.affected||'',f.comparison_detail||'',f.remediation||'',f.source_url]);
 const csv=rows.map(r=>r.map(v=>{
  let value=String(v??'');
  if(/^[=+\-@\t\r]/.test(value))value="'"+value;
  return '"'+value.replace(/"/g,'""')+'"';
 }).join(',')).join('\r\n');
 const url=URL.createObjectURL(new Blob(['\ufeff'+csv],{type:'text/csv;charset=utf-8'}));
 const a=document.createElement('a');a.href=url;a.download='cveharbor-customer-findings-'+new Date().toISOString().slice(0,10)+'.csv';
 document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function init(){
 try{
  const session=await api('me');
  if(!session.authenticated){$('customerDashLogin').hidden=false;$('customerDashStatus').textContent='Sign in required to access private customer records.';return}
  const flags=await api('inventory/status');
  if(!flags.ready){$('customerDashStatus').textContent='Customer inventory database migration is pending. No private records can be loaded yet.';return}
  inventory=await api('inventory');
  records=advisories();
  if(reporting){
   const saved=await api('finding-statuses').catch(()=>({ready:false,statuses:[]}));
   findingStatusReady=!!saved.ready;
   findingStatuses=new Map((saved.statuses||[]).map(s=>[s.asset_id+'|'+s.cve_id,s.status]));
  }
  $('customerDashAccess').hidden=false;
  filters();
  const requested=new URLSearchParams(location.search).get('customer');
  if(inventory.customers.some(c=>c.id===requested)){
   $('customerDashFilter').value=requested;environments();
  }
  const draw=reporting?drawReport:drawDashboard;draw();
  $('customerDashFilter').addEventListener('change',()=>{environments();draw()});
  $('customerDashEnvironment').addEventListener('change',draw);
  if(reporting){
   $('customerReportPrint').addEventListener('click',()=>window.print());
   $('customerReportCsv').addEventListener('click',csvReport);
  }
  $('customerDashStatus').textContent=inventory.customers.length+' customer records loaded privately. Advisory matching is preliminary.';
  void refreshPluginFindings();
 }catch(e){$('customerDashLogin').hidden=false;$('customerDashStatus').textContent=(e.status===404||e.status===503)?'Customer inventory backend is not active. The D1 migration and updated Cloudflare Worker must be deployed.':'Could not reach account data. Please sign in or check the service. '+e.message}
}
void init();
})();