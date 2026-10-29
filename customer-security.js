(()=>{
'use strict';
const $=id=>document.getElementById(id);
if(!$('customerDashStatus'))return;
const reporting=!!$('customerReportBody');
let inventory={customers:[],environments:[],assets:[]},records=[];
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
 const issues=matched.items.map(m=>({
  ...m,asset:assets.find(a=>a.id===m.asset_id),
  environment:environments.find(e=>e.id===assets.find(a=>a.id===m.asset_id)?.environment_id)
 }));
 const unique=new Set(issues.map(i=>i.id));
 return {environments,assets,issues,total:matched.total,limited:matched.limited,
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
 root.append(reportSection('Vulnerabilities Requiring Verification'),
 table(['CVE','Severity','Environment and asset','Technology','Matching evidence'],
 stats.issues.slice(0,250).map(i=>[i.id,i.severity,i.environment?.name+' / '+i.asset?.name,i.technology+' '+(i.version||''),
  i.evidence+' | '+(i.comparison_detail||'')+' | Affected: '+(i.affected||'Not provided')+' | Guidance: '+(i.remediation||'Not provided')+' | Source: '+(i.source_url||'Not provided')])));
 if(stats.total>250||stats.limited)root.append(text('p','The findings list is limited. Narrow the report by environment for a more complete review.','ops-note'));
 if(!stats.total)root.append(text('p','No matches in the available index. This does not establish absence of vulnerabilities.','ops-note'));
 root.append(reportSection('Recommended Follow-up'),
 text('p','Validate product identity, installed build, affected configurations and the original vendor advisory. Assign verified findings for remediation and retain evidence of patch verification.','ops-note'),
 text('p','Data classification: Customer confidential. Review before sharing. Report generated locally in your browser; CVEHarbor does not publish your inventory.','ops-note'));
}
function csvReport(){
 const id=$('customerDashFilter').value,env=$('customerDashEnvironment').value;
 const customer=inventory.customers.find(c=>c.id===id);if(!customer)return;
 const rows=[['Customer','Environment','Asset','Technology','Installed version','CVE','Severity','CISA KEV','Match classification','Affected versions','Version comparison','Remediation','Source']];
 for(const f of compute(id,env).issues)
  rows.push([customer.name,f.environment?.name||'',f.asset?.name||'',f.technology,f.version,f.id,f.severity,f.known_exploited?'Yes':'No',f.level,f.affected||'',f.comparison_detail||'',f.remediation||'',f.source_url]);
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
 }catch(e){$('customerDashLogin').hidden=false;$('customerDashStatus').textContent=(e.status===404||e.status===503)?'Customer inventory backend is not active. The D1 migration and updated Cloudflare Worker must be deployed.':'Could not reach account data. Please sign in or check the service. '+e.message}
}
void init();
})();