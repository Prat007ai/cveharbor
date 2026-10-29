(()=>{
'use strict';
const $=id=>document.getElementById(id);
if(!$('customerDashStatus'))return;
const reporting=!!$('customerReportBody');
let inventory={customers:[],environments:[],assets:[]},records=[];
const text=(tag,value,cls)=>{const el=document.createElement(tag);el.textContent=String(value??'');if(cls)el.className=cls;return el};
const api=async path=>{
 const r=await fetch('https://api.cveharbor.com/v1/'+path,{credentials:'include',headers:{Accept:'application/json'}});
 const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||'Account service unavailable');return d;
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
 const root=$('customerDashRows');root.replaceChildren();
 for(const {customer,stats} of all){
  const item=text('article','','ops-result');const row=text('div','','ops-result-top');
  row.append(text('strong',customer.name),text('span',stats.environments.length+' environments · '+stats.assets.length+' technologies · '+stats.total+' potential matches'));
  item.append(row);
  const a=text('a','Generate customer report','ops-link');
  a.href='/customer-reports/?customer='+encodeURIComponent(customer.id);
  item.append(a);root.append(item);
 }
 if(!all.length)root.append(text('p','No customer records yet. Create customers in My Environments.','ops-note'));
 const findings=$('customerDashFindings');findings.replaceChildren();
 const list=all.flatMap(x=>x.stats.issues.map(i=>({...i,customer:x.customer})));
 for(const i of list.slice(0,100)){
  const row=text('article','','ops-result');
  row.append(text('strong',i.id+' · '+i.severity.toUpperCase()+(i.known_exploited?' · CISA KEV':'')),
   text('p',i.customer.name+' / '+i.environment?.name+' / '+i.asset?.name+' / '+i.technology+' '+(i.version||'Version unknown')),
   text('p',i.evidence,'ops-note'));
  if(i.source_url)row.append(link(i.source_url,'Original advisory'));
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
 stats.issues.slice(0,250).map(i=>[i.id,i.severity,i.environment?.name+' / '+i.asset?.name,i.technology+' '+(i.version||''),i.evidence])));
 if(stats.total>250||stats.limited)root.append(text('p','The findings list is limited. Narrow the report by environment for a more complete review.','ops-note'));
 if(!stats.total)root.append(text('p','No matches in the available index. This does not establish absence of vulnerabilities.','ops-note'));
 root.append(reportSection('Recommended Follow-up'),
 text('p','Validate product identity, installed build, affected configurations and the original vendor advisory. Assign verified findings for remediation and retain evidence of patch verification.','ops-note'),
 text('p','Data classification: Customer confidential. Review before sharing. Report generated locally in your browser; CVEHarbor does not publish your inventory.','ops-note'));
}
function csvReport(){
 const id=$('customerDashFilter').value,env=$('customerDashEnvironment').value;
 const customer=inventory.customers.find(c=>c.id===id);if(!customer)return;
 const rows=[['Customer','Environment','Asset','Technology','Installed version','CVE','Severity','CISA KEV','Match classification','Source']];
 for(const f of compute(id,env).issues)
  rows.push([customer.name,f.environment?.name||'',f.asset?.name||'',f.technology,f.version,f.id,f.severity,f.known_exploited?'Yes':'No',f.level,f.source_url]);
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
  if(reporting&&inventory.customers.some(c=>c.id===requested)){
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
 }catch(e){$('customerDashStatus').textContent='Unable to load customer security data: '+e.message}
}
void init();
})();