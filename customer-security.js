(()=>{
'use strict';
const $=id=>document.getElementById(id);
if(!$('customerDashStatus'))return;
const reporting=!!$('customerReportBody');
let inventory={customers:[],environments:[],assets:[]},records=[];
let pluginFindings=[],pluginChecks={},pluginMonitorRows={};
let pluginInstallationReady=false,pluginInstallationStatuses=new Map();
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
  // Preserve existing on-demand checks until the additive D1 migration is activated.
  for(let i=0;i<assets.length;i+=4){
   await Promise.all(assets.slice(i,i+4).map(async asset=>{
    const slug=pluginSlug(asset.technology.slice('WordPress Plugin: '.length));
    try{
     const result=await api('plugin-advisories?asset_id='+encodeURIComponent(asset.id)+'&slug='+encodeURIComponent(slug));
     pluginChecks[asset.id]=result.status||'unavailable';
     if(result.status==='checked')for(const v of result.findings||[]){
      pluginFindings.push({...v,asset_id:asset.id,technology:asset.technology,version:asset.version,
       evidence:v.level==='version_review'?'Version range candidate; confirm applicability.':'Plugin advisory requires verification.',
       comparison_detail:v.affected||'',source_label:v.sources?.[0]?.label||'WPVulnerability',
       source_url:v.sources?.[0]?.url||''});
     }
    }catch(_){pluginChecks[asset.id]='unavailable'}
   }));
  }
 }
 if(reporting)drawReport();else drawDashboard();
}

let findingStatusReady=false,findingStatuses=new Map(),findingStatusFilter='Unresolved';
let findingSort={key:'',direction:'asc'};
const reportSectionStates=new Map();
let printSectionStates=null;
const scorePanelStates=new Map();
let printScoreState=null;
let ticketReady=false,ticketAppendReady=false,findingTickets=new Map();
let pluginSourceReady=false,pluginSources=new Map();
const ticketFor=i=>findingTickets.get(statusKey(i))||[];
async function saveFindingTicket(i,input,button){
 const ticket=input.value.trim();
 if(!ticket){window.alert('Enter a DevOps ticket number');return}
 button.disabled=true;
 try{
  const r=await fetch('https://api.cveharbor.com/v1/finding-tickets/'+encodeURIComponent(i.asset_id)+'/'+encodeURIComponent(i.id),{
   method:'POST',credentials:'include',headers:{'Content-Type':'application/json',Accept:'application/json'},
   body:JSON.stringify({ticket_number:ticket})});
  const payload=await r.json().catch(()=>({}));
  if(!r.ok)throw Error(payload.error||'Unable to append ticket');
  const key=statusKey(i);
  findingTickets.set(key,[...ticketFor(i),ticket]);
  drawReport();
 }catch(error){window.alert('Could not add DevOps ticket: '+error.message);button.disabled=false}
}
async function saveReportPluginSource(asset,input,message){
 const source=pluginSources.get(asset.id)||{};
 const value=input.value.trim();
 try{
  const r=await fetch('https://api.cveharbor.com/v1/plugin-sources/'+encodeURIComponent(asset.id),{
   method:'PUT',credentials:'include',headers:{'Content-Type':'application/json',Accept:'application/json'},
   body:JSON.stringify({vendor_url:value,release_url:source.release_url||'',advisory_url:source.advisory_url||''})});
  const body=await r.json().catch(()=>({}));
  if(!r.ok)throw Error(body.error||'Unable to save plugin source');
  pluginSources.set(asset.id,{...source,vendor_url:value,verification:body.verification});
  message.textContent='Source saved. '+body.verification;
 }catch(e){message.textContent='Could not save source: '+e.message}
}

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
  const statuses=findings.map(statusFor);
  const needsReview=statuses.filter(x=>x==='Needs Review').length;
  const inProgress=statuses.filter(x=>x==='Fix in Progress').length;
  const accepted=statuses.filter(x=>x==='Accepted Risk').length;
  const active=needsReview+inProgress;
  if(needsReview){card.classList.add('customer-software-attention');}
  else if(inProgress){card.classList.add('customer-software-progress');}
  else if(accepted){card.classList.add('customer-software-accepted');}
  card.setAttribute('aria-label',asset.technology+': '+needsReview+' needs review, '+inProgress+' fixes in progress, '+accepted+' accepted risks. '+(findings.length-active-accepted)+' fixed or not applicable.');
  card.append(text('strong',asset.technology),text('span',customer.name+' · '+(environment?.name||'Environment')+' · '+asset.name),
   text('span','Installed '+(asset.version||'version unknown')),
   text('span',active?active+' unresolved CVE '+(active===1?'finding':'findings'):accepted?accepted+' accepted '+(accepted===1?'risk':'risks'):'No unresolved CVE findings','customer-software-count'));
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
function collapseReportSections(root){
 const names=new Set(['Recorded Technology Inventory','Vulnerabilities Requiring Verification','WordPress Plugin Monitoring','CVE Findings','Advisory Evidence and References']);
 const headings=[...root.children].filter(el=>el.tagName==='H2'&&names.has(el.textContent));
 for(const heading of headings){
  const name=heading.textContent;
  const panel=text('details','','customer-report-section');
  panel.dataset.section=name;
  panel.open=reportSectionStates.get(name)===true;
  const header=text('summary',name,'customer-report-section-toggle');
  panel.append(header);
  const contents=text('div','','customer-report-section-content');
  let next=heading.nextSibling;
  while(next&&!(next.nodeType===1&&next.tagName==='H2')){
   const current=next;next=next.nextSibling;contents.append(current);
  }
  panel.append(contents);
  heading.replaceWith(panel);
  panel.addEventListener('toggle',()=>{
   if(printSectionStates===null)reportSectionStates.set(name,panel.open);
  });
 }
}
function setReportPrintMode(printing){
 const score=document.querySelector('#customerReportBody details.customer-security-score-panel');
 if(printing&&score){printScoreState=[score,score.open];score.open=true;const method=score.querySelector('details.customer-score-methodology');if(method){score.dataset.methodWasOpen=String(method.open);method.open=true}}
 if(!printing&&printScoreState){const [panel,opened]=printScoreState;printScoreState=null;panel.open=opened;const method=panel.querySelector('details.customer-score-methodology');if(method){method.open=panel.dataset.methodWasOpen==='true';delete panel.dataset.methodWasOpen}}
 const sections=[...document.querySelectorAll('#customerReportBody details.customer-report-section')];
 if(printing){
  printSectionStates=sections.map(section=>[section,section.open]);
  for(const [section] of printSectionStates)section.open=true;
 }else if(printSectionStates){
  const previous=printSectionStates;printSectionStates=null;
  for(const [section,opened] of previous)section.open=opened;
 }
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
function sortFindings(items){
 if(!findingSort.key)return items;
 const severity={critical:0,high:1,medium:2,low:3,unknown:4};
 const key=i=>{
  if(findingSort.key==='Published')return /^\\d{4}-\\d{2}-\\d{2}/.test(i.published||'')?i.published:'';
  if(findingSort.key==='Severity')return severity[String(i.severity||'').toLowerCase()]??5;
  if(findingSort.key==='Software / Asset')return i.technology+' '+(i.asset?.name||'');
  return statusFor(i);
 };
 return [...items].sort((a,b)=>{
  const x=key(a),y=key(b);
  if(findingSort.key==='Published'&&(!x||!y))return !x&&!y?0:!x?1:-1;
  const n=typeof x==='number'?x-y:String(x).localeCompare(String(y),undefined,{numeric:true,sensitivity:'base'});
  return (findingSort.direction==='asc'?1:-1)*n||a.id.localeCompare(b.id);
 });
}
function enableFindingSort(tableElement){
 const columns={'Published':1,'Severity':2,'Software / Asset':3,'Vulnerability Fix Status':5};
 for(const [key,index] of Object.entries(columns)){
  const th=tableElement.tHead.rows[0].cells[index];
  const button=text('button',key,'customer-report-sort');button.type='button';
  const selected=findingSort.key===key;
  button.append(text('span',selected?(findingSort.direction==='asc'?' ▲':' ▼'):' ⇅','customer-report-sort-indicator'));
  th.replaceChildren(button);
  th.setAttribute('aria-sort',selected?(findingSort.direction==='asc'?'ascending':'descending'):'none');
  button.addEventListener('click',()=>{
   findingSort=selected?{key,direction:findingSort.direction==='asc'?'desc':'asc'}:{key,direction:'asc'};
   drawReport();
  });
 }
}
const scoreSeries=new Map();
function renderScorePanel(root,customer,scope,stats){
 const engine=window.CVEHARBOR_SCORE;
 if(!engine)return;
 const statuses=Object.fromEntries(findingStatuses.entries());
 const checks=Object.fromEntries(stats.assets.map(a=>[a.id,pluginMonitorRows[a.id]||null]));
 const assessment=engine.assessCustomer({assets:stats.assets,issues:stats.issues,checks,statuses});
 const key=customer.id+'|'+scope;
 const rating=assessment.score===null?'Insufficient Data':assessment.score>=90?'Excellent':assessment.score>=80?'Good':assessment.score>=70?'Needs Improvement':assessment.score>=50?'High Risk':'Critical Risk';
 const tier=assessment.score===null?'unknown':assessment.score>=80?'good':assessment.score>=70?'caution':'risk';
 const card=document.createElement('details');
 card.className='customer-security-score-panel';
 card.dataset.tier=tier;
 card.dataset.customerScope=key;
 card.open=scorePanelStates.get(key)===true;
 const header=document.createElement('summary');
 header.className='customer-score-header';
 const headingWrap=text('div','','customer-score-heading');
 headingWrap.append(text('strong','Inventory Based Security Assessment','customer-score-title'),
  text('span','Methodology v'+assessment.version,'customer-score-version'));
 const overview=text('div','','customer-score-overview');
 const seal=text('div','','customer-score-seal');
 seal.setAttribute('role','img');
 seal.setAttribute('aria-label',assessment.score===null?'Security score unavailable':assessment.score+' out of 100, '+rating);
 const circle=document.createElement('span');circle.className='customer-score-seal-number';
 circle.textContent=assessment.score===null?'—':String(assessment.score);
 seal.append(circle,text('small',assessment.score===null?'NO SCORE':'OUT OF 100'));
 const summaryDetails=text('div','','customer-score-summary');
 summaryDetails.append(text('strong',rating,'customer-score-rating'),
  text('span','Assessment confidence: '+assessment.confidence,'customer-score-meta'),
  text('span','Monitoring coverage: '+assessment.coverage+'%','customer-score-meta'),
  text('span','View score breakdown and history','customer-score-hint'));
 overview.append(seal,summaryDetails);
 header.append(headingWrap,overview);
 card.append(header);
 const contentBox=text('div','','customer-score-expanded');
 contentBox.append(text('p',assessment.explanation,'ops-note'));
 const b=assessment.parts;
 contentBox.append(text('h3','Score Breakdown'));
 contentBox.append(table(['Score component','Maximum points','Provisional deduction'],[
  ['Verified vulnerability exposure',50,b.exposure],['Software and patch currency',25,b.currency],
  ['Remediation effectiveness',15,b.remediation],['Monitoring coverage',10,b.monitoring]
 ]));
 contentBox.append(text('p','Scoring methodology v'+assessment.version+'. Inventory findings are candidates, not authenticated proof of exposure.','ops-note'));
 const details=document.createElement('details');details.className='customer-score-methodology';
 const summary=text('summary','How is this score calculated?');
 details.append(summary);
 const content=text('div','','customer-score-methodology-body');
 content.append(text('p','CVEHarbor starts with 100 points and subtracts deductions based on the customer inventory and available advisory checks. The result is a provisional inventory based rating, not a confirmed security assessment.'));
 const rules=text('ul');
 for(const explanation of [
  'Vulnerability exposure (up to 50 points): Unresolved version range candidate CVEs deduct 12 points for Critical, 7 for High, 4 for Medium and 2 for Low. Unknown severity deducts 3. A CISA known exploited flag multiplies that finding’s deduction by 1.5. The total is capped at 50.',
  'Software updates (up to 25 points): Each inventoried WordPress plugin with a verified Update Available result deducts 2 points. The total is capped at 25. Other software update types are not included in this v1 calculation.',
  'Remediation (up to 15 points): The share of version range candidate findings still open determines this deduction. Fixed/Patched and Not Applicable are excluded from open findings. These are recorded review statuses, not independently verified fixes.',
  'Monitoring coverage (up to 10 points): Coverage is the percentage of software entries with a recorded version, including WordPress plugins only when their vulnerability check succeeds for the installed version. The deduction is the rounded percentage of missing coverage divided by 10.'
 ])rules.append(text('li',explanation));
 content.append(rules);
 content.append(text('p','A numeric score is displayed only when at least one inventory asset exists, monitoring coverage is 70% or higher, and at least one version range candidate CVE is available. Otherwise the report says Insufficient Data.'));
 content.append(text('p','Confidence reflects monitoring coverage: High at 90% or more, Medium from 70% to 89%, and Low below 70%. Confidence does not confirm the accuracy of every advisory match.'));
 content.append(text('p','Example: deductions of 18 for exposure, 8 for software updates, 3 for remediation and 1 for monitoring produce 70 out of 100. The historical trend uses saved assessment snapshots, not invented past scores.'));
 details.append(content);contentBox.append(details);
 const heading=text('h3','Security Score Trend');
 const chart=document.createElement('div');chart.className='customer-score-trend';
 const message=text('p','Historical scores will appear here as assessments are recorded.','ops-note');
 const renderHistory=history=>{
  const points=(history||[]).filter(r=>Number.isFinite(r.score)).map(r=>({score:r.score,time:r.recorded_at}));
  chart.replaceChildren();
  if(points.length<2){message.textContent=points.length===1?'One saved score is available. The trend appears after subsequent changes.':'No historical score data yet.';return}
  message.textContent='Actual saved assessment snapshots. No historical estimates are generated.';
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('viewBox','0 0 620 200');svg.setAttribute('role','img');svg.setAttribute('aria-label','Security score trend across '+points.length+' recorded assessments');
  const positions=points.map((p,i)=>[30+i*560/(points.length-1),170-p.score*1.4]);
  const grid=document.createElementNS(svg.namespaceURI,'path');
  grid.setAttribute('d','M30 30H590 M30 100H590 M30 170H590');grid.setAttribute('stroke','currentColor');grid.setAttribute('opacity','.2');grid.setAttribute('fill','none');svg.append(grid);
  const path=document.createElementNS(svg.namespaceURI,'polyline');
  path.setAttribute('points',positions.map(p=>p.join(',')).join(' '));path.setAttribute('fill','none');path.setAttribute('stroke','#75e0ce');path.setAttribute('stroke-width','3');svg.append(path);
  positions.forEach((p,i)=>{
   const dot=document.createElementNS(svg.namespaceURI,'circle');dot.setAttribute('cx',p[0]);dot.setAttribute('cy',p[1]);dot.setAttribute('r','4');dot.setAttribute('fill','#75e0ce');
   const label=document.createElementNS(svg.namespaceURI,'title');label.textContent=points[i].time+': '+points[i].score+'/100';dot.append(label);svg.append(dot);
  });
  chart.append(svg);
 };
 contentBox.append(heading,chart,message);
 card.append(contentBox);
 card.addEventListener('toggle',()=>{if(printScoreState===null)scorePanelStates.set(key,card.open)});
 root.append(card);
 if(scoreSeries.has(key))renderHistory(scoreSeries.get(key));
 void (async()=>{
  const query='customer_id='+encodeURIComponent(customer.id)+(scope?'&environment_id='+encodeURIComponent(scope):'');
  try{
   const data=await api('customer-score-history?'+query);
   if(!data.ready){message.textContent='Score history storage has not been activated.';return}
   scoreSeries.set(key,data.history||[]);
   renderHistory(data.history||[]);
   const payload={customer_id:customer.id,environment_id:scope,method_version:assessment.version,score:assessment.score,confidence:assessment.confidence,coverage:assessment.coverage,breakdown:assessment.parts,metrics:{total_assets:assessment.total_assets,plugin_assets:assessment.plugin_assets,checked_plugins:assessment.checked_plugins,candidates:assessment.candidates,open_candidates:assessment.open_candidates}};
   const response=await fetch('https://api.cveharbor.com/v1/customer-score-history',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
   if(response.ok){const fresh=await api('customer-score-history?'+query);if(fresh.ready){scoreSeries.set(key,fresh.history||[]);renderHistory(fresh.history||[])}}
  }catch(_){message.textContent='Score history could not be loaded. Current assessment is still available.'}
 })();
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
 renderScorePanel(root,customer,env,stats);
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
  const monitor=table(['Plugin','Installed version','Status','Latest available','Update status','Last check','Coverage','Potential CVEs','Vendor URL'],
   pluginAssets.map(a=>{
    const check=pluginMonitorRows[a.id];
    const release=check?.release;
    const validRelease=release?.installed_version===a.version&&release.release_status==='verified';
    return [a.technology.slice('WordPress Plugin: '.length),a.version||'Unknown',pluginInstallationStatuses.get(a.id)||'Not recorded',
     validRelease?release.latest_version:'Not verified',validRelease?release.update_status:(release?.reason?'Unknown: '+release.reason.slice(0,90):'Unknown'),
     check?.checked_at?new Date(check.checked_at*1000).toISOString().replace('T',' ').slice(0,16)+' UTC':'Not checked',
     pluginChecks[a.id]==='checked'?'Checked':pluginChecks[a.id]==='pending'?'Pending':'Vendor support status unknown',
     check?.status==='checked'?String(check.findings?.length||0):'Unknown',''];
   }));
  for(const [index,asset] of pluginAssets.entries()){
   const check=pluginMonitorRows[asset.id],release=check?.release;
   const statusCell=monitor.tBodies[0].rows[index].cells[2];
   const statusSelect=document.createElement('select');
   statusSelect.className='customer-finding-status-select';
   statusSelect.setAttribute('aria-label','WordPress installation status for '+asset.technology);
   for(const value of ['Not recorded','Active','Inactive','Network active','Inactive, listing closed'])option(statusSelect,value,value);
   statusSelect.value=pluginInstallationStatuses.get(asset.id)||'Not recorded';
   statusSelect.disabled=!pluginInstallationReady;
   statusSelect.addEventListener('change',async()=>{
    const value=statusSelect.value;
    statusSelect.disabled=true;
    try{
     if(value==='Not recorded')throw Error('Choose a status');
     const response=await fetch('https://api.cveharbor.com/v1/plugin-installation-status/'+encodeURIComponent(asset.id),{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:value})});
     if(!response.ok)throw Error((await response.json()).error||'Save failed');
     pluginInstallationStatuses.set(asset.id,value);
    }catch(error){statusSelect.value=pluginInstallationStatuses.get(asset.id)||'Not recorded';window.alert(error.message)}finally{statusSelect.disabled=!pluginInstallationReady}
   });
   statusCell.replaceChildren(statusSelect);
   const updateCell=monitor.tBodies[0].rows[index].cells[4];
   if(release?.release_status==='verified'&&release.update_status==='Update Available'){
    const marker=text('span','● Update Available','customer-update-indicator');
    marker.setAttribute('role','status');
    updateCell.replaceChildren(marker);
   }
   const cell=monitor.tBodies[0].rows[index].cells[8];
   const wrap=text('div','','customer-source-editor');
   const input=document.createElement('input');
   input.type='url';input.placeholder='https://vendor.example/plugin';
   input.setAttribute('aria-label','Official plugin URL for '+asset.technology);
   const saved=pluginSources.get(asset.id);
   input.value=saved?.vendor_url||'';
   input.disabled=!pluginSourceReady;
   const save=text('button','Save URL','customer-ticket-save');save.type='button';save.disabled=!pluginSourceReady;
   const info=text('small',pluginSourceReady?'':'Activate source storage to edit URLs','ops-note');
   save.addEventListener('click',()=>void saveReportPluginSource(asset,input,info));
   const url=saved?.release_url||saved?.vendor_url||release?.release_source||'';
   wrap.append(input,save);
   if(url.startsWith('https://')){
    const external=link(url,'Plugin page / releases');
    wrap.append(external);
   }
   wrap.append(info);
   cell.append(wrap);
  }
  monitor.classList.add('customer-plugin-monitor-table');
  const heading=reportSection('WordPress Plugin Monitoring');
  root.append(heading);
  const controls=text('div','','customer-plugin-monitor-actions');
  const run=text('button','Check plugins now','ops-download');run.type='button';
  const feedback=text('span','','ops-note');
  run.addEventListener('click',async()=>{
   run.disabled=true;
   let completed=0,failed=0;
   feedback.textContent='Starting plugin checks…';
   for(let k=0;k<pluginAssets.length;k+=3){
    const batch=pluginAssets.slice(k,k+3);
    try{
     const r=await fetch('https://api.cveharbor.com/v1/plugin-monitor/refresh-batch',{
      method:'POST',credentials:'include',headers:{'Content-Type':'application/json',Accept:'application/json'},
      body:JSON.stringify({asset_ids:batch.map(a=>a.id)})});
     const result=await r.json().catch(()=>({}));
     if(!r.ok)throw Error(result.error||'Monitoring service unavailable');
     completed+=(result.results||[]).filter(x=>x.status==='checked'||x.status==='recent').length;
     failed+=(result.results||[]).filter(x=>x.status!=='checked'&&x.status!=='recent').length;
    }catch(_){failed+=batch.length}
    feedback.textContent='Processed '+Math.min(k+batch.length,pluginAssets.length)+' of '+pluginAssets.length+' plugins';
   }
   await refreshPluginFindings();
   // The report has been redrawn; surface a durable status in the new section.
   const message=document.querySelector('.customer-plugin-monitor-message');
   if(message)message.textContent='Checks completed: '+completed+' checked or recently checked; '+failed+' unavailable or unverified. Review individual coverage results.';
  });
  controls.append(run,feedback);
  const message=text('p','','ops-note customer-plugin-monitor-message');
  root.append(controls,message,monitor);
 }
 root.append(reportSection('CVE Findings'));
 root.append(findingStatusControls(stats.issues));
 const filtered=stats.issues.filter(i=>findingStatusFilter==='All'||findingStatusFilter==='Unresolved'&&!closedStatus(statusFor(i))||statusFor(i)===findingStatusFilter);
 const compact=sortFindings(filtered).slice(0,250);
 const findingsTable=table(['CVE','Published','Severity','Software / Asset','Vulnerability summary','Vulnerability Fix Status','DevOps Ticket #'],
  compact.map(i=>[
   i.id,i.published||'Not available',i.severity,
   i.technology+' '+(i.version||'Unknown')+' · '+(i.asset?.name||'Asset'),
   shortSummary(i),'',''
  ]));
 findingsTable.classList.add('customer-vulnerability-table');
 enableFindingSort(findingsTable);
 for(const [index,i] of compact.entries()){
  const cell=findingsTable.tBodies[0].rows[index].cells[5];
  const select=text('select','','customer-finding-status-select');
  select.setAttribute('aria-label','Fix status for '+i.id+' on '+(i.asset?.name||'asset'));
  for(const optionValue of statusOptions)option(select,optionValue,optionValue);
  select.value=statusFor(i);select.disabled=!findingStatusReady;
  select.addEventListener('change',()=>void saveFindingStatus(i,select.value,select));
  cell.append(select);
  const ticketCell=findingsTable.tBodies[0].rows[index].cells[6];
  const ticketWrap=text('div','','customer-ticket-controls');
  const input=document.createElement('input');
  input.type='text';input.maxLength=64;input.placeholder='Ticket number';
  input.className='customer-ticket-input';
  input.setAttribute('aria-label','DevOps ticket number for '+i.id+' on '+(i.asset?.name||'asset'));
  const existing=ticketFor(i);
  const history=text('div','','customer-ticket-history');
  for(const value of existing)history.append(text('span',value,'customer-ticket-reference'));
  input.value='';
  input.disabled=!ticketAppendReady;
  const save=text('button','Add ticket','customer-ticket-save');
  save.type='button';save.disabled=!ticketAppendReady;
  save.addEventListener('click',()=>void saveFindingTicket(i,input,save));
  ticketWrap.append(history,input,save);ticketCell.append(ticketWrap);
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
 collapseReportSections(root);
}
function csvReport(){
 const id=$('customerDashFilter').value,env=$('customerDashEnvironment').value;
 const customer=inventory.customers.find(c=>c.id===id);if(!customer)return;
 const rows=[['Customer','Environment','Asset','Technology','Installed version','CVE','Severity','CISA KEV','Match classification','Published','Summary','Vulnerability Fix Status','DevOps Ticket #','Affected versions','Version comparison','Remediation','Source']];
 for(const f of compute(id,env).issues)
  rows.push([customer.name,f.environment?.name||'',f.asset?.name||'',f.technology,f.version,f.id,f.severity,f.known_exploited?'Yes':'No',f.level,f.published||'Not available',shortSummary(f),statusFor(f),ticketFor(f).join(' | '),f.affected||'',f.comparison_detail||'',f.remediation||'',f.source_url]);
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
   const tickets=await api('finding-tickets').catch(()=>({ready:false,tickets:[]}));
   ticketReady=!!tickets.ready;
   ticketAppendReady=!!tickets.append_ready;
   findingTickets=new Map();
   for(const t of tickets.tickets||[]){const k=t.asset_id+'|'+t.cve_id;findingTickets.set(k,[...(findingTickets.get(k)||[]),t.ticket_number])}
   const installed=await api('plugin-installation-status').catch(()=>({ready:false,statuses:[]}));
   pluginInstallationReady=!!installed.ready;
   pluginInstallationStatuses=new Map((installed.statuses||[]).map(row=>[row.asset_id,row.status]));
   const sources=await api('plugin-sources').catch(()=>({ready:false,sources:[]}));
   pluginSourceReady=!!sources.ready;
   pluginSources=new Map((sources.sources||[]).map(s=>[s.asset_id,s]));
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
   window.addEventListener('beforeprint',()=>setReportPrintMode(true));
   window.addEventListener('afterprint',()=>setReportPrintMode(false));
   $('customerReportPrint').addEventListener('click',()=>window.print());
   $('customerReportCsv').addEventListener('click',csvReport);
  }
  $('customerDashStatus').textContent=inventory.customers.length+' customer records loaded privately. Advisory matching is preliminary.';
  void refreshPluginFindings();
 }catch(e){$('customerDashLogin').hidden=false;$('customerDashStatus').textContent=(e.status===404||e.status===503)?'Customer inventory backend is not active. The D1 migration and updated Cloudflare Worker must be deployed.':'Could not reach account data. Please sign in or check the service. '+e.message}
}
void init();
})();