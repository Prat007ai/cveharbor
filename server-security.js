// Read-only server view of the inventory and matching evidence already in this workspace.
(function(root){
'use strict';
const normalize=value=>String(value||'').trim().toLowerCase();
const roles=new Map(['Web','Database','Application','Active Directory','File','Print','Remote Desktop','Other'].map(v=>[normalize(v),v]));
function recordedRoles(asset){
 const explicit=String(asset?.notes||'').match(/^Server role:\s*([^;]{1,160})(?:;|$)/i);
 if(explicit)return [...new Set(explicit[1].split(' / ').map(v=>roles.get(normalize(v))).filter(Boolean))];
 const legacy={web:'Web',database:'Database',application:'Application'};
 return legacy[normalize(asset?.asset_type)]?[legacy[normalize(asset.asset_type)]]:[];
}
function role(asset){return recordedRoles(asset).join(' / ')||'Not recorded';}
function group({assets=[],environments=[],customers=[],issues=[]}){
 const envs=new Map(environments.map(e=>[e.id,e])),clients=new Map(customers.map(c=>[c.id,c])),groups=new Map(),byAsset=new Map();
 for(const asset of assets){
  const environment=envs.get(asset.environment_id);
  // Missing scope/name must not collapse unrelated entries into one server.
  const key=JSON.stringify([environment?.customer_id||asset.customer_id||'',asset.environment_id||asset.id,normalize(asset.name)||asset.id]);
  if(!groups.has(key))groups.set(key,{key,name:asset.name||'Unnamed asset',customer:clients.get(environment?.customer_id)?.name||'',environment:environment?.name||asset.environment||'Environment not recorded',assets:[],issues:[],roles:new Set(),roleSets:new Set()});
  const server=groups.get(key);server.assets.push(asset);byAsset.set(asset.id,server);
  const values=recordedRoles(asset);for(const value of values)server.roles.add(value);
  if(values.length)server.roleSets.add([...values].sort().join(' / '));
 }
 for(const issue of issues){const server=byAsset.get(issue.asset_id||issue.asset?.id);if(server)server.issues.push(issue);}
 return [...groups.values()].map(s=>({...s,roles:[...s.roles].sort(),role:[...s.roles].sort().join(' / ')||'Not recorded',roleConflict:s.roleSets.size>1})).sort((a,b)=>a.name.localeCompare(b.name)||a.environment.localeCompare(b.environment));
}
function node(tag,value='',className=''){const n=document.createElement(tag);n.textContent=value;if(className)n.className=className;return n;}
function render(host,data,{findingLink}={}){
 const servers=group(data),priorSearch=host.querySelector('[data-server-search]')?.value||'',priorRole=host.querySelector('[data-server-role]')?.value||'';
 host.replaceChildren();host.classList.add('server-security');
 const heading=node('div','','server-heading');heading.append(node('h2','Security by server'),node('p','See installed software and potential vulnerability matches for each hostname or asset. Matches require verification; no matches does not establish that a server is secure.'));
 const controls=node('div','','server-controls'),searchLabel=node('label','Find a hostname or asset'),search=node('input');search.type='search';search.setAttribute('aria-label','Find a hostname or asset');search.placeholder='For example, WEB01';search.dataset.serverSearch='';search.value=priorSearch;searchLabel.append(search);
 const roleLabel=node('label','Server role'),roleSelect=node('select');roleSelect.dataset.serverRole='';roleSelect.setAttribute('aria-label','Server role');roleSelect.append(new Option('All roles',''));
 for(const value of [...new Set(servers.flatMap(s=>s.roles.length?s.roles:['Not recorded']))].sort())roleSelect.append(new Option(value,value));
 if([...roleSelect.options].some(o=>o.value===priorRole))roleSelect.value=priorRole;
 roleLabel.append(roleSelect);controls.append(searchLabel,roleLabel);
 const count=node('p','','server-count');count.setAttribute('role','status');
 const list=node('div','','server-list'),pager=node('div','','server-pages'),previous=node('button','Previous servers'),next=node('button','Next servers');previous.type=next.type='button';pager.append(previous,next);
 host.append(heading);if(data.limited)host.append(node('p','The assessment reached its result limit. Narrow the customer or environment selection to review additional matches.','server-warning'));host.append(controls,count,list,pager);let page=0;
 function draw(){
  const matches=servers.filter(s=>(!search.value||normalize(s.name).includes(normalize(search.value)))&&(!roleSelect.value||(s.roles.length?s.roles:['Not recorded']).includes(roleSelect.value)));
  page=Math.min(page,Math.max(0,Math.ceil(matches.length/12)-1));list.replaceChildren();
  count.textContent=matches.length+' of '+servers.length+' servers / named assets'+(matches.length?' · Showing '+(page*12+1)+'–'+Math.min((page+1)*12,matches.length):'');
  if(!matches.length)list.append(node('p',servers.length?'No servers match these filters.':'No inventory is recorded for this selection.'));
  for(const server of matches.slice(page*12,(page+1)*12)){
   const card=node('article','','server-card'),top=node('div','','server-card-heading'),identity=node('div');
   identity.append(node('span','HOSTNAME / ASSET','server-eyebrow'),node('h3',server.name),node('p',[server.customer,server.environment].filter(Boolean).join(' · '),'server-context'));
   top.append(identity,node('span','Server role: '+server.role,'server-role'));card.append(top);
   if(server.roleConflict)card.append(node('p','Conflicting role records — review the Notes on this server’s software entries.','server-warning'));
   if(!server.roles.length)card.append(node('p','Role not recorded. Set -ServerRole in the collector, or add “Server role: Web;” at the start of each software entry’s Notes.','server-help'));
   const cves=new Set(server.issues.map(i=>i.id));
   const details=node('details'),summary=node('summary',server.assets.length+' software entries · '+cves.size+' candidate CVEs · '+server.issues.length+' product matches');
   details.open=matches.length===1;details.append(summary);
   const body=node('div','','server-detail-body');details.addEventListener('toggle',()=>{if(details.open&&!body.childNodes.length)populate();});
   function populate(){
    body.append(node('h4','Potential vulnerability matches'));
    if(!server.issues.length)body.append(node('p','No matches in the loaded assessment. Check product mapping, versions and source coverage before drawing conclusions.'));
    else{
     const rows=server.issues.slice(0,100).map(f=>{const a=server.assets.find(a=>a.id===(f.asset_id||f.asset?.id));let reference=node('span','Source unavailable');
      try{if(new URL(f.source_url).protocol==='https:'){reference=node('a','Advisory');reference.href=f.source_url;reference.target='_blank';reference.rel='noopener noreferrer';}}catch{}
      return [findingLink?findingLink(f):f.id,a?.technology||f.technology,a?.version||'Unknown',f.severity||'Unknown',f.level==='version_review'?'Affected-version candidate':'Needs verification',f.evidence||'Review original advisory',reference];});
     body.append(grid(['CVE','Product','Installed version','Severity','Assessment','Evidence','Source'],rows));
     if(server.issues.length>100)body.append(node('p','Showing the first 100 product matches for this server. Use the full vulnerability list below to continue review.'));
    }
    body.append(node('h4','Installed software'),grid(['Product','Installed version','Recorded role'],server.assets.map(a=>[a.technology,a.version||'Unknown',role(a)])));
   }
   details.append(body);if(details.open)populate();card.append(details);list.append(card);
  }
  previous.disabled=page===0;next.disabled=(page+1)*12>=matches.length;pager.hidden=matches.length<=12;
 }
 search.oninput=roleSelect.onchange=()=>{page=0;draw();};previous.onclick=()=>{page--;draw();};next.onclick=()=>{page++;draw();};draw();
}
function grid(headers,rows){const wrap=node('div','','server-table-scroll');wrap.tabIndex=0;wrap.setAttribute('role','region');wrap.setAttribute('aria-label',headers[0]==='CVE'?'Server vulnerability matches':'Server installed software');const table=node('table'),head=node('thead'),tr=node('tr');for(const h of headers){const th=node('th',h);th.scope='col';tr.append(th);}head.append(tr);const body=node('tbody');for(const row of rows){const tr=node('tr');for(const value of row){const td=node('td');if(value instanceof Node)td.append(value);else td.textContent=String(value??'');tr.append(td);}body.append(tr);}table.append(head,body);wrap.append(table);return wrap;}
const api={group,role,render};if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.CVEHARBOR_SERVER_SECURITY=api;
})(typeof window==='undefined'?globalThis:window);
