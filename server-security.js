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
  const key=JSON.stringify([environment?.customer_id||asset.customer_id||'',asset.environment_id||asset.id,asset.agent_device_id||normalize(asset.name)||asset.id]);
  if(!groups.has(key))groups.set(key,{key,name:asset.name||'Unnamed asset',customer:clients.get(environment?.customer_id)?.name||'',environment:environment?.name||asset.environment||'Environment not recorded',assets:[],issues:[],roles:new Set(),roleSets:new Set()});
  const server=groups.get(key);server.assets.push(asset);byAsset.set(asset.id,server);
  const values=recordedRoles(asset);for(const value of values)server.roles.add(value);
  if(values.length)server.roleSets.add([...values].sort().join(' / '));
 }
 for(const issue of issues){const server=byAsset.get(issue.asset_id||issue.asset?.id);if(server)server.issues.push(issue);}
 return [...groups.values()].map(s=>({...s,roles:[...s.roles].sort(),role:[...s.roles].sort().join(' / ')||'Not recorded',roleConflict:s.roleSets.size>1})).sort((a,b)=>a.name.localeCompare(b.name)||a.environment.localeCompare(b.environment));
}
function node(tag,value='',className=''){const n=document.createElement(tag);n.textContent=value;if(className)n.className=className;return n;}
function render(host,data,{findingLink,loadNetworks,savePrimary}={}){
 const token={};host.networkToken=token;let networks=[],networkError='',networkLoading=!!loadNetworks;
 const expanded=host.expandedServers||(host.expandedServers=new Set());
 const servers=group(data),priorSearch=host.querySelector('[data-server-search]')?.value||'',priorRole=host.querySelector('[data-server-role]')?.value||'';
 host.replaceChildren();host.classList.add('server-security');
 const heading=node('div','','server-heading');heading.append(node('h2','Security by server'),node('p','See installed software and potential vulnerability matches for each hostname or asset. Matches require verification; no matches does not establish that a server is secure.'));
 const controls=node('div','','server-controls'),searchLabel=node('label','Find a hostname, asset or IP'),search=node('input');search.type='search';search.setAttribute('aria-label','Find a hostname or asset');search.placeholder='For example, WEB01 or 192.0.2.10';search.dataset.serverSearch='';search.value=priorSearch;searchLabel.append(search);
 const roleLabel=node('label','Server role'),roleSelect=node('select');roleSelect.dataset.serverRole='';roleSelect.setAttribute('aria-label','Server role');roleSelect.append(new Option('All roles',''));
 for(const value of [...new Set(servers.flatMap(s=>s.roles.length?s.roles:['Not recorded']))].sort())roleSelect.append(new Option(value,value));
 if([...roleSelect.options].some(o=>o.value===priorRole))roleSelect.value=priorRole;
 roleLabel.append(roleSelect);controls.append(searchLabel,roleLabel);
 const count=node('p','','server-count');count.setAttribute('role','status');
 const list=node('div','','server-list'),pager=node('div','','server-pages'),previous=node('button','Previous servers'),next=node('button','Next servers');previous.type=next.type='button';pager.append(previous,next);
 host.append(heading);if(data.limited)host.append(node('p','The assessment reached its result limit. Narrow the customer or environment selection to review additional matches.','server-warning'));host.append(controls,count,list,pager);let page=0;
 const networkFor=server=>networks.find(n=>n.environment_id===server.assets[0].environment_id&&n.server_key===normalize(server.name));
 function draw(){
  const matches=servers.filter(s=>(!search.value||normalize(s.name).includes(normalize(search.value))||s.assets.some(a=>normalize(a.agent_primary_ip||'').includes(normalize(search.value)))||networkFor(s)?.snapshot.adapters.some(a=>a.addresses.some(p=>normalize(p.ip).includes(normalize(search.value)))))&&(!roleSelect.value||(s.roles.length?s.roles:['Not recorded']).includes(roleSelect.value)));
  page=Math.min(page,Math.max(0,Math.ceil(matches.length/12)-1));list.replaceChildren();
  count.textContent=matches.length+' of '+servers.length+' servers / named assets'+(matches.length?' · Showing '+(page*12+1)+'–'+Math.min((page+1)*12,matches.length):'');
  if(!matches.length)list.append(node('p',servers.length?'No servers match these filters.':'No inventory is recorded for this selection.'));
  for(const server of matches.slice(page*12,(page+1)*12)){
   const card=node('article','','server-card'),top=node('div','','server-card-heading'),identity=node('div');
   identity.append(node('span','HOSTNAME / ASSET','server-eyebrow'),node('h3',server.name),node('p',[server.customer,server.environment].filter(Boolean).join(' · '),'server-context'));
   top.append(identity,node('span','Server role: '+server.role,'server-role'));card.append(top);
   if(server.assets[0].agent_device_id){
    const a=server.assets[0];card.append(node('p','Primary IP: '+(a.agent_primary_ip||'Not selected'),'server-primary'));
    card.append(node('p','Agent: '+a.agent_state+' · Last accepted sync: '+(a.agent_last_sync?new Date(a.agent_last_sync*1000).toLocaleString():'Awaiting review'),'server-help'));
   }else networkPanel(card,server,networkFor(server));
   if(server.roleConflict)card.append(node('p','Conflicting role records — review the Notes on this server’s software entries.','server-warning'));
   if(!server.roles.length)card.append(node('p','Role not recorded. Set -ServerRole in the collector, or add “Server role: Web;” at the start of each software entry’s Notes.','server-help'));
   const cves=new Set(server.issues.map(i=>i.id));
   const details=node('details'),summary=node('summary',server.assets.length+' software entries · '+cves.size+' candidate CVEs · '+server.issues.length+' product matches');
   details.open=expanded.has(server.key)||matches.length===1;details.append(summary);
   details.addEventListener('toggle',()=>{if(details.open)expanded.add(server.key);else expanded.delete(server.key);});
   const body=node('div','','server-detail-body');details.addEventListener('toggle',()=>{if(details.open&&!body.childNodes.length)populate();});
   function populate(){
    body.append(node('h4','Potential vulnerability matches'));
    if(!server.issues.length)body.append(node('p','No matches in the loaded assessment. Check product mapping, versions and source coverage before drawing conclusions.'));
    else{
     const rows=server.issues.slice(0,100).map(f=>{const a=server.assets.find(a=>a.id===(f.asset_id||f.asset?.id));let reference=node('span','Source unavailable');
      try{if(new URL(f.source_url).protocol==='https:'){reference=node('a','Advisory');reference.href=f.source_url;reference.target='_blank';reference.rel='noopener noreferrer';}}catch{}
      const state=root.CVEHARBOR_INVENTORY_MATCH?.applicability(f)||{label:'Needs verification',reason:'Review original advisory.'};
      return [findingLink?findingLink(f):f.id,a?.technology||f.technology,a?.version||'Unknown',f.severity||'Unknown',state.label,state.reason+' '+(f.evidence||''),reference];});
     body.append(grid(['CVE','Product','Installed version','Severity','Assessment','Evidence','Source'],rows));
     if(server.issues.length>100)body.append(node('p','Showing the first 100 product matches for this server. Use the full vulnerability list below to continue review.'));
    }
    body.append(node('h4','Installed software'),grid(['Product','Installed version','Recorded role'],server.assets.map(a=>[a.technology,a.version||'Unknown',role(a)])));
   }
   details.append(body);if(details.open)populate();card.append(details);list.append(card);
  }
  previous.disabled=page===0;next.disabled=(page+1)*12>=matches.length;pager.hidden=matches.length<=12;
 }
 function networkPanel(card,server,record){
  if(!record){card.append(node('p',networkLoading?'Loading network inventory…':networkError||'IP addresses not recorded. Import a new collector CSV to add them.','server-help'));return;}
  const snapshot=record.snapshot,chosen=record.primary_ip?{adapter_id:record.primary_adapter,ip:record.primary_ip}:snapshot.suggested;
  const adapter=snapshot.adapters.find(a=>a.id===chosen?.adapter_id),present=adapter?.addresses.some(p=>p.ip===chosen.ip);
  const status=node('p',chosen?(record.primary_ip?'Primary IP: ':'Suggested primary IP: ')+chosen.ip+' · '+(adapter?.name||'Adapter no longer recorded'):'Primary IP not selected','server-primary-ip');card.append(status);
  if(chosen&&!present)card.append(node('p','The saved primary IP is absent from this collection. Review the adapters and choose a current address.','server-warning'));
  const detail=node('details','','server-network'),summary=node('summary','Network adapters & additional IPs ('+snapshot.adapters.length+' adapters)');detail.append(summary);
  detail.append(node('p','Collected '+new Date(snapshot.collected_at).toLocaleString()+'. Addresses may have changed since collection.','server-help'));
  const radios=[],group='primary-'+Math.random().toString(36).slice(2);let selected=chosen;
  for(const a of snapshot.adapters){
   const section=node('section','','server-adapter');section.append(node('h4',a.name+' · '+a.status));
   if(!a.addresses.length)section.append(node('p','No IP addresses recorded.'));
   for(const p of a.addresses){
    const label=node('label','','server-ip-option');
    if(savePrimary){const radio=node('input');radio.type='radio';radio.name=group;radio.checked=a.id===chosen?.adapter_id&&p.ip===chosen?.ip;radio.setAttribute('aria-label',a.name+' '+p.ip);radio.onchange=()=>{selected={adapter_id:a.id,ip:p.ip};};radios.push(radio);label.append(radio);}
    label.append(node('span',p.ip+'/'+p.prefix+' · '+p.family+' · '+p.state+(p.skip_source?' · Not preferred as source':'')));section.append(label);
   }
   detail.append(section);
  }
  if(savePrimary){const button=node('button','Save primary adapter & IP'),feedback=node('p');button.type='button';feedback.setAttribute('role','status');
   button.onclick=async()=>{
    if(!selected||!snapshot.adapters.some(a=>a.id===selected.adapter_id&&a.addresses.some(p=>p.ip===selected.ip))){feedback.textContent='Select an adapter address first.';return;}
    if(host.networkToken!==token||!card.isConnected)return;
    button.disabled=true;radios.forEach(r=>r.disabled=true);feedback.textContent='Saving…';
    try{const saved=await savePrimary({environment_id:record.environment_id,name:server.name,revision:record.revision,...selected});
     if(host.networkToken!==token||!card.isConnected)return;Object.assign(record,saved);status.textContent='Primary IP: '+saved.primary_ip+' · '+snapshot.adapters.find(a=>a.id===saved.primary_adapter)?.name;feedback.textContent='Primary adapter and IP saved for this server.';
    }catch(e){feedback.textContent=e.message+' Refresh the assessment before retrying.';return;}
    button.disabled=false;radios.forEach(r=>r.disabled=false);
   };detail.append(button,feedback);
  }else detail.append(node('p','An Owner or Editor can change the primary adapter and IP.','server-help'));
  card.append(detail);
 }
 search.oninput=roleSelect.onchange=()=>{page=0;draw();};previous.onclick=()=>{page--;draw();};next.onclick=()=>{page++;draw();};draw();
 if(loadNetworks)Promise.resolve().then(loadNetworks).then(result=>{if(host.networkToken!==token||!heading.isConnected)return;networks=result.networks||[];networkLoading=false;draw();}).catch(()=>{if(host.networkToken!==token||!heading.isConnected)return;networkLoading=false;networkError='Network inventory unavailable. Refresh to check your access and connection.';draw();});
}
function grid(headers,rows){const wrap=node('div','','server-table-scroll');wrap.tabIndex=0;wrap.setAttribute('role','region');wrap.setAttribute('aria-label',headers[0]==='CVE'?'Server vulnerability matches':'Server installed software');const table=node('table'),head=node('thead'),tr=node('tr');for(const h of headers){const th=node('th',h);th.scope='col';tr.append(th);}head.append(tr);const body=node('tbody');for(const row of rows){const tr=node('tr');for(const value of row){const td=node('td');if(value instanceof Node)td.append(value);else td.textContent=String(value??'');tr.append(td);}body.append(tr);}table.append(head,body);wrap.append(table);return wrap;}
const api={group,role,render};if(typeof module!=='undefined'&&module.exports)module.exports=api;else root.CVEHARBOR_SERVER_SECURITY=api;
})(typeof window==='undefined'?globalThis:window);
