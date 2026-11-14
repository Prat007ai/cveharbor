const origin='https://api.cveharbor.com/v1/agents';
const el=(tag,text='',cls='')=>{const e=document.createElement(tag);e.textContent=text;e.className=cls;return e;};
const button=(label,fn)=>{const b=el('button',label);b.type='button';b.onclick=fn;return b;};
const stamp=n=>n?new Date(n*1000).toLocaleString():'Not yet received';
const roleNames=['Web','Database','Application','Active Directory','File','Print','Remote Desktop','Other'];
export function mountAgents(host,{scope,afterImport=async()=>{},onChange=()=>{},setup=true}={}){
 if(!document.querySelector('link[href="/agent-ui.css"]')){const css=document.createElement('link');css.rel='stylesheet';css.href='/agent-ui.css';document.head.append(css);}
 const panel=el('section','','agent-panel'),heading=el('h3',setup?'Connect Windows Agent':'Windows agent connections'),status=el('p','Choose a customer and environment to connect servers.'),actions=el('div','','agent-actions'),enrollment=el('div'),cards=el('div','','agent-cards');status.setAttribute('role','status');
 panel.append(heading,el('p','Install once on each server. Review its first inventory here, then keep software versions current with daily synchronization.'),status,actions,enrollment,cards);host.append(panel);
 let current='',generation=0,controller=null,timer,loading=false,rights={},fingerprint='',disposed=false;
 const expanded=new Set(),cache=new Map();
 const key=()=>JSON.stringify(scope());
 async function call(suffix='',method='GET',body,expected=generation){
  const target=scope(),query=new URLSearchParams({customer_id:target.customer||'',environment_id:target.environment||'',...(target.org?{org:target.org}:{})});
  const r=await fetch(origin+suffix+'?'+query,{method,credentials:'include',cache:'no-store',signal:controller.signal,headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});
  const data=await r.json();if(expected!==generation||key()!==current)throw new DOMException('Scope changed','AbortError');
  if(!r.ok)throw Error(data.error||'Unable to contact the agent service');return data;
 }
 async function perform(fn){try{await fn();await refresh(true);}catch(e){if(e.name!=='AbortError')status.textContent=e.message;}}
 function tools(data){
  actions.replaceChildren();
  if(data.installer&&data.can_edit){const a=el('a','Download Windows Agent installer');a.href=data.installer.url;a.className='ops-download';actions.append(a);
   const evaluation=data.installer.channel==='evaluation',consent=el('input');consent.type='checkbox';
   if(evaluation){const label=el('label','I understand this unsigned build is for testing and demos; Windows may show an unrecognized-app warning.');label.prepend(consent);actions.append(label);}
   const create=button('Create enrollment code',()=>perform(async()=>{const result=await call('/enrollment','POST',{evaluation_accepted:consent.checked});enrollment.replaceChildren();const label=el('label','One-time enrollment code — expires '+stamp(result.expires_at));const code=el('input');code.value=result.code;code.readOnly=true;code.autocomplete='off';label.append(code);enrollment.append(label,el('p','Enter this code in CVEHarbor Agent Setup on the target server. Each device needs its own code. Treat it as a temporary credential.'));}));create.disabled=evaluation;consent.onchange=()=>{create.disabled=evaluation&&!consent.checked;};actions.append(create);
  }else if(data.can_edit)actions.append(el('p','The Windows installer is not released yet. Enrollment will be available when it is ready.'));
  if(data.can_admin)actions.append(button('Security email contacts',()=>perform(async()=>{
   const saved=await call('/contacts');enrollment.replaceChildren();const label=el('label','Customer security contacts (comma separated)'),input=el('input');input.type='text';input.value=saved.contacts.map(r=>r.email).join(', ');label.append(input);
   enrollment.append(label,el('p','If empty, alerts go to the organization owner or account owner. CVEHarbor support receives a separate notification.'),button('Save contacts',()=>perform(async()=>{await call('/contacts','POST',{emails:input.value.split(',').map(x=>x.trim()).filter(Boolean)});enrollment.replaceChildren();status.textContent='Security contacts saved.';})));
  })));
 }
 async function detail(card,d,body){
  const gen=generation,result=await call('/'+d.id);if(gen!==generation||!card.isConnected)return;
  cache.set(d.id,result);body.replaceChildren();const snap=result.snapshot,device=result.device;
  if(!snap){body.append(el('p','Waiting for the first collection.'));return;}
  if(!snap.complete)body.append(el('p','Collection incomplete. Previously observed software will be retained.','agent-warning'));
  for(const warning of snap.warnings)body.append(el('p',warning,'agent-warning'));
  body.append(el('p','Collected '+new Date(snap.collected_at).toLocaleString()+'. Machine-wide software is collected; other users, portable apps and bundled runtimes may be absent.'));
  const table=el('table'),head=el('thead'),tr=el('tr');for(const name of ['Installed software','Version'])tr.append(el('th',name));head.append(tr);const tbody=el('tbody');table.append(head,tbody);body.append(table);
  const paging=el('div','','agent-actions'),count=el('span');let page=0;
  const previous=button('Previous software',()=>{page--;draw();}),next=button('Next software',()=>{page++;draw();});paging.append(previous,count,next);body.append(paging);
  function draw(){tbody.replaceChildren();for(const p of snap.products.slice(page*50,page*50+50)){const row=el('tr');row.append(el('td',p.name),el('td',p.version||'Version unknown'));tbody.append(row);}count.textContent=(page*50+1)+'–'+Math.min(page*50+50,snap.products.length)+' of '+snap.products.length;previous.disabled=page===0;next.disabled=page*50+50>=snap.products.length;paging.hidden=snap.products.length<=50;}draw();
  if(rights.can_edit){
   const settings=el('details'),summary=el('summary','Server role, primary IP and daily synchronization');settings.append(summary);
   const roleBox=el('div','','agent-roles'),chosen=JSON.parse(device.roles);
   const checks=roleNames.map(r=>{const label=el('label',r),input=el('input');input.type='checkbox';input.checked=chosen.includes(r);label.prepend(input);roleBox.append(label);return {r,input};});settings.append(roleBox);
   const ipLabel=el('label','Primary IP address'),ip=el('select');ip.append(new Option('Primary IP not selected',''));
   for(const adapter of snap.network?.adapters||[])for(const address of adapter.addresses)ip.append(new Option(adapter.name+' — '+address.ip,JSON.stringify([adapter.id,address.ip])));
   const selected=JSON.stringify([device.primary_adapter,device.primary_ip]);if([...ip.options].some(o=>o.value===selected))ip.value=selected;else if(device.primary_ip)settings.append(el('p','The previously selected primary IP is absent from this collection. Select a current address.','agent-warning'));
   ipLabel.append(ip);settings.append(ipLabel);const dailyLabel=el('label','Enable daily inventory synchronization'),daily=el('input');daily.type='checkbox';daily.checked=!!device.daily;dailyLabel.prepend(daily);settings.append(dailyLabel);
   settings.append(button('Save device settings',()=>perform(async()=>{const [adapter,address]=ip.value?JSON.parse(ip.value):['',''];await call('/'+d.id+'/settings','POST',{revision:device.revision,roles:checks.filter(x=>x.input.checked).map(x=>x.r),primary_ip:address,primary_adapter:adapter,daily:daily.checked});cache.delete(d.id);})));body.append(settings);
  }
  if(device.state==='review'&&rights.can_edit){const label=el('label','I reviewed this server and its customer/environment assignment, and enable daily synchronization.'),consent=el('input');consent.type='checkbox';label.prepend(consent);const confirm=button('Confirm inventory and assess',()=>perform(async()=>{
   if(!consent.checked)return;await call('/'+d.id+'/confirm','POST',{revision:device.revision,pending_hash:result.pending_hash,daily:true});await afterImport({...scope()});onChange();window.dispatchEvent(new Event('cveharbor-agent-inventory-changed'));
  }));confirm.disabled=true;consent.onchange=()=>{confirm.disabled=!consent.checked;};body.append(label,confirm);}
  if(device.state==='active'){const link=el('a','View vulnerability assessment');link.href='/customer-dashboard/?'+new URLSearchParams({customer:scope().customer,environment:scope().environment,...(scope().org?{org:scope().org}:{})});body.append(link);}
 }
 function render(data){
  const previous=new Map([...cards.querySelectorAll('[data-agent-id]')].map(c=>[c.dataset.agentId,c]));
  for(const d of data.devices){
   const signature=JSON.stringify(d);let card=previous.get(d.id);previous.delete(d.id);if(card?.dataset.signature===signature)continue;
   const open=card?.open||expanded.has(d.id),replacement=el('details','','agent-card');replacement.dataset.agentId=d.id;replacement.dataset.signature=signature;
   const offline=!d.last_seen||Date.now()/1000-d.last_seen>900,label=d.state==='suspended'?'Uploads suspended — review required':d.state==='revoked'?'Revoked':offline?'Offline / waiting for connection':d.state==='review'?'First inventory review required':'Connected';
   const summary=el('summary');summary.append(el('strong',d.hostname),el('span',d.primary_ip||'Primary IP not selected'),el('span',label));replacement.append(summary,el('p',(d.software_count||0)+' software entries · Last accepted sync: '+stamp(d.last_sync)+' · Daily sync '+(d.daily?'enabled':'disabled')));
   if(d.requested>d.completed_request)replacement.append(el('p',offline?'Sync pending — waiting for this device to reconnect.':'Collection requested — waiting for the agent.'));
   const controls=el('div','','agent-actions');
   if(rights.can_edit){const sync=button('Sync now',()=>perform(async()=>{await call('/'+d.id+'/sync','POST',{revision:d.revision});}));sync.disabled=!['active','review'].includes(d.state)||d.requested>d.completed_request;controls.append(sync);}
   controls.append(button('View history',()=>perform(async()=>{const h=await call('/'+d.id+'/history');extra.replaceChildren(el('h4','Accepted inventory history'));for(const entry of h.entries){const c=JSON.parse(entry.changes);extra.append(el('p',stamp(entry.received_at)+' — '+c.added.length+' added, '+c.removed.length+' no longer observed'+(c.incomplete?' (incomplete collection)':'')));for(const p of c.added)extra.append(el('p','Added: '+p.name+' '+p.version));for(const p of c.removed)extra.append(el('p','No longer observed: '+p.name+' '+p.version));}})));
   const extra=el('div'),body=el('div');
   if(d.state==='suspended')controls.append(button('Review incident',()=>perform(async()=>{const r=await call('/'+d.id+'/incident');extra.replaceChildren();for(const incident of r.incidents.filter(i=>!i.resolved_at))extra.append(el('p',incident.reason,'agent-warning'));extra.append(el('p','Alert delivery: '+r.notifications.map(n=>n.state).join(', ')));
    if(rights.can_admin){const label=el('label','Investigation and reason for resuming'),reason=el('textarea');label.append(reason);const safeLabel=el('label','I investigated the device and confirmed its credential is safe to reuse.'),safe=el('input');safe.type='checkbox';safeLabel.prepend(safe);const changeLabel=el('label','Allow the next collection to remove more than half the software (only after verified maintenance).'),change=el('input');change.type='checkbox';changeLabel.prepend(change);extra.append(label,safeLabel,changeLabel,button('Resume after review',()=>perform(async()=>{await call('/'+d.id+'/resume','POST',{revision:d.revision,reason:reason.value,credential_safe:safe.checked,approve_large_change:change.checked});})));}
   })));
   if(rights.can_admin&&d.state!=='revoked')controls.append(button('Revoke device',()=>perform(async()=>{if(!window.confirm('Stop this device’s access? Its saved inventory and history will remain.'))return;await call('/'+d.id+'/revoke','POST',{revision:d.revision});})));
   if(rights.can_admin&&d.state==='revoked')controls.append(button('Reconnect this device',()=>{
    extra.replaceChildren(el('p','After checking and repairing this server, create a replacement enrollment code. Its saved history and device identity will be retained.'));
    const label=el('label','I understand this installer is unsigned and for testing and demos.'),consent=el('input');consent.type='checkbox';label.prepend(consent);
    const reconnect=button('Create replacement code',()=>perform(async()=>{const r=await call('/'+d.id+'/enrollment','POST',{revision:d.revision,evaluation_accepted:consent.checked});extra.replaceChildren();const l=el('label','Replacement code � expires '+stamp(r.expires_at)),input=el('input');input.readOnly=true;input.autocomplete='off';input.value=r.code;l.append(input);extra.append(l,el('p','Open CVEHarbor Agent Setup on this device and enter this code. Review its first inventory here again.'));}));reconnect.disabled=true;consent.onchange=()=>{reconnect.disabled=!consent.checked;};extra.append(label,reconnect);
   }));
   replacement.append(controls,extra,body);replacement.open=open;
   replacement.addEventListener('toggle',()=>{if(replacement.open){expanded.add(d.id);if(!body.childNodes.length)void perform(()=>detail(replacement,d,body));}else expanded.delete(d.id);});
   if(card)card.replaceWith(replacement);else cards.append(replacement);if(open)void detail(replacement,d,body).catch(e=>{if(e.name!=='AbortError')body.textContent=e.message;});
  }
  for(const card of previous.values())card.remove();
 }
 async function refresh(force=false){
  if(disposed||!host.isConnected){dispose();return;}if(document.hidden&&!force)return;
  const next=key();if(next!==current){generation++;current=next;controller?.abort();controller=new AbortController();cards.replaceChildren();enrollment.replaceChildren();actions.replaceChildren();cache.clear();expanded.clear();fingerprint='';loading=false;}
  const target=scope();if(!target.customer||!target.environment){status.textContent='Choose a customer and environment to connect servers.';return;}if(loading)return;loading=true;const gen=generation;
  try{const data=await call();if(gen!==generation)return;rights=data;if(force||!actions.childNodes.length)tools(data);render(data);status.textContent=data.devices.length?data.devices.length+' connected device records. Expand a server to review installed software.':'Waiting for your first Windows Agent connection.';
   const nextFingerprint=JSON.stringify(data.devices.map(d=>[d.id,d.last_sync,d.state]));if(fingerprint&&fingerprint!==nextFingerprint){onChange();window.dispatchEvent(new Event('cveharbor-agent-inventory-changed'));}fingerprint=nextFingerprint;
  }catch(e){if(e.name!=='AbortError'&&gen===generation)status.textContent=e.message;}finally{if(gen===generation)loading=false;}
 }
 const scopeChanged=()=>{if(key()!==current)void refresh(true);};
 const authChanged=event=>{if(!event.detail?.authenticated){dispose();panel.replaceChildren(el('p','Sign in to view agent connections.'));}};
 function dispose(){disposed=true;clearInterval(timer);controller?.abort();document.removeEventListener('visibilitychange',visible);document.removeEventListener('change',scopeChanged);for(const name of ['cveharbor:account-state','cveharbor-auth-change'])window.removeEventListener(name,authChanged);}
 const visible=()=>{if(!document.hidden)void refresh();};document.addEventListener('visibilitychange',visible);document.addEventListener('change',scopeChanged);for(const name of ['cveharbor:account-state','cveharbor-auth-change'])window.addEventListener(name,authChanged);timer=setInterval(()=>void refresh(),10000);void refresh();return {refresh,dispose};
}
