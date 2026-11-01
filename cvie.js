(function(){
'use strict';
const API='https://api.cveharbor.com/v1/cvie';
let products=[],records=[],months=3,error='',ready=false,signedIn=false,timer=null,busy=false,pending=false,pendingSync=false;
const panels=[];
let lastSignature='';
let evidence={sources:[]},withdrawn=new Set();
let excluded=[],accountId='',accountEmail='',authEpoch=0;
class SessionChanged extends Error{}
const node=(tag,value,cls)=>{const el=document.createElement(tag);if(value)el.textContent=value;if(cls)el.className=cls;return el;};
const normalize=value=>String(value||'').normalize('NFKC').trim().toLowerCase().replace(/\s+/g,' ');
function merge(base=[]){
 const result=new Map();
 const scopes=products.filter(p=>p.component_scope).map(p=>p.name),verified=new Map();
 for(const r of records){if(!verified.has(r.id))verified.set(r.id,new Set());for(const name of r.cvie_products||[])verified.get(r.id).add(normalize(name));}
 for(const record of [...base,...records]){
  if(withdrawn.has(record.id))continue;
  const prior=result.get(record.id);
  if(!prior){result.set(record.id,{...record});continue;}
  const source=new Map([...(prior.sources||[]),...(record.sources||[])].map(x=>[x.url,x]));
  result.set(record.id,{...prior,...record,known_exploited:record.kev_verified_at?!!record.known_exploited:!!(prior.known_exploited||record.known_exploited),
   categories:[...new Set([...(prior.categories||[]),...(record.categories||[])])],
   cvie_products:[...new Set([...(prior.cvie_products||[]),...(record.cvie_products||[])])],
   cvie_identities:[...(prior.cvie_identities||[]),...(record.cvie_identities||[])],
   affected_cpes:[...(prior.affected_cpes||[]),...(record.affected_cpes||[])],sources:[...source.values()]});
 }
 return [...result.values()].map(record=>{
  // Shared keyword categories cannot establish which Windows host is affected.
  const names=[...new Set([...excluded.filter(item=>item.id===record.id).map(item=>item.product),...scopes.filter(name=>!verified.get(record.id)?.has(normalize(name)))])];
  if(!names.length)return record;
  return {...record,cvie_excluded_products:names,categories:(record.categories||[]).filter(name=>!names.some(product=>normalize(product)===normalize(name)))};
 });
}
function clearPrivate(){products=[];records=[];withdrawn=new Set();excluded=[];accountId='';evidence={sources:[]};ready=false;}
function statusFor(p){
 if(!p)return 'Waiting for CVIE registration';
 if(p.status==='needs_identity')return 'Choose the exact product';
 if(p.status==='retrying')return 'Source unavailable · retry scheduled';
 if(p.status==='queued')return 'Queued · preparing vulnerability scan';
 if(p.status==='scanning')return months===3&&p.recent_complete_at?'3-month results ready · preparing older history':'Scanning and preparing vulnerabilities';
 if(p.stale)return 'Saved results · source check overdue';
 const count=months===12?p.history_count:p.recent_count;
 const complete=months===12?p.history_complete_at:p.recent_complete_at;
 const older=months===12?p.older_kev_history_count:p.older_kev_recent_count;
 return (complete?(count?count+' advisories · last '+months+' months':'No published advisories found in '+months+' months'):'Preparing '+months+'-month history')+(older?' · '+older+' older KEV-listed':'');
}
function scanProgress(p){
 if(p.status==='needs_identity')return null;
 const finished=p.status==='ready',paused=p.status==='retrying'||!!error||finished&&p.stale;
 const running=!paused&&['queued','scanning'].includes(p.status);
 const total=Number.isInteger(p.progress?.windows_total)&&p.progress.windows_total>0?p.progress.windows_total:0;
 const completed=Math.max(0,Math.min(total,Number(p.progress?.windows_complete)||0));
 const block=node('div','','cvie-progress'+(paused?' is-paused':finished?' is-complete':''));
 const heading=node('div','','cvie-progress-heading'),label=node('span','NVD history scan');
 const activity=node('span',error?'Connection interrupted':p.status==='retrying'?'Paused · automatic retry':finished?(p.stale?'Previous check complete · refresh overdue':'History check complete'):p.status==='queued'?'Waiting to start':'Checking source records','cvie-progress-activity');
 if(running){const indicator=node('span','','cvie-activity');indicator.setAttribute('aria-hidden','true');activity.prepend(indicator);}
 heading.append(label,activity);
 const bar=node('progress');bar.max=finished?1:total||1;
 bar.setAttribute('aria-label',p.name+' NVD history scan');
 if(finished||total)bar.value=finished?1:completed;
 const description=finished?'History scan complete':total?completed+' of '+total+' history windows checked':'Preparing the product and history windows';
 bar.setAttribute('aria-valuetext',description);bar.textContent=description;
 const detail=node('div',description,'cvie-progress-detail');
 const recordTotal=p.progress?.records_in_window,checked=p.progress?.records_checked;
 if(!finished&&Number.isFinite(recordTotal)&&recordTotal>0&&Number.isFinite(checked))detail.append(node('span',Math.max(0,Math.min(recordTotal,checked))+' of '+recordTotal+' source records checked in the current window'));
 if(p.status==='retrying'&&p.next_attempt_at)detail.append(node('span','Next attempt: '+new Date(p.next_attempt_at).toLocaleString()));
 if(error)detail.append(node('span','Showing last saved progress. CVIE will reconnect automatically.'));
 block.append(heading,bar,detail);return block;
}
function notify(){const signature=JSON.stringify([months,records,[...withdrawn].sort(),excluded]);const recordsChanged=signature!==lastSignature;lastSignature=signature;draw();window.dispatchEvent(new CustomEvent('cvie:updated',{detail:{recordsChanged}}));}
async function request(path='',options={}){
 const epoch=authEpoch;
 const response=await fetch(API+path,{credentials:'include',...(globalThis.AbortSignal?.timeout?{signal:AbortSignal.timeout(20000)}:{}),headers:{Accept:'application/json',...(options.body?{'Content-Type':'application/json'}:{})},...options});
 if(epoch!==authEpoch)throw new SessionChanged();
 if(response.status===401){authEpoch++;signedIn=false;clearPrivate();throw Error('Sign in to use private CVIE monitoring.');}
 const data=await response.json();
 if(epoch!==authEpoch)throw new SessionChanged();
 if(!response.ok)throw Error(data.error||'CVIE is temporarily unavailable. Saved results may be incomplete.');
 signedIn=true;return data;
}
function mount(){
 const targets=[document.getElementById('cvieExplorer'),document.getElementById('inventoryMatchResults'),document.getElementById('customerDashStatus')].filter(Boolean);
 for(const target of targets){
  const panel=node('section','','cvie-panel');panel.hidden=true;
  panel.setAttribute('aria-label','CVEHarbor Vulnerability Intelligence Engine');
  if(target.id==='cvieExplorer')target.append(panel);else target.before(panel);
  panels.push(panel);
 }
}
function draw(){
 for(const panel of panels){
  panel.hidden=!signedIn;if(!signedIn)continue;
  const previousOpen=panel.querySelector('.cvie-scan-details')?.open;panel.replaceChildren();
  const header=node('div','','cvie-panel-head'),title=node('div');
  title.append(node('strong','CVIE · Vulnerability Intelligence Engine'),node('p','Source-backed product history, matched by affected product identity.','cvie-caption'));
  const label=node('label','History '),select=node('select');select.setAttribute('aria-label','CVIE vulnerability history');
  for(const n of [3,12]){const option=node('option','Last '+n+' months');option.value=String(n);select.append(option);}select.value=String(months);
  select.addEventListener('change',()=>{months=Number(select.value);void refresh();});label.append(select);
  const button=node('button','Refresh status');button.type='button';button.disabled=busy;button.addEventListener('click',()=>void refresh(true));
  header.append(title,label,button);panel.append(header);
  const sourceLabels={current:'Checked',scanning:'Scanning',needs_identity:'Waiting for product selection',catching_up:'Indexing disclosures',verifying_products:'Verifying product applicability',pending:'Waiting for first check',stale:'Check overdue',unavailable:'Source unavailable',rate_limited:'Rate limited · retry scheduled',setup_required:'Setup required',no_products:'Add a product'};
  const sourceGrid=node('div','','cvie-source-grid');
  for(const s of evidence.sources||[]){
   const card=node('div','','cvie-source '+s.status);
   card.append(node('strong',s.label||s.id),node('span',sourceLabels[s.status]||s.status));
   card.append(node('small',s.last_success_at?'Checked '+new Date(s.last_success_at).toLocaleString():'No successful check yet'));
   if(s.publisher_at)card.append(node('small','Publisher update: '+new Date(s.publisher_at).toLocaleString()));
   if(s.pending_records)card.append(node('small',s.pending_records+' records awaiting verification'));
   if(s.status==='rate_limited'&&s.retry_at)card.append(node('small','Retry after '+new Date(s.retry_at).toLocaleString()));
   if(s.error)card.append(node('small',s.error));sourceGrid.append(card);
   if(!error&&['scanning','catching_up','verifying_products'].includes(s.status)){
    const activity=node('progress','','cvie-source-activity');activity.setAttribute('aria-label',(s.label||s.id)+' verification in progress');card.append(activity);
   }
  }
  if(sourceGrid.children.length)panel.append(sourceGrid);
  const active=products.filter(p=>['queued','scanning','retrying'].includes(p.status));
  const attention=(evidence.sources||[]).some(s=>['pending','stale','unavailable','rate_limited','setup_required','catching_up','verifying_products'].includes(s.status));
  const message=error||(busy?'Loading '+months+'-month results...':!ready?'Preparing CVIE...':!products.length?'Add a product or register an asset to start CVIE.':attention?'Some sources are still being verified or need attention. Available results are shown below; check each source status.':products.some(p=>p.status==='needs_identity')?'Some products need an exact identity before CVIE can scan. Expand product status to choose.':products.some(p=>p.status==='retrying')?'A source check is unavailable. Saved results remain available; CVIE will retry automatically.':products.some(p=>p.status==='ready'&&p.stale)?'Some source checks are overdue. Saved results remain available while CVIE refreshes them.':active.length?active.length+' product'+(active.length===1?' is':'s are')+' being prepared. Results appear as source pages finish.':'Product checks complete. Review the source and installed version before acting.');
  const status=node('p',message,'cvie-status');status.setAttribute('role','status');panel.append(status);
  const list=node('div','','cvie-product-statuses');
  for(const p of products){
   const row=node('div','','cvie-product-status');
   row.append(node('strong',p.name),node('span',statusFor(p),'cvie-state '+p.status));
   const progress=scanProgress(p);if(progress)row.append(progress);
   if(p.last_success_at)row.append(node('small','Last successful source page: '+new Date(p.last_success_at).toLocaleString()));
   if(p.error)row.append(node('small',p.error));
   if(p.identity_label)row.append(node('small','Checking: '+p.identity_label));
   if(p.candidates?.length){
    const choose=node('select');choose.setAttribute('aria-label','Product identity for '+p.name);
    choose.append(node('option',p.identity_prompt||'Select the correct vendor and product'));
    for(const item of p.candidates){const o=node('option',item.label);o.value=item.cpe;choose.append(o);}
    choose.options[0].value='';
    choose.addEventListener('change',async()=>{if(!choose.value)return;choose.disabled=true;try{await request('/products/'+p.id+'/identity',{method:'PUT',body:JSON.stringify({cpe:choose.value})});await refresh();}catch(e){error=e.message;notify();}});
    row.append(choose);
   }
   list.append(row);
  }
  if(products.length){const details=node('details','','cvie-scan-details');details.open=previousOpen??active.length>0;
   details.append(node('summary','Product scan status ('+products.length+')'+(active.length?' · '+active.length+' in progress':'')),list,node('p','Progress updates automatically. History bars track NVD checks; original disclosures and CISA KEV verification are shown above. Scans continue if you leave this page. A completed source check does not establish that an installation is secure.','cvie-caption'));panel.append(details);}
 }
}
async function refresh(sync=false){
 if(busy){pending=true;pendingSync=pendingSync||sync;return;}busy=true;clearTimeout(timer);draw();
 const requestedMonths=months;
 try{
  if(sync)await request('/sync',{method:'POST',body:'{}'});
  const state=await request();
  if(accountId&&accountId!==state.account_id){clearPrivate();notify();}accountId=state.account_id||'';
  products=state.products||[];ready=state.ready;evidence=state.evidence||{sources:[]};withdrawn=new Set(state.withdrawn_ids||[]);excluded=state.excluded_product_cves||[];error='';draw();
  const incoming=[],visited=new Set();let after='';
  do{
   const page=await request('/advisories?months='+requestedMonths+(after?'&after='+encodeURIComponent(after):''));
   if(accountId&&page.account_id&&page.account_id!==accountId){authEpoch++;clearPrivate();pending=true;throw new SessionChanged();}
   incoming.push(...(page.advisories||[]));
   if(page.next&&visited.has(page.next))throw Error('CVIE pagination stalled. Saved results remain available.');
   if(page.next)visited.add(page.next);
   after=page.next||'';
  }while(after);
  if(requestedMonths===months){records=incoming;notify();}else pending=true;
 }catch(e){if(!(e instanceof SessionChanged)){error=e.name==='TimeoutError'?'The CVIE request timed out. Saved results remain available; automatic retry is scheduled.':e.message;notify();}}
 finally{
  busy=false;draw();
  if(pending){const syncNext=pendingSync;pending=false;pendingSync=false;timer=setTimeout(()=>void refresh(syncNext),250);}
  else if(signedIn)timer=setTimeout(()=>void refresh(),products.some(p=>['queued','scanning'].includes(p.status))?8000:60000);
 }
}
window.CVEHARBOR_CVIE={get products(){return products;},get records(){return merge();},get evidence(){return evidence;},get months(){return months;},get ready(){return ready;},get signedIn(){return signedIn;},get loading(){return busy;},merge,refresh,statusFor,
 setMonths:value=>{if(![3,12].includes(Number(value)))throw Error('Select 3 or 12 months');months=Number(value);return refresh();},
 product:name=>products.find(p=>normalize(p.name)===normalize(name))};
mount();
window.addEventListener('cveharbor:inventory-loaded',()=>void refresh(true));
window.addEventListener('cveharbor:account-state',event=>{
 const email=normalize(event.detail?.email||'');
 if(!event.detail?.authenticated||email!==accountEmail){authEpoch++;clearPrivate();accountEmail=email;signedIn=!!event.detail?.authenticated;error='';notify();}
 if(event.detail?.authenticated)void refresh(true);else{pending=false;pendingSync=false;clearTimeout(timer);}
});
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible'&&signedIn)void refresh();});
if(typeof fetch==='function')void refresh(true);
})();
