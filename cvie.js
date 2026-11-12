(function(){
'use strict';
// Organization inventory has a separate permission-scoped data path.
if(location.pathname.startsWith('/customer-dashboard/')&&new URLSearchParams(location.search).has('org'))return;
// Dedicated public routes share hidden explorer markup.
if(['threats','malware','lifecycle','admin-tools'].includes(document.body.dataset.page))return;
const API='https://api.cveharbor.com/v1/cvie';
const scope=/^\/(customer-dashboard|customer-reports|environments)(\/|$)/.test(location.pathname)?'inventory':'catalogue';
let catalogueNames=null,sessionKnown=false,lastCataloguePreferences='';
let products=[],records=[],months=3,error='',ready=false,signedIn=false,timer=null,busy=false,pending=false,pendingSync=false;
const panels=[];
let lastSignature='';
let evidence={sources:[]},withdrawn=new Set();
let excluded=[],accountId='',accountEmail='',authEpoch=0;
let lastFullAt=0,recordsMonths=0,checkingProgress=false;
const ACTIVE_POLL=30000,IDLE_POLL=60000,RESULT_MAX_AGE=60000;
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
  // Shared keyword categories cannot establish the registered product scope.
  const names=[...new Set([...excluded.filter(item=>item.id===record.id).map(item=>item.product),...scopes.filter(name=>!verified.get(record.id)?.has(normalize(name)))])];
  if(!names.length)return record;
  return {...record,cvie_excluded_products:names,categories:(record.categories||[]).filter(name=>!names.some(product=>normalize(product)===normalize(name)))};
 });
}
function clearPrivate(){indexedTopics=null;partialTopicRecords=null;fastQueue=[];fastMode=false;identityDialog?.close();catalogueNames=null;products=[];records=[];withdrawn=new Set();excluded=[];accountId='';evidence={sources:[]};ready=false;lastFullAt=0;recordsMonths=0;}
function followsTopic(p){
 return scope==='catalogue'&&(window.CVEHARBOR_CATALOG?.categories||[]).concat(window.CVEHARBOR_DATA?.categories||[]).some(c=>c.name===p.name);
}
let partialTopicRecords=null;
let indexedTopics=null;
function activeHistory(){
 return indexedTopics?.epoch===authEpoch&&indexedTopics.months===months&&signedIn?indexedTopics:null;
}
async function readTopicPage(first=false){
 const state=activeHistory();
 if(!state||state.loading||(!first&&!state.next))return;
 state.loading=true;state.error='';
 window.dispatchEvent(new Event('cvie:catalogue-page'));
 try{
  const page=await request('/catalogue-history?months='+months+(state.next?'&after='+encodeURIComponent(state.next):''));
  if(state!==activeHistory()||page.account_id!==accountId)return;
  if(page.next&&page.next===state.next)throw Error('History pagination did not advance.');
  state.rows.push(...page.advisories);state.next=page.next;state.coverage=page.coverage;state.sourceStart=page.source_start;state.archiveDiscoveryComplete=page.archive_discovery_complete;
 }catch(e){
  if(state===activeHistory()&&!(e instanceof SessionChanged))state.error='Shared disclosure history could not be loaded. Retry the history page.';
 }finally{state.loading=false;window.dispatchEvent(new Event('cvie:catalogue-page'));}
}
function openStoredHistory(enabled){
 if(!enabled||scope!=='catalogue'||!location.pathname.startsWith('/vulnerabilities/')){indexedTopics=null;return;}
 if(activeHistory()&&Date.now()-indexedTopics.openedAt<300000)return;
 indexedTopics={epoch:authEpoch,months,openedAt:Date.now(),rows:[],next:null,loading:false,coverage:'loading'};
 void readTopicPage(true);
}
function statusFor(p){
 if(!p)return 'Waiting for CVIE registration';
 if(p.status==='needs_identity')return followsTopic(p)?'Following topic · optional product refinement':'Choose the exact product';
 if(p.status==='retrying')return 'Source unavailable · retry scheduled';
 if(p.status==='queued')return 'Queued · preparing vulnerability scan';
 if(p.status==='scanning'){
  if(p.history_complete_at)return 'Updating saved vulnerabilities · previous results available';
  if(months===3&&p.recent_complete_at)return '3-month results ready · preparing older history';
  return p.last_success_at||p.progress?.windows_complete||p.progress?.records_checked?'Continuing saved vulnerability scan':'Scanning and preparing vulnerabilities';
 }
 if(p.stale)return 'Saved results · source check overdue';
 const count=months===12?p.history_count:p.recent_count;
 const complete=months===12?p.history_complete_at:p.recent_complete_at;
 const older=months===12?p.older_kev_history_count:p.older_kev_recent_count;
 const disclosurePending=(evidence.sources||[]).some(s=>s.id==='cve_program'&&s.status!=='current');
 if(p.coverage?.limited)return (count?count+' verified advisories · ':'')+(p.coverage.discovery_limited?'Additional disclosure history is incomplete':'Coverage limited · review the checked products');
 return (complete?(count?count+' advisories · last '+months+' months':disclosurePending?'No verified matches available yet · original disclosure checks pending':'No advisories matched the checked product identity in '+months+' months'):'Preparing '+months+'-month history')+(older?' · '+older+' older KEV-listed':'');
}
function scanProgress(p){
 if(p.status==='needs_identity')return null;
 const finished=p.status==='ready',paused=p.status==='retrying'||!!error||finished&&p.stale;
 const running=!paused&&['queued','scanning'].includes(p.status);
 const total=Number.isInteger(p.progress?.windows_total)&&p.progress.windows_total>0?p.progress.windows_total:0;
 const completed=Math.max(0,Math.min(total,Number(p.progress?.windows_complete)||0));
 const block=node('div','','cvie-progress'+(paused?' is-paused':finished?' is-complete':''));
 const heading=node('div','','cvie-progress-heading'),label=node('span',p.progress?.directory_total?'Product identity lookup':p.shared_scan?'Shared NVD history scan':'NVD history scan');
 const activity=node('span',error?'Connection interrupted':p.status==='retrying'?'Paused · automatic retry':finished?(p.coverage?.limited?'Checked within limited coverage':p.stale?'Previous check complete · refresh overdue':'Bounded history checked'):p.status==='queued'?'Waiting to start':'Checking source records','cvie-progress-activity');
 if(running){const indicator=node('span','','cvie-activity');indicator.setAttribute('aria-hidden','true');activity.prepend(indicator);}
 heading.append(label,activity);
 const bar=node('progress');bar.max=finished?1:total||1;
 bar.setAttribute('aria-label',p.name+' NVD history scan');
 if(finished||total)bar.value=finished?1:completed;
 const description=finished?(p.coverage?.limited?'Some source history remains unverified':'Configured source windows checked'):total?completed+' of '+total+' history windows checked':'Preparing the product and history windows';
 bar.setAttribute('aria-valuetext',description);bar.textContent=description;
 const detail=node('div',description,'cvie-progress-detail');
 if(p.progress?.directory_total)detail.append(node('span',p.progress.directory_checked+' of '+p.progress.directory_total+' directory entries checked'));
 const recordTotal=p.progress?.records_in_window,checked=p.progress?.records_checked;
 if(!finished&&Number.isFinite(recordTotal)&&recordTotal>0&&Number.isFinite(checked))detail.append(node('span',Math.max(0,Math.min(recordTotal,checked))+' of '+recordTotal+' source records checked in the current window'));
 if(p.status==='retrying'&&p.next_attempt_at)detail.append(node('span','Next attempt: '+new Date(p.next_attempt_at).toLocaleString()));
 if(error)detail.append(node('span','Showing last saved progress. CVIE will reconnect automatically.'));
 block.append(heading,bar,detail);return block;
}
let identityDialog=null,identityProductId='',identityBusy=false,identityOptionsSignature='',identityOpener=null,identityError='',identityGeneration=0,identityTimer=null,identityReading=false,identityStarted=0,identityResumedAt=0;
function drawIdentity(){
 if(!identityDialog?.open)return;
 const p=products.find(x=>x.id===identityProductId);
 if(!p){identityDialog.close();return;}
 const status=identityDialog.querySelector('[role="status"]'),query=identityDialog.querySelector('input[type="search"]').value.toLowerCase();
 const choices=(p.candidates||[]).filter(x=>x.label.toLowerCase().includes(query));
 const signature=JSON.stringify([choices,identityBusy,p.status,p.directory_complete]);
 if(signature!==identityOptionsSignature){
  const selected=identityDialog.querySelector('input[type="radio"]:checked')?.value;identityOptionsSignature=signature;const list=identityDialog.querySelector('.cvie-identity-options');list.replaceChildren();
  for(const item of choices){
   const label=node('label','','cvie-identity-option'),radio=node('input');radio.type='radio';radio.name='cvie-identity';radio.value=item.cpe;radio.checked=item.cpe===selected;radio.disabled=identityBusy;
   const words=node('span'),title=node('strong',item.label);words.append(title);label.append(radio,words);list.append(label);
  }
  if(!choices.length)list.append(node('p',query&&p.candidates?.length?'No matching options. Try another search.':p.status==='needs_identity'?'No identities were returned. Retry the directory lookup, or add a more specific product name and vendor in Customize technologies.':'Looking up product identities. You can leave this dialog open or return later.'));
 }
 if(!identityBusy)status.textContent=identityError||(p.status==='retrying'?(p.error||'NVD is unavailable; an automatic retry is scheduled.')+' Available choices remain selectable.':'')||choices.length+' of '+(p.candidates?.length||0)+' available identities'+(p.directory_limited?' · Directory search is partial.':p.directory_complete?' · Directory search complete.':['queued','scanning'].includes(p.status)?(Date.now()-identityStarted>20000?' · Waiting for NVD. Use Refresh options to resume.':' · Directory lookup in progress.'):'');
 identityDialog.querySelector('[data-confirm]').disabled=identityBusy||!identityDialog.querySelector('input[type="radio"]:checked');
 identityDialog.querySelector('[data-retry]').disabled=identityBusy;
}
async function lookupIdentity(retry=false){
 if(identityBusy)return;identityError='';identityBusy=true;drawIdentity();
 const id=identityProductId,generation=identityGeneration;
 try{const state=await request('/products/'+id+'/identity-options',{method:'POST',body:JSON.stringify({retry})});if(generation===identityGeneration){updateIdentityState(state);identityResumedAt=Date.now();}}
 catch(e){if(identityDialog.open&&identityProductId===id&&generation===identityGeneration)identityError=e.message;}
 finally{if(generation===identityGeneration){identityBusy=false;identityOptionsSignature='';drawIdentity();scheduleIdentityRead();}}
}
function updateIdentityState(state){
 if(state.id!==identityProductId)return;
 const p=products.find(x=>x.id===state.id);if(p)Object.assign(p,state);
 if(state.cpe){identityDialog.close();void refresh();return;}
 drawIdentity();
}
function scheduleIdentityRead(){
 clearTimeout(identityTimer);
 if(!identityDialog?.open||document.visibilityState==='hidden')return;
 const p=products.find(x=>x.id===identityProductId);
 if(p&&!['queued','scanning','retrying'].includes(p.status))return;
 identityTimer=setTimeout(()=>void readIdentity(),3000);
}
async function readIdentity(){
 if(identityReading||identityBusy||!identityDialog?.open){scheduleIdentityRead();return;}
 const id=identityProductId,generation=identityGeneration;identityReading=true;
 try{
  const state=await request('/products/'+id+'/identity-options');
  if(generation!==identityGeneration)return;identityError='';updateIdentityState(state);
  // Resume an interrupted lookup at most once per 15 seconds, never during a live lease/backoff.
  if(identityDialog.open&&(['queued','scanning'].includes(state.status)||state.status==='retrying'&&state.retry_at<=Date.now())&&state.lease_until<Date.now()&&Date.now()-identityResumedAt>=15000)await lookupIdentity();
 }catch(e){if(generation===identityGeneration){identityError=e.message;drawIdentity();}}
 finally{identityReading=false;if(generation===identityGeneration)scheduleIdentityRead();}
}
function openIdentity(name){
 if(window.CVEHarborOpenVersionPicker?.(name))return;
 const p=products.find(x=>normalize(x.name)===normalize(name));if(!p)return;
 if(!identityDialog){
  identityDialog=node('dialog','','cvie-identity-dialog');identityDialog.setAttribute('aria-labelledby','cvieIdentityTitle');
  const header=node('div','','cvie-identity-head'),title=node('h2');title.id='cvieIdentityTitle';const close=node('button','×');close.type='button';close.setAttribute('aria-label','Close product chooser');close.onclick=()=>identityDialog.close();header.append(title,close);
  const search=node('input');search.type='search';search.placeholder='Search available products…';search.setAttribute('aria-label','Search product identities');search.oninput=drawIdentity;
  const status=node('p');status.setAttribute('role','status');const options=node('div','','cvie-identity-options');
  const actions=node('div','','cvie-identity-actions'),retry=node('button','Refresh options'),confirm=node('button','Use selected product');retry.type=confirm.type='button';retry.dataset.retry='';confirm.dataset.confirm='';retry.onclick=()=>void lookupIdentity(true);
  options.onchange=()=>{confirm.disabled=identityBusy||!options.querySelector('input:checked')};
  confirm.onclick=async()=>{
   const selected=options.querySelector('input:checked');if(!selected||identityBusy)return;identityBusy=true;const id=identityProductId,generation=identityGeneration;confirm.disabled=true;retry.disabled=true;options.querySelectorAll('input').forEach(x=>x.disabled=true);status.textContent='Saving product identity…';
   try{await request('/products/'+id+'/identity',{method:'PUT',body:JSON.stringify({cpe:selected.value})});if(generation===identityGeneration)identityDialog.close();await refresh();}
   catch(e){if(generation===identityGeneration)status.textContent=e.message;}
   finally{if(generation===identityGeneration){identityBusy=false;confirm.disabled=false;retry.disabled=false;options.querySelectorAll('input').forEach(x=>x.disabled=false);}}
  };
  actions.append(retry,confirm);identityDialog.append(header,node('p','Choose the product you use. These identities come from the NVD product directory; the list may include older releases. Version applicability is checked separately.'),search,status,options,actions);document.body.append(identityDialog);
  identityDialog.addEventListener('close',()=>{clearTimeout(identityTimer);identityGeneration++;identityBusy=false;identityOptionsSignature='';if(identityOpener?.isConnected)identityOpener.focus();else document.getElementById('technologyManageButton')?.focus()});
 }
 identityGeneration++;identityStarted=Date.now();identityResumedAt=0;identityBusy=false;identityError='';identityProductId=p.id;identityOpener=document.activeElement;identityOptionsSignature='';identityDialog.querySelector('h2').textContent='Choose exact product · '+p.name;identityDialog.querySelector('input[type="search"]').value='';identityDialog.showModal();drawIdentity();void lookupIdentity();
}

function notify(){const signature=JSON.stringify([months,records,[...withdrawn].sort(),excluded]);const recordsChanged=signature!==lastSignature;lastSignature=signature;draw();drawIdentity();scheduleIdentityRead();window.dispatchEvent(new CustomEvent('cvie:updated',{detail:{recordsChanged}}));}
async function request(path='',options={}){
 const epoch=authEpoch;
 const read=()=>fetch(API+path+(path.includes('?')?'&':'?')+'scope='+scope,{credentials:'include',...(globalThis.AbortSignal?.timeout?{signal:AbortSignal.timeout(20000)}:{}),headers:{Accept:'application/json',...(options.body?{'Content-Type':'application/json'}:{})},...options});
 let response;
 const delays=[500,1500];
 for(let attempt=0;;attempt++){
  if(epoch!==authEpoch)throw new SessionChanged();
  try{response=await read()}catch(e){
   if(options.method||attempt===delays.length)throw e;
  }
  if(response&&(options.method||![502,503,504].includes(response.status)||attempt===delays.length))break;
  await new Promise(resolve=>setTimeout(resolve,delays[attempt]));
  response=null;
 }
 if(epoch!==authEpoch)throw new SessionChanged();
 if(response.status===401){sessionKnown=true;authEpoch++;signedIn=false;clearPrivate();throw Error('Sign in to use private CVIE monitoring.');}
 const data=await response.json();
 if(epoch!==authEpoch)throw new SessionChanged();
 if(!response.ok)throw Error(data.error||'CVIE is temporarily unavailable. Saved results may be incomplete.');
 sessionKnown=true;signedIn=true;return data;
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
  const previousOpen=panel.querySelector('.cvie-scan-details')?.open;
  const previousCoverage=new Map([...panel.querySelectorAll('.cvie-coverage-details')].map(el=>[el.dataset.productId,el.open]));panel.replaceChildren();
  const header=node('div','','cvie-panel-head'),title=node('div');
  title.append(node('strong','CVIE · Vulnerability Intelligence Engine'),node('p',scope==='catalogue'?'Selected catalogue product history. Shared sources synchronize independently.':'Inventory product history; independent of your personal catalogue.','cvie-caption'));
  const label=node('label','History '),select=node('select');select.setAttribute('aria-label','CVIE vulnerability history');
  for(const n of [3,12]){const option=node('option','Last '+n+' months');option.value=String(n);select.append(option);}select.value=String(months);
  select.addEventListener('change',()=>{months=Number(select.value);void refresh();});label.append(select);
  const button=node('button','Refresh status');button.type='button';button.disabled=busy;button.addEventListener('click',()=>void refresh());
  header.append(title,label,button);panel.append(header);
  const sourceLabels={current:'Checked',scanning:'Product history check in progress',needs_identity:'Some products need an exact identity',catching_up:'Shared disclosure indexing in progress',verifying_products:'Shared applicability verification in progress',pending:'Waiting for first check',stale:'Check overdue',unavailable:'Source unavailable',rate_limited:'Rate limited · retry scheduled',setup_required:'Setup required',no_products:'Add a product'};
  const sourceGrid=node('div','','cvie-source-grid');
  for(const s of evidence.sources||[]){
   const card=node('div','','cvie-source '+s.status);
   card.append(node('strong',s.label||s.id),node('span',sourceLabels[s.status]||s.status));
   card.append(node('small',s.last_success_at?'Checked '+new Date(s.last_success_at).toLocaleString():'No successful check yet'));
   if(s.publisher_at)card.append(node('small','Publisher update: '+new Date(s.publisher_at).toLocaleString()));
   if(s.coverage_start_at)card.append(node('small','Original disclosure feed coverage starts: '+new Date(s.coverage_start_at).toLocaleString()));
   if(s.pending_records)card.append(node('small',s.pending_records+(scope==='catalogue'?' public records awaiting shared background verification':' public records in shared verification queue')));
   if(s.id==='nvd'&&scope==='catalogue')card.append(node('small',scope==='catalogue'?'History status for your selected catalogue. Source checks may be shared with other accounts.':'History status for inventory products. Source checks may be shared with other accounts.'));
   if(s.id!=='nvd'){card.title='Shared source synchronization for all accounts.';if(scope==='catalogue')card.append(node('small','Shared source queue for all accounts. Opening a page does not restart it.'));}
   if(s.status==='rate_limited'&&s.retry_at)card.append(node('small','Retry after '+new Date(s.retry_at).toLocaleString()));
   if(s.error)card.append(node('small',s.error));sourceGrid.append(card);
   if(!error&&['scanning','catching_up','verifying_products'].includes(s.status)){
    const activity=node('progress','','cvie-source-activity');activity.setAttribute('aria-label',(s.label||s.id)+' verification in progress');card.append(activity);
   }
  }
  if(sourceGrid.children.length)panel.append(sourceGrid);
  const active=products.filter(p=>['queued','scanning','retrying'].includes(p.status));
  const attention=(evidence.sources||[]).some(s=>['pending','stale','unavailable','rate_limited','setup_required','catching_up','verifying_products'].includes(s.status));
  const message=error||(busy?(checkingProgress?'Updating scan status...':'Loading '+months+'-month results...'):!ready?'Preparing CVIE...':!products.length?(scope==='catalogue'?'No selected catalogue products. Save technologies to start personalized checks; shared sources continue independently.':'No inventory products registered for checking.'):products.some(p=>p.status==='needs_identity'&&!followsTopic(p))?'Choose an identity for custom products to check their applicability.':attention?'Shared sources are being verified or need attention. Saved results remain available; check each source status.':products.some(p=>p.status==='retrying')?'A source check is unavailable. Saved results remain available; CVIE will retry automatically.':products.some(p=>p.status==='ready'&&p.stale)?'Some source checks are overdue. Saved results remain available while CVIE refreshes them.':active.length?active.length+' product'+(active.length===1?' is':'s are')+' being prepared. Results appear as source pages finish.':'Product checks complete. Review the source and installed version before acting.');
  const status=node('p',message,'cvie-status');status.setAttribute('role','status');panel.append(status);
  if(fastMode){
   panel.append(node('p','Showing bounded stored evidence. Product/version applicability and complete source coverage require review.','cvie-caption'));
   if(fastQueue.length){const more=node('button','Load more stored CVEs');more.type='button';more.disabled=busy;more.onclick=async()=>{if(busy)return;busy=true;more.disabled=true;try{await loadFastPage();}catch(e){if(!(e instanceof SessionChanged))error=e.message;notify();}finally{busy=false;draw();if(pending){const syncNext=pendingSync;pending=false;pendingSync=false;void refresh(syncNext);}}};panel.append(more);}
  }
  const completed=products.filter(p=>p.status==='ready'&&!p.stale).length,failed=products.filter(p=>p.status==='retrying').length,verification=products.filter(p=>p.status==='needs_identity'&&!followsTopic(p)).length;
  if(scope==='catalogue'&&ready)panel.append(node('p',(scope==='catalogue'?'Selected catalogue products: ':'Inventory products: ')+products.length+' · Queued/checking: '+products.filter(p=>['queued','scanning'].includes(p.status)).length+' · History complete: '+completed+' · Needs your input: '+verification+' · Coverage incomplete: '+products.filter(p=>p.coverage?.limited).length+' · Failed/retrying: '+failed,'cvie-scope-summary'));
  const list=node('div','','cvie-product-statuses');
  for(const p of products){
   const row=node('div','','cvie-product-status');
   row.append(node('strong',p.name),node('span',statusFor(p),'cvie-state '+p.status+(p.coverage?.limited?' coverage-limited':'')));
   const progress=scanProgress(p);if(progress)row.append(progress);
   if(p.last_success_at)row.append(node('small','Last successful source page: '+new Date(p.last_success_at).toLocaleString()));
   if(p.error&&!(p.status==='needs_identity'&&followsTopic(p)))row.append(node('small',p.error));
   if(p.identity_label)row.append(node('small','Checking: '+p.identity_label));
   if(p.coverage){
    const coverage=node('details','','cvie-coverage-details');
    coverage.dataset.productId=p.id;coverage.open=previousCoverage.get(p.id)||false;
    coverage.append(node('summary',p.coverage.limited?'Coverage review required':'Products and source coverage'));
    const description=node('div','','cvie-caption');
    for(const identity of p.coverage.identities||(p.coverage.families||[]).map(cpe=>({label:cpe.split(':').slice(3,5).join(' / ').replaceAll('_',' ')})))description.append(node('p',identity.label));
    for(const note of p.coverage.notes||[])description.append(node('p',note));
    coverage.append(description);row.append(coverage);
   }
   if(p.status==='needs_identity'||!p.cpe){
    const choose=node('button',followsTopic(p)?'Refine for my environment':'Choose exact product','cvie-choose-product');choose.type='button';choose.setAttribute('aria-label','Choose exact product for '+p.name);choose.addEventListener('click',()=>openIdentity(p.name));row.append(choose);
   }
   list.append(row);
  }
  if(products.length){const details=node('details','','cvie-scan-details');details.open=previousOpen??active.length>0;
   details.append(node('summary',(scope==='catalogue'?'Catalogue product scan status (':'Inventory product scan status (')+products.length+')'+(active.length?' · '+active.length+' in progress':'')),list,node('p','Progress updates automatically. History bars track NVD checks; original disclosures and CISA KEV verification are shown above. Scans continue if you leave this page. A completed source check does not establish that an installation is secure.','cvie-caption'));panel.append(details);}
 }
}
const identitySignature=rows=>JSON.stringify(rows.map(p=>[p.id,p.name,p.vendor,p.cpe]));
const resultSignature=rows=>JSON.stringify(rows.map(p=>[p.id,p.status,p.last_success_at,p.recent_complete_at,p.history_complete_at]));
// Bounded pages are opt-in until staging D1 and downstream completeness checks pass.
let fastQueue=[],fastMode=false;
async function loadFastPage(reset=false){
 const epoch=authEpoch,requestedMonths=months;
 const incoming=reset?[]:[...records];let remaining=100,steps=0;
 while(fastQueue.length&&remaining>0&&steps++<8){
  const current=fastQueue[0];
  const page=await request('/products/'+current.id+'/evidence?limit='+remaining+'&months='+months+(current.after?'&after='+encodeURIComponent(current.after):''));
  if(page.account_id!==accountId||epoch!==authEpoch||requestedMonths!==months)throw new SessionChanged();
  incoming.push(...(page.advisories||[]));excluded.push(...(page.excluded_product_cves||[]));remaining-=page.scanned||0;
  if(page.next){current.after=page.next;break;}else fastQueue.shift();
  // Publish each stored page without waiting for other products or any provider.
  records=incoming;recordsMonths=months;notify();
 }
 records=incoming;recordsMonths=months;lastFullAt=Date.now();notify();
}
async function refresh(sync=false,progressOnly=false){
 if(progressOnly&&document.visibilityState==='hidden')return;
 if(busy){pending=true;pendingSync=pendingSync||sync;return;}
 const lightweight=progressOnly&&ready&&recordsMonths===months&&lastFullAt&&Date.now()-lastFullAt<RESULT_MAX_AGE;
 busy=true;checkingProgress=Boolean(lightweight);clearTimeout(timer);draw();
 const requestedMonths=months;
 try{
  if(sync){
   try{await request('/sync',{method:'POST',body:'{}'})}
   catch(e){if(e instanceof SessionChanged||sessionKnown&&!signedIn)throw e}
  }
  if(lightweight){
   const recovering=Boolean(error);
   const state=await request('/progress');
   if(accountId&&accountId!==state.account_id){clearPrivate();notify();}
   else if(identitySignature(products)===identitySignature(state.products||[])){
    const changed=resultSignature(products)!==resultSignature(state.products||[]);
    const previous=new Map(products.map(p=>[p.id,p]));
    products=scopedProducts(state.products||[]).map(p=>({...previous.get(p.id),...p}));evidence=state.evidence||{sources:[]};error='';notify();
    if(!recovering&&!changed&&recordsMonths===requestedMonths&&lastFullAt&&Date.now()-lastFullAt<RESULT_MAX_AGE)return;
   }
  }
  checkingProgress=false;
  const state=await request(location.pathname.startsWith('/customer-reports/')?'':'?view=bounded');
  fastMode=Boolean(state.fast_evidence);
  if(accountId&&accountId!==state.account_id){clearPrivate();notify();}accountId=state.account_id||'';
  products=scopedProducts(state.products||[]);ready=state.ready;evidence=state.evidence||{sources:[]};withdrawn=new Set(state.withdrawn_ids||[]);excluded=state.excluded_product_cves||[];error='';draw();
  openStoredHistory(state.topic_history);
  if(fastMode){
   products=products.map(p=>({...p,coverage:{limited:true,notes:['Indexed evidence is partial. No matches do not establish safety.']}}));
   fastQueue=products.filter(p=>p.cpe).map(p=>({id:p.id,after:''}));await loadFastPage(true);return;
  }
  const incoming=[],visited=new Set();let after='';
  do{
   const page=await request('/advisories?months='+requestedMonths+(after?'&after='+encodeURIComponent(after):''));
   if(accountId&&page.account_id&&page.account_id!==accountId){authEpoch++;clearPrivate();pending=true;throw new SessionChanged();}
   incoming.push(...(page.advisories||[]));
   if(scope==='catalogue'&&requestedMonths===months&&location.pathname.startsWith('/vulnerabilities/')){
    partialTopicRecords={epoch:authEpoch,months:requestedMonths,rows:incoming};
    if(!after)window.dispatchEvent(new CustomEvent('cvie:catalogue-page'));
   }
   if(page.next&&visited.has(page.next))throw Error('CVIE pagination stalled. Saved results remain available.');
   if(page.next)visited.add(page.next);
   after=page.next||'';
  }while(after);
  if(requestedMonths===months){partialTopicRecords=null;records=incoming;recordsMonths=requestedMonths;lastFullAt=Date.now();notify();}else pending=true;
 }catch(e){if(!(e instanceof SessionChanged)){error=e.name==='TypeError'?'The connection to CVIE was interrupted. Reconnecting to read saved results.':e.name==='TimeoutError'?'The CVIE request timed out. Saved results remain available; automatic retry is scheduled.':e.message;notify();}}
 finally{
  busy=false;checkingProgress=false;draw();
  if(pending){const syncNext=pendingSync;pending=false;pendingSync=false;timer=setTimeout(()=>void refresh(syncNext),250);}
  else if((signedIn||error&&!sessionKnown)&&document.visibilityState!=='hidden')timer=setTimeout(()=>void refresh(false,true),error?15000:products.some(p=>['queued','scanning'].includes(p.status))?ACTIVE_POLL:IDLE_POLL);
 }
}
function applyCatalogue(preferences){
 if(scope!=='catalogue')return;
 const nextNames=new Set([...(preferences.defaults||[]),...(preferences.products||[]).filter(p=>p.enabled!==false).map(p=>p.name)].map(normalize));
 const signature=JSON.stringify(preferences);
 if(catalogueNames&&signature===lastCataloguePreferences)return;
 lastCataloguePreferences=signature;
 authEpoch++;lastFullAt=0;catalogueNames=nextNames;
 products=products.filter(p=>catalogueNames.has(normalize(p.name)));
 records=records.filter(r=>(r.cvie_products||r.categories||[]).some(name=>catalogueNames.has(normalize(name))));
 notify();void refresh();
}
const scopedProducts=rows=>catalogueNames&&scope==='catalogue'?rows.filter(p=>catalogueNames.has(normalize(p.name))):rows;
window.CVEHARBOR_CVIE={get sessionKnown(){return sessionKnown;},scope,applyCatalogue,openIdentity,get coverageLimited(){return fastMode;},get hasMore(){return fastQueue.length>0;},get products(){return products;},get records(){return merge();},get evidence(){return evidence;},get months(){return months;},get ready(){return ready;},get signedIn(){return signedIn;},get loading(){return busy;},merge,refresh,statusFor,
 setMonths:value=>{if(![3,12].includes(Number(value)))throw Error('Select 3 or 12 months');months=Number(value);return refresh();},
 get historyLoaded(){return recordsMonths===months&&lastFullAt>0;},
 product:name=>products.find(p=>normalize(p.name)===normalize(name))};
window.CVEHARBOR_CVIE.isWithdrawn=id=>withdrawn.has(id);
Object.defineProperty(window.CVEHARBOR_CVIE,'indexedHistory',{get:activeHistory});
window.CVEHARBOR_CVIE.loadHistoryPage=()=>readTopicPage(activeHistory()?.rows.length===0);
Object.defineProperty(window.CVEHARBOR_CVIE,'topicRecords',{get(){
 if(partialTopicRecords&&partialTopicRecords.epoch===authEpoch&&partialTopicRecords.months===months)return partialTopicRecords.rows;
 return recordsMonths===months?records:[];
}});
function mountRegistryChoices(){
 for(const id of ['technologyAddName','inventoryTechnology']){
  const input=document.getElementById(id);if(!input||input.tagName!=='INPUT')continue;
  const box=node('div','','cvie-registry-options');box.setAttribute('aria-live','polite');input.after(box);let revision=0,debounce;
  input.addEventListener('input',()=>{
   delete input.dataset.cvieIdentity;const current=++revision;clearTimeout(debounce);box.replaceChildren();
   if(!signedIn||input.value.trim().length<2)return;
   debounce=setTimeout(async()=>{
    try{const result=await request('/directory?q='+encodeURIComponent(input.value.trim())+'&vendor='+encodeURIComponent(id==='technologyAddName'?document.getElementById('technologyAddVendor')?.value.trim()||'':''));
     if(current!==revision||result.enabled===false)return;
     box.append(node('p',result.guidance,'cvie-caption'));
     for(const candidate of result.candidates||[]){const choice=node('button',candidate.name+' · '+candidate.vendor+' · '+candidate.kind+(candidate.match==='suggestion'?' (suggestion)':''));choice.type='button';
      choice.onclick=()=>{input.value=candidate.name;input.dataset.cvieIdentity=candidate.id;revision++;box.replaceChildren(node('p',candidate.kind==='group'?'Choose a release or edition; product coverage is unresolved.':'Identity selected. Add the installed version; no version is assumed.','cvie-caption'));
       if(id==='technologyAddName'){const vendor=document.getElementById('technologyAddVendor'),cpe=document.getElementById('technologyAddCpe');if(vendor)vendor.value=candidate.vendor;if(cpe)cpe.value=candidate.cpe;}
      };box.append(choice);
     }
    }catch{/* Existing free-text save remains available if suggestions fail. */}
   },250);
  });
 }
}
mount();mountRegistryChoices();
window.addEventListener('cveharbor:inventory-loaded',()=>void refresh());
window.addEventListener('cveharbor:account-state',event=>{
 const email=normalize(event.detail?.email||'');
 if(!event.detail?.authenticated||email!==accountEmail){authEpoch++;clearPrivate();accountEmail=email;signedIn=!!event.detail?.authenticated;error='';notify();}
 if(event.detail?.authenticated)void refresh(true);else{pending=false;pendingSync=false;clearTimeout(timer);}
});
document.addEventListener('visibilitychange',()=>{clearTimeout(timer);if(document.visibilityState==='visible'&&signedIn)void refresh(false,true);});
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')scheduleIdentityRead();else clearTimeout(identityTimer)});
if(typeof fetch==='function')void refresh(true);
})();

