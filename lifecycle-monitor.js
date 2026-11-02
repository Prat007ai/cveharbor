(() => {
'use strict';
const $=id=>document.getElementById(id);
if(!$('lifecycleMonitor'))return;
const endpoint='https://api.cveharbor.com/v1/lifecycle';
const catalog=window.CVEHARBOR_LIFECYCLE||{cycles:[],products:[],errors:[]};
const staticProducts=[
 ['windows-server','Windows Server'],['windows','Windows Client'],['mssqlserver','SQL Server'],
 ['sharepoint','SharePoint Server'],['dotnet','.NET'],['dotnet-framework','.NET Framework'],
 ['exchange-server','Exchange Server'],['system-center','System Center'],['powershell','PowerShell'],
 ['azure-devops-server','Azure DevOps Server'],['sitefinity','Sitefinity CMS'],
 ['wordpress','WordPress'],['php','PHP'],['ubuntu','Ubuntu'],['debian','Debian'],
 ['rhel','Red Hat Enterprise Linux'],['centos','CentOS'],['almalinux','AlmaLinux'],
 ['rocky-linux','Rocky Linux'],['mysql','MySQL'],['mariadb','MariaDB'],
 ['python','Python'],['nodejs','Node.js'],['docker-engine','Docker Engine'],
 ['kubernetes','Kubernetes'],['fortios','FortiOS']
];
let signed=false,ready=false,logged=[],prefs={email_enabled:0,lead_days:90},delivery=false,enhanced=false,monitorFlags={},accountEmail='',authEpoch=0;
const queued=[];
const make=(tag,cls,value)=>{
 const node=document.createElement(tag);if(cls)node.className=cls;if(value!==undefined)node.textContent=String(value);return node;
};
const message=value=>{$('lifecycleUserStatus').textContent=value};
let dismissConfirmation=null,preferencesSaving=false;
function confirmLifecycle({title,description,acceptLabel}){
 if(dismissConfirmation)return Promise.resolve(false);
 return new Promise(resolve=>{
  const previous=document.activeElement,dialog=make('dialog','detail-dialog cvh-small-dialog');
  dialog.id='lifecycleConfirmDialog';
  dialog.setAttribute('aria-labelledby','lifecycleConfirmTitle');
  dialog.setAttribute('aria-describedby','lifecycleConfirmText');
  dialog.innerHTML='<div class="dialog-layout"><button type="button" class="close-dialog" aria-label="Close confirmation">×</button><div class="cvh-dialog-symbol" aria-hidden="true">C</div><p class="eyebrow">CVEHarbor</p><h2 id="lifecycleConfirmTitle"></h2><p id="lifecycleConfirmText" class="ops-note"></p><div class="cvh-dialog-actions"><button type="button" class="ops-download cvh-secondary-action" id="lifecycleConfirmCancel">Cancel</button><button type="button" class="ops-download" id="lifecycleConfirmAccept"></button></div></div>';
  dialog.querySelector('h2').textContent=title;
  dialog.querySelector('#lifecycleConfirmText').textContent=description;
  const accept=dialog.querySelector('#lifecycleConfirmAccept'),cancel=dialog.querySelector('#lifecycleConfirmCancel');
  accept.textContent=acceptLabel;
  let settled=false;
  function finish(confirmed){
   if(settled)return;settled=true;dismissConfirmation=null;
   if(dialog.open&&typeof dialog.close==='function')dialog.close();
   dialog.remove();
   if(previous?.isConnected)previous.focus();
   resolve(confirmed);
  }
  dismissConfirmation=()=>finish(false);
  accept.addEventListener('click',()=>finish(true));
  cancel.addEventListener('click',()=>finish(false));
  dialog.querySelector('.close-dialog').addEventListener('click',()=>finish(false));
  dialog.addEventListener('cancel',event=>{event.preventDefault();finish(false)});
  dialog.addEventListener('close',()=>finish(false));
  dialog.addEventListener('click',event=>{if(event.target===dialog)finish(false)});
  document.body.append(dialog);
  if(typeof dialog.showModal==='function')dialog.showModal();else dialog.setAttribute('open','');
  cancel.focus();
 });
}

async function call(path='',method='GET',data){
 const epoch=authEpoch;
 const res=await fetch((enhanced?'https://api.cveharbor.com/v1/monitoring':endpoint)+path,{method,credentials:'include',
  headers:{'Content-Type':'application/json'},body:data===undefined?undefined:JSON.stringify(data)});
 let body={};try{body=await res.json()}catch(_){}
 if(epoch!==authEpoch)throw Error('Account changed; response discarded');
 if(!res.ok)throw Error(body.error||'Lifecycle account service unavailable');
 return body;
}
function daysTo(date){
 if(!/^\d{4}-\d{2}-\d{2}$/.test(String(date||'')))return null;
 const start=new Date().toISOString().slice(0,10);
 return Math.floor((Date.parse(date+'T00:00:00Z')-Date.parse(start+'T00:00:00Z'))/86400000);
}
function itemLabel(entry){return entry.product+' '+entry.cycle;}
function summary(watch){
 if(enhanced){const s=watch.verified;return s?{date:s.milestones?.security||s.milestones?.eol||s.milestones?.mainstream||'',source:s.source_url,origin:s.source_label||'Official checked source',latest:s.version}:null;}
 if(watch.directory)return {date:watch.directory.eol_date,source:watch.directory.source_url,origin:watch.directory.source_label,latest:watch.directory.latest};
 if(watch.custom_eol_date)return {date:watch.custom_eol_date,source:watch.custom_source_url,origin:'Customer supplied'};
 const c=catalog.cycles.find(x=>x.slug===watch.slug&&(!watch.cycle||String(x.cycle).toLowerCase()===watch.cycle.toLowerCase()));
 return c?{date:c.eol_date,source:c.url,origin:'Source published',latest:c.latest}:null;
}
const MAX_ROWS=60;
let directoryCategory='All Products';
const commonProducts=window.CVEHARBOR_COMMON_PRODUCTS||[],sharedProducts=[],lookupCycles=new Map();
// Initial browsing highlights familiar products; typed searches keep relevance ranking.
const featuredProducts=['windows-server','ubuntu','php','wordpress','dotnet','mssqlserver','mysql','mariadb','debian','rhel','rocky-linux','almalinux','sles','amazon-linux'];
const productChoices=()=>{
 const entries=[...new Map([...catalogList.map(slug=>({slug,name:titleCase(slug),category:'Other',aliases:[]})),...staticProducts.filter(([slug])=>!commonProducts.some(p=>p.aliases.includes(slug))).map(([slug,name])=>({slug,name,category:'Other',aliases:[]})),...sharedProducts,...commonProducts].map(p=>[p.slug,p])).values()];
 const priority=new Map([...new Set([...featuredProducts,...commonProducts.map(p=>p.slug)])].map((slug,index)=>[slug,index]));
 return entries.sort((a,b)=>(priority.get(a.slug)??Infinity)-(priority.get(b.slug)??Infinity)||a.name.localeCompare(b.name));
};
const searchProducts=query=>window.CVEHARBOR_DIRECTORY_SEARCH?.search(productChoices(),query)||productChoices().filter(p=>(p.name+' '+p.slug).toLowerCase().includes(query.toLowerCase())).map(product=>({product}));
const categoryOf=slug=>commonProducts.find(p=>p.slug===slug)?.category||'Other';
const catalogList=Array.isArray(catalog.available_products)?catalog.available_products:[];
const titleCase=slug=>String(slug||'').split('-').map(x=>x==='mssqlserver'?'SQL':x.charAt(0).toUpperCase()+x.slice(1)).join(' ');
const detail=$('lifecycleDetailDialog');
const detailStatus=$('lifecycleDetailStatus');
const detailBody=$('lifecycleDetailBody');
const safeLink=(url,label)=>{
 const a=make('a','ops-link',label);
 try{
  const target=new URL(url);
  if(target.protocol!=='https:')return null;
  a.href=target.href;a.target='_blank';a.rel='noopener noreferrer';return a;
 }catch(_){return null;}
};
const field=(name,value)=>{
 const row=make('div','lifecycle-detail-field');
 row.append(make('strong','',name),make('span','',value===undefined||value===null||value===''?'Not published':String(value)));
 return row;
};
function openModal(){
 if(typeof detail.showModal==='function')detail.showModal();
 else detail.setAttribute('open','');
}
$('lifecycleDetailClose').addEventListener('click',()=>{
 if(typeof detail.close==='function')detail.close();else detail.removeAttribute('open');
});
detail.addEventListener('click',event=>{
 if(event.target===detail)$('lifecycleDetailClose').click();
});
function showCycles(slug,product,cycles,origin){
 detailBody.replaceChildren();
 $('lifecycleDetailTitle').textContent=product+' lifecycle and support';
 detailStatus.textContent=cycles.length?
  'Published support information from '+origin+'. Check vendor editions, extended support and release channels.':
  'No lifecycle dates are published by this source.';
 const source='https://endoflife.date/'+slug;
 const list=make('div','lifecycle-detail-cycles');
 for(const c of cycles){
  const card=make('section','lifecycle-detail-cycle');
  card.append(make('h3','',product+' '+(c.cycle||'Unknown release')));
  const date=c.eol_date||(typeof c.eol==='string'?c.eol:null);
  const active=c.support_date||(typeof c.support==='string'?c.support:null);
  card.append(field('End of life / security support',date||(c.eol===true?'Ended; exact date unavailable':c.eol===false?'Not listed as ended; no date supplied':'Unknown')));
  card.append(field('End of active support',active));
  card.append(field('Latest reported version',c.latest||''));
  card.append(field('Latest release date',c.latest_release_date||c.latestReleaseDate||''));
  card.append(field('Original release date',c.releaseDate||c.release_date||''));
  if(c.lts!==undefined)card.append(field('Long term support',typeof c.lts==='boolean'?(c.lts?'Yes':'No'):String(c.lts)));
  if(c.extendedSupport!==undefined)card.append(field('Extended support',c.extendedSupport));
  list.append(card);
 }
 detailBody.append(list);
 const note=make('p','ops-note','This information does not establish that a security patch is installed or that the product is exposed. No source data is treated as a guaranteed support entitlement.');
 detailBody.append(note);
 const foot=make('div','lifecycle-detail-references');
 foot.append(make('strong','','Original source and verification'));
 const link=safeLink(source,'Review product at endoflife.date');
 if(link)foot.append(link);
 const vendor=safeLink('https://learn.microsoft.com/lifecycle/','Microsoft Lifecycle documentation');
 if(/windows|mssql|sharepoint|dotnet|exchange/i.test(slug)&&vendor)foot.append(vendor);
 detailBody.append(foot);
 openModal();
}
function normalizedCycle(row){
 return {cycle:String(row?.cycle||'Unknown').slice(0,80),
  eol:row?.eol,eol_date:typeof row?.eol==='string'?row.eol:null,
  support:row?.support,support_date:typeof row?.support==='string'?row.support:null,
  latest:row?.latest,latest_release_date:row?.latestReleaseDate,releaseDate:row?.releaseDate,
  lts:row?.lts,extendedSupport:row?.extendedSupport};
}
let remoteController=null,remoteVersion=0;
async function openRemote(slug,product){
 const version=++remoteVersion;
 if(remoteController)remoteController.abort();
 remoteController=new AbortController();
 $('lifecycleDetailTitle').textContent=product+' lifecycle';
 detailBody.replaceChildren();
 detailStatus.textContent='Looking up the latest published release history...';
 openModal();
 try{
  const response=await fetch('https://endoflife.date/api/'+encodeURIComponent(slug)+'.json',{
   method:'GET',credentials:'omit',headers:{Accept:'application/json'},signal:remoteController.signal
  });
  if(!response.ok)throw Error('HTTP '+response.status);
  const data=await response.json();
  if(version!==remoteVersion)return;
  if(!Array.isArray(data))throw Error('Unexpected product response');
  const cycles=data.filter(x=>x&&typeof x==='object').slice(0,40).map(normalizedCycle);
  showCycles(slug,product,cycles,'endoflife.date');
 }catch(error){
  if(version!==remoteVersion||error.name==='AbortError')return;
  const fallback=catalog.cycles.filter(x=>x.slug===slug);
  if(fallback.length){
   showCycles(slug,product,fallback,'CVEHarbor last collected snapshot');
   detailStatus.textContent+=' Live lookup was unavailable; dates may be stale.';
  }else{
   detailBody.replaceChildren();
   detailStatus.textContent='Live lifecycle retrieval is unavailable for this product. The product may be outside the source coverage, or direct requests may be restricted.';
   const link=safeLink('https://endoflife.date/'+slug,'View the source product page');
   if(link)detailBody.append(link);
  }
 }
}
function renderFeed(){
 const products=$('lifecycleProduct'),existing=products.value;
 products.replaceChildren();let empty=make('option','', 'Choose a monitored product');empty.value='';products.append(empty);
 const entries=productChoices(),choices=entries.map(p=>p.slug);
 for(const {slug,name} of entries){
  const option=make('option','',name);option.value=slug;products.append(option);
 }
 if(choices.includes(existing))products.value=existing;
 syncCycles();
 const results=$('lifecyclePublished');results.replaceChildren();
 const query=$('lifecyclePublicSearch').value.trim().toLowerCase();
 const matches=searchProducts(query).map(x=>x.product.slug);
 const filtered=matches.filter(slug=>directoryCategory==='All Products'||categoryOf(slug)===directoryCategory);
 const filters=$('lifecycleDirectoryFilters');
 if(filters){filters.replaceChildren();for(const label of ['All Products','Microsoft','Linux','Frameworks','Web & CMS','Databases','Infrastructure','Other']){const button=make('button','',label);button.append(make('span','filter-count',matches.filter(slug=>label==='All Products'||categoryOf(slug)===label).length));button.type='button';button.setAttribute('aria-pressed',String(label===directoryCategory));button.addEventListener('click',()=>{directoryCategory=label;renderFeed()});filters.append(button)}}
 for(const slug of filtered.slice(0,MAX_ROWS)){
  const known=lookupCycles.get(slug)||catalog.cycles.filter(x=>x.slug===slug);
  const title=entries.find(p=>p.slug===slug)?.name||titleCase(slug);
  const row=make('div','lifecycle-source-row lifecycle-source-interactive');
  const mark=make('span','lifecycle-product-mark');mark.setAttribute('aria-hidden','true');
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 48 48');
  // Fixed local artwork only; vendor data is never interpreted as SVG/HTML.
  const brands={windows:'<path fill="#08b7ff" d="m2 9 19-3v17H2Zm22-3 22-4v21H24ZM2 26h19v17L2 40Zm22 0h22v21l-22-4Z"/>',
   wordpress:'<circle cx="24" cy="24" r="22" fill="#0b6289" stroke="#a6e9ff"/><text x="24" y="35" text-anchor="middle" fill="white" font-size="35" font-family="Georgia">W</text>',
   'mssqlserver':'<ellipse cx="25" cy="11" rx="17" ry="7" fill="#e4edf3"/><path d="M8 11v26c0 10 34 10 34 0V11c0 10-34 10-34 0" fill="#a9bdce"/><path d="m3 17 39-9-4 21L1 38Z" fill="#c53550"/><text x="20" y="28" text-anchor="middle" fill="white" font-size="13" font-family="Georgia">SQL</text>',
   sharepoint:'<circle cx="30" cy="15" r="13" fill="#13b9be"/><circle cx="35" cy="31" r="11" fill="#0c969c"/><circle cx="23" cy="39" r="9" fill="#22cddd"/><rect x="2" y="13" width="26" height="28" rx="3" fill="#087d8b"/><text x="15" y="34" text-anchor="middle" fill="white" font-size="24" font-family="Arial">S</text>',
   dotnet:'<rect width="48" height="48" rx="8" fill="#6542bf"/><text x="24" y="30" text-anchor="middle" fill="white" font-size="17" font-family="Arial">.NET</text>'};
  const brand=slug.startsWith('windows')?brands.windows:brands[slug];if(brand){svg.innerHTML=brand;mark.append(svg)}else mark.textContent=title.slice(0,2).toUpperCase();row.append(mark);
  const copy=make('div','lifecycle-product-copy'),heading=make('div');heading.append(make('strong','',title));if(categoryOf(slug)==='Microsoft')heading.append(make('span','lifecycle-vendor','Microsoft'));copy.append(heading);
  copy.append(make('p','ops-note',known.length?known.length+' release cycles. Latest: '+(known[0].cycle||'Unknown')+'.':'Source verification required. Open release history.'));
  const published=known[0],validDate=value=>/^\d{4}-\d{2}-\d{2}$/.test(value||'')&&Number.isFinite(Date.parse(value));
  const end=validDate(published?.eol_date)?Date.parse(published.eol_date+'T00:00:00Z'):null;
  const years=end===null?null:(end-Date.now())/(365.25*86400000),ended=years!==null&&years<=0;
  copy.append(make('span','lifecycle-support-pill'+(ended?' ended':''),end===null?'Support date not published':ended?'Published support ended':'Published support dates'));row.append(copy);
  const countdown=make('div','lifecycle-countdown');countdown.dataset.state=end===null?'unknown':ended?'ended':years<1?'soon':'future';
  const ring=make('div','lifecycle-ring'),value=make('span','',end===null?'?':ended?'0':years.toFixed(1));value.append(make('small','',end===null?'unknown':'years'));ring.append(value);ring.title='Time to the published end of support for '+(published?.cycle||title)+'. Ring is a visual indicator, not a support percentage.';
  const caption=make('div','lifecycle-countdown-label',end===null?'Not published':ended?'Support ended':'Until support end');if(end!==null){const time=make('time','',new Date(end).toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric',timeZone:'UTC'}));time.dateTime=published.eol_date;caption.append(time);}countdown.append(ring,caption);row.append(countdown);
  const timeline=make('div','lifecycle-timeline');timeline.append(make('small','','Published milestones'));
  const milestones=[['Release',published?.release_date],['Support',published?.support_date],['End',published?.eol_date]];
  const verified=milestones.filter(([,date])=>validDate(date));
  if(verified.length>=2){const track=make('div','lifecycle-timeline-track'),legend=make('div','lifecycle-timeline-legend');for(const [label,date] of verified){const dot=make('i');dot.title=label+': '+date;track.append(dot);const item=make('span','',label);item.title=date;legend.append(item);}timeline.append(track,legend);}else timeline.append(make('div','lifecycle-timeline-unknown',end===null?'Dates not published':'End: '+published.eol_date));row.append(timeline);
  const btn=make('button','ops-download lifecycle-view-details','View lifecycle details');
  btn.type='button';btn.addEventListener('click',()=>openRemote(slug,title));
  const choose=make('button','ops-download','Select product');choose.type='button';choose.addEventListener('click',()=>{selectProduct(slug);$('lifecycleWatchForm').scrollIntoView?.({block:'start',behavior:'smooth'})});const actions=make('div','lifecycle-source-actions');actions.append(choose,btn);row.append(actions);results.append(row);
 }
 if(!matches.length)results.append(make('p','ops-note','No matching product in the currently indexed lifecycle directory. This does not mean the product is supported. Check the vendor directly or add a custom verified date to your account.'));
 $('lifecycleSearchStatus').textContent=query?
  filtered.length+' products found; showing up to '+MAX_ROWS+'. Select a product for its detailed release history.':
  'Browse the monitored product catalogue or search by any name in the extended directory.';
 if($('lifecycleDirectoryCount'))$('lifecycleDirectoryCount').textContent=entries.length+' products';
 const failures=(catalog.errors||[]).length;
 $('lifecyclePublicSearch').placeholder=catalogList.length?'Search '+entries.length+' products or aliases…':'Search products or release branches…';
 $('lifecycleFreshness').textContent=!catalog.checked_at?'Source snapshot unavailable. Product counts and dates cannot be confirmed.':'Snapshot: '+catalog.checked_at+
  '. '+failures+' product sources unavailable. '+catalogList.length+' products indexed in the broader directory. Verify vendor lifecycle terms and editions.';
}
function syncCycles(){
 const chosen=$('lifecycleProduct').value,select=$('lifecycleCycle');
 const was=select.value;select.replaceChildren();
 const first=make('option','','Choose release / cycle');first.value='';select.append(first);
 for(const row of lookupCycles.get(chosen)||catalog.cycles.filter(x=>x.slug===chosen)){
  const option=make('option','',row.cycle);option.value=row.cycle;select.append(option);
 }
 if([...select.options].some(x=>x.value===was))select.value=was;
}
let lookupGeneration=0,lookupBusy=false;
function renderSuggestions(){
 const root=$('lifecycleProductSuggestions');if(!root)return;root.replaceChildren();
 const query=$('lifecycleProductSearch').value.trim(),matches=searchProducts(query);
 for(const {product,suggested} of matches.slice(0,8)){
  const button=make('button','lifecycle-product-suggestion',(suggested?'Did you mean: ':'')+product.name);button.type='button';
  button.append(make('small','',product.category));button.addEventListener('click',()=>selectProduct(product.slug));root.append(button);
 }
 if(!matches.length)root.append(make('p','ops-note','No matching product. Add the official name below to look it up.'));
}
function selectProduct(slug){
 const product=productChoices().find(p=>p.slug===slug);if(!product)return;
 $('lifecycleProduct').value=slug;$('lifecycleProductSearch').value=product.name;
 $('lifecycleCustomName').value='';$('lifecycleCustomCycle').value='';$('lifecycleManualBranch').value='';syncCycles();renderSuggestions();void lookupProduct(slug);
}
async function lookupProduct(name){
 const generation=++lookupGeneration,epoch=authEpoch;
 const status=$('lifecycleLookupStatus');if(!status)return;
 if(!signed||!ready){status.textContent='Sign in to look up and save additional product release history.';return;}
 lookupBusy=true;$('lifecycleLookupProduct').disabled=true;status.textContent='Looking up published release branches…';
 try{
  const result=await call('/directory/lookup','POST',{name});if(generation!==lookupGeneration||epoch!==authEpoch)return;
  if(result.status!=='found'){status.textContent=result.message||'Source information unavailable. You can save this as an unverified product.';return;}
  const p=result.product;sharedProducts.push(p);lookupCycles.set(p.slug,result.cycles);
  const branch=$('lifecycleCycle').value||$('lifecycleCustomCycle').value.trim()||$('lifecycleManualBranch').value.trim();
  renderFeed();$('lifecycleProduct').value=p.slug;syncCycles();
  if([...$('lifecycleCycle').options].some(o=>o.value===branch))$('lifecycleCycle').value=branch;
  else if(branch)$('lifecycleManualBranch').value=branch;
  $('lifecycleProductSearch').value=p.name;renderSuggestions();
  status.textContent=(result.stale?'Live source unavailable; last checked history. ':'')+result.cycles.length+' release branches from '+result.source_label+'. Choose your release; unknown support dates stay unknown.'+(result.limited?' Older branches may require manual entry.':'');
 }catch(error){if(generation===lookupGeneration&&epoch===authEpoch)status.textContent='Lookup unavailable. Your product can still be saved for review. '+error.message;}
 finally{if(generation===lookupGeneration){lookupBusy=false;$('lifecycleLookupProduct').disabled=false;}}
}
$('lifecycleCustomName')?.addEventListener('input',()=>{lookupGeneration++;lookupBusy=false;$('lifecycleLookupProduct').disabled=false;});
$('lifecycleProductSearch')?.addEventListener('input',renderSuggestions);
$('lifecycleAddUnlisted')?.addEventListener('click',()=>{lookupGeneration++;lookupBusy=false;$('lifecycleLookupProduct').disabled=false;$('lifecycleProduct').value='';syncCycles();$('lifecycleCustomName').value=$('lifecycleProductSearch').value.trim();$('lifecycleCustomName').focus();$('lifecycleLookupStatus').textContent='Enter the official product name. Incorrect or incomplete names may return no matches.';});
$('lifecycleLookupProduct')?.addEventListener('click',()=>void lookupProduct($('lifecycleProduct').value||$('lifecycleCustomName').value.trim()||$('lifecycleProductSearch').value.trim()));
function getCandidate(){
 if(lookupBusy)throw Error('Wait for the product lookup to finish before saving.');
 const slug=$('lifecycleProduct').value;
 const product=slug?(productChoices().find(p=>p.slug===slug)?.name||titleCase(slug)):$('lifecycleCustomName').value.trim();
 const cycle=slug?($('lifecycleCycle').value||$('lifecycleManualBranch')?.value.trim()||''):$('lifecycleCustomCycle').value.trim();
 const customDate=slug?'':$('lifecycleCustomDate').value.trim();
 const customSource=slug?'':$('lifecycleCustomSource').value.trim();
 const installed=$('lifecycleInstalled').value.trim();
 if(!product)throw Error('Choose a product or enter a custom product name.');
 if(slug&&!cycle)throw Error('Choose a specific release cycle.');
 if(customSource&&(!/^https:\/\//.test(customSource)))
  throw Error('Use an official HTTPS source URL, or leave it blank.');
 const types=[...document.querySelectorAll('#productMonitorTypes input:checked')].map(x=>x.value);
 return {product,slug,cycle,installed_version:installed,custom_eol_date:customDate,custom_source_url:customSource,edition:$('lifecycleEdition')?.value.trim()||'',...(types.length?{alert_types:types}:{}),delivery_mode:$('productMonitorCadence')?.value||'daily'};
}
function queueKey(w){
 return [w.slug,w.cycle,w.product.toLowerCase(),w.custom_eol_date].join('|');
}
function renderQueue(){
 document.querySelector('.lifecycle-watch-queue').hidden=queued.length===0;
 const root=$('lifecycleQueueItems');root.replaceChildren();
 $('lifecycleQueueCount').textContent=queued.length+' selected';
 for(const [index,watch] of queued.entries()){
  const row=make('div','ops-result ops-result-top');
  row.append(make('span','',watch.product+' '+watch.cycle+(watch.installed_version?' · Installed '+watch.installed_version:'')));
  const remove=make('button','ops-remove','Remove');remove.type='button';
  remove.addEventListener('click',()=>{queued.splice(index,1);renderQueue()});
  row.append(remove);root.append(row);
 }
 $('lifecycleSaveAll').disabled=!signed||!ready||!queued.length;
}
$('lifecycleWatchQueue').addEventListener('click',async()=>{
 const epoch=authEpoch;
 try{
  if(signed&&ready&&!$('lifecycleProduct').value&&$('lifecycleCustomName').value.trim())await lookupProduct($('lifecycleCustomName').value.trim());
  if(epoch!==authEpoch)throw Error('Account changed; selection discarded.');
  const candidate=getCandidate();
  if(queued.length>=30)throw Error('You can add 30 products in one batch.');
  if(queued.some(x=>queueKey(x)===queueKey(candidate)))throw Error('This product and release are already selected.');
  queued.push(candidate);renderQueue();
  message(candidate.product+' added to your list. Add more products, then save all when signed in.');
 }catch(e){message(e.message)}
});
$('lifecycleSaveAll').addEventListener('click',async()=>{
 if(!signed||!ready){message('Sign in and activate the Cloudflare D1 lifecycle tables before saving.');return;}
 const button=$('lifecycleSaveAll');button.disabled=true;
 try{
  const result=await call('/watches/bulk','POST',{watches:queued});
  queued.splice(0);renderQueue();await load();
  message(result.count+' monitored products saved. Automatic email delivery requires Cloudflare activation and your email opt-in.');
 }catch(e){message(e.message)}
 finally{renderQueue()}
});
function updateActions(){
 $('lifecycleWatchSave').disabled=!signed||!ready;
 $('lifecyclePrefsSave').disabled=!signed||!ready;
 if($('lifecycleSaveAll'))$('lifecycleSaveAll').disabled=!signed||!ready||!queued.length;
 for(const option of $('lifecycleLead').options)option.disabled=!enhanced&&['7','14'].includes(option.value);
 for(const control of document.querySelectorAll('#productMonitorTypes input,#productMonitorCadence,#lifecycleEdition')){control.disabled=!enhanced;control.title=enhanced?'':'Enhanced monitoring setup must be approved before these settings can be saved.';}
 // Preferences can be explored without sign in; saving requires an account.
}
function renderUser(){
 const results=$('lifecycleWatches');results.replaceChildren();
 $('lifecycleWatchCount').textContent=logged.length+' monitored';
 $('lifecycleLead').value=String(prefs.lead_days||90);
 $('lifecycleEmailOptin').checked=!!prefs.email_enabled;
 if(Array.isArray(prefs.alert_types))for(const checkbox of document.querySelectorAll('#productMonitorTypes input'))checkbox.checked=prefs.alert_types.includes(checkbox.value);
 if(prefs.delivery_mode&&$('productMonitorCadence'))$('productMonitorCadence').value=prefs.delivery_mode;
 $('lifecycleDeliveryState').textContent=delivery
  ? 'Scheduled monitoring is operating. Email requires your saved consent; provider acceptance and delivery are recorded separately.'
  : 'Email monitoring is not active yet. Your preferences remain saved.';
 updateActions();
 if(!signed||!ready){results.append(make('p','ops-note','You can choose products and versions above. Sign in to save your private watchlist.'));return;}
 if(!logged.length){results.append(make('p','ops-note','No saved product lifecycle watches. Choose a product or look up an unlisted product.'));return;}
 for(const watch of logged){
  const div=make('article','ops-result');div.dataset.productMark=watch.slug==='wordpress'?'W':watch.product.slice(0,2);
  const top=make('div','ops-result-top');
  top.append(make('strong','',watch.product+(watch.cycle?' · '+watch.cycle:'')));
  const del=make('button','ops-remove','Remove');del.type='button';
  del.addEventListener('click',async()=>{
   const epoch=authEpoch;
   if(!await confirmLifecycle({title:'Remove product watch?',description:'Stop monitoring '+watch.product+'? This removes it from your saved watchlist.',acceptLabel:'Remove watch'}))return;
   if(epoch!==authEpoch||!signed||!ready)return;
   del.disabled=true;
   try{await call('/watches/'+watch.id,'DELETE');await load();message('Watch removed.')}
   catch(e){message(e.message)}
   finally{del.disabled=false}
  });
  top.append(del);div.append(top);
  if(!watch.source_id){
   const resolveButton=make('button','ops-download','Find product and release');resolveButton.type='button';
   resolveButton.addEventListener('click',async()=>{
    resolveButton.disabled=true;const epoch=authEpoch;
    try{
     const result=await call('/directory/lookup','POST',{name:watch.slug||watch.product});if(epoch!==authEpoch)return;
     div.querySelector('.lifecycle-resolve')?.remove();const box=make('div','lifecycle-resolve');div.append(box);
     if(result.status!=='found'){box.append(make('p','ops-note',result.message));return;}
     const label=make('label','',result.product.name+' — choose release'),select=make('select');
     for(const c of result.cycles){const option=make('option','',c.cycle);option.value=c.cycle;select.append(option);}
     if(result.cycles.some(c=>c.cycle===watch.cycle))select.value=watch.cycle;
     label.append(select);box.append(label);const confirm=make('button','ops-download','Use this product and release');confirm.type='button';box.append(confirm);
     confirm.addEventListener('click',async()=>{confirm.disabled=true;try{await call('/watches/'+watch.id+'/identity','PUT',{slug:result.product.slug,cycle:select.value});await load();message('Product identity saved. Published lifecycle information is shown with its source.');}catch(error){message(error.message);confirm.disabled=false;}});
    }catch(error){message(error.message)}finally{resolveButton.disabled=false;}
   });div.append(resolveButton);
  }

  div.append(make('span','monitor-state-tag',watch.monitoring_label||(watch.directory?'Published source information':'Support dates not yet verified')));
  if(watch.directory)div.append(make('p','ops-note','Source checked: '+new Date(watch.directory.checked_at).toLocaleString()+'. Refresh the lookup if you need a current check.'));
  if(watch.last_attempt_at)div.append(make('p','ops-note','Last attempt: '+new Date(watch.last_attempt_at).toLocaleString()));
  if(watch.last_success_at)div.append(make('p','ops-note','Last verified source check: '+new Date(watch.last_success_at).toLocaleString()));
  if(watch.next_due_at)div.append(make('p','ops-note','Next due check: '+new Date(watch.next_due_at).toLocaleString()));
  if(watch.last_notification_at)div.append(make('p','ops-note','Last alert: '+new Date(watch.last_notification_at).toLocaleString()+' · '+watch.last_alert_kind+' · '+watch.last_delivery_state));
  if(watch.verified)div.append(make('p','ops-note',(watch.verified.reliability==='community_lifecycle'?'Community lifecycle source · branch release: ':'Official branch release: ')+(watch.verified.version||'Not published')+' · Publication date: '+(watch.verified.published||'Not published')));
  if(watch.verification_error||watch.source_error)div.append(make('p','ops-note',watch.verification_error||watch.source_error));
  if(enhanced&&watch.monitoring_status){
   const controls=make('div','monitor-watch-controls');
   const pause=make('button','ops-download',watch.monitoring_status==='paused'?'Resume':'Pause');pause.type='button';pause.addEventListener('click',async()=>{try{await call('/watches/'+watch.id,'PUT',{status:watch.monitoring_status==='paused'?'enabled':'paused'});await load()}catch(e){message(e.message)}});
   const edit=make('button','ops-download','Edit installed version');edit.type='button';edit.addEventListener('click',async()=>{const version=window.prompt('Installed version / build',watch.installed_version||'');if(version===null)return;try{await call('/watches/'+watch.id,'PUT',{installed_version:version});await load()}catch(e){message(e.message)}});
   const options=make('button','ops-download','Alert options');options.type='button';
   options.addEventListener('click',()=>{
    if(div.querySelector('.monitor-watch-options')){div.querySelector('.monitor-watch-options').remove();return;}
    const form=make('form','monitor-watch-options monitor-type-options'),types=[];
    for(const original of document.querySelectorAll('#productMonitorTypes label')){const label=make('label'),checkbox=document.createElement('input');checkbox.type='checkbox';checkbox.value=original.querySelector('input').value;checkbox.checked=(watch.alert_types||[]).includes(checkbox.value);types.push(checkbox);label.append(checkbox,document.createTextNode(original.textContent));form.append(label);}
    const warning=make('fieldset');warning.append(make('legend','','Reminder thresholds'));const days=[];
    for(const day of [180,90,60,30,14,7]){const label=make('label'),checkbox=document.createElement('input');checkbox.type='checkbox';checkbox.value=String(day);checkbox.checked=(watch.notice_days||[]).includes(day);days.push(checkbox);label.append(checkbox,document.createTextNode(day+' days'));warning.append(label);}form.append(warning);
    const entitledLabel=make('label'),entitled=document.createElement('input');entitled.type='checkbox';entitled.checked=watch.extended_entitled===1;entitledLabel.append(entitled,document.createTextNode('I have verified entitlement to published extended support'));form.append(entitledLabel);
    const save=make('button','ops-download','Save watch alert options');save.type='submit';form.append(save);form.addEventListener('submit',async event=>{event.preventDefault();try{await call('/watches/'+watch.id,'PUT',{alert_types:types.filter(c=>c.checked).map(c=>c.value),notice_days:days.filter(c=>c.checked).map(c=>Number(c.value)),extended_entitled:entitled.checked});await load();message('Watch-specific alert options saved.')}catch(error){message(error.message)}});div.append(form);
   });
   controls.append(pause,edit,options);div.append(controls);
  }
  const info=summary(watch),day=daysTo(info?.date);
  div.append(make('p','ops-note','Installed: '+(watch.installed_version||'Not recorded')+' · Latest recorded release: '+(info?.latest||'Not verified')+'. Verify vendor updates before assuming the release is a security fix.'));
  const releases=(window.CVEHARBOR_PATCH_NOTES?.releases||[]).filter(x=>x.slug===watch.slug &&
    x.version?.startsWith(watch.cycle+'.')).sort((a,b)=>String(b.published).localeCompare(String(a.published)));
  if(releases.length){
   const release=releases[0];
   div.append(make('p','ops-note','Publisher release notes · '+release.version+' · '+release.published+
    (release.security_mentioned?' · Source mentions security':' · Security status not confirmed')));
   if(release.notes)div.append(make('p','ops-note',release.notes.slice(0,450)));
   const link=make('a','ops-link','Read full original release notes');
   link.href=release.url;link.target='_blank';link.rel='noopener noreferrer';div.append(link);
  }
  div.append(make('p','ops-note',info?.date?
   (day===null?'Verify support date':day<0?'Ended '+Math.abs(day)+' days ago':day+' days remaining')+
    ' · '+info.date+' · '+info.origin:
   'Source data unavailable. No automatic lifecycle conclusion.'));
  if(info?.source&&info.source.startsWith('https://')){
   const a=make('a','ops-link','Check source');a.href=info.source;a.target='_blank';a.rel='noopener noreferrer';div.append(a);
  }
  const details=make('details','monitor-watch-details');details.append(make('summary','','Release and check details'));for(const paragraph of [...div.querySelectorAll(':scope > p')])details.append(paragraph);div.append(details);
  results.append(div);
 }
}
async function load(){
 const state=await call();logged=state.watches||[];
 prefs=state.preferences||{email_enabled:0,lead_days:90};delivery=enhanced&&!!state.email_delivery_active;renderUser();
 window.dispatchEvent(new CustomEvent('lifecycle:loaded',{detail:{watches:logged,enhanced,flags:monitorFlags,scheduler:state.scheduler,recipient:state.recipient||accountEmail}}));
}
window.addEventListener('cveharbor:account-state',async event=>{
 const email=String(event.detail?.email||'').toLowerCase();
 if(!event.detail?.authenticated||email!==accountEmail){authEpoch++;dismissConfirmation?.();lookupGeneration++;lookupBusy=false;if($('lifecycleLookupProduct'))$('lifecycleLookupProduct').disabled=false;if($('lifecycleLookupStatus'))$('lifecycleLookupStatus').textContent='';ready=false;logged=[];queued.splice(0);prefs={email_enabled:0,lead_days:90};enhanced=false;delivery=false;monitorFlags={};accountEmail=email;renderQueue();renderUser();}
 signed=!!event.detail?.authenticated;
 // Keep selection and custom product fields browsable for everyone.
 // Only account mutations require sign in and the D1 migration.
 updateActions();
 if(!signed){ready=false;logged=[];prefs={email_enabled:0,lead_days:90};delivery=false;renderUser();window.dispatchEvent(new CustomEvent('lifecycle:loaded',{detail:{watches:[],enhanced:false,flags:{}}}));message('Sign in above to save lifecycle watches and email preferences.');return;}
 try{
  const epoch=authEpoch;
  try{const r=await fetch('https://api.cveharbor.com/v1/monitoring/status',{credentials:'include'});const state=await r.json();if(epoch!==authEpoch)return;if(r.ok){monitorFlags=state;enhanced=!!state.ready;}}catch{}
  const flags=await call('/status');ready=!!flags.ready;
  if(!ready){message('Cloudflare D1 lifecycle migration is required to save preferences. Product and release browsing remains available.');renderUser();return;}
  {try{const directory=await call('/directory');if(epoch!==authEpoch)return;sharedProducts.splice(0,sharedProducts.length,...directory.products||[]);renderFeed();renderSuggestions();}catch{}}
  await load();message('Saved lifecycle watches loaded from your private account.');
 }catch(e){message(e.message)}
});
$('lifecycleProduct').addEventListener('change',()=>{lookupGeneration++;lookupBusy=false;$('lifecycleLookupProduct').disabled=false;syncCycles();if($('lifecycleProduct').value)void lookupProduct($('lifecycleProduct').value)});
$('lifecyclePublicSearch').addEventListener('input',renderFeed);
$('lifecycleWatchForm').addEventListener('submit',async event=>{
 event.preventDefault();
 if(!signed||!ready){message('Sign in and deploy the lifecycle D1 migration before saving watches.');return;}
 const button=$('lifecycleWatchSave'),epoch=authEpoch;button.disabled=true;
 try{
  if(signed&&ready&&!$('lifecycleProduct').value&&$('lifecycleCustomName').value.trim())await lookupProduct($('lifecycleCustomName').value.trim());
  if(epoch!==authEpoch)throw Error('Account changed; save cancelled.');
  const watch=getCandidate();
  await call('/watches','POST',watch);
  await load();message('Lifecycle watch saved to your D1 account.');
 }catch(e){message('Cannot save lifecycle watch: '+e.message)}
 finally{button.disabled=false}
});
$('lifecyclePreferencesForm').addEventListener('submit',async event=>{
 event.preventDefault();
 if(!signed||!ready){message('Sign in and complete lifecycle D1 migration first.');return;}
 if(preferencesSaving)return;
 const enabled=$('lifecycleEmailOptin').checked,lead=Number($('lifecycleLead').value),epoch=authEpoch;
 const payload={email_enabled:enabled,lead_days:lead,...(enhanced?{alert_types:[...document.querySelectorAll('#productMonitorTypes input:checked')].map(c=>c.value),delivery_mode:$('productMonitorCadence')?.value||'daily'}:{})};
 const button=$('lifecyclePrefsSave');preferencesSaving=true;
 try{
  if(enabled&&!await confirmLifecycle({title:'Enable lifecycle email notices?',description:'Save your consent to receive lifecycle email notices for products in your watchlist. Emails are sent only when scheduled monitoring and delivery are active.',acceptLabel:'Enable notices'}))return;
  if(epoch!==authEpoch||!signed||!ready)return;
  button.disabled=true;
  await call('/preferences','PUT',payload);
  await load();message(enabled?'Email preference saved. Scheduled sending requires separate backend activation.':'Lifecycle email notices disabled.');
 }catch(e){message(e.message)}
 finally{preferencesSaving=false;button.disabled=!signed||!ready}
});
renderFeed();renderSuggestions();renderQueue();renderUser();
window.CVEHARBOR_LIFECYCLE_MONITOR={refresh:load};
})();
