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
let signed=false,ready=false,logged=[],prefs={email_enabled:0,lead_days:90},delivery=false;
const queued=[];
const make=(tag,cls,value)=>{
 const node=document.createElement(tag);if(cls)node.className=cls;if(value!==undefined)node.textContent=String(value);return node;
};
const message=value=>{$('lifecycleUserStatus').textContent=value};
async function call(path='',method='GET',data){
 const res=await fetch(endpoint+path,{method,credentials:'include',
  headers:{'Content-Type':'application/json'},body:data===undefined?undefined:JSON.stringify(data)});
 let body={};try{body=await res.json()}catch(_){}
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
 if(watch.custom_eol_date)return {date:watch.custom_eol_date,source:watch.custom_source_url,origin:'Customer supplied'};
 const c=catalog.cycles.find(x=>x.slug===watch.slug&&(!watch.cycle||String(x.cycle).toLowerCase()===watch.cycle.toLowerCase()));
 return c?{date:c.eol_date,source:c.url,origin:'Source published',latest:c.latest}:null;
}
const MAX_ROWS=60;
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
 for(const [slug,label] of staticProducts){
  const available=catalog.cycles.some(c=>c.slug===slug);
  const option=make('option','',label+(available?'':' · Dates unavailable'));
  option.value=slug;option.disabled=!available;products.append(option);
 }
 if(staticProducts.some(([slug])=>slug===existing))products.value=existing;
 syncCycles();
 const results=$('lifecyclePublished');results.replaceChildren();
 const query=$('lifecyclePublicSearch').value.trim().toLowerCase();
 const existingSlugs=new Set(catalog.cycles.map(x=>x.slug));
 const matches=[];
 if(query){
  const found=catalogList.filter(slug=>slug.includes(query)||titleCase(slug).toLowerCase().includes(query));
  const backup=catalog.cycles.filter(c=>(c.product+' '+c.cycle).toLowerCase().includes(query)).map(c=>c.slug);
  for(const slug of [...found,...backup])if(!matches.includes(slug))matches.push(slug);
 }else{
  for(const slug of catalog.cycles.map(x=>x.slug))if(!matches.includes(slug))matches.push(slug);
 }
 for(const slug of matches.slice(0,MAX_ROWS)){
  const known=catalog.cycles.filter(x=>x.slug===slug);
  const title=known[0]?.product||staticProducts.find(x=>x[0]===slug)?.[1]||titleCase(slug);
  const row=make('div','lifecycle-source-row lifecycle-source-interactive');
  row.append(make('strong','',title));
  const description=known.length?
   known.length+' release cycles in the collected snapshot. Latest: '+(known[0].cycle||'Unknown')+
    '. Select to review support dates and versions.':
   'Additional product found in the lifecycle directory. Select to load its release history.';
  row.append(make('p','ops-note',description));
  const btn=make('button','ops-download lifecycle-view-details','View lifecycle details');
  btn.type='button';btn.addEventListener('click',()=>openRemote(slug,title));
  row.append(btn);results.append(row);
 }
 if(!matches.length)results.append(make('p','ops-note','No matching product in the currently indexed lifecycle directory. This does not mean the product is supported. Check the vendor directly or add a custom verified date to your account.'));
 $('lifecycleSearchStatus').textContent=query?
  matches.length+' products found; showing up to '+MAX_ROWS+'. Select a product for its detailed release history.':
  'Browse the monitored product catalogue or search by any name in the extended directory.';
 const failures=(catalog.errors||[]).length;
 $('lifecycleFreshness').textContent='Snapshot: '+(catalog.checked_at||'Unavailable')+
  '. '+failures+' product sources unavailable. '+catalogList.length+' products indexed in the broader directory. Verify vendor lifecycle terms and editions.';
}
function syncCycles(){
 const chosen=$('lifecycleProduct').value,select=$('lifecycleCycle');
 const was=select.value;select.replaceChildren();
 const first=make('option','','Choose release / cycle');first.value='';select.append(first);
 for(const row of catalog.cycles.filter(x=>x.slug===chosen)){
  const option=make('option','',row.cycle);option.value=row.cycle;select.append(option);
 }
 if([...select.options].some(x=>x.value===was))select.value=was;
}
function getCandidate(){
 const slug=$('lifecycleProduct').value;
 const product=slug?staticProducts.find(([name])=>name===slug)?.[1]:$('lifecycleCustomName').value.trim();
 const cycle=slug?$('lifecycleCycle').value:$('lifecycleCustomCycle').value.trim();
 const customDate=slug?'':$('lifecycleCustomDate').value.trim();
 const customSource=slug?'':$('lifecycleCustomSource').value.trim();
 const installed=$('lifecycleInstalled').value.trim();
 if(!product)throw Error('Choose a product or enter a custom product name.');
 if(slug&&!cycle)throw Error('Choose a specific release cycle.');
 if(!slug&&!/^\d{4}-\d{2}-\d{2}$/.test(customDate))
  throw Error('Custom products need a verified end of support date.');
 if(!slug&&(!/^https:\/\//.test(customSource)))
  throw Error('Custom products need an official HTTPS source URL.');
 return {product,slug,cycle,installed_version:installed,custom_eol_date:customDate,custom_source_url:customSource};
}
function queueKey(w){
 return [w.slug,w.cycle,w.product.toLowerCase(),w.custom_eol_date].join('|');
}
function renderQueue(){
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
$('lifecycleWatchQueue').addEventListener('click',()=>{
 try{
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
 // Preferences can be explored without sign in; saving requires an account.
}
function renderUser(){
 const results=$('lifecycleWatches');results.replaceChildren();
 $('lifecycleWatchCount').textContent=logged.length+' monitored';
 $('lifecycleLead').value=String(prefs.lead_days||90);
 $('lifecycleEmailOptin').checked=!!prefs.email_enabled;
 $('lifecycleDeliveryState').textContent=delivery
  ? 'Automatic lifecycle sending is enabled in the Cloudflare Worker.'
  : 'Saved preferences are not yet sending emails. Scheduled delivery requires activation in Cloudflare.';
 updateActions();
 if(!signed||!ready){results.append(make('p','ops-note','You can choose products and versions above. Sign in and complete the D1 migration to save monitoring and notifications.'));return;}
 if(!logged.length){results.append(make('p','ops-note','No saved product lifecycle watches. Choose a monitored product or add your own verified support date.'));return;}
 for(const watch of logged){
  const div=make('article','ops-result');
  const top=make('div','ops-result-top');
  top.append(make('strong','',watch.product+(watch.cycle?' · '+watch.cycle:'')));
  const del=make('button','ops-remove','Remove');del.type='button';
  del.addEventListener('click',async()=>{
   if(!window.confirm('Stop monitoring '+watch.product+'?'))return;
   try{await call('/watches/'+watch.id,'DELETE');await load();message('Watch removed.')}
   catch(e){message(e.message)}
  });
  top.append(del);div.append(top);
  const info=summary(watch),day=daysTo(info?.date);
  if(watch.installed_version&&info?.latest)div.append(make('p','ops-note','Installed: '+watch.installed_version+' · Latest recorded release: '+info.latest+'. Verify vendor updates before assuming the release is a security fix.'));
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
  results.append(div);
 }
}
async function load(){
 const state=await call();logged=state.watches||[];
 prefs=state.preferences||{email_enabled:0,lead_days:90};delivery=!!state.email_delivery_active;renderUser();
}
window.addEventListener('cveharbor:account-state',async event=>{
 signed=!!event.detail?.authenticated;
 // Keep selection and custom product fields browsable for everyone.
 // Only account mutations require sign in and the D1 migration.
 updateActions();
 if(!signed){ready=false;logged=[];prefs={email_enabled:0,lead_days:90};delivery=false;renderUser();message('Sign in above to save lifecycle watches and email preferences.');return;}
 try{
  const flags=await call('/status');ready=!!flags.ready;
  if(!ready){message('Cloudflare D1 lifecycle migration is required to save preferences. Product and release browsing remains available.');renderUser();return;}
  await load();message('Saved lifecycle watches loaded from your private account.');
 }catch(e){message(e.message)}
});
$('lifecycleProduct').addEventListener('change',syncCycles);
$('lifecyclePublicSearch').addEventListener('input',renderFeed);
$('lifecycleWatchForm').addEventListener('submit',async event=>{
 event.preventDefault();
 if(!signed||!ready){message('Sign in and deploy the lifecycle D1 migration before saving watches.');return;}
 const button=$('lifecycleWatchSave');button.disabled=true;
 try{
  const watch=getCandidate();
  await call('/watches','POST',watch);
  await load();message('Lifecycle watch saved to your D1 account.');
 }catch(e){message('Cannot save lifecycle watch: '+e.message)}
 finally{button.disabled=false}
});
$('lifecyclePreferencesForm').addEventListener('submit',async event=>{
 event.preventDefault();
 if(!signed||!ready){message('Sign in and complete lifecycle D1 migration first.');return;}
 const enabled=$('lifecycleEmailOptin').checked,lead=Number($('lifecycleLead').value);
 if(enabled&&!window.confirm('Enable lifecycle email notices for the products saved in your watchlist?'))return;
 const button=$('lifecyclePrefsSave');button.disabled=true;
 try{
  await call('/preferences','PUT',{email_enabled:enabled,lead_days:lead});
  await load();message(enabled?'Email preference saved. Scheduled sending requires separate backend activation.':'Lifecycle email notices disabled.');
 }catch(e){message(e.message)}
 finally{button.disabled=false}
});
renderFeed();renderQueue();renderUser();
})();
