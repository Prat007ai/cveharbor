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
 const search=$('lifecyclePublicSearch').value.trim().toLowerCase();
 const sources=catalog.cycles.filter(x=>(x.product+' '+x.cycle).toLowerCase().includes(search)).slice(0,50);
 for(const x of sources){
  const row=make('div','lifecycle-source-row');
  const day=daysTo(x.eol_date);
  const status=day===null?'Verify support date':day<0?'Support ended':day<=90?'Ending soon':'Published support date';
  row.append(make('strong','',itemLabel(x)),make('span','ops-tag',status),
   make('p','ops-note','Security support: '+(x.eol_date||'Not supplied')+
    (x.latest?' · Latest recorded: '+x.latest:'')+
    (x.support_date?' · Active support: '+x.support_date:'')));
  const a=make('a','ops-link','Review lifecycle source');a.href=x.url;a.rel='noopener noreferrer';a.target='_blank';
  row.append(a);results.append(row);
 }
 if(!sources.length)results.append(make('p','ops-note','No covered lifecycle rows found. This is not a statement about vendor support or patch availability.'));
 const failures=(catalog.errors||[]).length;
 $('lifecycleFreshness').textContent='Snapshot: '+(catalog.checked_at||'Unavailable')+
  '. '+failures+' product sources unavailable. Always verify vendor lifecycle terms and editions.';
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
function renderUser(){
 const results=$('lifecycleWatches');results.replaceChildren();
 $('lifecycleWatchCount').textContent=logged.length+' monitored';
 $('lifecycleLead').value=String(prefs.lead_days||90);
 $('lifecycleEmailOptin').checked=!!prefs.email_enabled;
 $('lifecycleDeliveryState').textContent=delivery
  ? 'Automatic lifecycle sending is enabled in the Cloudflare Worker.'
  : 'Saved preferences are not yet sending emails. Scheduled delivery requires activation in Cloudflare.';
 if(!signed||!ready){results.append(make('p','ops-note','Sign in and complete the D1 lifecycle migration to save preferences.'));return;}
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
 for(const control of document.querySelectorAll('#lifecycleMonitor .lifecycle-auth-control'))control.disabled=!signed;
 if(!signed){ready=false;logged=[];prefs={email_enabled:0,lead_days:90};delivery=false;renderUser();message('Sign in above to save lifecycle watches and email preferences.');return;}
 try{
  const flags=await call('/status');ready=!!flags.ready;
  if(!ready){message('Cloudflare D1 lifecycle migration is required. Public lifecycle dates are still visible.');renderUser();return;}
  await load();message('Saved lifecycle watches loaded from your private account.');
 }catch(e){message(e.message)}
});
$('lifecycleProduct').addEventListener('change',syncCycles);
$('lifecyclePublicSearch').addEventListener('input',renderFeed);
$('lifecycleWatchForm').addEventListener('submit',async event=>{
 event.preventDefault();
 if(!signed||!ready){message('Sign in and deploy the lifecycle D1 migration before saving watches.');return;}
 const slug=$('lifecycleProduct').value;
 const product=slug?staticProducts.find(([name])=>name===slug)?.[1]:$('lifecycleCustomName').value.trim();
 const cycle=slug?$('lifecycleCycle').value:$('lifecycleCustomCycle').value.trim();
 const customDate=slug?'':$('lifecycleCustomDate').value;
 const customSource=slug?'':$('lifecycleCustomSource').value.trim();
 if(slug&&!cycle){message('Choose the exact release or cycle to monitor.');return;}
 const button=$('lifecycleWatchSave');button.disabled=true;
 try{
  await call('/watches','POST',{product,slug,cycle,installed_version:$('lifecycleInstalled').value.trim(),custom_eol_date:customDate,custom_source_url:customSource});
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
renderFeed();renderUser();
})();
