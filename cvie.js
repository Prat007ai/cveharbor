(function(){
'use strict';
const API='https://api.cveharbor.com/v1/cvie';
let products=[],records=[],months=3,error='',ready=false,signedIn=false,timer=null,busy=false,pending=false,pendingSync=false;
const panels=[];
let lastSignature='';
const node=(tag,value,cls)=>{const el=document.createElement(tag);if(value)el.textContent=value;if(cls)el.className=cls;return el;};
const normalize=value=>String(value||'').normalize('NFKC').trim().toLowerCase().replace(/\s+/g,' ');
function merge(base=[]){
 const result=new Map();
 for(const record of [...base,...records]){
  const prior=result.get(record.id);
  if(!prior){result.set(record.id,{...record});continue;}
  const source=new Map([...(prior.sources||[]),...(record.sources||[])].map(x=>[x.url,x]));
  result.set(record.id,{...prior,...record,known_exploited:!!(prior.known_exploited||record.known_exploited),
   categories:[...new Set([...(prior.categories||[]),...(record.categories||[])])],
   cvie_products:[...new Set([...(prior.cvie_products||[]),...(record.cvie_products||[])])],
   cvie_identities:[...(prior.cvie_identities||[]),...(record.cvie_identities||[])],
   affected_cpes:[...(prior.affected_cpes||[]),...(record.affected_cpes||[])],sources:[...source.values()]});
 }
 return [...result.values()];
}
function statusFor(p){
 if(!p)return 'Waiting for CVIE registration';
 if(p.status==='needs_identity')return 'Choose the exact product';
 if(p.status==='retrying')return 'Source unavailable · retry scheduled';
 if(p.status==='queued')return 'Queued · preparing vulnerability scan';
 if(p.status==='scanning')return months===3&&p.recent_complete_at?'3-month results ready · preparing older history':'Scanning and preparing vulnerabilities';
 if(p.stale)return 'Saved results · source check overdue';
 const count=months===12?p.history_count:p.recent_count;
 const complete=months===12?p.history_complete_at:p.recent_complete_at;
 return complete?(count?count+' advisories · last '+months+' months':'No published advisories found in '+months+' months'):'Preparing '+months+'-month history';
}
function notify(){const signature=JSON.stringify([months,records]);const recordsChanged=signature!==lastSignature;lastSignature=signature;draw();window.dispatchEvent(new CustomEvent('cvie:updated',{detail:{recordsChanged}}));}
async function request(path='',options={}){
 const response=await fetch(API+path,{credentials:'include',headers:{Accept:'application/json',...(options.body?{'Content-Type':'application/json'}:{})},...options});
 if(response.status===401){signedIn=false;products=[];records=[];ready=false;throw Error('Sign in to use private CVIE monitoring.');}
 signedIn=true;
 const data=await response.json();
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
  panel.hidden=!signedIn;if(!signedIn)continue;panel.replaceChildren();
  const header=node('div','','cvie-panel-head'),title=node('div');
  title.append(node('strong','CVIE · Vulnerability Intelligence Engine'),node('p','Source-backed product history, matched by affected product identity.','cvie-caption'));
  const label=node('label','History '),select=node('select');select.setAttribute('aria-label','CVIE vulnerability history');
  for(const n of [3,12]){const option=node('option','Last '+n+' months');option.value=String(n);select.append(option);}select.value=String(months);
  select.addEventListener('change',()=>{months=Number(select.value);void refresh();});label.append(select);
  const button=node('button','Refresh status');button.type='button';button.disabled=busy;button.addEventListener('click',()=>void refresh(true));
  header.append(title,label,button);panel.append(header);
  const active=products.filter(p=>['queued','scanning','retrying'].includes(p.status));
  const message=error||(!ready?'Preparing CVIE...':!products.length?'Add a product or register an asset to start CVIE.':products.some(p=>p.status==='needs_identity')?'Some products need an exact identity before CVIE can scan. Expand product status to choose.':active.length?active.length+' product'+(active.length===1?' is':'s are')+' being prepared. Results appear as source pages finish.':'Product checks complete. Review the source and installed version before acting.');
  const status=node('p',message,'cvie-status');status.setAttribute('role','status');panel.append(status);
  const list=node('div','','cvie-product-statuses');
  for(const p of products){
   const row=node('div','','cvie-product-status');
   row.append(node('strong',p.name),node('span',statusFor(p),'cvie-state '+p.status));
   if(p.last_success_at)row.append(node('small','Last successful source page: '+new Date(p.last_success_at).toLocaleString()));
   if(p.status==='scanning'&&p.progress?.windows_total)row.append(node('small',p.progress.windows_complete+' of '+p.progress.windows_total+' history windows complete'+(p.progress.records_in_window!==null?' · '+p.progress.records_checked+' of '+p.progress.records_in_window+' source records in this window':'')));
   if(p.error)row.append(node('small',p.error));
   if(p.candidates?.length){
    const choose=node('select');choose.setAttribute('aria-label','Product identity for '+p.name);
    choose.append(node('option','Select the correct vendor and product'));
    for(const item of p.candidates){const o=node('option',item.label);o.value=item.cpe;choose.append(o);}
    choose.options[0].value='';
    choose.addEventListener('change',async()=>{if(!choose.value)return;choose.disabled=true;try{await request('/products/'+p.id+'/identity',{method:'PUT',body:JSON.stringify({cpe:choose.value})});await refresh();}catch(e){error=e.message;notify();}});
    row.append(choose);
   }
   list.append(row);
  }
  if(products.length){const details=node('details');details.append(node('summary','Product scan status ('+products.length+')'),list);panel.append(details);}
  panel.append(node('p','Coverage: NVD affected-product records published in the selected period. A completed check with no results does not establish that a product is secure.','cvie-caption'));
 }
}
async function refresh(sync=false){
 if(busy){pending=true;pendingSync=pendingSync||sync;return;}busy=true;clearTimeout(timer);draw();
 const requestedMonths=months;
 try{
  if(sync)await request('/sync',{method:'POST',body:'{}'});
  const state=await request();products=state.products||[];ready=state.ready;error='';
  const incoming=[];let after='';
  do{
   const page=await request('/advisories?months='+requestedMonths+(after?'&after='+encodeURIComponent(after):''));
   incoming.push(...(page.advisories||[]));
   if(page.next&&page.next===after)throw Error('CVIE pagination stalled. Saved results remain available.');
   after=page.next||'';
  }while(after);
  if(requestedMonths===months){records=incoming;notify();}else pending=true;
 }catch(e){error=e.message;notify();}
 finally{
  busy=false;draw();
  if(pending){const syncNext=pendingSync;pending=false;pendingSync=false;timer=setTimeout(()=>void refresh(syncNext),250);}
  else if(signedIn)timer=setTimeout(()=>void refresh(),products.some(p=>['queued','scanning'].includes(p.status))?8000:60000);
 }
}
window.CVEHARBOR_CVIE={get products(){return products;},get records(){return merge();},get months(){return months;},get ready(){return ready;},get signedIn(){return signedIn;},merge,refresh,statusFor,
 setMonths:value=>{if(![3,12].includes(Number(value)))throw Error('Select 3 or 12 months');months=Number(value);return refresh();},
 product:name=>products.find(p=>normalize(p.name)===normalize(name))};
mount();
window.addEventListener('cveharbor:inventory-loaded',()=>void refresh(true));
window.addEventListener('cveharbor:account-state',()=>void refresh(true));
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible'&&signedIn)void refresh();});
if(typeof fetch==='function')void refresh(true);
})();
