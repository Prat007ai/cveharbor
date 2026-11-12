import {$,element,money,api,metric,table,status} from './ai-common.js';
let report,view='organizations',offset=0,loading=false,serial=0;
const personal=()=>$('workspaceType').value==='personal';
const adminBase=()=>'/ai/admin'+(personal()?'/personal':'');
$('workspaceType').onchange=()=>{offset=0;$('organization').replaceChildren(new Option(personal()?'All personal workspaces':'All organizations',''));load();};
$('month').value=new Date().toISOString().slice(0,7);
const dollars=n=>money((n||0)/(report?.units_per_usd||1e12));
function name(primary,secondary){const n=element('div',primary);if(secondary)n.append(element('small',secondary));return n;}
function render(){
 $('tab-organizations').textContent=personal()?'Personal workspaces':'Organizations';$('tab-users').textContent=personal()?'User consumption':'Staff consumption';
 const rows=report[view];$('reportTitle').textContent={organizations:personal()?'Personal workspaces':'Organizations',users:personal()?'User consumption':'Staff consumption',requests:'Requests & holds'}[view];
 $('report').setAttribute('aria-labelledby','tab-'+view);
 let headers,values;
 if(view==='organizations'){
  headers=[personal()?'Personal account':'Organization','Monthly allowance','Consumed','Reserved','Available','Requests','AI access'];
  values=rows.map(o=>{let state=element('span',o.enabled?'Enabled':'Paused','ai-badge');
   if(report.platform_owner){state=element('button',o.enabled?'Pause':'Enable');state.className='secondary';state.disabled=loading||(!o.enabled&&(!report.inference_enabled||!report.price_current));state.onclick=async()=>{if(!confirm((o.enabled?'Pause':'Enable')+' AI for '+o.name+'? The '+(personal()?'personal':'shared')+' monthly allowance remains $20 USD.'))return;await mutate(adminBase()+(personal()?'/accounts':'/organizations'),{org:o.id,enabled:!o.enabled});};}
   const link=element('button',o.name,'secondary');link.onclick=()=>{let option=[...$('organization').options].find(x=>x.value===o.id);if(!option){option=new Option(o.name,o.id);$('organization').add(option);}$('organization').value=o.id;offset=0;load();};
   return [link,'$20.00 USD',dollars(o.spent),dollars(o.reserved),dollars(20e12-o.spent-o.reserved),o.requests,state];});
 }else if(view==='users'){
  headers=[personal()?'User':'Staff member',personal()?'Personal workspace':'Organization','Requests','Consumed','Reserved','Input / output tokens'];values=rows.map(u=>[u.email||'Former account',u.organization,u.requests,dollars(u.spent),dollars(u.reserved),u.input_tokens.toLocaleString()+' / '+u.output_tokens.toLocaleString()]);
 }else{
  headers=['Request / user',personal()?'Personal workspace':'Organization','Feature / model','Status','Consumed / reserved','Tokens in / out','Time (UTC)'];
  values=rows.map(r=>[name(r.email||'Former account',r.id),r.organization,name(r.feature,r.model),name('',r.reason),dollars(r.charged)+' / '+dollars(['held','reserved','dispatched'].includes(r.state)?r.reservation:0),(r.input_tokens??'—')+' / '+(r.output_tokens??'—'),new Date(r.created_at*1000).toISOString().replace('T',' ').slice(0,19)]);
  rows.forEach((r,i)=>values[i][3].prepend(element('span',r.state,'ai-badge '+r.state)));
 }
 $('table').replaceChildren(rows.length?table(headers,values):element('p','No usage records for this selection.'));
 $('previous').disabled=loading||offset===0;$('next').disabled=loading||rows.length<50;
 $('pageLabel').textContent=rows.length?'Showing '+(offset+1)+'–'+(offset+rows.length):'No records';
}
async function load(){
 const current=++serial;loading=true;status('Refreshing usage…');
 $('table').replaceChildren(element('p','Loading usage…'));
 try{
  const params=new URLSearchParams({month:$('month').value,org:$('organization').value,offset:String(offset)});
  const result=await api(adminBase()+'/usage?'+params);if(current!==serial)return;report=result;
  const s=report.states,requests=s.reduce((n,r)=>n+r.requests,0),blocked=s.find(r=>r.state==='blocked')?.requests||0;
  $('metrics').replaceChildren(metric('Consumed',dollars(report.totals.spent),'Recorded usage · USD'),metric('Reserved',dollars(report.totals.reserved),'In progress or awaiting reconciliation'),metric('Requests',requests.toLocaleString(),blocked+' blocked by allowance'),metric(personal()?'Personal workspaces':'Organizations',report.totals.organizations.toLocaleString(),personal()?'One $20 allowance per user':'One shared $20 allowance each'));
  const max=Math.max(1,...report.daily.map(d=>d.spent));$('daily').replaceChildren();
  const [year,month]=report.month.split('-').map(Number),days=new Date(Date.UTC(year,month,0)).getUTCDate();
  for(let day=1;day<=days;day++){const key=report.month+'-'+String(day).padStart(2,'0'),d=report.daily.find(r=>r.day===key)||{spent:0,requests:0};const slot=element('div',undefined,'ai-day'),bar=element('div',undefined,'ai-bar');bar.style.height=Math.max(2,90*d.spent/max)+'px';slot.title=key+': '+dollars(d.spent)+' · '+d.requests+' requests';slot.append(bar,element('small',day===1||day%5===0||day===days?day:'\u00a0'));$('daily').append(slot);}
  $('daily').setAttribute('aria-label',report.daily.map(d=>d.day+' '+dollars(d.spent)).join('; ')||'No recorded consumption');
  for(const o of report.organizations)if(![...$('organization').options].some(x=>x.value===o.id))$('organization').add(new Option(o.name,o.id));
  $('dashboard').hidden=false;$('ownerControls').hidden=!report.platform_owner;
  $('configuration').textContent='Monthly reset: 00:00 UTC on the first. No rollover or overage. Price review due '+report.price.validUntil.slice(0,10)+'. Inference '+(report.inference_enabled&&report.price_current?'available for enabled workspaces.':'paused.');
  loading=false;render();status('Usage refreshed.');
 }catch(error){if(current!==serial)return;status(error.status===401?'Sign in to CVEHarbor first.':error.message);if([401,403,404].includes(error.status)){$('dashboard').hidden=true;report=null;}}
 finally{if(current===serial)loading=false;}
}
async function admins(){const data=await api('/ai/admin/access');$('adminList').textContent=data.admins.length?'Dashboard viewers: '+data.admins.map(a=>a.email).join(', '):'No additional dashboard viewers.';}
async function mutate(path,data){try{await api(path,'POST',data);await load();if(report?.platform_owner)await admins();status('Change saved.');}catch(e){status(e.message);}}
$('filters').onsubmit=e=>{e.preventDefault();offset=0;load();};
document.querySelectorAll('[data-view]').forEach(btn=>btn.onclick=()=>{view=btn.dataset.view;offset=0;document.querySelectorAll('[data-view]').forEach(b=>b.setAttribute('aria-selected',String(b===btn)));load();});
$('previous').onclick=()=>{offset=Math.max(0,offset-50);load();};$('next').onclick=()=>{offset+=50;load();};
$('accessForm').onsubmit=async e=>{e.preventDefault();if(confirm('Apply '+$('adminAction').value+' for '+$('adminEmail').value+' to the platform AI dashboard?'))await mutate('/ai/admin/access',{action:$('adminAction').value,email:$('adminEmail').value});};
$('reconcileForm').onsubmit=async e=>{e.preventDefault();if(!confirm('Record these verified usage figures and release the unused reservation?'))return;await mutate(adminBase()+'/reconcile',{request_id:$('holdId').value,evidence:$('holdEvidence').value,usage:{input_tokens:Number($('holdInput').value),output_tokens:Number($('holdOutput').value),cached_input_tokens:Number($('holdCached').value),reasoning_tokens:Number($('holdReasoning').value)}});};
try{const caps=await api('/ai/capabilities');if(!caps.admin)status('This dashboard is available only to CVEHarbor platform administrators.');else{await load();if(caps.platform_owner)await admins();}}catch(e){status(e.status===401?'Sign in to CVEHarbor first.':e.message);}
