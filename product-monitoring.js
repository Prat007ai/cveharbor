(()=>{
'use strict';
const root=document.getElementById('lifecycleMonitor');if(!root)return;
const $=id=>document.getElementById(id),make=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=String(text);if(cls)e.className=cls;return e;};
let state={watches:[],enhanced:false,flags:{}},epoch=0,activeTab='watchlist';
const base='https://api.cveharbor.com/v1/monitoring';
async function request(path,options={}){const current=epoch;const r=await fetch(base+path,{credentials:'include',headers:{'Content-Type':'application/json'},...options});const data=await r.json();if(current!==epoch)throw Error('Account changed; private response discarded');if(!r.ok)throw Error(data.error||'Monitoring service unavailable');return data;}
function metrics(){
 const catalog=window.CVEHARBOR_LIFECYCLE||{},cycles=catalog.cycles||[],now=Date.now();
 const directory=new Set([...(catalog.available_products||[]),...cycles.map(c=>c.slug)]).size;
 const upcoming=cycles.filter(c=>{const d=Date.parse(c.eol_date);return Number.isFinite(d)&&d>=now&&d-now<=365*86400000}).length;
 const recent=cycles.filter(c=>{const d=Date.parse(c.latest_release_date);return Number.isFinite(d)&&d<=now&&now-d<=30*86400000}).length;
 const panel=$('lifecycleMetrics');if(!panel)return;panel.replaceChildren();
 for(const [icon,value,label] of [['◇',directory||'—','Products in reference directory'],['◷',cycles.length?upcoming:'—','Published support ends · next year'],['↻',cycles.length?recent:'—','Recorded releases · last 30 days'],['♧',state.watches.length,'My saved product watches']]){const card=make('article',undefined,'lifecycle-metric'),body=make('div');body.append(make('strong',value),make('small',label));card.append(make('span',icon),body);panel.append(card);}
}
function activation(){
 const node=$('productMonitorActivation'),health=state.scheduler||state.flags.scheduler||{};
 const operating=state.enhanced&&health.operating;
 node.classList.toggle('is-operating',!!operating);
 node.textContent=operating?'Scheduled product monitoring is operating'+(state.flags.delivery_enabled?' · email delivery enabled':' · email delivery not enabled'):'Monitoring Not Yet Active · '+(!state.enhanced?'Enhanced backend setup awaits approval. Existing preferences remain saved.':health.enabled?'No recent successful scheduled run has been verified.':'Scheduled checks await approved activation.');
 $('productMonitorRecipient').textContent=state.recipient||'Sign in to view your verified recipient';
 $('productMonitorTest').disabled=!state.enhanced||!state.flags.test_allowed;
 const admin=root.querySelector('[data-monitor-tab="admin"]');admin.hidden=!state.flags.admin;
 if(activeTab==='admin'&&!state.flags.admin)showTab('watchlist');
}
function showTab(tab){
 activeTab=tab;for(const el of root.querySelectorAll('[data-monitor-view]'))el.hidden=el.dataset.monitorView!==tab;
 for(const button of root.querySelectorAll('[data-monitor-tab]'))button.setAttribute('aria-pressed',String(button.dataset.monitorTab===tab));
 if(tab==='history')void history();if(tab==='admin')void health();
}
async function history(){
 const target=$('productMonitorHistory');target.replaceChildren();
 if(!state.enhanced){target.textContent='Delivery history is not active yet. Saved legacy preferences do not imply that an email was sent.';return;}
 target.textContent='Loading private delivery history…';
 try{
  const data=await request('/history');target.replaceChildren();
  if(!data.history.length)target.append(make('p','No notifications have been created for this account.'));
  for(const item of data.history){const card=make('article');card.append(make('strong',item.event.product+' · '+item.event.branch),make('p',item.kind+' · '+(item.delivery_state||item.notification_state)),make('p','Created: '+new Date(item.created_at).toLocaleString()));if(item.provider_id)card.append(make('p','SMTP2GO message: '+item.provider_id));if(item.submitted_at)card.append(make('p','Accepted: '+new Date(item.submitted_at).toLocaleString()));if(item.delivered_at)card.append(make('p','Recipient server acknowledged: '+new Date(item.delivered_at).toLocaleString()));if(item.detail)card.append(make('p',item.detail));const url=item.event.source_url;try{const safe=new URL(url);if(safe.protocol==='https:'){const link=make('a','Original vendor source','ops-link');link.href=safe.href;link.target='_blank';link.rel='noopener noreferrer';card.append(link)}}catch{}target.append(card);}
 }catch(error){target.textContent=error.message;}
}
async function health(){
 const target=$('productMonitorHealth');if(!state.enhanced||!state.flags.admin){target.textContent='Administrator configuration required.';return;}
 try{const data=await request('/admin');target.replaceChildren();target.append(make('p',data.attention?'Attention required: inspect source freshness, backlog or failed deliveries.':'No current monitoring health alerts.'));target.append(make('p','Pending notifications: '+data.pending.count));for(const source of data.sources){const card=make('article');card.append(make('strong',source.id),make('p','Last successful check: '+(source.last_success_at?new Date(source.last_success_at).toLocaleString():'Never')),make('p','Source failures: '+source.failures+(source.error?' · '+source.error:'')));target.append(card);}for(const message of data.messages.slice(0,20)){const card=make('article');card.append(make('strong',message.state),make('p','Attempts: '+message.attempts+' · '+(message.provider_id||'No provider ID')),make('p',message.detail));target.append(card);}}catch(error){target.textContent=error.message;}
}
for(const button of root.querySelectorAll('[data-monitor-tab]'))button.addEventListener('click',()=>showTab(button.dataset.monitorTab));
$('productMonitorHistoryRefresh').addEventListener('click',()=>void history());$('productMonitorHealthRefresh').addEventListener('click',()=>void health());
$('productMonitorTest').addEventListener('click',async()=>{const button=$('productMonitorTest'),result=$('productMonitorTestResult');button.disabled=true;try{const r=await request('/test-email',{method:'POST',body:JSON.stringify({})});result.textContent='SMTP2GO accepted test '+r.provider_id+'. Delivery is not yet confirmed; check Delivery History.';}catch(error){result.textContent=error.message;}finally{button.disabled=!state.flags.test_allowed;}});
window.addEventListener('lifecycle:loaded',event=>{state=event.detail;metrics();activation();if(activeTab==='history')void history();});
window.addEventListener('cveharbor:account-state',()=>{epoch++;state={watches:[],enhanced:false,flags:{}};$('productMonitorHistory').replaceChildren();$('productMonitorHealth').replaceChildren();metrics();activation();});
metrics();activation();
})();
