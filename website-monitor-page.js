(()=>{'use strict';const API='https://api.cveharbor.com/v1/website-monitor';const $=id=>document.getElementById(id);
const status=(message,error=false)=>{$('monitorStatus').textContent=message;$('monitorStatus').className=error?'monitor-error':'monitor-muted'};
const call=async(path='',method='GET',data)=>{const r=await fetch(API+path,{method,credentials:'include',headers:{'content-type':'application/json'},body:data?JSON.stringify(data):undefined});const b=await r.json();if(!r.ok)throw Error(b.error||'Request failed');return b};
const warningButton=$('webRiskEmailTest');
if(warningButton)warningButton.addEventListener('click',async()=>{
 const result=$('webRiskEmailTestResult');
 warningButton.disabled=true;
 warningButton.textContent='Sending test...';
 result.textContent='Contacting CVEHarbor to send a test warning email.';
 try{
  const response=await call('/test-warning-email','POST');
  result.textContent='SMTP2GO accepted the test email for '+response.recipient+'. Verify it arrived in your inbox.';
  status('Test warning email accepted by the email provider.');
 }catch(error){
  result.textContent='Test warning email failed: '+error.message;
  status('Test warning email failed: '+error.message,true);
 }finally{warningButton.disabled=false;warningButton.textContent='Send test warning email'}
});
const renderUsage=async()=>{try{const u=await call('/web-risk-usage');$('webRiskUsage').textContent='Month '+u.month+' · Your account: '+u.account_used.toLocaleString()+' lookups · Global usage: '+u.global_used.toLocaleString()+' / '+u.global_limit.toLocaleString()+' · Remaining: '+u.global_remaining.toLocaleString()+(u.paused?' · Lookups paused at the monthly limit':'')+(u.warning_sent?' · 90% warning sent':'')}catch{$('webRiskUsage').textContent='Usage reporting is unavailable. Web Risk lookups will pause if quota tracking is unavailable.'}};

const threatState={sites:[],id:''};
function threatBox(title,value,detail){
 const el=document.createElement('article'),strong=document.createElement('strong'),small=document.createElement('small');
 strong.textContent=title+': '+value;small.textContent=detail;el.append(strong,small);return el;
}
async function showThreatAssessment(){
 const site=threatState.sites.find(x=>x.id===threatState.id),panel=$('threatAssessment'),history=$('threatHistory');
 panel.replaceChildren();history.replaceChildren();
 if(!site){$('threatSiteDescription').textContent='Select a registered website.';return}
 $('threatSiteDescription').textContent=site.label+' · '+site.url+' · '+site.profile+' profile';
 $('threatHttp').textContent=site.last_status?'HTTP '+site.last_status:'Not checked';
 $('threatLatest').textContent=site.last_checked_at?new Date(site.last_checked_at*1000).toLocaleString():'Never';
 try{
  const result=await call('/history?id='+encodeURIComponent(site.id)),checks=result.checks||[];
  if(!checks.length){panel.append(threatBox('Reputation','Not checked','Run Check Now to record an assessment.'));history.textContent='No checks recorded.';return}
  const latest=checks[0];let evidence={};try{evidence=JSON.parse(latest.security_headers||'{}')}catch{}
  const risk=evidence.threat_intelligence||{status:'not_recorded',threats:[]};
  $('threatReputation').textContent=risk.status.replaceAll('_',' ');
  $('threatProvider').textContent=risk.status==='not_configured'?'Google Web Risk not configured':'Google Web Risk: '+risk.status.replaceAll('_',' ');
  panel.append(threatBox('Malware and phishing',risk.status==='listed'?'Listed':risk.status==='no_known_listing'?'No known listing':'Unknown','Provider status: '+risk.status+'. A missing listing does not prove a site is safe.'));
  panel.append(threatBox('HTTPS response',latest.http_status?'HTTP '+latest.http_status:'Unavailable',latest.error||'Last response received from the public website'));
  panel.append(threatBox('Security headers',(evidence.http_findings||[]).length+' findings',(evidence.http_findings||[]).map(x=>x.description).join('; ')||'No recorded header issues'));
  panel.append(threatBox('Configuration drift',latest.changed?'Change detected':'No observed change','Response status and selected headers compared with previous check'));
  for(const check of checks.slice(0,10)){let data={};try{data=JSON.parse(check.security_headers||'{}')}catch{}const row=document.createElement('div');row.className='threat-history-row';row.textContent=new Date(check.checked_at*1000).toLocaleString()+' · '+(check.error||'HTTP '+check.http_status)+' · Reputation: '+(data.threat_intelligence?.status||'not recorded');history.append(row)}
 }catch(err){history.textContent='Could not load site history: '+err.message}
}
function updateThreatSites(sites){
 threatState.sites=sites;$('threatSites').textContent=String(sites.length);
 const select=$('threatSiteSelect'),previous=threatState.id;select.replaceChildren();
 for(const site of sites){const option=document.createElement('option');option.value=site.id;option.textContent=site.label;select.append(option)}
 threatState.id=sites.some(x=>x.id===previous)?previous:sites[0]?.id||'';
 select.value=threatState.id;void showThreatAssessment();
}
$('threatSiteSelect').addEventListener('change',()=>{threatState.id=$('threatSiteSelect').value;void showThreatAssessment()});

const render=async()=>{try{const data=await call();const list=$('monitorList');window.dispatchEvent(new CustomEvent('cveharbor-monitor-sites',{detail:data.monitors}));list.replaceChildren();updateThreatSites(data.monitors);if(!data.monitors.length){list.textContent='No websites registered yet.';return}for(const item of data.monitors){const row=document.createElement('div');row.className='monitor-site';const main=document.createElement('div');const name=document.createElement('strong');name.textContent=item.label;const description=document.createElement('p');description.className='monitor-muted';description.textContent=item.url+' · '+item.profile+' · '+(item.last_checked_at?'Checked '+new Date(item.last_checked_at*1000).toLocaleString():'Awaiting first scheduled check')+(item.last_status?' · HTTP '+item.last_status:'')+(item.last_error?' · Check unavailable':'');main.append(name,description);const remove=document.createElement('button');remove.textContent='Remove';remove.type='button';remove.addEventListener('click',async()=>{if(!confirm('Remove this website from monitoring?'))return;try{await call('/'+item.id,'DELETE');await render()}catch(e){status(e.message,true)}});const actions=document.createElement('div');actions.className='monitor-actions';const check=document.createElement('button');check.type='button';check.className='monitor-check-button';check.textContent='Check Now';const details=document.createElement('div');details.className='monitor-check-details monitor-muted';details.textContent='';check.addEventListener('click',async()=>{check.disabled=true;check.textContent='Checking...';try{const result=await call('/'+item.id+'/check','POST');const value=result.check;details.textContent=value.error?'Check failed: '+value.error:'HTTP '+value.http_status+' · '+(value.changed?'Header or status change':'No header or status change')+' · '+new Date(value.checked_at*1000).toLocaleString()+' · Threat intelligence: '+(value.threat_intelligence?.status||'not checked')+(value.threat_intelligence?.threats?.length?' ('+value.threat_intelligence.threats.join(', ')+')':'')+' · HTTP findings: '+(value.http_findings?.length||0);status('Website check completed.');await render();await renderUsage()}catch(e){status(e.message,true);details.textContent=e.message}finally{check.disabled=false;check.textContent='Check Now'}});const history=document.createElement('button');history.type='button';history.className='monitor-history-button';history.textContent='History';history.addEventListener('click',async()=>{try{const result=await call('/history?id='+encodeURIComponent(item.id));details.replaceChildren();if(!result.checks.length){details.textContent='No checks recorded yet.';return}for(const resultItem of result.checks.slice(0,10)){const record=document.createElement('div');let evidence={};try{evidence=JSON.parse(resultItem.security_headers||'{}')}catch{}record.textContent=new Date(resultItem.checked_at*1000).toLocaleString()+' · '+(resultItem.error||('HTTP '+resultItem.http_status))+' · Reputation: '+(evidence.threat_intelligence?.status||'not recorded')+' · Header findings: '+(evidence.http_findings?.length||0)+(resultItem.changed?' · Configuration changed':'');details.append(record)}}catch(e){status(e.message,true)}});actions.append(check,history,remove,details);row.append(main,actions);list.append(row)}}catch(e){$('monitorList').textContent='Unable to load your monitoring sites';status(e.message,true)}};
window.addEventListener('cveharbor-monitor-refresh',()=>void render());
$('monitorForm').addEventListener('submit',async e=>{e.preventDefault();try{await call('','POST',{url:$('monitorUrl').value,label:$('monitorLabel').value,profile:$('monitorProfile').value,authorized:$('monitorAuthorized').checked});$('monitorForm').reset();status('Website registered. Daily checks begin when monitoring is activated.');await render()}catch(error){status(error.message,true)}});
call('/status').then(data=>{status(data.automatic_checks?'Daily monitoring is enabled.':'Registration is available. Automated monitoring is not yet enabled.');return Promise.all([render(),renderUsage()])}).catch(e=>{status(e.message,true);$('monitorForm').querySelector('button').disabled=true;$('monitorList').textContent='Monitoring is not configured yet.'});
})();