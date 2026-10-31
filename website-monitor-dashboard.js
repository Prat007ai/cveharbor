(()=>{'use strict';
const $=id=>document.getElementById(id),api='https://api.cveharbor.com/v1/website-monitor';let sites=[],selected='';
const set=(id,text)=>{if($(id))$(id).textContent=text};
const get=async path=>{const res=await fetch(api+path,{credentials:'include',cache:'no-store'});if(!res.ok)throw Error('Assessment unavailable');return res.json()};
const format=time=>time?new Date(time*1000).toLocaleString():'Not yet checked';
function tableRow(values){const tr=document.createElement('tr');for(const v of values){const td=document.createElement('td');td.textContent=v;tr.append(td)}return tr}
async function loadSite(){
 const site=sites.find(x=>x.id===selected);if(!site)return;
 set('mockSiteName',site.label);set('mockProfile',site.profile==='enhanced'?'Enhanced':'Basic');
 set('mockProfilePill',site.profile==='enhanced'?'Enhanced':'Basic');set('mockSiteCount',sites.length+' registered website(s)');
 set('mockSiteStatus',site.last_error?'Last check encountered an error':site.last_checked_at?'Last check recorded':'Awaiting first check');
 set('mockAvailability',site.last_status?'HTTP '+site.last_status:'Not checked');
 set('mockAvailabilityDetail',site.last_error||'Observed public HTTPS response');
 const tbody=$('mockRecentChecks');tbody.replaceChildren();
 try{
  const response=await get('/history?id='+encodeURIComponent(site.id)),checks=response.checks||[];
  if(!checks.length){tbody.append(tableRow(['No checks yet','CVEHarbor','Not checked','Use Check Now to begin']));set('mockMalware','Not checked');set('mockPhishing','Not checked');set('mockUnwanted','Not checked');return}
  const latest=checks[0];let evidence={};try{evidence=JSON.parse(latest.security_headers||'{}')}catch{}
  const risk=evidence.threat_intelligence||{status:'not_recorded',threats:[]},listed=risk.threats||[];
  const label=type=>risk.status==='listed'?(listed.includes(type)?'Listed':'Not listed'):risk.status==='no_known_listing'?'No known listing':risk.status==='not_configured'?'Not configured':'Not assessed';
  set('mockMalware',label('MALWARE'));set('mockPhishing',label('SOCIAL_ENGINEERING'));set('mockUnwanted',label('UNWANTED_SOFTWARE'));
  set('mockHeaderNotes',Array.isArray(evidence.http_findings)?'HTTP header observations: '+evidence.http_findings.length+' (these are not malware detections).':'HTTP header findings are not available for this check.');
  for(const check of checks.slice(0,8)){
   let item={};try{item=JSON.parse(check.security_headers||'{}')}catch{}
   const threat=item.threat_intelligence?.status||'not recorded';
   tbody.append(tableRow([format(check.checked_at),'CVEHarbor / Web Risk',threat.replaceAll('_',' '),check.error||('HTTP '+(check.http_status??'N/A')+(check.changed?' · Configuration changed':''))]));
  }
 }catch{tbody.append(tableRow(['—','CVEHarbor','Unavailable','Unable to load assessment history']))}
}
async function load(){
 try{const response=await get();sites=response.monitors||[];set('mockSiteCount',sites.length+' registered website(s)');
 const picker=$('threatSiteSelect');picker.replaceChildren();
 if(!sites.length){const option=document.createElement('option');option.textContent='No registered websites';picker.append(option);set('mockSiteName','No website registered');return}
 for(const site of sites){const o=document.createElement('option');o.value=site.id;o.textContent=site.label;picker.append(o)}
 selected=sites.some(x=>x.id===selected)?selected:sites[0].id;picker.value=selected;await loadSite();
 }catch{set('mockSiteStatus','Unable to load registered sites')}
}
$('threatSiteSelect').addEventListener('change',event=>{selected=event.target.value;void loadSite()});
$('mockSettings').addEventListener('click',()=>{$('mockManage').open=true;$('mockManage').scrollIntoView({behavior:'smooth',block:'start'})});
$('mockHistory').addEventListener('click',()=>{$('mockRecentChecks').closest('.monitor-panel').scrollIntoView({behavior:'smooth',block:'start'})});
$('mockCheckNow').addEventListener('click',async()=>{const site=sites.find(x=>x.id===selected);if(!site)return;const button=$('mockCheckNow');button.disabled=true;button.textContent='Checking...';try{const target=[...document.querySelectorAll('#monitorList .monitor-site')].find(x=>x.textContent.includes(site.url));const sourceButton=target?.querySelector('.monitor-check-button');if(sourceButton){sourceButton.click()}else{const res=await fetch(api+'/'+site.id+'/check',{method:'POST',credentials:'include'});const body=await res.json();if(!res.ok)throw Error(body.error||'Check failed')};set('mockSiteStatus','Check requested. Refreshing results.');setTimeout(()=>void load(),1500)}catch(e){set('mockSiteStatus',e.message)}finally{button.disabled=false;button.textContent='⌕ Check Now'}});
void load();
})();