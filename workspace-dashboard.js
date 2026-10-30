(()=>{'use strict';
const $=id=>document.getElementById(id);
const API='https://api.cveharbor.com/v1';
const request=async path=>{const response=await fetch(API+path,{credentials:'include',cache:'no-store',headers:{Accept:'application/json'}});if(!response.ok)throw Error('Unavailable');return response.json()};
const set=(id,value,hintId,hint)=>{const node=$(id);if(node)node.textContent=value;if(hintId&&$(hintId))$(hintId).textContent=hint};
const addRow=(parent,title,detail,url)=>{const a=document.createElement('a');a.href=url;a.className='workspace-feed-row';const strong=document.createElement('strong'),small=document.createElement('small');strong.textContent=title;small.textContent=detail;a.append(strong,small);parent.append(a)};
async function loadPrivate(){
 try{
  const rem=await request('/remediations');
  const records=Array.isArray(rem.remediations)?rem.remediations:[];
  const open=records.filter(x=>!['Remediated','Not Applicable','Accepted Risk'].includes(x.status)).length;
  set('wsOpenRemediation',String(open),'wsRemediationHint',records.length+' tracked records');
  const target=$('wsRecentRemediation');target.replaceChildren();
  for(const item of records.slice(0,5))addRow(target,item.id,(item.status||'Open')+' · '+(item.owner||'Unassigned')+' · '+(item.due?'Due '+item.due:'No target date'),'/remediation/#remediationTracker');
  if(!records.length)target.textContent='No remediation records saved yet.';
 }catch{set('wsOpenRemediation','—','wsRemediationHint','Unavailable');$('wsRecentRemediation').textContent='Remediation records are temporarily unavailable.'}
 try{
  const response=await request('/inventory/environments');
  const environments=Array.isArray(response)?response:(response.environments||[]);
  set('wsEnvironments',String(environments.length),'wsEnvironmentHint','Saved in your account');
 }catch{set('wsEnvironments','—','wsEnvironmentHint','View environments to check')}
 set('wsCritical','—','wsCriticalHint','Requires validated matching');
}
async function loadPublic(){
 try{
  const response=await fetch('/data.js',{cache:'no-store'});if(!response.ok)throw Error('feed');
  const text=await response.text();
  const matches=[...text.matchAll(/CVE-\d{4}-\d{4,}/g)];
  const unique=[...new Set(matches.map(m=>m[0]))];
  set('wsAdvisories',unique.length?String(unique.length):'—','wsAdvisoriesHint','Published CVEs in feed snapshot');
  const container=$('wsRecentCves');container.replaceChildren();
  for(const id of unique.slice(0,5))addRow(container,id,'Review current advisory and affected products','/vulnerabilities/?q='+encodeURIComponent(id));
  if(!unique.length)container.textContent='No indexed CVEs available in the current feed snapshot.';
 }catch{$('wsRecentCves').textContent='Published feed is temporarily unavailable.'}
}
function start(){if(!$('workspaceAccess')||$('workspaceAccess').hidden)return;loadPrivate();loadPublic()}
window.addEventListener('cveharbor-auth-change',event=>{if(event.detail?.authenticated)start()});
fetch(API+'/me',{credentials:'include',cache:'no-store'}).then(r=>r.ok?r.json():null).then(x=>{if(x?.authenticated)setTimeout(start,0)}).catch(()=>{});
})();