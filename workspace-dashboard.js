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
  const response=await request('/inventory');
  const environments=Array.isArray(response)?response:(response.environments||[]);
  set('wsEnvironments',String(environments.length),'wsEnvironmentHint','Saved in your account');
 }catch{set('wsEnvironments','—','wsEnvironmentHint','View environments to check')}
 set('wsCritical','—','wsCriticalHint','Requires validated matching');
}
async function loadPublic(){
 const target=$('wsRecentCves');
 try{
  const response=await fetch('/feed-health.json',{cache:'no-store'});
  if(!response.ok)throw Error('feed unavailable');
  const feed=await response.json();
  const indexed=Number(feed.records_indexed);
  if(!Number.isFinite(indexed)||indexed<0)throw Error('invalid feed data');
  set('wsAdvisories',indexed.toLocaleString(),'wsAdvisoriesHint','Indexed public advisory records');
  target.replaceChildren();
  const p=document.createElement('p');
  p.textContent='The public advisory index currently contains '+indexed.toLocaleString()+' records. Open Vulnerabilities to search the current feed.';
  target.append(p);
  addRow(target,'Browse published CVEs','Review severity, vendor references and affected software','/vulnerabilities/');
  if(feed.coverage_limited){
   const note=document.createElement('p');
   note.textContent='The advisory index has a coverage limit and is not a complete vulnerability database.';
   target.append(note);
  }
 }catch{
  set('wsAdvisories','—','wsAdvisoriesHint','Feed unavailable');
  target.textContent='Published advisory data is temporarily unavailable. Browse the public Vulnerabilities page.';
 }
}
let loaded=false;
function start(){if(loaded||!$('workspaceAccess')||$('workspaceAccess').hidden)return;loaded=true;void loadPrivate();void loadPublic()}
window.addEventListener('cveharbor-auth-change',event=>{if(event.detail?.authenticated)start()});
fetch(API+'/me',{credentials:'include',cache:'no-store'}).then(r=>r.ok?r.json():null).then(x=>{if(x?.authenticated){setTimeout(start,0);window.setTimeout(start,600)}}).catch(()=>{});
})();