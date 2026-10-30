(() => {
'use strict';
const $=id=>document.getElementById(id);
if(!$('operationsCentre'))return;
const key='cveharbor.remediation.v1',API='https://api.cveharbor.com/v1',
  src=window.CVEHARBOR_DATA||{},base=window.CVEHARBOR_CATALOG||{},threats=window.CVEHARBOR_THREATS||{};
const elem=(tag,cls,value)=>{const x=document.createElement(tag);if(cls)x.className=cls;if(value!==undefined)x.textContent=String(value);return x;};
const valid=id=>/^CVE-\d{4}-\d{4,}$/i.test(String(id||''))&&String(id).length<=28;
const records=new Map();
for(const x of [...(base.advisories||[]),...(src.advisories||[])])if(x?.id)records.set(x.id,x);
const readLegacy=()=>{
  try{
    const saved=JSON.parse(localStorage.getItem(key)||'[]');
    return Array.isArray(saved)?saved.filter(x=>x&&valid(x.id)).slice(0,250):[];
  }catch(_){return [];}
};
let legacy=readLegacy(),tasks=[...legacy],cloudMode=false,authenticated=false,
  accountEmail='',capabilities=null,imported=false;
const msg=value=>{$('remediationMessage').textContent=value};
const storage=value=>{$('remediationStorage').textContent=value};
async function api(path,method='GET',payload){
  const res=await fetch(API+path,{
    method,credentials:'include',headers:{'Content-Type':'application/json'},
    body:payload===undefined?undefined:JSON.stringify(payload)
  });
  let data={};try{data=await res.json()}catch(_){}
  if(!res.ok){const error=Error(data.error||'Cloud account service unavailable');error.status=res.status;throw error;}
  return data;
}
function persistLegacy(){
  try{localStorage.setItem(key,JSON.stringify(tasks));legacy=readLegacy();
    storage('These records are currently stored in this browser only. Sign in and enable the D1 tracker to use cloud storage.');
  }catch(_){storage('Browser storage unavailable. Export your records before leaving.');}
}
function uiMode(){
  const btn=$('remediationImport');
  btn.hidden=!cloudMode||!legacy.length||imported;
  if(cloudMode){
    storage('Your remediation records are saved in your private Cloudflare D1 account. This device is not the main record store. Assignment emails use approved organization domains.');
  }else if(authenticated){
    storage('The updated cloud remediation API is not deployed yet. Existing browser tracking is still available until the Worker is upgraded.');
  }else{
    storage('Records are currently local to this browser. Sign in above to save and manage remediations in Cloudflare D1.');
  }
}
function editRecord(task){
  $('remediationCve').value=task.id;
  $('remediationStatus').value=task.status||'Open';
  $('remediationOwner').value=task.owner||'';
  $('remediationDue').value=task.due||'';
  $('remediationNotes').value=task.notes||'';
  msg(task.id+' loaded for editing. Save to update this record.');
  $('remediationCve').focus();
}
function render(){
  const target=$('remediationRows');target.replaceChildren();
  $('remediationCount').textContent=tasks.length+' tracked';
  if(!tasks.length){target.append(elem('p','ops-note',cloudMode?'No records in your D1 account yet. Open a CVE and choose Assign, or add an ID below.':'No CVEs tracked yet. Add an ID below.'));uiMode();return;}
  for(const task of tasks){
    const row=elem('article','ops-result'),head=elem('div','ops-result-top');
    head.append(elem('strong','',task.id),elem('span','ops-tag',task.status));
    const edit=elem('button','ops-remove','Edit');edit.type='button';
    edit.addEventListener('click',()=>editRecord(task));head.append(edit);
    const assign=elem('button','ops-download remediation-row-assign','Assign');
    assign.type='button';assign.addEventListener('click',()=>openAssign(task.id));head.append(assign);
    const remove=elem('button','ops-remove','Remove');remove.type='button';
    remove.addEventListener('click',async()=>{
      if(!window.confirm('Remove '+task.id+' from '+(cloudMode?'your private D1 tracker':'this browser')+'?'))return;
      if(cloudMode){
        remove.disabled=true;
        try{await api('/remediations/'+task.id,'DELETE');await refreshRecords();msg(task.id+' removed from your D1 account.')}
        catch(error){msg('Unable to remove record: '+error.message)}
        finally{remove.disabled=false}
      }else{
        tasks=tasks.filter(x=>x.id!==task.id);persistLegacy();render();
        msg(task.id+' removed from this browser.');
      }
    });head.append(remove);row.append(head);
    row.append(elem('p','', 'Owner: '+(task.owner||'Unassigned')+' · Target: '+(task.due||'None')+' · Updated: '+(task.updated||'Unknown')));
    if(task.assigned_to)row.append(elem('p','remediation-assignee','Assigned by email to: '+task.assigned_to+' · Notification: '+(task.assignment_status||'Unknown')));
    if(task.notes)row.append(elem('p','',task.notes));
    if(records.has(task.id))row.append(elem('p','ops-note',records.get(task.id).title||'Indexed vulnerability'));
    target.append(row);
  }
  uiMode();
}
async function refreshRecords(){
  if(!cloudMode)return;
  const data=await api('/remediations');
  tasks=(data.remediations||[]).filter(x=>valid(x.id)).slice(0,250);
  render();
}
async function accountState(data){
  authenticated=!!data.authenticated;accountEmail=authenticated?(data.email||''):'';
  if(!authenticated){
    cloudMode=false;capabilities=null;tasks=readLegacy();legacy=[...tasks];
    imported=false;render();
    return;
  }
  try{
    const features=await api('/remediations/features');
    if(features.storage!=='d1'||features.version!==2)throw Error('Updated cloud service is not available');
    capabilities=features;cloudMode=true;
    await refreshRecords();
    msg('Signed in. Your remediation records are managed in your Cloudflare D1 account.');
  }catch(_){
    cloudMode=false;capabilities=null;tasks=readLegacy();render();
    msg('The updated Cloudflare remediation API is not ready. Local records are still available until backend deployment.');
  }
}
function openAssign(id){
  const cve=String(id||'').trim().toUpperCase();
  if(!valid(cve)){msg('Enter a complete CVE ID before assigning.');return;}
  const modal=$('remediationAssignDialog');
  if(!modal)return;
  $('remediationAssignCve').value=cve;
  $('remediationAssignConfirm').checked=false;
  $('remediationAssignEmail').value='';
  $('remediationAssignNotes').value='';
  $('remediationAssignNotesCount').textContent='0/1000 characters';
  const status=$('remediationAssignMessage'),send=$('remediationSendAssignment');
  send.disabled=!(cloudMode&&capabilities?.assignments_available&&capabilities?.assignment_email_enabled);
  if(!authenticated)status.textContent='Please sign in to CVEHarbor first. You can use the account form above.';
  else if(!cloudMode)status.textContent='The updated Cloudflare Worker must be deployed before email assignments can be sent.';
  else if(!capabilities?.assignments_available)status.textContent='The D1 assignment table has not been migrated yet.';
  else if(!capabilities?.assignment_email_enabled)status.textContent='Assignment email is disabled until the verified sender and delivery provider are configured.';
  else status.textContent='An external colleague can receive the review email. You can send up to 10 assignments per hour, subject to recipient limits.';
  if(typeof modal.showModal==='function')modal.showModal();else modal.setAttribute('open','');
  $('remediationAssignEmail').focus();
}
$('remediationAssignNotes').addEventListener('input',()=>{$('remediationAssignNotesCount').textContent=$('remediationAssignNotes').value.length+'/1000 characters'});
window.CVEHARBOR_REMEDIATION={openAssign};
window.addEventListener('cveharbor:assign-remediation',event=>openAssign(event.detail?.id));
window.addEventListener('cveharbor:account-state',event=>{void accountState(event.detail||{});});
$('remediationAssign').addEventListener('click',()=>openAssign($('remediationCve').value));
$('closeRemediationAssign').addEventListener('click',()=>{
  const modal=$('remediationAssignDialog');
  if(typeof modal.close==='function')modal.close();else modal.removeAttribute('open');
});
$('remediationAssignDialog').addEventListener('click',event=>{
  if(event.target===$('remediationAssignDialog'))$('closeRemediationAssign').click();
});
function closeCvhDialog(id){
 const dialog=$(id);
 if(typeof dialog.close==='function'&&dialog.open)dialog.close();
 else dialog.removeAttribute('open');
}
function openCvhDialog(id){
 const dialog=$(id);
 if(typeof dialog.showModal==='function'&&!dialog.open)dialog.showModal();
 else dialog.setAttribute('open','');
}
function confirmReviewRequest(cve,email){
 return new Promise(resolve=>{
  const dialog=$('remediationConfirmDialog');
  $('remediationConfirmText').textContent='Send the '+cve+' vulnerability review request to '+email+'?';
  const send=$('remediationConfirmSend'),cancel=$('remediationConfirmCancel'),x=$('remediationConfirmX');
  let settled=false;
  function finish(value){
   if(settled)return;settled=true;
   send.removeEventListener('click',onSend);cancel.removeEventListener('click',onCancel);
   x.removeEventListener('click',onCancel);dialog.removeEventListener('cancel',onCancel);
   dialog.removeEventListener('close',onClose);
   closeCvhDialog('remediationConfirmDialog');
   resolve(value);
  }
  function onSend(){finish(true)}
  function onCancel(event){if(event?.type==='cancel')event.preventDefault();finish(false)}
  function onClose(){finish(false)}
  send.addEventListener('click',onSend);cancel.addEventListener('click',onCancel);
  x.addEventListener('click',onCancel);dialog.addEventListener('cancel',onCancel);
  dialog.addEventListener('close',onClose);
  openCvhDialog('remediationConfirmDialog');
 });
}
function showReviewSuccess(email){
 $('remediationSuccessText').textContent='Your request has been submitted to '+email+'.';
 openCvhDialog('remediationSuccessDialog');
}
for(const id of ['remediationSuccessClose','remediationSuccessX'])
 $(id).addEventListener('click',()=>{
  closeCvhDialog('remediationSuccessDialog');
  $('closeRemediationAssign').click();
 });
$('remediationAssignForm').addEventListener('submit',async event=>{
 event.preventDefault();
 const cve=$('remediationAssignCve').value;
 const email=$('remediationAssignEmail').value.trim().toLowerCase();
 const send=$('remediationSendAssignment'),status=$('remediationAssignMessage');
 if(!cloudMode||!capabilities?.assignments_available||!capabilities?.assignment_email_enabled){
  status.textContent='Email assignment is currently unavailable. Please try again later.';return;
 }
 if(!$('remediationAssignConfirm').checked){status.textContent='Confirm that this is an appropriate recipient.';return;}
 if(!await confirmReviewRequest(cve,email))return;
 send.disabled=true;status.textContent='Submitting your review request...';
 try{
  const result=await api('/remediations/'+cve+'/assign','POST',{email,reviewer_notes:$('remediationAssignNotes').value.trim().slice(0,1000)});
  if(!result.assigned||!result.notified)throw Error('The request was not confirmed as sent.');
  try{await refreshRecords()}catch(_){}
  status.textContent='Request submitted successfully.';
  msg('Review request submitted for '+cve+'.');
  showReviewSuccess(email);
 }catch(error){
  status.textContent='Request not sent: '+error.message;
  msg('Review request could not be completed. '+error.message);
 }finally{send.disabled=false}
});

$('remediationForm').addEventListener('submit',async event=>{
  event.preventDefault();
  const id=$('remediationCve').value.trim().toUpperCase();
  if(!valid(id)){msg('Enter a valid CVE ID, such as CVE-2026-12345.');return;}
  const item={id,status:$('remediationStatus').value,owner:$('remediationOwner').value.trim().slice(0,100),
    due:$('remediationDue').value,notes:$('remediationNotes').value.trim().slice(0,1200),
    updated:new Date().toISOString().slice(0,10)};
  const button=$('remediationSave');button.disabled=true;
  try{
    if(cloudMode){
      await api('/remediations/'+id,'PUT',item);
      await refreshRecords();msg(id+' saved to your private Cloudflare D1 account.');
    }else{
      tasks=[item,...tasks.filter(x=>x.id!==id)].slice(0,250);persistLegacy();render();
      msg(id+' saved locally. Sign in to use cloud tracking when the updated Worker is deployed.');
    }
  }catch(error){msg('Unable to save: '+error.message)}
  finally{button.disabled=false;}
});
$('remediationImport').addEventListener('click',async()=>{
  if(!cloudMode||!legacy.length)return;
  if(!window.confirm('Import '+legacy.length+' existing browser remediation records into this account? Existing cloud records and assignments will not be removed. Matching CVE details may be updated.'))return;
  const button=$('remediationImport');button.disabled=true;
  try{
    const result=await api('/remediations','PUT',{remediations:legacy});
    imported=true;await refreshRecords();
    msg(result.saved+' browser records imported to D1. A copy remains in this browser until you clear its site data.');
  }catch(error){msg('Import failed: '+error.message)}
  finally{button.disabled=false;}
});
$('remediationExport').addEventListener('click',()=>{
  const quote=value=>{
    let s=String(value||'');
    // Prevent spreadsheet formula execution when CSV is opened in Excel.
    if(/^[\s]*[=+\-@]/.test(s))s="'"+s;
    return '"'+s.replaceAll('"','""')+'"';
  };
  const csv=[['CVE','Status','Owner','Target Date','Notes','Updated','Assigned Email','Email Status'],
    ...tasks.map(x=>[x.id,x.status,x.owner,x.due,x.notes,x.updated,x.assigned_to||'',x.assignment_status||''])]
    .map(fields=>fields.map(quote).join(',')).join('\r\n');
  const link=elem('a');link.href=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));
  link.download='cveharbor-remediation.csv';document.body.append(link);link.click();link.remove();
  setTimeout(()=>URL.revokeObjectURL(link.href),1000);
});
render();
const ecos=$('versionEcosystem');for(const name of ['npm','PyPI','Go','Maven','NuGet','RubyGems','crates.io','Packagist']){const option=elem('option','',name);option.value=name;ecos.append(option)}
$('versionForm').addEventListener('submit',async event=>{
 event.preventDefault();const name=$('versionPackage').value.trim(),version=$('versionValue').value.trim(),result=$('versionResult');
 result.replaceChildren();if(!name||!version||name.length>160||version.length>80){result.append(elem('p','ops-note','Enter a package name and exact version.'));return}
 $('versionCheck').disabled=true;result.append(elem('p','ops-note','Checking OSV for affected package versions...'));
 try{
  const response=await fetch('https://api.osv.dev/v1/query',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({package:{name,ecosystem:ecos.value},version})});
  if(!response.ok)throw Error('OSV HTTP '+response.status);
  const data=await response.json(),findings=Array.isArray(data.vulns)?data.vulns:[];
  result.replaceChildren();result.append(elem('strong','',findings.length?findings.length+' OSV vulnerability records returned':'No matching OSV records returned'));
  result.append(elem('p','ops-note',findings.length?'Confirm affected ranges and patch details against primary sources.':'No results does not prove the version secure or supported. OSV coverage may be incomplete.'));
  for(const f of findings.slice(0,25)){
   const row=elem('div','ops-result');row.append(elem('strong','',f.id||'OSV advisory'),elem('p','',f.summary||'See source details.'));
   const link=elem('a','ops-link','View source');link.href='https://osv.dev/vulnerability/'+encodeURIComponent(f.id||'');link.rel='noopener noreferrer';link.target='_blank';row.append(link);result.append(row);
  }
  if(data.next_page_token)result.append(elem('p','ops-note','Further results exist. Only the first page is shown.'));
 }catch(_){result.replaceChildren(elem('p','ops-note','OSV request could not be completed. Affected status is unknown. Confirm connectivity and consult OSV directly.'))}
 finally{$('versionCheck').disabled=false}
});
const snapshot=window.CVEHARBOR_LIFECYCLE||{},cycles=Array.isArray(snapshot.cycles)?snapshot.cycles:[];
$('lifecycleStatus').textContent=cycles.length?'Lifecycle snapshot: '+(snapshot.checked_at||'date unavailable')+'. Verify dates with vendors.':'Lifecycle feed unavailable. Use official vendor references below.';
for(const entry of cycles){
 const row=elem('article','ops-result'),header=elem('div','ops-result-top');
 header.append(elem('strong','',entry.product+' '+entry.cycle),elem('span','ops-tag',entry.eol===true?'EOL':entry.eol===false?'Supported per source':'Verify'));
 row.append(header,elem('p','', 'End of life: '+(entry.eol_date||'Not confirmed')+' · Support: '+(entry.support_date||'Not confirmed')));
 const a=elem('a','ops-link','Check lifecycle source');a.href=entry.url;a.target='_blank';a.rel='noopener noreferrer';row.append(a);$('lifecycleRows').append(row);
}
$('firewallObservedCount').textContent=(threats.indicators||[]).length+' reported IP indicators in the current snapshot';
for(const item of [['FortiGate initial','fortigate-suspicious-ip-initial.txt'],['FortiGate incremental','fortigate-suspicious-ip-incremental.txt'],['Sophos initial','sophos-suspicious-ip-initial.txt'],['Sophos incremental','sophos-suspicious-ip-incremental.txt']]){
 const a=elem('a','ops-download',item[0]);a.href='/'+item[1];a.download=item[1];$('firewallDownloads').append(a);
}
})();