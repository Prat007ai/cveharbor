(() => {
'use strict';
const $=id=>document.getElementById(id);
if(!$('operationsCentre'))return;
const key='cveharbor.remediation.v1',API='https://api.cveharbor.com/v1',
  src=window.CVEHARBOR_DATA||{},base=window.CVEHARBOR_CATALOG||{},threats=window.CVEHARBOR_THREATS||{};
const elem=(tag,cls,value)=>{const x=document.createElement(tag);if(cls)x.className=cls;if(value!==undefined)x.textContent=String(value);return x;};
const displayCve=id=>String(id||'').split('~')[0];
const validWork=id=>/^CVE-\d{4}-\d{4,}(?:~[A-F0-9-]{36})?$/.test(String(id||''));
let assignmentKey='',assignmentScope=null;
const valid=id=>/^CVE-\d{4}-\d{4,}$/i.test(String(id||''))&&String(id).length<=28;
const headerTools=document.querySelector('.rt-header-tools');
if(headerTools&&/^\/remediation(?:\/|$)/.test(location.pathname))headerTools.hidden=false;
const records=new Map();
const customers=window.CVEHARBOR_CUSTOMER_REMEDIATION;let recordsEpoch=0;
for(const x of [...(base.advisories||[]),...(src.advisories||[])])if(x?.id)records.set(x.id,x);
function openAdvisory(id){
  if(!valid(id))return;
  const advisory=records.get(id)||{id,title:id,summary:'This CVE is not present in the available advisory index. Review the official source references below. Severity and affected versions have not been verified here.'};
  if(!window.CVEHARBOR_ADVISORY_DETAILS)return;
  window.CVEHARBOR_ADVISORY_DETAILS.render($('dialogContent'),advisory,{onAssign:()=>{
    closeCvhDialog('detailDialog');openAssign(id);
  }});
  openCvhDialog('detailDialog');
}
headerTools?.querySelector('form').addEventListener('submit',event=>{
  event.preventDefault();const input=event.currentTarget.elements.cve;
  const id=input.value.trim().toUpperCase();if(valid(id))openAdvisory(id);
});
const readLegacy=()=>{
  try{
    const saved=JSON.parse(localStorage.getItem(key)||'[]');
    return Array.isArray(saved)?saved.filter(x=>x&&valid(x.id)).slice(0,250):[];
  }catch(_){return [];}
};
let legacy=readLegacy(),tasks=[...legacy],cloudMode=false,authenticated=false,
  accountEmail='',capabilities=null,imported=false,accountEpoch=0,showAll=false,loading=false,loadFailed=false,ackDataAvailable=false,historyCve="",historyBefore=null,historyEpoch=0;
let editing=null,statusCve='',statusBefore=null,statusEpoch=0,progressCve='',progressBefore=null,progressEpoch=0;
const msg=value=>{$('remediationMessage').textContent=value};
const storage=value=>{$('remediationStorage').textContent=value};
async function api(path,method='GET',payload){
  if(method!=='GET'&&writesBlocked())throw Error('Wait for your records to finish loading, or retry the failed load.');
  const res=await fetch(API+path,{
    method,credentials:'include',headers:{'Content-Type':'application/json'},
    body:payload===undefined?undefined:JSON.stringify(payload)
  });
  let data={};try{data=await res.json()}catch(_){}
  if(!res.ok){const error=Error(data.error||'Cloud account service unavailable');error.status=res.status;throw error;}
  return data;
}
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const optionalText=value=>value==null||typeof value==='string';
const loadDetails=new WeakMap();
function loadError(phase,resource,status){
  const error=Error('Tracker loading failed');loadDetails.set(error,{phase,resource,...(Number.isInteger(status)?{status}:{})});return error;
}
function validResponse(resource,data){
  if(!object(data))return false;
  if(resource==='features')return data.storage==='d1'&&data.version===2&&
    ['customer_records_available','shared_records_available','assignments_available','assignment_email_enabled','reviewer_updates_available','workflow_available','fyi_available','acknowledgements_available'].every(k=>data[k]===undefined||typeof data[k]==='boolean');
  if(resource==='inventory')return ['customers','environments','assets'].every(k=>Array.isArray(data[k]))&&
    data.customers.every(c=>object(c)&&typeof c.id==='string'&&typeof c.name==='string')&&
    data.environments.every(e=>object(e)&&typeof e.id==='string'&&typeof e.customer_id==='string'&&typeof e.name==='string')&&
    data.assets.every(a=>object(a)&&typeof a.id==='string'&&typeof a.environment_id==='string'&&typeof a.name==='string'&&typeof a.technology==='string'&&optionalText(a.version));
  return Array.isArray(data.remediations)&&data.remediations.every(r=>object(r)&&typeof r.id==='string'&&validWork(r.id)&&
    ['status','owner','due','notes','updated','assigned_to','assigned_severity'].every(k=>optionalText(r[k]))&&
    (r.scope==null||object(r.scope)&&['customer_id','customer_name','environment_id','environment_name','asset_id','asset_name','technology','version'].every(k=>optionalText(r.scope[k])))&&
    (r.acknowledgements==null||object(r.acknowledgements)&&object(r.acknowledgements.states)&&typeof r.acknowledgements.total==='number')&&
    (r.latest_status_change==null||object(r.latest_status_change))&&(r.review_progress==null||object(r.review_progress)));
}
async function trackerRequest(path){
  // Resource names are fixed: never include query values, response bodies or error messages in diagnostics.
  const resource=path==='/remediations/features'?'features':path==='/inventory'?'inventory':'records';
  let response,data;
  try{response=await fetch(API+path,{credentials:'include',headers:{'Content-Type':'application/json'}});}
  catch{throw loadError('request',resource);}
  if(!response.ok)throw loadError('request',resource,response.status);
  try{data=await response.json();}catch{throw loadError('response-validation',resource,response.status);}
  if(!validResponse(resource,data))throw loadError('response-validation',resource,response.status);
  return data;
}
function writesBlocked(){return loading||(authenticated&&(!cloudMode||loadFailed));}
function writeControls(){
  const blocked=writesBlocked();
  for(const id of ['remediationSave','remediationAssign','remediationImport'])$(id).disabled=blocked;
  if(blocked)$('remediationSendAssignment').disabled=true;
}
function failedLoad(error,resource){
  // Log only metadata constructed here; arbitrary exceptions may contain private response data.
  const detail=loadDetails.get(error);
  console.warn('Remediation tracker load failed',detail||{phase:'rendering',resource});
  loadFailed=true;loading=false;tasks=[];ackDataAvailable=false;
  render();$('remediationRecentActivity')?.replaceChildren();
  msg('Unable to load your cloud records. Use Refresh records to retry.');
}
function persistLegacy(){
  try{localStorage.setItem(key,JSON.stringify(tasks));legacy=readLegacy();
    storage('These records are currently stored in this browser only. Sign in to save records to your private workspace.');
  }catch(_){storage('Browser storage unavailable. Export your records before leaving.');}
}
function uiMode(){
  const btn=$('remediationImport');
  btn.hidden=!cloudMode||!legacy.length||imported;
  if(authenticated&&loading){
    storage('Loading your private remediation records…');
  }else if(authenticated&&loadFailed){
    storage('Cloud records are unavailable. Use Refresh records to retry. Your browser records remain available after signing out.');
  }else if(cloudMode){
    storage('Records are saved privately in your CVEHarbor workspace. Acknowledgement confirms receipt; remediation progress is tracked separately.');
  }else if(authenticated){
    storage('Loading your private remediation records…');
  }else{
    storage('Records are currently local to this browser. Sign in above to save and manage your private remediation records.');
  }
}
function editRecord(task){
  if(task.scope){window.CVEHARBOR_SHARED.open(task.id);return;}
  $('remediationCve').value=task.id;
  $('remediationStatus').value=task.status||'Open';
  $('remediationOwner').value=task.owner||'';
  $('remediationDue').value=task.due||'';
  $('remediationNotes').value=task.notes||'';
  editing={id:task.id,updated:task.updated,status:task.status};$('remediationReason').value='';updateReason();
  customers?.beginEdit(task);
  msg(task.id+' loaded for editing. Save to update this record.');
  $('remediationFormTitle').textContent='Edit Vulnerability Record';
  updateNotesCount();validateOwner(false);
  $('remediationCve').focus();
}
function selectedRecord(){return tasks.find(x=>x.id===$('remediationCve').value.trim().toUpperCase());}
function updateReason(){
 const previous=editing?.id===$('remediationCve').value.trim().toUpperCase()?editing:selectedRecord();
 const changed=!!previous&&previous.status!==$('remediationStatus').value;
 $('remediationReasonLabel').hidden=!changed;$('remediationReason').required=changed;
}
$('remediationStatus').addEventListener('change',updateReason);
$('remediationCve').addEventListener('input',()=>{if(editing)customers?.defaults();editing=null;updateReason();});
function displayTime(value){
 if(!value)return 'Not recorded';
 if(/^\d{4}-\d{2}-\d{2}$/.test(value))return value+' · time not recorded';
 const date=new Date(value);return Number.isNaN(date.getTime())?'Not recorded':new Intl.DateTimeFormat(undefined,{year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',timeZoneName:'short'}).format(date);
}
const severityLabel=value=>value==='info'?'Informational':value?value[0].toUpperCase()+value.slice(1):'Not available';
function updateNotesCount(){
  $('remediationNotesCount').textContent=$('remediationNotes').value.length+'/1200';
}
function validateOwner(showError=true){
  const input=$('remediationOwner'),ok=!!input.value.trim();
  input.setCustomValidity(ok?'':'Please select an owner.');
  input.setAttribute('aria-invalid',String(!ok&&showError));
  $('remediationOwnerError').hidden=ok||!showError;
  return ok;
}
$('remediationOwner').addEventListener('input',()=>validateOwner());
$('remediationOwner').addEventListener('invalid',()=>validateOwner());
$('remediationNotes').addEventListener('input',updateNotesCount);
$('remediationViewAll').addEventListener('click',()=>{showAll=!showAll;render();});
const statusTones={'Open':'open','Investigating':'investigating','Remediated':'remediated','Accepted Risk':'risk','Not Applicable':'neutral'};
function badge(value,tone){const node=elem('span','rt-badge',value);node.dataset.tone=tone||'neutral';return node;}
function render(){
  const target=$('remediationRows');target.replaceChildren();
  const isPrivate=authenticated&&cloudMode&&!loading&&!loadFailed;
  const counts=[tasks.filter(x=>x.status==='Open').length,tasks.filter(x=>x.status==='Investigating').length,tasks.filter(x=>x.status==='Remediated').length,tasks.length];
  ['remediationOpen','remediationProgress','remediationResolved','remediationTotal'].forEach((id,i)=>{$(id).textContent=isPrivate?counts[i].toLocaleString():'—';});
  $('remediationCount').textContent=tasks.length+' tracked'+(cloudMode?'':' · browser only');
  writeControls();
  $('remediationExport').disabled=loading||!tasks.length;
  $('remediationRefresh').disabled=loading||!authenticated;
  const view=$('remediationViewAll');view.textContent=showAll?'Show recent records':'View all records →';view.setAttribute('aria-expanded',String(showAll));view.disabled=tasks.length<=5;
  $('remediationRecordsScope').textContent=loading?'Loading private records…':isPrivate?'Your latest private account records.':authenticated?'Unable to load private account records.':'Browser-only records · sign in for your private account tracker.';
  target.closest('table').setAttribute('aria-busy',String(loading));
  if(!tasks.length){
    const row=elem('tr'),cell=elem('td','rt-empty');cell.colSpan=customers?.active?11:10;
    cell.append(elem('strong','',loading?'Loading records…':authenticated&&(!cloudMode||loadFailed)?'Records unavailable':'No remediation records yet'),elem('span','',loading?'Retrieving your private account records.':authenticated&&(!cloudMode||loadFailed)?'Use Refresh records to retry.':cloudMode?'Add a CVE and its owner using the form above.':'Sign in to manage private account records, or add a browser-only record above.'));
    row.append(cell);target.append(row);uiMode();return;
  }
  const ordered=[...tasks].sort((a,b)=>String(b.updated||'').localeCompare(String(a.updated||'')));
  for(const task of (showAll?ordered:ordered.slice(0,5))){
    const row=elem('tr');row.dataset.cve=task.id;row.setAttribute('role','row');
    const labels=['Last updated','CVE ID','Title','Severity','Status','Owner','Target date','Acknowledgement','Latest status change','Actions'];
    const cell=(value)=>{const td=elem('td'),label=elem('span','rt-cell-label',labels[row.children.length]);label.setAttribute('aria-hidden','true');td.setAttribute('role','cell');td.append(label);if(value!==undefined)td.append(document.createTextNode(String(value)));row.append(td);return td;};
    cell(displayTime(task.updated));
    const link=elem('a','',displayCve(task.id));link.href='https://www.cve.org/CVERecord?id='+encodeURIComponent(displayCve(task.id));link.addEventListener('click',event=>{if(window.CVEHARBOR_ADVISORY_DETAILS){event.preventDefault();openAdvisory(displayCve(task.id));}});cell().append(link);
    const advisory=records.get(displayCve(task.id)),title=cell(advisory?.title||'Advisory details not available');
    if(task.scope)title.append(elem('p','',scopeText(task.scope)));
    if(task.notes||task.assigned_to){
      const details=elem('details','rt-record-detail');details.append(elem('summary','','Record details'));
      if(task.notes)details.append(elem('p','',task.notes));
      if(task.assigned_to)details.append(elem('p','remediation-assignee','Assigned by email to: '+task.assigned_to+' · Notification: '+(task.assignment_status||'Unknown')));
      title.append(details);
    }
    if(cloudMode&&capabilities?.reviewer_updates_available){const updates=elem('button','rt-history-link','View updates'+(task.review_progress?.total?' ('+task.review_progress.total+')':''));updates.type='button';updates.setAttribute('aria-label','Reviewer updates for '+task.id);updates.addEventListener('click',()=>openProgress(task.id));title.append(updates);if(task.review_progress?.latest)title.append(elem('small','','Reviewer update: '+displayTime(task.review_progress.latest*1000)));}
    const severity=String(advisory?.severity||'').toLowerCase();
    const rating=cell(),assigned=task.assigned_severity||'';
    rating.append(badge(severityLabel(assigned||(['critical','high','medium','low','info'].includes(severity)?severity:'')),assigned||severity));
    rating.append(elem('small','',assigned?'Assigned · requester assessment':'Published severity'));
    if(assigned)rating.append(elem('small','','Published: '+severityLabel(severity)));
    cell().append(badge(task.scope?({Open:'Needs Review',Investigating:'Fix in Progress',Remediated:'Fixed/Patched'}[task.status]||task.status):(task.status||'Not recorded'),statusTones[task.status]));
    const owner=cell(task.owner||'Unassigned');if(!task.owner)owner.append(elem('small','','Owner required when editing'));
    cell(task.due||'Not set');
    const ack=cell(),summary=task.acknowledgements;
    const ackText=summary?(summary.total===1?Object.keys(summary.states)[0]:(summary.states.Acknowledged||0)+' / '+summary.total+' acknowledged'):task.assigned_to?'Not requested':'Not sent';
    const status=cloudMode&&capabilities?.acknowledgements_available&&!ackDataAvailable?'Unavailable':ackText;
    const ackState=elem('div','rt-ack-state');ackState.append(badge(status,status==='Acknowledged'?'remediated':status==='Pending'?'risk':'neutral'));ack.append(ackState);
    if(status==='Not sent'&&isPrivate&&capabilities?.acknowledgements_available&&capabilities?.assignments_available&&capabilities?.assignment_email_enabled){const request=elem('button','rt-ack-request','Request acknowledgement');request.type='button';request.setAttribute('aria-label','Request acknowledgement for '+task.id);request.addEventListener('click',()=>openAssign(task.id));ackState.append(request);}
    if(summary?.latest_acknowledged_at)ack.append(elem('small','',(summary.total>1?'Latest: ':'')+displayTime(summary.latest_acknowledged_at*1000)));
    if(summary){const history=elem('button','rt-history-link','View recipients');history.type='button';history.setAttribute('aria-label','Assignment history for '+task.id);history.addEventListener('click',()=>openHistory(task.id));ack.append(history);}

    const change=cell(),latest=task.latest_status_change;
    if(latest){change.append(elem('strong','',latest.previous_status+' → '+latest.new_status),elem('p','rt-change-reason',latest.reason),elem('small','',displayTime(latest.changed_at)),elem('small','',latest.changed_by));}
    else change.append(elem('small','','No recorded changes'));
    if(capabilities?.workflow_available||task.status_changes?.length){const history=elem('button','rt-history-link','View status history');history.type='button';history.addEventListener('click',()=>openStatusHistory(task.id));change.append(history);}
    const actions=elem('div','rt-row-actions');cell().append(actions);
    const edit=elem('button','ops-remove','Edit');edit.type='button';edit.setAttribute('aria-label','Edit '+task.id);
    edit.addEventListener('click',()=>editRecord(task));actions.append(edit);
    const assign=elem('button','remediation-row-assign','Assign');assign.type='button';assign.setAttribute('aria-label','Assign '+task.id+' by email');assign.addEventListener('click',()=>openAssign(task.id));if(!(summary?.states?.Acknowledged>0))actions.append(assign);
    const remove=elem('button','ops-remove','Remove');remove.type='button';remove.setAttribute('aria-label','Remove '+task.id);
    remove.addEventListener('click',async()=>{
      if(!window.confirm('Remove '+task.id+' from '+(cloudMode?'your private tracker':'this browser')+'?'))return;
      if(cloudMode){
        remove.disabled=true;
        try{await api('/remediations/'+task.id,'DELETE');await refreshRecords();msg(task.id+' removed from your workspace.')}
        catch(error){msg('Unable to remove record: '+error.message)}
        finally{remove.disabled=false}
      }else{
        tasks=tasks.filter(x=>x.id!==task.id);persistLegacy();render();msg(task.id+' removed from this browser.');
      }
    });if(!task.scope)actions.append(remove);if(capabilities?.shared_records_available){const shared=elem('button','','View record');shared.type='button';shared.addEventListener('click',()=>window.CVEHARBOR_SHARED.open(task.id));actions.prepend(shared);}if(customers?.active)customers.decorate(row,task);target.append(row);
  }
  uiMode();
}
async function refreshRecords(epoch=accountEpoch){
  if(epoch!==accountEpoch||!authenticated||!cloudMode)return false;
  const generation=++recordsEpoch;
  loading=true;loadFailed=false;tasks=[];msg('');
  try{
    render();$('remediationRecentActivity')?.replaceChildren();
    const data=await trackerRequest('/remediations'+(customers?.query()||''));
    if(epoch!==accountEpoch||!authenticated||generation!==recordsEpoch)return false;
    ackDataAvailable=data.acknowledgements_available===true;
    tasks=data.remediations.slice(0,250);
    loading=false;render();renderRecentActivity();return true;
  }catch(error){
    if(epoch!==accountEpoch||!authenticated||generation!==recordsEpoch)return false;
    failedLoad(error,'records');return false;
  }
}
let progressRefreshTimer=null;
async function accountState(data){
  if(progressRefreshTimer!==null){window.clearInterval(progressRefreshTimer);progressRefreshTimer=null;}
  const epoch=++accountEpoch;historyEpoch++;statusEpoch++;progressEpoch++;
  for(const id of ['remediationProgressRows','remediationProgressInvitations','remediationProgressNotifications'])$(id).replaceChildren();closeCvhDialog('remediationProgressDialog');editing=null;ackDataAvailable=false;
  $('remediationStatusHistoryRows').replaceChildren();closeCvhDialog('remediationStatusHistoryDialog');
  $('remediationHistoryRows').replaceChildren();closeCvhDialog('remediationHistoryDialog');
  pickerVersion++;$('assignCustomer').replaceChildren();$('assignEnvironment').replaceChildren();
  $('previewCustomer').textContent='';$('previewEnvironment').textContent='';
  authenticated=!!data.authenticated;accountEmail=authenticated?(data.email||''):'';
  cloudMode=false;capabilities=null;imported=false;showAll=false;loading=authenticated;loadFailed=false;
  customers?.clear();recordsEpoch++;
  // Clear the previous account immediately, including values loaded into the edit form.
  $('remediationForm').reset();$('remediationFormTitle').textContent='Add Vulnerability Record';
  updateNotesCount();updateReason();validateOwner(false);msg('');
  for(const id of ['remediationAssignDialog','remediationSuccessDialog'])closeCvhDialog(id);
  $('remediationAssignForm').reset();$('remediationSendAssignment').disabled=true;
  tasks=authenticated?[]:readLegacy();legacy=readLegacy();render();$('remediationRecentActivity')?.replaceChildren();
  if(!authenticated)return;
  try{
    const features=await trackerRequest('/remediations/features');
    if(epoch!==accountEpoch)return;
    capabilities=features;cloudMode=true;
    if(customers)await customers.load(features,trackerRequest,()=>{editing=null;$('remediationForm').reset();customers.defaults();void refreshRecords();},api);
    // A stale initialization must never clear the newer account's customer controls.
    if(epoch!==accountEpoch)return;
    const head=$('remediationRows').closest('table').querySelector('thead tr');
    head.querySelector('[data-customer-column]')?.remove();
    if(customers?.active){const th=elem('th','','Customer');th.scope='col';th.dataset.customerColumn='true';head.insertBefore(th,head.children[3]);}
    if(features.reviewer_updates_available)progressRefreshTimer=window.setInterval(refreshReviewerProgress,60000);
    if(!await refreshRecords(epoch))return;
    if(epoch!==accountEpoch)return;
    msg('');
    const requested=new URLSearchParams(location.search).get('record');if(requested&&tasks.some(t=>t.id===requested)){if(new URLSearchParams(location.search).get('assign')==='1')openAssign(requested);else window.CVEHARBOR_SHARED?.open(requested);history.replaceState(null,'',location.pathname);}
  }catch(error){
    if(epoch!==accountEpoch)return;
    cloudMode=false;capabilities=null;customers?.clear();
    failedLoad(error,'initialization');
  }
}
function renderRecentActivity(){let panel=$('remediationRecentActivity');if(!panel){panel=elem('section','rt-panel rt-recent-activity');panel.id='remediationRecentActivity';$('remediationTracker').append(panel);}panel.replaceChildren(elem('h2','','Recent activity'));const list=elem('ul');for(const t of [...tasks].sort((a,b)=>String(b.updated).localeCompare(String(a.updated))).slice(0,8)){const li=elem('li'),b=elem('button','',displayCve(t.id)+(t.scope?' · '+scopeText(t.scope):'')+' — '+(t.latest_status_change? t.latest_status_change.new_status:'Record updated')+' · '+displayTime(t.updated));b.type='button';b.addEventListener('click',()=>window.CVEHARBOR_SHARED.open(t.id));li.append(b);list.append(li);}panel.append(list);}
function scopeText(s){return s?[s.customer_name,s.environment_name,s.asset_name,s.technology,s.version].filter(Boolean).join(' · '):'';}
let pickerVersion=0,previewAudience='reviewer';
async function loadAssignmentPicker(scope){
 const version=++pickerVersion,epoch=accountEpoch;
 const customer=$('assignCustomer'),environment=$('assignEnvironment'),hint=$('assignCustomerHint');
 customer.replaceChildren(new Option('Unassigned / Internal',''));environment.replaceChildren(new Option('Customer-wide',''));
 customer.disabled=true;environment.disabled=true;customer.onchange=null;hint.textContent='';
 if(scope){
  customer.replaceChildren(new Option(scope.customer_name,scope.customer_id));
  environment.replaceChildren(new Option(scope.environment_name||'Customer-wide',scope.environment_id||''));
  updateAssignmentPreview();return;
 }
 if(!cloudMode)return;
 try{
  const inventory=await api('/inventory');
  if(epoch!==accountEpoch||version!==pickerVersion)return;
  if(!capabilities?.customer_records_available){
   hint.textContent='Customer selection requires the customer records service.';return;
  }
  for(const row of inventory.customers)customer.add(new Option(row.name,row.id));
  customer.disabled=false;
  const filter=$('remediationCustomerFilter')||$('queueCustomer');
  if(filter&&Array.from(customer.options).some(o=>o.value===filter.value))customer.value=filter.value;
  customer.onchange=()=>{
   environment.replaceChildren(new Option('Customer-wide',''));
   for(const row of inventory.environments.filter(e=>e.customer_id===customer.value))environment.add(new Option(row.name,row.id));
   environment.disabled=!customer.value;
   $('remediationAssignConfirm').checked=false;updateAssignmentPreview();
  };
  customer.onchange();
 }catch{if(epoch===accountEpoch&&version===pickerVersion)hint.textContent='Customer list unavailable. Reopen the form to retry.';}
}
function openAssign(id,scope){
  if(writesBlocked())return;
  const cve=String(id||'').trim().toUpperCase();
  if(cve&&!validWork(cve)){msg('Enter a complete CVE ID before assigning.');return;}
  const modal=$('remediationAssignDialog');
  if(!modal)return;
  assignmentKey=cve;assignmentScope=scope||tasks.find(x=>x.id===cve)?.scope||null;
  $('remediationAssignCve').value=displayCve(cve);
  // Keep the scoped record key when assigning a customer finding.
  $('remediationAssignCve').readOnly=!!assignmentScope||cve.includes('~');
  $('changeCve').hidden=$('remediationAssignCve').readOnly;
  $('extraOptions').open=true;$('deliveryRules').open=true;
  let context=$('remediationAssignScope');if(!context){context=elem('p');context.id='remediationAssignScope';$('remediationAssignForm').prepend(context);}context.textContent=scopeText(assignmentScope);
  previewAudience='reviewer';void loadAssignmentPicker(assignmentScope);
  $('remediationAssignConfirm').checked=false;
  $('remediationAssignResend').checked=false;
  $('remediationResendLabel').hidden=!capabilities?.acknowledgements_available;
  $('remediationProgressPolicy').hidden=!capabilities?.reviewer_updates_available;
  $('remediationSeverityLabel').hidden=!capabilities?.workflow_available;
  $('remediationAssignSeverity').value=tasks.find(x=>x.id===cve)?.assigned_severity||'';
  $('remediationAssignEmail').value='';
  $('remediationAssignFyi').value='';$('remediationFyiLabel').hidden=!capabilities?.fyi_available;
  $('remediationFyiError').textContent='';$('remediationAssignFyi').removeAttribute('aria-invalid');
  $('remediationAssignNotes').value='';
  $('remediationAssignNotesCount').textContent='0/1000 characters';
  const status=$('remediationAssignMessage'),send=$('remediationSendAssignment');
  send.disabled=!(cloudMode&&capabilities?.assignments_available&&capabilities?.assignment_email_enabled);
  if(!authenticated)status.textContent='Please sign in to CVEHarbor first. You can use the account form above.';
  else if(!cloudMode)status.textContent='Email assignments are temporarily unavailable. Please try again later.';
  else if(!capabilities?.assignments_available)status.textContent='Email assignments are temporarily unavailable. Please try again later.';
  else if(!capabilities?.assignment_email_enabled)status.textContent='Email assignments are currently unavailable. Please try again later.';
  else status.textContent=capabilities?.acknowledgements_available?'The recipient can acknowledge receipt without an account. This does not change remediation status. Up to 10 assignments per hour, subject to recipient limits.':'An external reviewer can receive the review email. You can send up to 10 assignments per hour, subject to recipient limits.';
  updateAssignmentPreview();
  if(typeof modal.showModal==='function')modal.showModal();else modal.setAttribute('open','');
  $('remediationAssignEmail').focus();
}
$('remediationAssignFyi').addEventListener('input',()=>{$('remediationFyiError').textContent='';$('remediationAssignFyi').removeAttribute('aria-invalid');});
$('remediationAssignNotes').addEventListener('input',()=>{$('remediationAssignNotesCount').textContent=$('remediationAssignNotes').value.length+'/1000 characters'});
function updateAssignmentPreview(){
 const id=$('remediationAssignCve').value.trim().toUpperCase(),email=$('remediationAssignEmail').value.trim().toLowerCase();
 const fyi=[...new Set($('remediationAssignFyi').value.toLowerCase().split(/[,;\n]/).map(value=>value.trim()).filter(value=>value&&value!==email))];
 $('previewCve').textContent=valid(id)?id:'Enter a complete CVE ID';
 const observer=previewAudience==='fyi';
 $('previewTo').textContent=observer?(fyi.join(', ')||'Add FYI recipients'):email||'Reviewer email';
 $('previewCustomer').textContent=$('assignCustomer').selectedOptions[0]?.textContent||'Unassigned / Internal';
 $('previewEnvironment').textContent=$('assignCustomer').value?($('assignEnvironment').selectedOptions[0]?.textContent||'Customer-wide'):'—';
 $('previewMailTitle').textContent=observer?'FYI · Vulnerability review assigned':'Vulnerability review request';
 $('previewFyiTab').setAttribute('aria-pressed',String(observer));
 $('previewReviewerTab').setAttribute('aria-pressed',String(!observer));
 $('previewEnclosures').hidden=observer;
 $('previewFyi').textContent=fyi.join(', ');$('previewFyi').hidden=$('fyiHeading').hidden=observer||!fyi.length;
 const assigned=$('remediationAssignSeverity').value,published=records.get(id)?.severity;
 $('previewSeverity').textContent=assigned?severityLabel(assigned)+' · assigned':published?severityLabel(published)+' · published':'Published severity when available';
 const notes=$('remediationAssignNotes').value.trim();$('previewNote').textContent=notes;
 $('previewNote').hidden=$('noteHeading').hidden=observer||!notes;
 $('resendWarning').hidden=!$('remediationAssignResend').checked;
}
$('previewFyiTab').onclick=()=>{previewAudience='fyi';updateAssignmentPreview();};
$('previewReviewerTab').onclick=()=>{previewAudience='reviewer';updateAssignmentPreview();};
$('changeCve').onclick=()=>{$('remediationAssignCve').focus();$('remediationAssignCve').select();};
$('remediationAssignCve').oninput=event=>{event.target.value=event.target.value.trim().toUpperCase();};
$('remediationAssignForm').addEventListener('input',event=>{
 if(event.target!==$('remediationAssignConfirm'))$('remediationAssignConfirm').checked=false;
 updateAssignmentPreview();
});
window.CVEHARBOR_REMEDIATION={openAssign};
window.addEventListener('cveharbor:remediation-changed',()=>{if(cloudMode)void refreshRecords();});
if(typeof BroadcastChannel==='function'){const channel=new BroadcastChannel('cveharbor-remediation-changed');channel.onmessage=()=>{if(cloudMode)void refreshRecords();};}
window.addEventListener('cveharbor:assign-remediation',event=>openAssign(event.detail?.id));
window.addEventListener('cveharbor:account-state',event=>{void accountState(event.detail||{});});
$('remediationAssign').addEventListener('click',()=>{if(customers?.active){const row=customers.recordFor(tasks,$('remediationCve').value.trim().toUpperCase());if(row){openAssign(row.id,row.scope);return;}}openAssign($('remediationCve').value);});
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
function showReviewSuccess(email,fyiCount=0){
 $('remediationSuccessText').textContent='Your request has been submitted to '+email+'.'+(fyiCount?' FYI notifications queued for '+fyiCount+' recipient(s). Delivery status is available in assignment history.':'');
 openCvhDialog('remediationSuccessDialog');
}
for(const id of ['remediationSuccessClose','remediationSuccessX'])
 $(id).addEventListener('click',()=>{
  closeCvhDialog('remediationSuccessDialog');
  $('closeRemediationAssign').click();
 });
$('remediationAssignForm').addEventListener('submit',async event=>{
 event.preventDefault();
 const entered=$('remediationAssignCve').value.trim().toUpperCase();
 if(!valid(entered))return;
 const cve=entered===displayCve(assignmentKey)?assignmentKey:entered;
 if((assignmentScope||assignmentKey.includes('~'))&&cve!==assignmentKey)return;
 const email=$('remediationAssignEmail').value.trim().toLowerCase();
 const send=$('remediationSendAssignment'),status=$('remediationAssignMessage');
 if(writesBlocked()||!cloudMode||!capabilities?.assignments_available||!capabilities?.assignment_email_enabled){
  status.textContent='Email assignment is currently unavailable. Please try again later.';return;
 }
 if(!$('remediationAssignConfirm').checked){status.textContent='Confirm that this is an appropriate recipient.';return;}
 const fyi=[...new Set($('remediationAssignFyi').value.split(/[,;\n]/).map(x=>x.trim().toLowerCase()).filter(Boolean))].filter(x=>x!==email);
 if(fyi.length>5||fyi.some(x=>x.length>254||! /^[^\s<>@,;]{1,64}@[^\s<>@,;]{1,189}\.[^\s<>@,;]+$/.test(x))){$('remediationFyiError').textContent='Enter up to five valid FYI email addresses.';$('remediationAssignFyi').setAttribute('aria-invalid','true');$('extraOptions').open=true;$('remediationAssignFyi').focus();return;}
 $('remediationFyiError').textContent='';$('remediationAssignFyi').removeAttribute('aria-invalid');
 const assigned=capabilities?.workflow_available?$('remediationAssignSeverity').value:undefined;
 const requestAccount=accountEpoch;
 if(send.disabled)return;
 send.disabled=true;status.textContent='Submitting your review request...';
 try{
  const customer=$('assignCustomer').value,environment=$('assignEnvironment').value;
  const selection=!assignmentScope&&customer?{customer_id:customer,environment_id:environment||null}:{};
  const result=await api('/remediations/'+cve+'/assign','POST',{...selection,share_customer_context:!!(customer||assignmentScope),email,assigned_severity:assigned,fyi_recipients:fyi,reviewer_notes:$('remediationAssignNotes').value.trim().slice(0,1000),resend:$('remediationAssignResend').checked});
  if(requestAccount!==accountEpoch)return;
  if(!result.assigned||!result.notified)throw Error('The request was not confirmed as sent.');
  try{await refreshRecords()}catch(_){}
  status.textContent=result.duplicate?result.message:'Request submitted successfully.';
  msg('Review request submitted for '+cve+'.');
  if(!result.duplicate)showReviewSuccess(email,result.fyi_queued||0);
 }catch(error){
  status.textContent='Request not sent: '+error.message;
  msg('Review request could not be completed. '+error.message);
 }finally{if(requestAccount===accountEpoch)send.disabled=writesBlocked()||!cloudMode||!capabilities?.assignment_email_enabled}
});

$('remediationForm').addEventListener('submit',async event=>{
  event.preventDefault();
  if(writesBlocked()){msg(loading?'Please wait for your records to finish loading.':'Unable to save until your records load successfully. Use Refresh records to retry.');return;}
  const id=$('remediationCve').value.trim().toUpperCase();
  if(!valid(id)){msg('Enter a valid CVE ID, such as CVE-2026-12345.');return;}
  if(!validateOwner()){msg('Please select an owner.');$('remediationOwner').focus();return;}
  const item={id,status:$('remediationStatus').value,owner:$('remediationOwner').value.trim().slice(0,100),
    due:$('remediationDue').value,notes:$('remediationNotes').value.trim().slice(0,1200),
    updated:new Date().toISOString()};
  const previous=selectedRecord(),baseline=customers?.active?(editing?.id===id?editing:null):(editing?.id===id?editing:previous);
  item.status_change_reason=$('remediationReason').value.trim();
  if(baseline&&baseline.status!==item.status&&!item.status_change_reason){updateReason();msg('Enter a reason for the status change.');$('remediationReason').focus();return;}
  if(cloudMode&&capabilities?.workflow_available)item.expected_updated=baseline?.updated||'';
  const epoch=accountEpoch;
  const button=$('remediationSave');button.disabled=true;
  try{
    if(cloudMode){
      const saved=customers?.active?await customers.save(item,editing):await api('/remediations/'+id,'PUT',item);
      if(epoch!==accountEpoch||!await refreshRecords())return;msg(id+' saved to your private workspace.');
      if(saved?.open_record)window.CVEHARBOR_SHARED?.open(saved.id);
    }else{
      item.status_changes=previous?.status_changes||[];
      if(previous&&previous.status!==item.status)item.status_changes=[{previous_status:previous.status,new_status:item.status,reason:item.status_change_reason,changed_by:'This browser',changed_at:item.updated},...item.status_changes];
      item.latest_status_change=item.status_changes[0]||null;
      tasks=[item,...tasks.filter(x=>x.id!==id)].slice(0,250);persistLegacy();render();
      msg(id+' saved in this browser. Sign in to save records to your private workspace.');
    }
    editing=null;$('remediationReason').value='';updateReason();customers?.defaults();
  }catch(error){if(epoch===accountEpoch)msg('Unable to save: '+error.message)}
  finally{button.disabled=writesBlocked();}
});
$('remediationImport').addEventListener('click',async()=>{
  if(writesBlocked()||!cloudMode||!legacy.length)return;
  if(legacy.some(row=>!String(row.owner||'').trim())){msg('Some browser records need an owner. Sign out to edit those browser records, then sign in and import again. No records have been changed.');return;}
  if(legacy.some(row=>tasks.some(x=>x.id===row.id&&x.status!==row.status))){msg('Some browser records have a different status. Update those records in your workspace with a reason before importing.');return;}
  if(!window.confirm('Import '+legacy.length+' existing browser remediation records into this account? Existing cloud records and assignments will not be removed. Matching CVE details may be updated.'))return;
  const button=$('remediationImport');button.disabled=true;
  try{
    const result=await api('/remediations','PUT',{remediations:legacy});
    imported=true;if(!await refreshRecords())return;
    msg(result.saved+' browser records imported to your workspace. A copy remains in this browser until you clear its site data.');
  }catch(error){msg('Import failed: '+error.message)}
  finally{button.disabled=writesBlocked();}
});
$('remediationRefresh').addEventListener('click',async()=>{
  if(!authenticated||loading)return;
  if(!cloudMode){await accountState({authenticated:true,email:accountEmail});return;}
  const epoch=accountEpoch;
  if(await refreshRecords(epoch)&&epoch===accountEpoch)msg('Records refreshed. Acknowledgements confirm receipt only.');
});
let progressRefreshBusy=false;
async function refreshReviewerProgress(){
 if(progressRefreshBusy||!authenticated||!cloudMode||!capabilities?.reviewer_updates_available||loading||document.visibilityState==='hidden'||!$('remediationTracker').getClientRects().length||document.querySelector('dialog[open]'))return;
 progressRefreshBusy=true;try{await refreshRecords(accountEpoch);}catch{}finally{progressRefreshBusy=false;}
}
// Keep an open Recent Records view current without disturbing an edit dialog.
window.addEventListener('focus',refreshReviewerProgress);
document.addEventListener('visibilitychange',refreshReviewerProgress);
const ackTimestamp=value=>value?displayTime(value*1000):'Not recorded';
async function openHistory(cve){
  historyCve=cve;historyBefore=null;historyEpoch++;
  $('remediationHistoryTitle').textContent=displayCve(cve)+' · Assignments';$('remediationHistoryRows').replaceChildren();
  openCvhDialog('remediationHistoryDialog');await loadHistory();
}
async function loadHistory(){
  const epoch=historyEpoch,account=accountEpoch,cve=historyCve;
  $('remediationHistoryMore').hidden=true;$('remediationHistoryStatus').textContent='Loading assignment history…';
  try{
    const data=await api('/remediations/'+cve+'/assignments'+(historyBefore?'?before='+historyBefore:''));
    if(epoch!==historyEpoch||account!==accountEpoch)return;
    for(const item of data.assignments||[]){
      const row=elem('article','rt-assignment-item');
      row.append(elem('strong','',item.recipient_email),badge(item.status,item.status==='Acknowledged'?'remediated':item.status==='Pending'?'risk':'neutral'));
      row.append(elem('p','ops-note','Created '+ackTimestamp(item.created_at)+' · Sent '+ackTimestamp(item.sent_at)+' · Expires '+ackTimestamp(item.expires_at)));
      if(item.acknowledged_at)row.append(elem('p','ops-note','Acknowledged via emailed link for '+item.recipient_email+' at '+ackTimestamp(item.acknowledged_at)+'. Identity is not verified.'));
      if(item.revoked_at)row.append(elem('p','ops-note','Link revoked '+ackTimestamp(item.revoked_at)));
      if(item.fyi?.length){
        const box=elem('div','rt-fyi-history');box.append(elem('strong','','FYI notifications'));
        const labels={queued:'Queued',sending:'Sending',sent:'Accepted by email provider',unconfirmed:'Delivery unconfirmed',cancelled:'Cancelled'};
        for(const fyi of item.fyi)box.append(elem('p','ops-note',fyi.recipient_email+' · '+(fyi.kind==='acknowledged'?'Receipt update':'Assignment FYI')+': '+(labels[fyi.state]||'Not queued')+(fyi.completed_at?' · '+ackTimestamp(fyi.completed_at):'')));
        row.append(box);
      }
      const actions=elem('div','rt-assignment-actions');
      if(!item.revoked_at&&item.fyi?.some(x=>x.state==='unconfirmed'&&x.attempts<3)){
        const retry=elem('button','ops-download','Retry FYI notifications');retry.type='button';retry.addEventListener('click',async()=>{
          if(!window.confirm('Retry unconfirmed FYI emails? If the provider accepted an earlier attempt, a duplicate may be received.'))return;
          retry.disabled=true;try{await api('/remediations/'+cve+'/assignments/'+item.id+'/fyi/retry','POST',{});if(account!==accountEpoch)return;await openHistory(cve);}catch(error){if(account===accountEpoch)$('remediationHistoryStatus').textContent=error.message;}finally{retry.disabled=false;}
        });actions.append(retry);
      }
      if(capabilities?.acknowledgements_available){
        const resend=elem('button','ops-download','Resend');resend.type='button';resend.addEventListener('click',()=>{closeCvhDialog('remediationHistoryDialog');openAssign(cve);$('remediationAssignEmail').value=item.recipient_email;$('remediationAssignResend').checked=true;$('remediationAssignFyi').value=[...new Set((item.fyi||[]).map(x=>x.recipient_email))].join(', ');});actions.append(resend);
        if(!item.revoked_at){const revoke=elem('button','ops-download','Revoke link');revoke.type='button';revoke.addEventListener('click',async()=>{
          if(!window.confirm('Revoke this assignment link for '+item.recipient_email+'? Receipt history will remain available.'))return;
          revoke.disabled=true;try{await api('/remediations/'+cve+'/assignments/'+item.id+'/revoke','POST',{});if(account!==accountEpoch)return;await refreshRecords();await openHistory(cve);}catch(error){if(account===accountEpoch)$('remediationHistoryStatus').textContent='Unable to revoke: '+error.message;}finally{revoke.disabled=false;}
        });actions.append(revoke);}
      }
      row.append(actions);$('remediationHistoryRows').append(row);
    }
    historyBefore=data.next||null;$('remediationHistoryMore').hidden=!historyBefore;
    $('remediationHistoryStatus').textContent=data.available===false?'Acknowledgement history is not available.':$('remediationHistoryRows').childElementCount?'Receipt tracking is separate from remediation status.':'No acknowledgement requests have been sent.';
  }catch(error){if(epoch===historyEpoch&&account===accountEpoch)$('remediationHistoryStatus').textContent='Unable to load history: '+error.message;}
}
$('remediationHistoryMore').addEventListener('click',()=>loadHistory());
$('remediationHistoryClose').addEventListener('click',()=>{historyEpoch++;closeCvhDialog('remediationHistoryDialog');});
async function openStatusHistory(cve){
 statusCve=cve;statusBefore=null;statusEpoch++;$('remediationStatusHistoryRows').replaceChildren();
 $('remediationStatusHistoryTitle').textContent=cve+' · Status changes';openCvhDialog('remediationStatusHistoryDialog');await loadStatusHistory();
}
async function loadStatusHistory(){
 const epoch=statusEpoch,account=accountEpoch,cve=statusCve;
 $('remediationStatusHistoryMore').hidden=true;$('remediationStatusHistoryMessage').textContent='Loading status history…';
 try{
  const data=cloudMode?await api('/remediations/'+cve+'/status-history'+(statusBefore?'?before='+statusBefore:'')):{changes:tasks.find(x=>x.id===cve)?.status_changes||[]};
  if(epoch!==statusEpoch||account!==accountEpoch)return;
  for(const item of data.changes||[]){const row=elem('article','rt-assignment-item');row.append(elem('strong','',item.previous_status+' → '+item.new_status),elem('p','rt-history-reason',item.reason),elem('small','',item.changed_by+' · '+displayTime(item.changed_at)));$('remediationStatusHistoryRows').append(row);}
  statusBefore=data.next||null;$('remediationStatusHistoryMore').hidden=!statusBefore;
  $('remediationStatusHistoryMessage').textContent=$('remediationStatusHistoryRows').childElementCount?'Status changes are separate from acknowledgement.':'No recorded status changes. Earlier changes have not been reconstructed.';
 }catch(error){if(epoch===statusEpoch&&account===accountEpoch)$('remediationStatusHistoryMessage').textContent='Unable to load history: '+error.message;}
}
$('remediationStatusHistoryMore').addEventListener('click',()=>loadStatusHistory());
$('remediationStatusHistoryClose').addEventListener('click',()=>{statusEpoch++;closeCvhDialog('remediationStatusHistoryDialog');});
async function openProgress(cve){
 progressCve=cve;progressBefore=null;progressEpoch++;
 $('remediationProgressTitle').textContent=displayCve(cve)+' · Progress and reminders';
 for(const id of ['remediationProgressRows','remediationProgressInvitations','remediationProgressNotifications'])$(id).replaceChildren();
 openCvhDialog('remediationProgressDialog');await loadProgress();
}
async function loadProgress(){
 const epoch=progressEpoch,account=accountEpoch,cve=progressCve;
 $('remediationProgressMore').hidden=true;$('remediationProgressMessage').textContent='Loading reviewer updates…';
 try{
  const data=await api('/remediations/'+cve+'/review-activity'+(progressBefore?'?before='+progressBefore:''));
  if(epoch!==progressEpoch||account!==accountEpoch)return;
  for(const item of data.activity||[]){const row=elem('article','rt-assignment-item');row.append(elem('strong','',item.author_email),elem('small','','Email verified · '+displayTime(item.created_at*1000)),elem('p','',item.previous_status+' → '+item.new_status));if(item.reason)row.append(elem('p','rt-history-reason','Reason: '+item.reason));if(item.comment)row.append(elem('p','rt-history-reason',item.comment));$('remediationProgressRows').append(row);}
  if(!$('remediationProgressRows').childElementCount)$('remediationProgressRows').append(elem('p','ops-note','No reviewer progress updates have been recorded.'));
  $('remediationProgressInvitations').replaceChildren();
  for(const invite of data.assignments||[]){const row=elem('article','rt-assignment-item'),task=tasks.find(x=>x.id===cve),active=!invite.revoked_at&&invite.expires_at>Date.now()/1000&&invite.delivery_status==='sent';row.append(elem('strong','',invite.recipient_email),elem('small','','Access: '+(active?'Active':invite.revoked_at?'Revoked':invite.delivery_status!=='sent'?'Email not confirmed as sent':'Expired')+' · Expires '+displayTime(invite.expires_at*1000)),elem('p','ops-note','Last recorded progress: '+displayTime(invite.last_progress_at*1000)));row.append(elem('p','ops-note',!active?'Reminders stopped.':!['Open','Investigating'].includes(task?.status)?'Reminders stopped for the current status.':invite.interval_seconds?'One reminder after '+invite.interval_seconds/3600+' hours without progress. Progress resets the interval. Listed FYI recipients receive a manager notice at the same threshold.':'No automatic reminders for this severity.'));$('remediationProgressInvitations').append(row);}
  $('remediationProgressNotifications').replaceChildren();
  const labels={queued:'Queued',sending:'Sending',sent:'Accepted by email provider',unconfirmed:'Delivery unconfirmed',cancelled:'Cancelled'};
  for(const n of data.notifications||[]){const row=elem('article','rt-assignment-item');row.append(elem('strong','',n.kind==='reminder'?(n.audience==='manager'?'Manager / FYI inactivity notice':'Reviewer update reminder'):'Progress notification'),elem('p','ops-note',n.recipient_email+' · '+(labels[n.state]||n.state)),elem('small','',displayTime((n.completed_at||n.created_at)*1000)));if(n.state==='unconfirmed'&&n.attempts<3){const retry=elem('button','ops-download','Retry notification');retry.type='button';retry.addEventListener('click',async()=>{if(!window.confirm('Retry this unconfirmed notification? A duplicate may be received if an earlier attempt was accepted.'))return;retry.disabled=true;try{await api('/remediations/'+cve+'/review-notifications/'+n.id+'/retry','POST',{});if(account===accountEpoch&&epoch===progressEpoch)await openProgress(cve);}catch(error){if(account===accountEpoch)$('remediationProgressMessage').textContent=error.message;}finally{retry.disabled=false;}});row.append(retry);}$('remediationProgressNotifications').append(row);}
  if(!data.notifications?.length)$('remediationProgressNotifications').append(elem('p','ops-note','No progress or reminder notifications yet.'));
  progressBefore=data.next||null;$('remediationProgressMore').hidden=!progressBefore;
  $('remediationProgressMessage').textContent=data.available===false?'Reviewer updates are unavailable.':data.assignments?.length?'Comments stay private to your account and the reviewer who posted them. Showing the latest 50 invitations and notifications.':'Send a new assignment invitation to enable secure reviewer updates and severity-based reminders. Existing invitations are not enrolled automatically.';
 }catch(error){if(epoch===progressEpoch&&account===accountEpoch)$('remediationProgressMessage').textContent='Unable to load updates: '+error.message;}
}
$('remediationProgressMore').addEventListener('click',()=>loadProgress());
$('remediationProgressClose').addEventListener('click',()=>{progressEpoch++;closeCvhDialog('remediationProgressDialog');});
$('remediationExport').addEventListener('click',()=>{
  const quote=value=>{
    let s=String(value||'');
    // Prevent spreadsheet formula execution when CSV is opened in Excel.
    if(/^[\s]*[=+\-@]/.test(s))s="'"+s;
    return '"'+s.replaceAll('"','""')+'"';
  };
  const csv=[['CVE','Status','Owner','Target Date','Notes','Updated','Assigned Email','Email Status','Acknowledgements (current recipients)','Assigned Severity','Last Status Change','Status Change Reason','Status Changed By','Customer','Environment','Software / Asset'],
    ...tasks.map(x=>[displayCve(x.id),x.scope?({Open:'Needs Review',Investigating:'Fix in Progress',Remediated:'Fixed/Patched'}[x.status]||x.status):x.status,x.owner,x.due,x.notes,x.updated,x.assigned_to||'',x.assignment_status||'',x.acknowledgements?Object.entries(x.acknowledgements.states).map(([state,count])=>state+': '+count).join('; '):'Not requested',x.assigned_severity||'',x.latest_status_change?.changed_at||'',x.latest_status_change?.reason||'',x.latest_status_change?.changed_by||'',x.scope?.customer_name||'',x.scope?.environment_name||'',x.scope?[x.scope.asset_name,x.scope.technology,x.scope.version].filter(Boolean).join(' · '):''])]
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
