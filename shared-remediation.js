(()=>{'use strict';
const API='https://api.cveharbor.com/v1',labels={Open:'Needs Review',Investigating:'Fix in Progress',Remediated:'Fixed/Patched','Not Applicable':'Not Applicable','Accepted Risk':'Accepted Risk'};
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
let epoch=0,current=null,dialog=null;
const valid=id=>/^CVE-\d{4}-\d{4,}(?:~[A-F0-9-]{36})?$/.test(id);
async function api(path,method='GET',data){const r=await fetch(API+path,{method,credentials:'include',headers:{'Content-Type':'application/json'},...(data===undefined?{}:{body:JSON.stringify(data)})});const body=await r.json();if(!r.ok){const e=Error(body.error||'Unable to load shared record');e.status=r.status;throw e;}return body;}
function changed(){window.dispatchEvent(new Event('cveharbor:remediation-changed'));if(typeof BroadcastChannel==='function'){const c=new BroadcastChannel('cveharbor-remediation-changed');c.postMessage({changed:true});c.close();}}
function field(form,label,input){const l=el('label',label);l.append(input);form.append(l);return input;}
function button(text,fn,cls=''){const b=el('button',text,cls);b.type='button';b.addEventListener('click',fn);return b;}
const stamp=value=>new Date(typeof value==='number'?value*1000:value).toLocaleString();
async function open(id){if(!valid(id))return;const token=++epoch;current=null;
 if(!dialog){dialog=el('dialog',undefined,'shared-record');dialog.setAttribute('aria-label','Shared remediation record');document.body.append(dialog);dialog.addEventListener('close',()=>{epoch++;current=null;dialog.replaceChildren();});}
 dialog.replaceChildren(button('Close',()=>dialog.close(),'shared-close'),el('p','Loading shared record…'));if(!dialog.open)dialog.showModal();
 try{const [row,history,progress,assignments]=await Promise.all([api('/remediation-records/'+id),api('/remediations/'+id+'/status-history'),api('/remediations/'+id+'/review-activity'),api('/remediations/'+id+'/assignments')]);if(token!==epoch)return;current=row;draw(row,history,progress,assignments);}catch(e){if(token===epoch)dialog.append(el('p',e.message,'shared-error'));}
}
function draw(row,history,progress,assignments){dialog.replaceChildren(button('Close',()=>dialog.close(),'shared-close'),el('p','SHARED REMEDIATION RECORD','shared-eyebrow'),el('h2',row.cve_id));
 const scope=row.scope,context=scope?[scope.customer_name,scope.environment_name,scope.asset_name,scope.technology,scope.version].filter(Boolean).join(' · '):'Standalone CVE record';dialog.append(el('p',context,'shared-context'));
 const all=[...(window.CVEHARBOR_DATA?.advisories||[]),...(window.CVEHARBOR_CATALOG?.advisories||[])],advisory=all.find(a=>a.id===row.cve_id);if(advisory)dialog.append(el('p',advisory.title||advisory.summary||''));
 const message=el('p','','shared-message');message.setAttribute('role','status');dialog.append(message);
 const form=el('form',undefined,'shared-fields');const status=field(form,'Vulnerability Fix Status',el('select'));for(const [v,l] of Object.entries(labels)){const o=el('option',l);o.value=v;status.append(o);}status.value=row.status;
 const owner=field(form,'Owner',el('input'));owner.value=row.owner;owner.required=true;owner.maxLength=100;
 const due=field(form,'Target date',el('input'));due.type='date';due.value=row.due;
 const notes=field(form,'Notes',el('textarea'));notes.maxLength=1200;notes.value=row.notes||'';
 const reason=field(form,'Reason for status change',el('textarea'));reason.maxLength=1000;reason.rows=2;reason.placeholder='Explain the change and supporting evidence';
 const save=el('button','Save status and details');save.type='submit';form.append(save);
 form.addEventListener('submit',async e=>{e.preventDefault();if(status.value!==row.status&&!reason.value.trim()){message.textContent='Enter a reason for the status change.';reason.focus();return;}await mutate(save,message,()=>api('/remediations/'+row.id,'PUT',{status:status.value,owner:owner.value,due:due.value,notes:notes.value,status_change_reason:reason.value,expected_updated:row.updated}),row.id);});dialog.append(form);
 dialog.append(button('Assign by email',()=>{dialog.close();if(window.CVEHARBOR_REMEDIATION)window.CVEHARBOR_REMEDIATION.openAssign(row.id,scope);else location.assign('/remediation/?record='+encodeURIComponent(row.id)+'&assign=1');}));
 dialog.append(el('h3','Assignment and acknowledgement'));for(const a of assignments.assignments||[]){dialog.append(el('p',a.recipient_email+' · '+(a.status||a.delivery_status)+(a.acknowledged_at?' · '+stamp(a.acknowledged_at):'')));if(a.fyi?.length)dialog.append(el('p','FYI: '+a.fyi.map(x=>typeof x==='string'?x:x.recipient_email).join(', ')));}if(!assignments.assignments?.length)dialog.append(el('p','No acknowledgement request sent.'));
 if(row.status_mail?.available){dialog.append(el('h3','Status update emails'),el('p',row.status_mail.recipients?.length?'Recipients: '+row.status_mail.recipients.join(', '):'No email recipients are linked to this record. Assign a reviewer or link the existing assignment to receive status updates.'));if(!row.status_mail.notifications?.length)dialog.append(el('p','No status emails have been queued for this record.'));const states={queued:'Queued',sending:'Sending',sent:'Accepted by email provider',unconfirmed:'Delivery not confirmed',cancelled:'Cancelled'};for(const n of row.status_mail.notifications||[])dialog.append(el('p',n.recipient_email+' · '+(labels[n.new_status]||n.new_status)+' · '+(states[n.state]||n.state)+(n.state==='queued'&&n.not_before>Date.now()/1000?' · Deferred until '+stamp(n.not_before):'')));}
 dialog.append(el('h3','DevOps Ticket #'));dialog.append(el('p',row.tickets.map(t=>t.ticket_number).join(' · ')||'No tickets recorded.'));
 if(scope){const tickets=el('form');const input=field(tickets,'Add ticket reference',el('input'));input.maxLength=64;input.required=true;const add=el('button','Add ticket');tickets.append(add);tickets.addEventListener('submit',async e=>{e.preventDefault();await mutate(add,message,()=>api(scope.asset_id?'/finding-tickets/'+scope.asset_id+'/'+row.cve_id:'/remediation-records/'+row.id+'/tickets','POST',{ticket_number:input.value}),row.id);});dialog.append(tickets);}
 dialog.append(el('h3','Activity and comments'));const activity=[...(history.changes||[]).map(x=>({date:x.changed_at,author:x.changed_by,text:(labels[x.previous_status]||x.previous_status)+' → '+(labels[x.new_status]||x.new_status)+': '+x.reason})),...(progress.activity||[]).filter(x=>x.comment).map(x=>({date:x.created_at*1000,author:x.author_email,text:x.comment})),...row.comments.map(x=>({date:x.created_at*1000,author:x.author_email,text:x.comment}))].sort((a,b)=>new Date(b.date)-new Date(a.date));
 for(const link of row.link_history||[]){let snapshot={};try{snapshot=JSON.parse(link.snapshot_json);}catch{}activity.push({date:link.linked_at,author:link.linked_by,text:'Linked the existing assignment to this customer asset.'+(snapshot.retired?.notes?' Retained finding notes: '+snapshot.retired.notes:'')});}
 activity.sort((a,b)=>new Date(b.date)-new Date(a.date));
 for(const a of activity){const article=el('article');article.append(el('strong',a.author),el('small',new Date(a.date).toLocaleString()),el('p',a.text));dialog.append(article);}if(!activity.length)dialog.append(el('p','No updates recorded yet.'));
 const commentForm=el('form');const comment=field(commentForm,'Progress update or comment',el('textarea'));comment.minLength=10;comment.maxLength=2000;comment.required=true;comment.rows=3;const post=el('button','Post update');commentForm.append(post);commentForm.addEventListener('submit',async e=>{e.preventDefault();await mutate(post,message,()=>api('/remediation-records/'+row.id+'/comments','POST',{comment:comment.value,expected_updated:row.updated}),row.id);});dialog.append(commentForm);
}
async function mutate(button,message,fn,id){const token=epoch;button.disabled=true;try{await fn();if(token!==epoch)return;changed();await open(id);}catch(e){if(token===epoch)message.textContent=e.message;}finally{button.disabled=false;}}
async function finding(asset,cve,trigger,options={}){if(trigger)trigger.disabled=true;const token=epoch;try{
 const preview=await api('/finding-remediations/'+asset+'/'+cve);
 if(token!==epoch)return;
 if(preview.manual){await offerLink(asset,cve,preview,options);return;}
 if(preview.record){await open(preview.record.id);return;}
 const r=await api('/finding-remediations/'+asset+'/'+cve,'POST',{});if(token!==epoch)return;changed();await open(r.id);
}catch(e){if(token===epoch)window.alert(e.message);}finally{if(trigger)trigger.disabled=false;}}
async function offerLink(asset,cve,p,options={}){
 if(!dialog){dialog=el('dialog',undefined,'shared-record');dialog.setAttribute('aria-label','Shared remediation record');document.body.append(dialog);dialog.addEventListener('close',()=>{epoch++;current=null;dialog.replaceChildren();});}
 const token=++epoch;current=null;dialog.replaceChildren(button('Close',()=>dialog.close(),'shared-close'),el('h2','Link existing assignment'),el('p',cve+' was tracked separately. Link the existing assignment here if it belongs to this customer asset.'));
 dialog.append(el('p',[p.asset.customer_name,p.asset.environment_name,p.asset.asset_name,p.asset.technology,p.asset.version].filter(Boolean).join(' · '),'shared-context'),el('p','Existing owner: '+p.manual.owner+' · Target date: '+(p.manual.due||'Not set')+' · Status: '+p.manual.fix_status));
 const summary=el('div');dialog.append(summary);if(!dialog.open)dialog.showModal();
 const response=await api('/remediations/'+p.manual.id+'/assignments');if(token!==epoch)return;
 for(const a of response.assignments||[])summary.append(el('p',a.recipient_email+' · '+a.status+(a.acknowledged_at?' · '+stamp(a.acknowledged_at):'')));
 const message=el('p',p.blocked_reason||'The existing acknowledgement, recipients, due date, severity and email links will be retained. Status history and comments from both records will be preserved. Linking does not resend the assignment email. If the selected status changes, a status-update email is sent to the reviewers, requester and FYI recipients.',p.blocked_reason?'shared-message':'shared-link-note');message.setAttribute('role','status');dialog.append(message);
 if(p.can_link){
 const findingStatus=p.record?.status||Object.keys(labels).find(k=>labels[k]===p.finding?.status)||p.manual.status;
 dialog.append(el('p','Current finding status: '+labels[findingStatus]+' · Existing assignment status: '+p.manual.fix_status));
 const form=el('form');const status=field(form,'Status after linking',el('select'));for(const [value,label] of Object.entries(labels)){const option=el('option',label);option.value=value;status.append(option);}status.value=(options.status&&(Object.keys(labels).find(k=>labels[k]===options.status)||options.status))||p.record?.status||Object.keys(labels).find(k=>labels[k]===p.finding?.status)||p.manual.status;
 let reason=null;if(options.status||p.integrity){reason=field(form,'Reason for this change',el('textarea'));reason.rows=3;reason.maxLength=700;const needsReason=()=>!!options.status||status.value!==p.manual.status||status.value!==findingStatus;reason.required=needsReason();status.addEventListener('change',()=>{reason.required=needsReason();});}
 if(p.manual_mail?.available)form.append(el('p',p.manual_mail.recipients.length?'Status update recipients: '+p.manual_mail.recipients.join(', '):'This existing record has no email recipients. Linking alone will not send a status email.'));
 const confirm=field(form,'I confirm this existing assignment belongs to the customer and asset shown above.',el('input'));confirm.type='checkbox';confirm.required=true;
 const submit=el('button','Link existing assignment');form.append(submit);form.addEventListener('submit',async e=>{e.preventDefault();submit.disabled=true;try{const r=await api('/finding-remediations/'+asset+'/'+cve+'/link-existing','POST',{confirm:confirm.checked,status:status.value,status_change_reason:reason?.value||'',expected_source:p.manual.updated,expected_target:p.record?.updated||'',expected_finding:JSON.stringify(p.finding),expected_asset:JSON.stringify(p.asset)});if(token!==epoch)return;changed();await open(r.id);}catch(error){if(token===epoch){message.className='shared-message';message.textContent=error.message;}}finally{submit.disabled=false;}});dialog.append(form);
 }
 dialog.append(button(p.record?'Keep separate — view asset record':'Keep separate — create asset record',async()=>{try{const r=p.record||await api('/finding-remediations/'+asset+'/'+cve,'POST',{keep_separate:true,expected_manual:p.manual.updated});if(token!==epoch)return;changed();await open(r.id);}catch(e){if(token===epoch)message.textContent=e.message;}}));
}
window.CVEHARBOR_SHARED={open,finding,async findingContext(asset,cve){return api('/finding-remediations/'+asset+'/'+cve);},async statusContext(asset,cve){try{return (await api('/finding-remediations/'+asset+'/'+cve)).record;}catch(e){if(e.status===404||e.status===503)return null;throw e;}},changed};
window.addEventListener('cveharbor:account-state',()=>{epoch++;current=null;if(dialog){if(dialog.open)dialog.close();dialog.replaceChildren();}});
})();
