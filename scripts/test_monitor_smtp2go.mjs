// Approved recipients from the user's Task 3 reply. No customer campaign,
// production D1 changes, new key, sender verification or DNS modification.
import fs from 'node:fs/promises';
import {submitSmtp2go,renderMonitorMail} from '../account-backend/src/monitor-mail.js';
const path='work/product-monitoring-smtp-test.json',report={checked_at:new Date().toISOString(),sender:process.env.EMAIL_FROM||'',production_writes:0,tests:[]};
await fs.mkdir('work',{recursive:true});
const save=()=>fs.writeFile(path,JSON.stringify(report,null,2)+'\n');
if(!process.env.SMTP2GO_API_KEY){report.status='not_run';report.reason='No existing SMTP2GO key is bound to this CI task. Worker secret values cannot be extracted or copied.';await save();console.log(report.reason);process.exit(0);}
const prior=await fetch('https://api.github.com/repos/'+process.env.GITHUB_REPOSITORY+'/actions/artifacts?name=product-monitoring-approved-test-20261101&per_page=10',{headers:{Authorization:'Bearer '+process.env.GITHUB_TOKEN,Accept:'application/vnd.github+json'}});
if(!prior.ok)throw Error('Unable to check for a previous approved test; refusing duplicate submission');
if((await prior.json()).artifacts?.some(a=>!a.expired)){report.status='not_repeated';await save();console.log('An approved test artifact already exists; no messages resent.');process.exit(0);}
for(const recipient of ['prat.mahen@gmail.com','PMahendran@whitecapcanada.com']){
 const item={recipient,state:'submitting',delivery_confirmed:false};report.tests.push(item);await save();
 try{
  const mail=renderMonitorMail([{kind:'test',record:{product:'Product lifecycle monitoring',branch:'approved integration test',version:'',source_url:'https://developers.smtp2go.com/docs/send-an-email'}}],{test:true});
  const accepted=await submitSmtp2go(process.env,recipient,mail);Object.assign(item,accepted,{state:'submitted'});await save();
 }catch(error){item.state=error.unknown?'submission_unknown':'failed';item.detail=error.unknown?'Do not resend; reconcile with SMTP2GO':'Provider did not confirm acceptance';await save();}
}
// Acceptance and event lookup are deliberately separate. No inbox claim.
await new Promise(r=>setTimeout(r,20000));
for(const item of report.tests.filter(t=>t.provider_id)){
 try{
  const r=await fetch('https://api.smtp2go.com/v3/activity/search',{method:'POST',headers:{'Content-Type':'application/json','X-Smtp2go-Api-Key':process.env.SMTP2GO_API_KEY},body:JSON.stringify({search_email_id:item.provider_id,start_date:report.checked_at,limit:20})});const body=await r.json();
  const events=Array.isArray(body.data?.events)?body.data.events:[];
  const matched=events.filter(e=>e.email_id===item.provider_id);
  item.provider_events=matched.map(e=>({event:e.event,time:e.time}));
  if(matched.some(e=>e.event==='delivered')){item.state='delivered';item.delivery_confirmed=true;}
  else item.reconciliation='No matching delivered event confirmed yet; webhook/activity follow-up required';
 }catch{item.reconciliation='Activity API unavailable; acceptance remains separate from delivery';}
}
report.status=report.tests.every(t=>['submitted','delivered'].includes(t.state))?'accepted':'review_required';await save();console.log(JSON.stringify({status:report.status,submitted:report.tests.filter(t=>t.provider_id).length,delivered:report.tests.filter(t=>t.delivery_confirmed).length}));
