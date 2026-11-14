import {submitSmtp2go} from './monitor-mail.js';
import {agentEnabled} from './agents.js';
import {now} from './agent-validation.js';
const q=(db,sql,...args)=>db.prepare(sql).bind(...args);
const escape=value=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function agentAlert(row){
 const link='https://cveharbor.com/customer-dashboard/?'+new URLSearchParams({customer:row.customer_id,environment:row.environment_id,...(row.org_id?{org:row.org_id}:{})});
 const facts=['Suspicious agent activity detected; this is not confirmation of a server compromise.',
  'Customer: '+row.customer,'Environment: '+row.environment,'Server: '+row.hostname,
  'Detected: '+new Date(row.opened_at*1000).toISOString(),'Incident: '+row.id,
  'Reason: '+row.reason,'Action at detection: CVEHarbor suspended uploads from this device and retained the last accepted inventory.',
  row.resolved_at?'Incident reviewed: '+new Date(row.resolved_at*1000).toISOString()+'. Check the dashboard for current device status.':'Uploads remain suspended pending review.',
  'Last accepted collection: '+(row.last_sync?new Date(row.last_sync*1000).toISOString():'None'),
  'Check the affected server for recent maintenance, agent errors, unexpected processes and unauthorized access. If credentials may be compromised, revoke this device and re-enroll after investigation.',
  'An authorized owner must review the incident before uploads resume. Signing in is required; this email does not grant access.',link];
 return {subject:'[CVEHarbor] Agent uploads suspended — review required',text:facts.join('\n\n'),html:'<!doctype html><html><body><h1>Agent uploads suspended</h1>'+facts.map(s=>'<p>'+escape(s)+'</p>').join('')+'</body></html>'};
}
export async function dispatchAgentMail(env,fetcher=fetch){
 if(!agentEnabled(env)||env.AGENT_EMAIL_ENABLED!=='true'||!env.EMAIL_FROM||!(env.ALERT_SMTP2GO_API_KEY||env.SMTP2GO_API_KEY))return;
 const db=env.DB,t=now();
 // A provider timeout has an unknown outcome. Do not automatically duplicate it.
 await q(db,"UPDATE inventory_agent_mail SET state='unconfirmed' WHERE state='sending' AND claimed_at<?",t-900).run();
 const rows=(await q(db,`SELECT m.incident_id,m.recipient FROM inventory_agent_mail m WHERE m.state='queued' AND m.not_before<=? ORDER BY m.not_before LIMIT 10`,t).all()).results||[];
 for(const m of rows){
  const row=await q(db,`SELECT i.*,a.customer_id,a.environment_id,a.org_id,a.user_id,a.hostname,a.last_sync,c.name customer,e.name environment
   FROM inventory_agent_incidents i JOIN inventory_agents a ON a.id=i.device_id JOIN inventory_customers c ON c.id=a.customer_id AND c.user_id=a.user_id JOIN inventory_environments e ON e.id=a.environment_id AND e.user_id=a.user_id WHERE i.id=?`,m.incident_id).first();
  if(!row)continue;
  const support=m.recipient===(env.AGENT_SUPPORT_EMAIL||'prat.mahen@gmail.com');
  const configured=await q(db,'SELECT 1 FROM inventory_agent_contacts WHERE user_id=? AND customer_id=? LIMIT 1',row.user_id,row.customer_id).first();
  const eligible=support||(configured?await q(db,'SELECT 1 FROM inventory_agent_contacts WHERE user_id=? AND customer_id=? AND email=?',row.user_id,row.customer_id,m.recipient).first():row.org_id?await q(db,"SELECT 1 FROM team_members WHERE org=? AND email=? AND role='Owner' AND user_id IS NOT NULL",row.org_id,m.recipient).first():await q(db,'SELECT 1 FROM users WHERE id=? AND email=?',row.user_id,m.recipient).first());
  if(!eligible){await q(db,"UPDATE inventory_agent_mail SET state='cancelled' WHERE incident_id=? AND recipient=? AND state='queued'",m.incident_id,m.recipient).run();continue;}
  const claim=await q(db,"UPDATE inventory_agent_mail SET state='sending',claimed_at=?,attempts=attempts+1 WHERE incident_id=? AND recipient=? AND state='queued'",t,m.incident_id,m.recipient).run();if(claim.meta?.changes!==1)continue;
  try{const provider=await submitSmtp2go(env,m.recipient,agentAlert(row),fetcher);await q(db,"UPDATE inventory_agent_mail SET state='sent',provider_id=? WHERE incident_id=? AND recipient=? AND state='sending'",provider.provider_id,m.incident_id,m.recipient).run();}
  catch(error){
   if(error.retry)await q(db,"UPDATE inventory_agent_mail SET state=CASE WHEN attempts<5 THEN 'queued' ELSE 'failed' END,not_before=? WHERE incident_id=? AND recipient=? AND state='sending'",t+1800,m.incident_id,m.recipient).run();
   else await q(db,"UPDATE inventory_agent_mail SET state=? WHERE incident_id=? AND recipient=? AND state='sending'",error.permanent?'failed':'unconfirmed',m.incident_id,m.recipient).run();
  }
 }
}
