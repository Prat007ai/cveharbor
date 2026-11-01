import {monitorIdentity,SOURCE_REGISTRY,compareVersions,sameBranch,DAY} from './monitor-sources.js';
import {q,sha,json,monitorReady,ALERT_TYPES,DEFAULT_TYPES,NOTICE_DAYS,checkSubscribedSources,dailyReminders} from './monitor-engine.js';
import {dispatchMonitorMail,submitSmtp2go,renderMonitorMail,monitorDeliveryReady} from './monitor-mail.js';
export class MonitorError extends Error{constructor(message,status=400){super(message);this.status=status;}}
export const monitorAdmin=(env,user)=>String(env.PRODUCT_MONITOR_ADMIN_EMAILS||'').toLowerCase().split(',').map(x=>x.trim()).includes(user.email.toLowerCase());
const audit=(env,user,watch,action,now)=>q(env.DB,'INSERT INTO lifecycle_monitor_audit(id,user_id,watch_id,action,created_at) VALUES(?,?,?,?,?)',crypto.randomUUID(),user.id,watch||'',action,now);
function watchInput(data){
 const product=String(data.product||'').trim(),slug=String(data.slug||'').toLowerCase(),cycle=String(data.cycle||'').trim(),installed_version=String(data.installed_version||'').trim(),edition=String(data.edition||'').trim(),custom_source_url=String(data.custom_source_url||'').trim();
 if(!product||product.length>120||!/^[a-z0-9-]{0,70}$/.test(slug)||cycle.length>80||installed_version.length>80||edition.length>80||/[\u0000-\u001f]/.test(product+cycle+installed_version+edition))throw new MonitorError('Invalid product, version or edition');
 if(!slug){let url;try{url=new URL(custom_source_url);}catch{throw new MonitorError('Custom products require an official HTTPS source');}
  if(url.protocol!=='https:'||url.username||url.password||url.port||url.hostname==='localhost'||!url.hostname.includes('.')||custom_source_url.length>500)throw new MonitorError('Use an official HTTPS source URL without credentials');}
 return {product,slug,cycle,installed_version,edition,custom_source_url,custom_eol_date:''};
}
function settingsInput(data){
 const alert_types=data.alert_types??DEFAULT_TYPES,notice_days=data.notice_days??[90,30,7],status=data.status??'enabled',delivery_mode=data.delivery_mode??'daily';
 if(!Array.isArray(alert_types)||alert_types.some(x=>!ALERT_TYPES.includes(x))||!Array.isArray(notice_days)||!notice_days.length||notice_days.some(x=>!NOTICE_DAYS.includes(x))||!['enabled','paused','disabled'].includes(status)||!['daily','immediate_security'].includes(delivery_mode))throw new MonitorError('Invalid monitoring or alert settings');
 return {alert_types:JSON.stringify([...new Set(alert_types)].sort()),notice_days:JSON.stringify([...new Set(notice_days)].sort((a,b)=>b-a)),status,delivery_mode,extended_entitled:data.extended_entitled===true?1:0};
}
async function schedulerHealth(env,now){
 const last=await env.DB.prepare("SELECT * FROM lifecycle_monitor_runs WHERE slot NOT LIKE 'mail:%' ORDER BY started_at DESC LIMIT 1").first();
 return {enabled:env.PRODUCT_MONITOR_CHECKS_ENABLED==='true',operating:env.PRODUCT_MONITOR_CHECKS_ENABLED==='true'&&Boolean(last?.completed_at)&&now-last.completed_at<3*3600000,last_run:last?.completed_at||null,next_expected:last?.started_at?last.started_at+3600000:null,error:last?.error||''};
}
export async function monitoringHandler(req,env,user,path,data={},now=Date.now()){
 if(path==='/v1/monitoring/status'){
  const ready=await monitorReady(env);return json({ready,scheduler:ready?await schedulerHealth(env,now):{enabled:false,operating:false},delivery_enabled:monitorDeliveryReady(env),webhook_configured:!!env.SMTP2GO_MONITOR_WEBHOOK_TOKEN,source_adapters:Object.keys(SOURCE_REGISTRY),recipient:user.email,admin:monitorAdmin(env,user),test_allowed:env.PRODUCT_MONITOR_TEST_ENABLED==='true'&&String(env.PRODUCT_MONITOR_TEST_RECIPIENTS||'').toLowerCase().split(',').map(s=>s.trim()).includes(user.email.toLowerCase()),message:ready?'':'Monitoring Not Yet Active: enhanced monitoring schema awaits approval.'});
 }
 if(!await monitorReady(env))throw new MonitorError('Monitoring Not Yet Active: schema and activation await approval. Existing saved lifecycle preferences are preserved.',503);
 if(path==='/v1/monitoring'&&req.method==='GET'){
  const rows=(await q(env.DB,`SELECT w.*,s.status AS monitoring_status,s.alert_types,s.notice_days,s.delivery_mode,s.extended_entitled,s.consented_at,
   p.edition,p.official_url,p.source_id,p.branch,p.verification_error,x.last_attempt_at,x.last_success_at,x.next_due_at,x.error AS source_error,v.record_json,
   (SELECT MAX(n.created_at) FROM lifecycle_monitor_notifications n WHERE n.user_id=w.user_id AND n.watch_id=w.id) AS last_notification_at,
   (SELECT CASE WHEN n.state='suppressed' THEN 'suppressed' ELSE COALESCE(m.state,n.state) END FROM lifecycle_monitor_notifications n LEFT JOIN lifecycle_monitor_messages m ON m.id=n.message_id WHERE n.user_id=w.user_id AND n.watch_id=w.id ORDER BY n.created_at DESC LIMIT 1) AS last_delivery_state,
   (SELECT e.kind FROM lifecycle_monitor_notifications n JOIN lifecycle_monitor_events e ON e.id=n.event_id WHERE n.user_id=w.user_id AND n.watch_id=w.id ORDER BY n.created_at DESC LIMIT 1) AS last_alert_kind
   FROM lifecycle_watches w LEFT JOIN lifecycle_watch_settings s ON s.user_id=w.user_id AND s.watch_id=w.id
   LEFT JOIN lifecycle_monitor_products p ON p.id=s.product_id LEFT JOIN lifecycle_monitor_sources x ON x.id=p.source_id
   LEFT JOIN lifecycle_monitor_state v ON v.product_id=p.id WHERE w.user_id=? ORDER BY w.product,w.cycle LIMIT 100`,user.id).all()).results||[];
  const health=await schedulerHealth(env,now);
  const watches=rows.map(row=>{
   const state=row.record_json?JSON.parse(row.record_json):null;
   let monitoring_label=row.monitoring_status==='paused'?'Paused':row.monitoring_status==='disabled'?'Disabled':!health.operating?'Monitoring Not Yet Active':!row.source_id||!row.monitoring_status||!state?'Source Verification Required':row.source_error||row.verification_error?'Monitoring Failed':!row.last_success_at||now-row.last_success_at>3*DAY?'Source Verification Required':'Monitoring Active';
   if(monitoring_label==='Monitoring Active'&&state){
    const remaining=Object.values(state.milestones).map(d=>(Date.parse(d)-now)/DAY);
    if(remaining.some(d=>d<=0))monitoring_label='End of Support Reached';
    else if(remaining.some(d=>d<=Math.max(...JSON.parse(row.notice_days||'[90]'))))monitoring_label='End of Support Approaching';
    else if(sameBranch(row.installed_version,state.branch)&&compareVersions(state.version,row.installed_version)===1&&!row.edition)monitoring_label=state.security?'Security Update Available':'Upgrade Available';
    else if(!sameBranch(row.installed_version,state.branch)||row.edition)monitoring_label='Needs Review';
   }
   return {...row,record_json:undefined,verified:state,monitoring_label,alert_types:JSON.parse(row.alert_types||'[]'),notice_days:JSON.parse(row.notice_days||'[]')};
  });
  const prefs=await q(env.DB,'SELECT p.email_enabled,p.lead_days,x.alert_types,x.delivery_mode FROM lifecycle_preferences p LEFT JOIN lifecycle_monitor_preferences x ON x.user_id=p.user_id WHERE p.user_id=?',user.id).first();
  if(prefs?.alert_types)prefs.alert_types=JSON.parse(prefs.alert_types);
  return json({watches,preferences:prefs||{email_enabled:0,lead_days:90},scheduler:health,email_delivery_active:monitorDeliveryReady(env)&&health.operating,recipient:user.email});
 }
 if((path==='/v1/monitoring/watches'||path==='/v1/monitoring/watches/bulk')&&req.method==='POST'){
  const inputs=path.endsWith('/bulk')?data.watches:[data];if(!Array.isArray(inputs)||!inputs.length||inputs.length>30)throw new MonitorError('Choose 1–30 products per save');
  const total=await q(env.DB,'SELECT COUNT(*) AS n FROM lifecycle_watches WHERE user_id=?',user.id).first();if(total.n+inputs.length>100)throw new MonitorError('Limit of 100 watches per account',409);
  const statements=[],ids=[];
  for(const input of inputs){
   if(input.recipient&&input.recipient.toLowerCase()!==user.email.toLowerCase())throw new MonitorError('Additional recipients must be separately authorized and verified',403);
   const w=watchInput(input),s=settingsInput(input);let p;try{p=monitorIdentity(w);}catch(error){throw new MonitorError(error.message);}
   const id=crypto.randomUUID();ids.push(id);
   // Unsupported and custom identities remain private, unverified references.
   p.id=await sha(p.source_id?p.id:JSON.stringify([user.id,w.product,w.cycle,w.custom_source_url]));
   if(p.source)statements.push(q(env.DB,'INSERT OR IGNORE INTO lifecycle_monitor_sources(id,adapter,url) VALUES(?,?,?)',p.source_id,p.source.adapter,p.source.url));
   statements.push(q(env.DB,'INSERT OR IGNORE INTO lifecycle_monitor_products(id,source_id,slug,name,vendor,branch,edition,official_url) VALUES(?,?,?,?,?,?,?,?)',p.id,p.source_id,p.source_id?p.slug:'unverified-'+p.id,p.name,p.vendor,p.branch,p.edition,p.official_url),
    q(env.DB,'INSERT INTO lifecycle_watches(user_id,id,product,slug,cycle,installed_version,custom_eol_date,custom_source_url,created_at) SELECT ?,?,?,?,?,?,?,?,? WHERE (SELECT COUNT(*) FROM lifecycle_watches WHERE user_id=?)<100',user.id,id,w.product,w.slug,w.cycle,w.installed_version,'',w.custom_source_url,Math.floor(now/1000),user.id),
    q(env.DB,'INSERT INTO lifecycle_watch_settings(user_id,watch_id,product_id,status,alert_types,notice_days,delivery_mode,extended_entitled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)',user.id,id,p.id,s.status,s.alert_types,s.notice_days,s.delivery_mode,s.extended_entitled,now,now),audit(env,user,id,'watch_created',now));
  }
  await env.DB.batch(statements);return json({saved:true,ids,count:ids.length,message:'Watch saved. Monitoring and delivery status are shown separately; saving does not activate infrastructure or email.'},201);
 }
 if(path==='/v1/monitoring/preferences'&&req.method==='PUT'){
  if(typeof data.email_enabled!=='boolean'||!NOTICE_DAYS.includes(data.lead_days))throw new MonitorError('Choose a valid notice period and explicit email consent');
  const options=settingsInput({...data,notice_days:[data.lead_days]});
  const statements=[q(env.DB,'INSERT INTO lifecycle_preferences(user_id,email_enabled,lead_days,updated_at) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET email_enabled=excluded.email_enabled,lead_days=excluded.lead_days,updated_at=excluded.updated_at',user.id,Number(data.email_enabled),data.lead_days,Math.floor(now/1000)),
   q(env.DB,'UPDATE lifecycle_watch_settings SET consented_at=?,notice_days=?,updated_at=? WHERE user_id=?',data.email_enabled?now:null,JSON.stringify([data.lead_days]),now,user.id),audit(env,user,'',data.email_enabled?'email_opt_in':'email_opt_out',now)];
  if(data.alert_types!==undefined||data.delivery_mode!==undefined){
   statements.push(q(env.DB,'INSERT INTO lifecycle_monitor_preferences(user_id,alert_types,delivery_mode) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET alert_types=excluded.alert_types,delivery_mode=excluded.delivery_mode',user.id,options.alert_types,options.delivery_mode),q(env.DB,'UPDATE lifecycle_watch_settings SET alert_types=?,delivery_mode=? WHERE user_id=?',options.alert_types,options.delivery_mode,user.id));
  }
  if(!data.email_enabled)statements.push(q(env.DB,"UPDATE lifecycle_monitor_notifications SET state='suppressed' WHERE user_id=? AND state IN('pending','queued')",user.id));
  await env.DB.batch(statements);return json({saved:true,delivery_active:env.PRODUCT_MONITOR_DELIVERY_ENABLED==='true'});
 }
 const match=/^\/v1\/monitoring\/watches\/([a-f0-9-]{36})$/.exec(path);
 if(match&&['PUT','DELETE'].includes(req.method)){
  const existing=await q(env.DB,'SELECT * FROM lifecycle_watch_settings WHERE user_id=? AND watch_id=?',user.id,match[1]).first();if(!existing)throw new MonitorError('Watch not found',404);
  const statements=[];
  if(req.method==='DELETE')statements.push(q(env.DB,'DELETE FROM lifecycle_watches WHERE user_id=? AND id=?',user.id,match[1]));
  else{
   const s=settingsInput({...existing,alert_types:JSON.parse(existing.alert_types),notice_days:JSON.parse(existing.notice_days),...data});
   const installed=data.installed_version;
   if(installed!==undefined&&(typeof installed!=='string'||installed.length>80||/[\u0000-\u001f]/.test(installed)))throw new MonitorError('Invalid installed version');
   statements.push(q(env.DB,'UPDATE lifecycle_watch_settings SET status=?,alert_types=?,notice_days=?,delivery_mode=?,extended_entitled=?,updated_at=? WHERE user_id=? AND watch_id=?',s.status,s.alert_types,s.notice_days,s.delivery_mode,s.extended_entitled,now,user.id,match[1]));
   if(installed!==undefined)statements.push(q(env.DB,'UPDATE lifecycle_watches SET installed_version=? WHERE user_id=? AND id=?',installed,user.id,match[1]));
  }
  statements.push(q(env.DB,"UPDATE lifecycle_monitor_notifications SET state='suppressed' WHERE user_id=? AND watch_id=? AND state IN('pending','queued')",user.id,match[1]),audit(env,user,match[1],req.method==='DELETE'?'watch_removed':'watch_updated',now));
  await env.DB.batch(statements);return json({saved:true});
 }
 if(path==='/v1/monitoring/history'&&req.method==='GET'){
  const rows=(await q(env.DB,`SELECT n.id,n.created_at,n.installed_version,n.state AS notification_state,e.kind,e.record_json,m.state AS delivery_state,m.provider_id,m.submitted_at,m.delivered_at,m.attempts,m.detail
   FROM lifecycle_monitor_notifications n JOIN lifecycle_monitor_events e ON e.id=n.event_id LEFT JOIN lifecycle_monitor_messages m ON m.id=n.message_id
   WHERE n.user_id=? ORDER BY n.created_at DESC LIMIT 100`,user.id).all()).results||[];
  const tests=(await q(env.DB,"SELECT id,created_at,state AS delivery_state,provider_id,submitted_at,delivered_at,attempts,detail FROM lifecycle_monitor_messages WHERE user_id=? AND slot LIKE 'test:%' ORDER BY created_at DESC LIMIT 20",user.id).all()).results||[];
  return json({history:[...rows.map(r=>({...r,record_json:undefined,event:JSON.parse(r.record_json)})),...tests.map(r=>({...r,kind:'test',event:{product:'SMTP2GO test message',branch:'approved test',source_url:'https://developers.smtp2go.com/docs/send-an-email'}}))].sort((a,b)=>b.created_at-a.created_at).slice(0,100)});
 }
 if(path==='/v1/monitoring/admin'&&req.method==='GET'){
  if(!monitorAdmin(env,user))throw new MonitorError('Administrator permission required',403);
  const sources=(await env.DB.prepare('SELECT id,last_attempt_at,last_success_at,next_due_at,failures,error FROM lifecycle_monitor_sources ORDER BY id').all()).results||[];
  const messages=(await env.DB.prepare('SELECT id,state,provider_id,attempts,created_at,submitted_at,delivered_at,detail FROM lifecycle_monitor_messages ORDER BY created_at DESC LIMIT 100').all()).results||[];
  const runs=(await env.DB.prepare('SELECT * FROM lifecycle_monitor_runs ORDER BY started_at DESC LIMIT 24').all()).results||[];
  const pending=await env.DB.prepare("SELECT COUNT(*) AS count,MIN(n.created_at) AS oldest FROM lifecycle_monitor_notifications n LEFT JOIN lifecycle_monitor_messages m ON m.id=n.message_id WHERE n.state='pending' OR (n.state='queued' AND m.state IN('pending','submitting'))").first();
  return json({scheduler:await schedulerHealth(env,now),sources,messages,runs,pending,attention:sources.some(s=>s.failures>0||!s.last_success_at||now-s.last_success_at>3*DAY)||Boolean(pending.oldest&&now-pending.oldest>2*DAY)||messages.some(m=>['failed','submission_unknown'].includes(m.state))});
 }
 if(path==='/v1/monitoring/test-email'&&req.method==='POST'){
  if(env.PRODUCT_MONITOR_TEST_ENABLED!=='true')throw new MonitorError('Test delivery awaits approved configuration',503);
  const approved=String(env.PRODUCT_MONITOR_TEST_RECIPIENTS||'').toLowerCase().split(',').map(s=>s.trim());
  const recipient=String(data.recipient||user.email).toLowerCase();
  if(!approved.includes(recipient)||recipient!==user.email.toLowerCase()&&!monitorAdmin(env,user))throw new MonitorError('Use an approved recipient owned by your account or an authorized administrator',403);
  if(await q(env.DB,'SELECT 1 FROM lifecycle_monitor_suppressions WHERE recipient_hash=?',await sha(recipient)).first())throw new MonitorError('This recipient is suppressed; resolve the suppression with the provider before testing',409);
  const recent=await q(env.DB,"SELECT COUNT(*) AS n FROM lifecycle_monitor_messages WHERE user_id=? AND slot LIKE 'test:%' AND created_at>?",user.id,now-3600000).first();if(recent.n>=2)throw new MonitorError('Limit of two tests per hour',429);
  const id=crypto.randomUUID(),record={product:'SMTP2GO connection',branch:'test',version:'',source_url:'https://developers.smtp2go.com/docs/send-an-email'};
  await q(env.DB,"INSERT INTO lifecycle_monitor_messages(id,user_id,recipient,slot,state,attempts,created_at,lease_until) VALUES(?,?,?,?,'submitting',1,?,?)",id,user.id,recipient,'test:'+id,now,now+120000).run();
  try{const result=await submitSmtp2go(env,recipient,renderMonitorMail([{kind:'test',record}],{test:true}));await q(env.DB,"UPDATE lifecycle_monitor_messages SET state='submitted',provider_id=?,request_id=?,submitted_at=?,lease_until=0,detail='Test accepted; delivery pending' WHERE id=?",result.provider_id,result.request_id,now,id).run();return json({state:'submitted',provider_id:result.provider_id,delivery_confirmed:false});}
  catch(error){await q(env.DB,'UPDATE lifecycle_monitor_messages SET state=?,lease_until=0,detail=? WHERE id=?',error.unknown?'submission_unknown':'failed','Test submission failed or requires reconciliation',id).run();throw new MonitorError('Test was not confirmed accepted; see delivery log',502);}
 }
 return json({error:'Not found'},404);
}
export async function dispatchProductMonitoring(env,day=new Date(),fetcher=fetch){
 if(env.PRODUCT_MONITOR_CHECKS_ENABLED!=='true')return {disabled:true};
 if(!await monitorReady(env))return {migration_required:true};
 const now=day.getTime(),slot=day.toISOString().slice(0,13),claim=await q(env.DB,'INSERT OR IGNORE INTO lifecycle_monitor_runs(slot,started_at) VALUES(?,?)',slot,now).run();
 if(claim.meta.changes!==1)return {already_claimed:true};
 const metrics={read:0,written:0},db=env.DB,originals=new WeakMap();
 const count=r=>{metrics.read+=r.meta?.rows_read||0;metrics.written+=r.meta?.rows_written||0;return r;};
 const wrap=statement=>{const wrapped={bind:(...args)=>wrap(statement.bind(...args))};for(const method of ['all','run'])wrapped[method]=async()=>count(await statement[method]());wrapped.first=async()=>{const r=count(await statement.all());return r.results?.[0]||null;};originals.set(wrapped,statement);return wrapped;};
 const metered={...env,DB:{prepare:sql=>wrap(db.prepare(sql)),batch:async statements=>(await db.batch(statements.map(s=>originals.get(s)))).map(count)}};
 try{
  const source=await checkSubscribedSources(metered,fetcher,now),reminderDay=day.toISOString().slice(0,10);
  const alreadyEvaluated=await q(metered.DB,'SELECT 1 FROM lifecycle_monitor_runs WHERE reminder_day=? AND completed_at IS NOT NULL LIMIT 1',reminderDay).first();
  const reminders=alreadyEvaluated?0:await dailyReminders(metered,now);
  await q(env.DB,'UPDATE lifecycle_monitor_runs SET completed_at=?,checked=?,failed=?,new_events=?,submitted=?,rows_read=?,rows_written=?,reminder_day=?,error=? WHERE slot=?',now,source.checked,source.failed,source.events+reminders,0,metrics.read,metrics.written,alreadyEvaluated?'':reminderDay,source.failed?'Some source checks failed; verified state retained':'',slot).run();
  return source;
 }catch{await q(env.DB,"UPDATE lifecycle_monitor_runs SET completed_at=?,error='Monitoring run failed; inspect source and delivery logs' WHERE slot=?",now,slot).run();return {failed:true};}
}
export async function dispatchProductMonitorMail(env,day=new Date(),fetcher=fetch){
 if(env.PRODUCT_MONITOR_CHECKS_ENABLED!=='true'||!monitorDeliveryReady(env)||!await monitorReady(env))return {disabled:true};
 const now=day.getTime();
 const work=await q(env.DB,`SELECT EXISTS(SELECT 1 FROM lifecycle_monitor_notifications n JOIN lifecycle_monitor_events e ON e.id=n.event_id
  LEFT JOIN lifecycle_watch_settings s ON s.user_id=n.user_id AND s.watch_id=n.watch_id
  WHERE n.state='pending' AND n.due_at<=? AND (COALESCE(s.delivery_mode,'daily')='immediate_security' AND e.kind='security' OR NOT EXISTS(
   SELECT 1 FROM lifecycle_monitor_messages m WHERE m.user_id=n.user_id AND m.recipient=n.recipient AND m.slot=? AND m.state<>'pending')))
  OR EXISTS(SELECT 1 FROM lifecycle_monitor_messages WHERE (state='pending' AND attempts<5 AND next_attempt_at<=?) OR (state='submitting' AND lease_until<?)) AS due`,now,'digest:'+day.toISOString().slice(0,10),now,now).first();
 if(!work?.due)return {idle:true};
 const slot='mail:'+day.toISOString().slice(0,16);
 if((await q(env.DB,'INSERT OR IGNORE INTO lifecycle_monitor_runs(slot,started_at) VALUES(?,?)',slot,now).run()).meta.changes!==1)return {already_claimed:true};
 try{const result=await dispatchMonitorMail(env,fetcher,now);await q(env.DB,'UPDATE lifecycle_monitor_runs SET completed_at=?,submitted=? WHERE slot=?',now,result.submitted||0,slot).run();return result;}
 catch{await q(env.DB,"UPDATE lifecycle_monitor_runs SET completed_at=?,error='Delivery worker failed; inspect outbox before retrying' WHERE slot=?",now,slot).run();return {failed:true};}
}
