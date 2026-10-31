const LIMIT=150000,WARNING=135000;
export const usageMonth=(date=new Date())=>date.toISOString().slice(0,7);
export async function usageReport(env,userId,month=usageMonth()){
 const total=await env.DB.prepare('SELECT reserved,warning_sent_at FROM web_risk_usage WHERE month=?').bind(month).first();
 const account=await env.DB.prepare('SELECT requests FROM web_risk_account_usage WHERE month=? AND user_id=?').bind(month,userId).first();
 return {month,global_limit:LIMIT,global_used:total?.reserved||0,global_remaining:Math.max(0,LIMIT-(total?.reserved||0)),warning_threshold:WARNING,warning_sent:!!total?.warning_sent_at,account_used:account?.requests||0,paused:(total?.reserved||0)>=LIMIT};
}
async function warn(env,month,count){
 if(count<WARNING||!env.SMTP2GO_API_KEY||!env.EMAIL_FROM||!env.WEB_RISK_BILLING_ALERT_EMAIL)return;
 const claimed=await env.DB.prepare('UPDATE web_risk_usage SET warning_sent_at=? WHERE month=? AND warning_sent_at IS NULL').bind(Math.floor(Date.now()/1000),month).run();
 if(claimed.meta.changes!==1)return;
 try{
  const result=await fetch('https://api.smtp2go.com/v3/email/send',{method:'POST',headers:{'content-type':'application/json','X-Smtp2go-Api-Key':env.SMTP2GO_API_KEY},body:JSON.stringify({sender:env.EMAIL_FROM,to:[env.WEB_RISK_BILLING_ALERT_EMAIL],subject:'CVEHarbor Web Risk usage warning: '+count+' / '+LIMIT, text_body:'CVEHarbor has reserved '+count+' Google Web Risk requests in '+month+'. The automatic stop applies at '+LIMIT+'. Review Google Cloud billing and API usage.'})});
  if(!result.ok)throw Error('Email service unavailable');
 }catch{
  // Allow retry of alert delivery on the next eligible lookup.
  await env.DB.prepare('UPDATE web_risk_usage SET warning_sent_at=NULL WHERE month=?').bind(month).run();
 }
}
export async function reserveLookup(env,userId){
 if(!env.DB)return {allowed:false,reason:'tracking_unavailable'};
 const month=usageMonth(),timestamp=Math.floor(Date.now()/1000);
 try{
  await env.DB.prepare('INSERT OR IGNORE INTO web_risk_usage(month,reserved,updated_at) VALUES(?,0,?)').bind(month,timestamp).run();
  // Conditional D1 UPDATE serializes concurrent requests and enforces the global cap.
  const claim=await env.DB.prepare('UPDATE web_risk_usage SET reserved=reserved+1,updated_at=? WHERE month=? AND reserved<?').bind(timestamp,month,LIMIT).run();
  if(claim.meta.changes!==1)return {allowed:false,reason:'monthly_limit',month};
  await env.DB.prepare('INSERT INTO web_risk_account_usage(month,user_id,requests) VALUES(?,?,1) ON CONFLICT(month,user_id) DO UPDATE SET requests=requests+1').bind(month,userId).run();
  const row=await env.DB.prepare('SELECT reserved FROM web_risk_usage WHERE month=?').bind(month).first();
  const count=row?.reserved||0;
  await warn(env,month,count);
  return {allowed:true,month,global_used:count};
 }catch{return {allowed:false,reason:'tracking_unavailable',month}}
}
