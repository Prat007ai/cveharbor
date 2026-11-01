// One-time test explicitly approved by the account owner on 2026-11-01.
// Runs inside the existing Worker: the SMTP2GO secret never leaves Cloudflare.
// No public trigger, arbitrary recipient, schema change, new secret or customer enrollment.
import {submitSmtp2go} from './monitor-mail.js';
export const TEST_ID='monitor-approved-20261101';
export const TEST_EXPIRES=Date.parse('2026-11-03T00:00:00Z');
const START=Date.parse('2026-11-01T22:45:00Z');
const RECIPIENTS=['prat.mahen@gmail.com','PMahendran@whitecapcanada.com'];
const PREFIX=TEST_ID+':';
// Existing email rate-limit store, in an isolated namespace. Keep the one-time
// claim beyond the test's hard expiry so hourly auth cleanup cannot permit replay.
const RETAIN_UNTIL=Math.floor(TEST_EXPIRES/1000)+86400;
const stmt=(env,sql,...args)=>env.DB.prepare(sql).bind(...args);
async function receipt(env,index,data){
 const prefix=PREFIX+index+':result:';
 await env.DB.batch([
  stmt(env,'DELETE FROM auth_rate_limits WHERE key LIKE ?',prefix+'%'),
  stmt(env,'INSERT INTO auth_rate_limits(key,window_start,count) VALUES(?,?,1)',prefix+JSON.stringify(data),RETAIN_UNTIL)
 ]);
}
export async function approvedTest(env,now=Date.now(),fetcher=fetch){
 if(now<START||now>=TEST_EXPIRES||!env.DB||!env.SMTP2GO_API_KEY||env.EMAIL_FROM!=='alerts@cveharbor.com')return {inactive:true};
 const records=(await stmt(env,'SELECT key,count FROM auth_rate_limits WHERE key LIKE ?',PREFIX+'%').all()).results;
 const outcomes=[];
 for(let index=0;index<RECIPIENTS.length;index++){
  const claimKey=PREFIX+index+':claim',resultKey=PREFIX+index+':result:';
  const saved=records.find(r=>r.key.startsWith(resultKey));
  let result=saved?JSON.parse(saved.key.slice(resultKey.length)):null;
  if(!records.some(r=>r.key===claimKey)){
   const claimed=await stmt(env,'INSERT OR IGNORE INTO auth_rate_limits(key,window_start,count) VALUES(?,?,1)',claimKey,RETAIN_UNTIL).run();
   if(claimed.meta.changes!==1)continue;
   // Store before external side effects. Crash or timeout is never retried.
   result={state:'submission_unknown',started_at:now,checks:0};
   await receipt(env,index,result);
   try{
    const text='CVEHarbor — End of Support & Patch Watch\n\nThis is the one-time SMTP2GO test email you approved. It was sent from the existing CVEHarbor Cloudflare Worker using its existing SMTP2GO secret.\n\nThis verifies the email path only. It does not announce a product release or lifecycle deadline, and it does not activate customer alerts.\n\nOpen your monitoring workspace: https://cveharbor.com/lifecycle/\n\nTest reference: '+TEST_ID+'\nProvider acceptance and recipient-server delivery are checked separately.';
    const mail={subject:'CVEHarbor — approved Patch Watch test email',text,html:'<!doctype html><html><body style="margin:0;background:#031421;color:#dceef8;font:15px Arial,sans-serif;padding:32px"><div style="max-width:600px;margin:auto;border:1px solid #17617a;border-radius:14px;padding:28px"><h1 style="color:#25ead6">CVEHarbor</h1><h2>End of Support &amp; Patch Watch</h2><p>This is the one-time SMTP2GO test email you approved.</p><p>It was sent by the existing CVEHarbor Cloudflare Worker using its existing SMTP2GO secret.</p><p>This tests email delivery only. It does not announce a product event or activate customer alerts.</p><p><a style="color:#2df4d8" href="https://cveharbor.com/lifecycle/">Open your monitoring workspace →</a></p><p style="font-size:12px;color:#a8c7d8">Test reference: '+TEST_ID+'</p></div></body></html>'};
    const accepted=await submitSmtp2go({...env,ALERT_SMTP2GO_API_KEY:undefined},RECIPIENTS[index],mail,fetcher,[{header:'X-CVEHarbor-Test',value:TEST_ID}]);
    result={...result,...accepted,state:'submitted',submitted_at:now};
   }catch(error){result={...result,state:error.unknown?'submission_unknown':'failed',detail:error.unknown?'Acceptance unknown; do not resend':'Provider did not confirm acceptance'};}
   await receipt(env,index,result);outcomes.push({index,...result});continue;
  }
  if(!result||result.state!=='submitted'||result.checks>=6||now<(result.checked_at||result.submitted_at)+60000)continue;
  // Claim each reconciliation slot too, so overlapping Cron deliveries are bounded.
  const slot=PREFIX+index+':check:'+result.checks;
  const claimed=await stmt(env,'INSERT OR IGNORE INTO auth_rate_limits(key,window_start,count) VALUES(?,?,1)',slot,RETAIN_UNTIL).run();
  if(claimed.meta.changes!==1)continue;
  result={...result,checks:result.checks+1,checked_at:now};
  try{
   const response=await fetcher('https://api.smtp2go.com/v3/activity/search',{method:'POST',headers:{'Content-Type':'application/json','X-Smtp2go-Api-Key':env.SMTP2GO_API_KEY},signal:AbortSignal.timeout(15000),body:JSON.stringify({search_email_id:result.provider_id,search_recipient:RECIPIENTS[index],start_date:new Date(result.started_at-60000).toISOString(),limit:100})});
   const payload=await response.json();
   if(!response.ok||!Array.isArray(payload.data?.events)){result.reconciliation='Activity lookup unavailable with the existing key';result.checks=6;}
   else{
    const events=payload.data.events.filter(e=>e.email_id===result.provider_id&&String(e.recipient||'').toLowerCase()===RECIPIENTS[index].toLowerCase()&&Date.parse(e.date)>=result.started_at-60000&&Date.parse(e.date)<=now+60000);
    const failure=events.find(e=>['hard-bounced','rejected','spam','unsubscribed'].includes(e.event)),delivered=events.find(e=>e.event==='delivered');
    if(failure){result.state='failed';result.event=failure.event;result.event_at=failure.date;}
    else if(delivered){result.state='delivered';result.event_at=delivered.date;}
    else result.reconciliation=payload.data.continue_token?'More activity exists; no matching delivery confirmed':'No matching delivery event yet';
   }
  }catch{result.reconciliation='Activity lookup unavailable; delivery unconfirmed';}
  await receipt(env,index,result);outcomes.push({index,...result});
 }
 return {outcomes};
}
