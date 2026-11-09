import {sendEmail} from './delivery.js';
import {openIntelligenceSnapshot} from './intelligence-store.js';

const base = 'https://api.cveharbor.com/v1/firewall-updates';
const site = 'https://cveharbor.com';
const dayMs = 86400000;
const seconds = () => Math.floor(Date.now()/1000);
const token = () => crypto.randomUUID().replaceAll('-','') + crypto.randomUUID().replaceAll('-','');
const hex = bytes => Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2,'0')).join('');
const hashed = async value => hex(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value)));
const style = 'body{background:#0c2232;color:#eef7f8;font:18px/1.6 system-ui;max-width:36rem;margin:12vh auto;padding:1.5rem}a{color:#8be2d1}button,input{font:inherit;padding:.6rem .9rem;margin:.5rem 0;box-sizing:border-box;width:100%}button{background:#83dfcf;color:#132c38;border:0;border-radius:.35rem}';
function page(title, content, status=200) {
  return new Response('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>'+title+' | CVEHarbor</title><style>'+style+'</style><main><b>CVEHarbor</b><h1>'+title+'</h1>'+content+'</main></html>',{status,headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://api.cveharbor.com; frame-ancestors 'none'; base-uri 'none'",'X-Content-Type-Options':'nosniff'}});
}
const button = (label) => '<form method="post"><button>'+label+'</button></form>';
export function dailyHosts(history, day) {
  const start=Date.parse(day+'T00:00:00Z');
  return Object.entries(history.addresses).filter(([,record])=>{
    const seen=Date.parse(record.first_indexed);return seen>=start && seen<start+dayMs;
  })
    .map(([ip])=>ip).filter(ip=>/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip) && ip.split('.').every(n=>Number(n)<=255)).sort((a,b)=>a.localeCompare(b,'en',{numeric:true}));
}
async function historyFor(env,day) {
  const history=await (await openIntelligenceSnapshot(env)).json('data/threat-ip-history.json');
  if (!history.addresses || !(Date.parse(history.generated_at)>=Date.parse(day)+dayMs)) throw Error('Incomplete firewall publication');
  return dailyHosts(history,day);
}
export async function firewallRoute(req,env,limit){
  const url=new URL(req.url), suffix=url.pathname.slice('/v1/firewall-updates'.length);
  const get=req.method==='GET', post=req.method==='POST';
  if(!get&&!post)return new Response(null,{status:405,headers:{Allow:'GET, POST'}});
  if(!suffix){
    if(get)return page('Daily firewall updates','<p>Receive one email on days when CVEHarbor has newly observed firewall IPs. Confirm your address to subscribe.</p><form method="post"><label>Email address<input name="email" type="email" required maxlength="254" autocomplete="email"></label><button>Subscribe to daily updates</button></form>');
    if(![site,new URL(base).origin].includes(req.headers.get('Origin')))return page('Request unavailable','Please open the signup form again.',403);
    if(!req.headers.get('Content-Type')?.startsWith('application/x-www-form-urlencoded'))return page('Invalid form','Please open the signup form again.',415);
    const reader=req.body?.getReader(); if(!reader)return page('Email required','Please enter an email address.',400);
    const decoder=new TextDecoder(); let bytes=0,encoded='';
    for(;;){const part=await reader.read();if(part.done)break;bytes+=part.value.byteLength;if(bytes>1024){await reader.cancel();return page('Form too large','Please enter one email address.',413);}encoded+=decoder.decode(part.value,{stream:true});}
    const email=String(new URLSearchParams(encoded+decoder.decode()).get('email')||'').toLowerCase().trim();
    if(email.length>254||!/^[^\s@<>]{1,64}@[^\s@<>]+\.[^\s@<>]+$/.test(email))return page('Email required','Please enter a valid email address.',400);
    const ipKey='firewall:'+await hashed(req.headers.get('CF-Connecting-IP')||'unknown');
    if(!await limit(env,ipKey,6))return page('Please try later','Too many signup attempts. Please try again in an hour.',429);
    const proof=token(), now=seconds();
    const row=await env.DB.prepare(`INSERT INTO firewall_subscribers(id,email,confirmation_hash,requested_at,unsubscribe_token) VALUES(?,?,?,?,?)
      ON CONFLICT(email) DO UPDATE SET confirmation_hash=excluded.confirmation_hash,requested_at=excluded.requested_at
      WHERE firewall_subscribers.confirmed_at IS NULL AND firewall_subscribers.requested_at<=excluded.requested_at-86400 RETURNING id`)
      .bind(crypto.randomUUID(),email,await hashed(proof),now,token()).first();
    if(row){
      const link=base+'/confirm/'+proof;
      try {await sendEmail(env,email,{subject:'Confirm your CVEHarbor firewall updates',text:'Confirm your email to receive daily updates about newly observed firewall IPs. This link expires in 24 hours. '+link,html:'<p>Confirm your address to receive daily firewall updates.</p><p><a href="'+link+'">Confirm subscription</a> (valid for 24 hours)</p>'});}
      catch(error){await env.DB.prepare('DELETE FROM firewall_subscribers WHERE id=? AND confirmation_hash=? AND confirmed_at IS NULL').bind(row.id,await hashed(proof)).run();throw error;}
    }
    return page('Check your inbox','If your address needs confirmation, you will receive a link by email.');
  }
  const action=/^\/(confirm|unsubscribe)\/([a-f0-9]{64})$/.exec(suffix);
  if(action){
    const confirm=action[1]==='confirm';
    if(get)return page(confirm?'Confirm your subscription':'Unsubscribe from daily firewall updates',button(confirm?'Confirm subscription':'Unsubscribe'));
    if(confirm){
      const result=await env.DB.prepare('UPDATE firewall_subscribers SET confirmed_at=?, confirmation_hash=NULL WHERE confirmation_hash=? AND requested_at>=? AND confirmed_at IS NULL')
        .bind(seconds(),await hashed(action[2]),seconds()-86400).run();
      if(!result.meta.changes)return page('Link already used or expired','If you still need to subscribe, <a href="'+base+'">request a confirmation email</a>.');
    }else await env.DB.prepare('DELETE FROM firewall_subscribers WHERE unsubscribe_token=?').bind(action[2]).run();
    return page(confirm?'Subscription confirmed':'Unsubscribed',confirm?'You will receive updates for new firewall IPs starting with your first full UTC day.':'Daily firewall emails have been stopped for this subscription.');
  }
  const file=/^\/addresses\/(\d{4}-\d{2}-\d{2})\.txt$/.exec(suffix);
  if(file&&get){
    const stamp=Date.parse(file[1]), today=Math.floor(Date.now()/dayMs)*dayMs;
    if(!Number.isFinite(stamp)||new Date(stamp).toISOString().slice(0,10)!==file[1]||stamp>=today||stamp<today-30*dayMs)return new Response('Date unavailable',{status:404});
    const cache=globalThis.caches?.default, key=base+suffix;
    const cached=await cache?.match(key); if(cached)return cached;
    const ips=await historyFor(env,file[1]);
    const response=new Response(ips.length?ips.join('\n')+'\n':'',{headers:{'Content-Type':'text/plain','Cache-Control':'public, max-age=86400','X-Content-Type-Options':'nosniff'}});
    if(cache)await cache.put(key,response.clone());return response;
  }
  return new Response('Not found',{status:404});
}
export async function dispatchFirewallDigest(env,now=new Date(),sender=sendEmail){
  const begin=Math.floor(now.getTime()/dayMs)*dayMs-dayMs, day=new Date(begin).toISOString().slice(0,10);
  await env.DB.prepare('DELETE FROM firewall_subscribers WHERE confirmed_at IS NULL AND requested_at<?').bind(seconds()-2*86400).run();
  const subscribers=(await env.DB.prepare(`SELECT id,email,unsubscribe_token FROM firewall_subscribers s WHERE s.confirmed_at<=?
    AND NOT EXISTS(SELECT 1 FROM firewall_digest_deliveries d WHERE d.subscriber_id=s.id AND d.day=?) ORDER BY s.confirmed_at,s.id LIMIT 20`).bind(begin/1000,day).all()).results;
  if(!subscribers.length)return;
  const ips=await historyFor(env,day);if(!ips.length)return;
  const file=base+'/addresses/'+day+'.txt', subject='CVEHarbor firewall updates · '+day+' · '+ips.length+' new IPs';
  for(const sub of subscribers){
    const claim=await env.DB.prepare(`INSERT OR IGNORE INTO firewall_digest_deliveries(subscriber_id,day,claimed_at) SELECT id,?,? FROM firewall_subscribers WHERE id=? AND confirmed_at IS NOT NULL`).bind(day,seconds(),sub.id).run();
    if(!claim.meta.changes)continue;
    const unsubscribe=base+'/unsubscribe/'+sub.unsubscribe_token;
    const message=ips.length+' IPv4 addresses first appeared in the firewall exports on '+day+' (UTC). Review them before changing any firewall policy.';
    try{
      const receipt=await sender(env,sub.email,{subject,text:message+'\n'+ips.slice(0,10).join('\n')+'\nFull list: '+file+'\nUnsubscribe: '+unsubscribe,html:'<p>'+message+'</p><pre>'+ips.slice(0,10).join('\n')+'</pre><p><a href="'+file+'">Download all '+ips.length+' addresses</a></p><p><a href="'+unsubscribe+'">Unsubscribe</a></p>'},unsubscribe);
      await env.DB.prepare('UPDATE firewall_digest_deliveries SET accepted_at=?,provider_id=? WHERE subscriber_id=? AND day=?').bind(seconds(),receipt,sub.id,day).run();
    }catch{console.error('Firewall digest delivery needs reconciliation for day '+day+' and claim '+sub.id);}
  }
}

