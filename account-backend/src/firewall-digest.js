import {CONFIRM_ORIGIN} from './confirmation-host.js';
import {firewallPage as page,confirmEmail,confirmPage,activePage,preferencesPage,stoppedPage,dailyEmail} from './firewall-templates.js';
import {sendEmail} from './delivery.js';
import {openIntelligenceSnapshot} from './intelligence-store.js';

const base = 'https://api.cveharbor.com/v1/firewall-updates';
const publicLinks=CONFIRM_ORIGIN+'/firewall-updates';
const site = 'https://cveharbor.com';
const dayMs = 86400000;
const seconds = () => Math.floor(Date.now()/1000);
const token = () => crypto.randomUUID().replaceAll('-','') + crypto.randomUUID().replaceAll('-','');
const hex = bytes => Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2,'0')).join('');
const hashed = async value => hex(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value)));
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
  const url=new URL(req.url), branded=url.origin===CONFIRM_ORIGIN,
    suffix=url.pathname.slice((branded?'/firewall-updates':'/v1/firewall-updates').length);
  const get=req.method==='GET', post=req.method==='POST';
  if(!get&&!post)return new Response(null,{status:405,headers:{Allow:'GET, POST'}});
  if(!suffix&&!branded){
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
      const link=publicLinks+'/confirm/'+proof;
      try {await sendEmail(env,email,confirmEmail(link));}
      catch(error){await env.DB.prepare('DELETE FROM firewall_subscribers WHERE id=? AND confirmation_hash=? AND confirmed_at IS NULL').bind(row.id,await hashed(proof)).run();throw error;}
    }
    return page('Check your inbox','If your address needs confirmation, you will receive a link by email.');
  }
  const action=/^\/(confirm|unsubscribe)\/([a-f0-9]{64})$/.exec(suffix);
  if(action){
    const confirm=action[1]==='confirm';
    const token=action[2];
    if(post && req.headers.has('Origin') && req.headers.get('Origin')!==url.origin)
      return page('Request unavailable','<p>Open the link in your email again.</p>',403);
    if(confirm){
      const hash=await hashed(token), cutoff=seconds()-86400;
      const row=get
        ? await env.DB.prepare('SELECT email FROM firewall_subscribers WHERE confirmation_hash=? AND requested_at>=? AND confirmed_at IS NULL').bind(hash,cutoff).first()
        : await env.DB.prepare('UPDATE firewall_subscribers SET confirmed_at=?,confirmation_hash=NULL WHERE confirmation_hash=? AND requested_at>=? AND confirmed_at IS NULL RETURNING email,unsubscribe_token').bind(seconds(),hash,cutoff).first();
      if(!row)return page('Link already used or expired','<p>Already confirmed? Your subscription is active. Otherwise, <a href="'+base+'">request another confirmation email</a>.</p>');
      return get?confirmPage(row.email):activePage(row.email,publicLinks+'/unsubscribe/'+row.unsubscribe_token);
    }
    const row=await env.DB.prepare('SELECT email FROM firewall_subscribers WHERE unsubscribe_token=? AND confirmed_at IS NOT NULL').bind(token).first();
    if(!row)return page('Subscription link is inactive','<p>This link has already been used or is no longer valid.</p>');
    if(get)return preferencesPage(row.email);
    let scope='digest';
    if(req.body){
      const reader=req.body.getReader();let data='',size=0;
      for(;;){const {value,done}=await reader.read();if(done)break;size+=value.length;
        if(size>128){await reader.cancel();return page('Invalid selection','<p>Open the preferences page again.</p>',400);}
        data+=String.fromCharCode(...value);}
      if(data==='scope=all' && req.headers.get('Origin')===url.origin)scope='all';
      else if(!['','scope=digest','List-Unsubscribe=One-Click'].includes(data))return page('Invalid selection','<p>Choose an option on the preferences page.</p>',400);
    }
    await stopSubscriptions(env.DB,token,scope);
    return stoppedPage(scope,row.email);
  }
  const file=/^\/addresses\/(\d{4}-\d{2}-\d{2})\.txt$/.exec(suffix);
  if(file&&get&&!branded){
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
async function stopSubscriptions(db,token,scope){
  const writes=[];
  if(scope==='all'){
    // Every statement rechecks the same live bearer, inside one D1 transaction.
    const owner='(SELECT u.id FROM users u JOIN firewall_subscribers s ON s.email=u.email COLLATE NOCASE WHERE s.unsubscribe_token=? AND s.confirmed_at IS NOT NULL)';
    writes.push(
      db.prepare('UPDATE alert_preferences SET enabled=0,updated_at=CURRENT_TIMESTAMP WHERE user_id IN '+owner).bind(token),
      db.prepare('DELETE FROM alert_optins WHERE user_id IN '+owner).bind(token),
      db.prepare('UPDATE lifecycle_preferences SET email_enabled=0,updated_at=? WHERE user_id IN '+owner).bind(seconds(),token)
    );
    // Some deployments have lifecycle preferences before notification delivery is installed.
    if(await db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='lifecycle_monitor_notifications'").first())
      writes.push(db.prepare("UPDATE lifecycle_monitor_notifications SET state='suppressed' WHERE state IN ('pending','queued') AND user_id IN "+owner).bind(token));
  }
  writes.push(db.prepare('DELETE FROM firewall_subscribers WHERE unsubscribe_token=? AND confirmed_at IS NOT NULL').bind(token));
  await db.batch(writes);
}
export async function dispatchFirewallDigest(env,now=new Date(),sender=sendEmail){
  const begin=Math.floor(now.getTime()/dayMs)*dayMs-dayMs, day=new Date(begin).toISOString().slice(0,10);
  await env.DB.prepare('DELETE FROM firewall_subscribers WHERE confirmed_at IS NULL AND requested_at<?').bind(seconds()-2*86400).run();
  const subscribers=(await env.DB.prepare(`SELECT id,email,unsubscribe_token FROM firewall_subscribers s WHERE s.confirmed_at<=?
    AND NOT EXISTS(SELECT 1 FROM firewall_digest_deliveries d WHERE d.subscriber_id=s.id AND d.day=?) ORDER BY s.confirmed_at,s.id LIMIT 20`).bind(begin/1000,day).all()).results;
  if(!subscribers.length)return;
  const ips=await historyFor(env,day);if(!ips.length)return;
  const file=base+'/addresses/'+day+'.txt';
  for(const sub of subscribers){
    const claim=await env.DB.prepare(`INSERT OR IGNORE INTO firewall_digest_deliveries(subscriber_id,day,claimed_at) SELECT id,?,? FROM firewall_subscribers WHERE id=? AND confirmed_at IS NOT NULL`).bind(day,seconds(),sub.id).run();
    if(!claim.meta.changes)continue;
    const unsubscribe=publicLinks+'/unsubscribe/'+sub.unsubscribe_token;
    try{
      const receipt=await sender(env,sub.email,dailyEmail(day,ips,file,unsubscribe),unsubscribe);
      await env.DB.prepare('UPDATE firewall_digest_deliveries SET accepted_at=?,provider_id=? WHERE subscriber_id=? AND day=?').bind(seconds(),receipt,sub.id,day).run();
    }catch{console.error('Firewall digest delivery needs reconciliation for day '+day+' and claim '+sub.id);}
  }
}

