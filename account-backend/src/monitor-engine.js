import {DAY,SOURCE_REGISTRY,normalizeVendor,fetchVendor,compareVersions,sameBranch} from './monitor-sources.js';
export const q=(db,sql,...args)=>db.prepare(sql).bind(...args);
export const sha=async value=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value)))].map(n=>n.toString(16).padStart(2,'0')).join('');
export const json=(value,status=200)=>Response.json(value,{status,headers:{'Cache-Control':'no-store','Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true','Vary':'Origin'}});
export async function monitorReady(env){try{await env.DB.prepare('SELECT slot FROM lifecycle_monitor_runs LIMIT 1').first();return true;}catch{return false;}}
export const ALERT_TYPES=['stable','maintenance','security','critical','lifecycle_change','mainstream','extended','security_support','eol'];
export const DEFAULT_TYPES=['maintenance','security','lifecycle_change','mainstream','security_support','eol'];
export const NOTICE_DAYS=[180,90,60,30,14,7];
export function reminderThreshold(date,days,now){
 const remaining=Math.ceil((Date.parse(date+'T00:00:00Z')-Date.parse(new Date(now).toISOString().slice(0,10)+'T00:00:00Z'))/DAY);
 if(!Number.isFinite(remaining))return null;
 if(remaining<=0)return 0;
 const crossed=days.filter(d=>d>=remaining).sort((a,b)=>a-b);
 return crossed[0]??null;
}
export const digestDue=now=>{const today=Date.parse(new Date(now).toISOString().slice(0,10)+'T08:00:00Z');return today>=now?today:today+DAY;};
async function event(env,product,kind,key,record,now){
 const eventKey=product.id+':'+kind+':'+key,id=await sha(eventKey);
 const fence=env.MONITOR_CHECK_FENCE;
 const result=await q(env.DB,`INSERT OR IGNORE INTO lifecycle_monitor_events(id,product_id,kind,event_key,record_json,created_at) SELECT ?,?,?,?,?,?
  WHERE ?='' OR EXISTS(SELECT 1 FROM lifecycle_monitor_sources WHERE id=? AND lease_token=? AND lease_until=?)`,id,product.id,kind,eventKey,JSON.stringify(record),now,fence?.id||'',fence?.id||'',fence?.token||'',fence?.lease||0).run();
 return {id,kind,record,new:result.meta.changes===1};
}
const activeWatches=`SELECT w.*,s.alert_types,s.notice_days,s.delivery_mode,s.extended_entitled,s.consented_at,u.email
 FROM lifecycle_watch_settings s JOIN lifecycle_watches w ON w.user_id=s.user_id AND w.id=s.watch_id
 JOIN users u ON u.id=s.user_id JOIN lifecycle_preferences f ON f.user_id=u.id
 LEFT JOIN lifecycle_monitor_accounts a ON a.user_id=u.id
 WHERE s.product_id=? AND s.status='enabled' AND s.consented_at IS NOT NULL AND f.email_enabled=1 AND COALESCE(a.disabled,0)=0`;
export async function evaluateProduct(env,product,record,previous,now){
 let events=0,notifications=0;const release=await event(env,product,record.security?'security':'maintenance',record.version,record,now);events+=Number(release.new);
 let change;
 if(previous&&JSON.stringify(previous.milestones)!==JSON.stringify(record.milestones)){
  change=await event(env,product,'lifecycle_change',await sha(JSON.stringify(record.milestones)),record,now);events+=Number(change.new);
 }
 const watches=(await q(env.DB,activeWatches,product.id).all()).results||[];
 const creates=[];
 for(const watch of watches){
  const types=JSON.parse(watch.alert_types),days=JSON.parse(watch.notice_days),applicable=[];
  // Unknown builds, editions and major upgrades require human review.
  const comparable=sameBranch(watch.installed_version,product.branch)&&compareVersions(record.version,watch.installed_version)===1&&!product.edition;
  if(comparable&&(types.includes(release.kind)||types.includes('stable')))applicable.push(release);
  if(change&&types.includes('lifecycle_change'))applicable.push(change);
  for(const [milestone,date] of Object.entries(record.milestones)){
   if(!types.includes(milestone==='security'?'security_support':milestone)||milestone==='extended'&&!watch.extended_entitled)continue;
   const threshold=reminderThreshold(date,days,now);if(threshold===null)continue;
   const reminder=await event(env,product,milestone==='eol'?'eol':milestone+'_support',date+':'+threshold,{...record,milestone,date,threshold},now);events+=Number(reminder.new);applicable.push(reminder);
  }
  const recipientHash=await sha(watch.email.toLowerCase());
  if(await q(env.DB,'SELECT 1 FROM lifecycle_monitor_suppressions WHERE recipient_hash=?',recipientHash).first())continue;
  for(const entry of applicable){
   const id=await sha(watch.user_id+':'+entry.id+':'+watch.email.toLowerCase()),due=watch.delivery_mode==='immediate_security'&&entry.kind==='security'?now:digestDue(now);
   const fence=env.MONITOR_CHECK_FENCE;
   creates.push(q(env.DB,`INSERT OR IGNORE INTO lifecycle_monitor_notifications(id,user_id,watch_id,event_id,recipient,installed_version,due_at,unsubscribe_token,created_at)
    SELECT ?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM lifecycle_monitor_events WHERE id=?)
    AND (?='' OR EXISTS(SELECT 1 FROM lifecycle_monitor_sources WHERE id=? AND lease_token=? AND lease_until=?))
    AND EXISTS(SELECT 1 FROM lifecycle_watch_settings s JOIN lifecycle_preferences f ON f.user_id=s.user_id
      WHERE s.user_id=? AND s.watch_id=? AND s.status='enabled' AND s.consented_at IS NOT NULL AND f.email_enabled=1)`,id,watch.user_id,watch.id,entry.id,watch.email,watch.installed_version,due,crypto.randomUUID()+crypto.randomUUID(),now,entry.id,fence?.id||'',fence?.id||'',fence?.token||'',fence?.lease||0,watch.user_id,watch.id));
  }
 }
 if(creates.length){const result=await env.DB.batch(creates);notifications=result.reduce((n,r)=>n+(r.meta?.changes||0),0);}
 return {events,notifications};
}
export async function checkSubscribedSources(env,fetcher=fetch,now=Date.now()){
 const due=(await q(env.DB,`SELECT x.* FROM lifecycle_monitor_sources x WHERE x.next_due_at<=? AND x.lease_until<? AND EXISTS(
  SELECT 1 FROM lifecycle_monitor_products p JOIN lifecycle_watch_settings s ON s.product_id=p.id
  JOIN users u ON u.id=s.user_id LEFT JOIN lifecycle_monitor_accounts a ON a.user_id=u.id
  WHERE p.source_id=x.id AND s.status='enabled' AND COALESCE(a.disabled,0)=0) ORDER BY x.next_due_at,x.id LIMIT 4`,now,now).all()).results||[];
 const result={checked:0,failed:0,events:0,notifications:0};
 for(const source of due){
  const token=crypto.randomUUID(),lease=now+180000;
  if((await q(env.DB,'UPDATE lifecycle_monitor_sources SET lease_until=?,lease_token=?,last_attempt_at=? WHERE id=? AND lease_until<?',lease,token,now,source.id,now).run()).meta.changes!==1)continue;
  try{
   if(!SOURCE_REGISTRY[source.id]||SOURCE_REGISTRY[source.id].url!==source.url)throw Error('Unapproved source configuration');
   const raw=await fetchVendor(source,fetcher);
   if(!await q(env.DB,'SELECT 1 FROM lifecycle_monitor_sources WHERE id=? AND lease_token=? AND lease_until=?',source.id,token,lease).first())continue;
   const products=(await q(env.DB,`SELECT p.* FROM lifecycle_monitor_products p WHERE p.source_id=? AND EXISTS(SELECT 1 FROM lifecycle_watch_settings s
    JOIN users u ON u.id=s.user_id LEFT JOIN lifecycle_monitor_accounts a ON a.user_id=u.id WHERE s.product_id=p.id AND s.status='enabled' AND COALESCE(a.disabled,0)=0) LIMIT 100`,source.id).all()).results||[];
   const fenced={...env,MONITOR_CHECK_FENCE:{id:source.id,token,lease}};
   for(const product of products){
    let record;
    try{record=normalizeVendor(source.adapter,raw,product);if(record.published&&Date.parse(record.published)>now+DAY)throw Error('Future vendor publication date');}
    catch{
     await q(env.DB,"UPDATE lifecycle_monitor_products SET verification_error='Subscribed branch is absent or invalid in the official source; review required' WHERE id=? AND verification_error<>?",product.id,'Subscribed branch is absent or invalid in the official source; review required').run();result.failed++;continue;
    }
    const old=await q(env.DB,'SELECT * FROM lifecycle_monitor_state WHERE product_id=?',product.id).first(),hash=await sha(JSON.stringify(record));
    const previous=old?JSON.parse(old.record_json):null;
    if(previous&&compareVersions(record.version,previous.version)===-1){await q(env.DB,"UPDATE lifecycle_monitor_products SET verification_error='Official release regressed; review required' WHERE id=? AND verification_error<>?",product.id,'Official release regressed; review required').run();result.failed++;continue;}
    // Keep the lease until evaluation has durably queued changes. On failure,
    // rerun against the old verified state; event and recipient keys dedupe it.
    const changes=await evaluateProduct(fenced,product,record,previous,now);result.events+=changes.events;result.notifications+=changes.notifications;
    if(!old||hash!==old.semantic_hash)await q(env.DB,`INSERT INTO lifecycle_monitor_state(product_id,semantic_hash,record_json,verified_at)
     SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM lifecycle_monitor_sources WHERE id=? AND lease_token=? AND lease_until=?)
     ON CONFLICT(product_id) DO UPDATE SET semantic_hash=excluded.semantic_hash,record_json=excluded.record_json,verified_at=excluded.verified_at`,product.id,hash,JSON.stringify(record),now,source.id,token,lease).run();
    if(product.verification_error)await q(env.DB,"UPDATE lifecycle_monitor_products SET verification_error='' WHERE id=?",product.id).run();
   }
   await q(env.DB,`UPDATE lifecycle_monitor_sources SET last_success_at=?,next_due_at=?,lease_until=0,lease_token='',failures=0,error=''
    WHERE id=? AND lease_token=? AND lease_until=?`,now,now+DAY,source.id,token,lease).run();result.checked++;
  }catch(error){
   const delay=Math.max(error.delay||0,Math.min(DAY,300000*2**Math.min(source.failures,8)));
   await q(env.DB,`UPDATE lifecycle_monitor_sources SET next_due_at=?,lease_until=0,lease_token='',failures=failures+1,error=? WHERE id=? AND lease_token=? AND lease_until=?`,now+delay,'Official source verification failed; last verified data retained.',source.id,token,lease).run();result.failed++;
  }
 }
 return result;
}
export async function dailyReminders(env,now){
 const rows=(await q(env.DB,`SELECT p.*,v.record_json FROM lifecycle_monitor_products p JOIN lifecycle_monitor_state v ON v.product_id=p.id
  JOIN lifecycle_monitor_sources x ON x.id=p.source_id WHERE x.last_success_at>=? AND p.verification_error='' AND EXISTS(SELECT 1 FROM lifecycle_watch_settings s WHERE s.product_id=p.id AND s.status='enabled') LIMIT 100`,now-3*DAY).all()).results||[];
 let events=0;for(const row of rows){const r=await evaluateProduct(env,row,JSON.parse(row.record_json),null,now);events+=r.events;}return events;
}
