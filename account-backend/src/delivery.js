import { MAX_DIGEST_ITEMS, selectDigest, revisionOf, renderDigest, loadPublicFeed } from './digest.js';

const API = 'https://api.smtp2go.com/v3/email/send';
const SITE = 'https://cveharbor.com';
const MAX_SEND_PER_TICK = 8;
const isToken = x => /^[a-f0-9]{64}$/.test(x || '');
const nowSec = () => Math.floor(Date.now() / 1000);
const randomToken = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), x => x.toString(16).padStart(2, '0')).join('');
const json = (value, status = 200) => new Response(JSON.stringify(value), { status,
  headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });

export async function saveOptin(env, userId, enabled) {
  if (!enabled) {
    await env.DB.prepare('DELETE FROM alert_optins WHERE user_id=?').bind(userId).run();
    return false;
  }
  const existing = await env.DB.prepare('SELECT user_id FROM alert_optins WHERE user_id=?').bind(userId).first();
  if (!existing) {
    await env.DB.prepare('INSERT INTO alert_optins(user_id,consented_at,unsubscribe_token) VALUES(?,?,?)')
      .bind(userId, nowSec(), randomToken()).run();
  }
  return true;
}
export async function loadAlertSubscription(env, userId) {
  try {
    const row = await env.DB.prepare('SELECT consented_at FROM alert_optins WHERE user_id=?').bind(userId).first();
    const last = await env.DB.prepare("SELECT completed_at,item_count FROM alert_digest_runs WHERE user_id=? AND status='sent' ORDER BY completed_at DESC LIMIT 1").bind(userId).first();
    return { consented: !!row, consented_at: row?.consented_at || null, last_sent_at: last?.completed_at || null, last_sent_items: last?.item_count || 0 };
  } catch (_) {
    // A new Worker can deploy before the database migration. Existing accounts stay usable.
    return { consented: false, consented_at: null, last_sent_at: null, last_sent_items: 0, migration_required: true };
  }
}
export async function sendEmail(env, to, report, unsubscribeUrl = '') {
  const key = env.ALERT_SMTP2GO_API_KEY || env.SMTP2GO_API_KEY;
  if (!key || !env.EMAIL_FROM) throw Error('SMTP2GO is not configured');
  const headers = unsubscribeUrl ? [
    { header: 'List-Unsubscribe', value: '<' + unsubscribeUrl + '>' },
    { header: 'List-Unsubscribe-Post', value: 'List-Unsubscribe=One-Click' }
  ] : [];
  const outgoing = await fetch(API, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Smtp2go-Api-Key': key },
    body: JSON.stringify({ sender: env.EMAIL_FROM, to: [to], subject: report.subject,
      html_body: report.html, text_body: report.text, custom_headers: headers })
  });
  if (!outgoing.ok) throw Error('SMTP2GO rejected the request');
  const payload = await outgoing.json();
  if (!payload?.data || Number(payload.data.succeeded) !== 1 || Number(payload.data.failed) > 0)
    throw Error('SMTP2GO did not accept the message');
  return String(payload.data.email_id || '').slice(0, 100);
}
export function localClock(date = new Date()) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Toronto', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', hourCycle: 'h23'
  }).formatToParts(date);
  const part = type => parts.find(x => x.type === type)?.value || '';
  return { day: part('year') + part('month') + part('day'), hour: Number(part('hour')) };
}
export function digestSlot(frequency, date = new Date()) {
  const stamp = localClock(date);
  return frequency === 'hourly' ? 'hourly:' + stamp.day + ':' + String(stamp.hour).padStart(2, '0') : 'daily:' + stamp.day;
}

function unsubscribeLink(token) { return 'https://api.cveharbor.com/v1/unsubscribe/' + token; }
async function previousRevisions(env, userId) {
  const result = await env.DB.prepare('SELECT advisory_id,revision FROM alert_delivery_items WHERE user_id=?').bind(userId).all();
  return new Map((result.results || []).map(row => [row.advisory_id, row.revision]));
}
async function claimDigest(env, userId, slot) {
  const now = nowSec();
  const insert = await env.DB.prepare(
    "INSERT OR IGNORE INTO alert_digest_runs (user_id,slot,status,claimed_at,attempts) VALUES(?,?,'sending',?,1)"
  ).bind(userId, slot, now).run();
  if (insert.meta?.changes === 1) return true;
  const retry = await env.DB.prepare(
    "UPDATE alert_digest_runs SET status='sending',claimed_at=?,attempts=attempts+1 WHERE user_id=? AND slot=? AND (status='failed' OR (status='sending' AND claimed_at<?))"
  ).bind(now, userId, slot, now - 3600).run();
  return retry.meta?.changes === 1;
}
async function finishDigest(env, userId, slot, status, items = [], providerId = '') {
  const now = nowSec();
  const writes = [
    env.DB.prepare('UPDATE alert_digest_runs SET status=?,item_count=?,provider_id=?,completed_at=? WHERE user_id=? AND slot=?')
      .bind(status, items.length, providerId, now, userId, slot)
  ];
  if (status === 'sent') {
    for (const item of items) {
      writes.push(env.DB.prepare(
        'INSERT INTO alert_delivery_items (user_id,advisory_id,revision,delivered_at) VALUES(?,?,?,?) ON CONFLICT(user_id,advisory_id) DO UPDATE SET revision=excluded.revision,delivered_at=excluded.delivered_at'
      ).bind(userId, item.id, revisionOf(item), now));
    }
  }
  await env.DB.batch(writes);
}

export async function dispatchDueDigests(env, currentDate = new Date()) {
  if (env.ALERT_DELIVERY_ENABLED !== 'true') return { status: 'disabled' };
  const hour = localClock(currentDate).hour;
  if (!env.DB || !(env.ALERT_SMTP2GO_API_KEY || env.SMTP2GO_API_KEY) || !env.EMAIL_FROM) throw Error('Digest backend is not configured');
  const hourlySlot = digestSlot('hourly', currentDate);
  const dailySlot = digestSlot('daily', currentDate);
  // Prioritize due daily reports, and leave completed slots out of the query
  // so older subscribers do not starve other customers as the audience grows.
  const subscribers = await env.DB.prepare(
    "SELECT u.id,u.email,p.severity,p.frequency,o.unsubscribe_token FROM users u " +
    "JOIN alert_preferences p ON p.user_id=u.id JOIN alert_optins o ON o.user_id=u.id " +
    "WHERE p.enabled=1 AND (p.frequency='hourly' OR (p.frequency='daily' AND ? >= 8)) " +
    "AND NOT EXISTS (SELECT 1 FROM alert_digest_runs r WHERE r.user_id=u.id " +
    "AND r.slot=CASE WHEN p.frequency='hourly' THEN ? ELSE ? END " +
    "AND (r.status IN ('sent','empty') OR (r.status='sending' AND r.claimed_at>=?))) " +
    "ORDER BY CASE WHEN p.frequency='daily' THEN 0 ELSE 1 END, o.consented_at LIMIT ?"
  ).bind(hour, hourlySlot, dailySlot, nowSec() - 3600, MAX_SEND_PER_TICK).all();
  const pending = (subscribers.results || []).map(user => ({ ...user, slot: digestSlot(user.frequency, currentDate) }));
  if (!pending.length) return { status: 'up_to_date' };
  const feed = await loadPublicFeed();
  let sent = 0, empty = 0, failed = 0;
  for (const user of pending) {
    if (!await claimDigest(env, user.id, user.slot)) continue;
    try {
      const stack = await env.DB.prepare('SELECT technology FROM user_stack WHERE user_id=? ORDER BY technology').bind(user.id).all();
      const selected = (stack.results || []).map(r => r.technology);
      const history = await previousRevisions(env, user.id);
      const digest = selectDigest(feed.records, selected, user.severity, history, currentDate.getTime());
      if (!digest.items.length) { await finishDigest(env, user.id, user.slot, 'empty'); empty++; continue; }
      const url = unsubscribeLink(user.unsubscribe_token);
      const report = renderDigest({ ...digest, cadence: user.frequency, date: currentDate,
        unsubscribeUrl: url, degraded: feed.degraded, coverageLimited: feed.coverageLimited });
      const providerId = await sendEmail(env, user.email, report, url);
      await finishDigest(env, user.id, user.slot, 'sent', digest.items, providerId);
      sent++;
    } catch (_) {
      failed++;
      try { await finishDigest(env, user.id, user.slot, 'failed'); } catch (_) {}
      // Never log email addresses, login tokens, or rendered advisory bodies.
    }
  }
  return { status: 'processed', sent, empty, failed, considered: pending.length };
}

export async function sendUserSample(env, user) {
  // Each user may request at most two tests in a rolling hour.
  const now = nowSec();
  await env.DB.prepare("DELETE FROM auth_rate_limits WHERE window_start<?").bind(now - 3600).run();
  await env.DB.prepare(
    "INSERT INTO auth_rate_limits(key,window_start,count) VALUES(?,?,1) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN window_start<? THEN 1 ELSE count+1 END, window_start=CASE WHEN window_start<? THEN ? ELSE window_start END"
  ).bind('digest-test:' + user.id, now, now - 3600, now - 3600, now).run();
  const attempts = await env.DB.prepare('SELECT count FROM auth_rate_limits WHERE key=?').bind('digest-test:' + user.id).first();
  if (attempts.count > 2) return json({ error: 'Test email limit reached. Try again later.' }, 429);
  const p = await env.DB.prepare('SELECT severity,frequency FROM alert_preferences WHERE user_id=?').bind(user.id).first();
  const prefs = p || { severity: 'high', frequency: 'daily' };
  const rows = await env.DB.prepare('SELECT technology FROM user_stack WHERE user_id=?').bind(user.id).all();
  const selected = (rows.results || []).map(x => x.technology);
  if (!selected.length) return json({ error: 'Upload a technology selection to your account before requesting a sample.' }, 409);
  const feed = await loadPublicFeed();
  const digest = selectDigest(feed.records, selected, prefs.severity, new Map(), Date.now(), 10);
  const subscribed = await env.DB.prepare('SELECT unsubscribe_token FROM alert_optins WHERE user_id=?').bind(user.id).first();
  const unsubscribe = subscribed?.unsubscribe_token ? unsubscribeLink(subscribed.unsubscribe_token) : '';
  const report = renderDigest({ ...digest, cadence: prefs.frequency, date: new Date(),
    unsubscribeUrl: unsubscribe, test: true, degraded: feed.degraded, coverageLimited: feed.coverageLimited });
  await sendEmail(env, user.email, report, unsubscribe);
  return json({ sent: true, included: digest.items.length, message: 'Sample report accepted by SMTP2GO. Check your inbox.' });
}
export async function unsubscribe(request, env, tokenValue) {
  if (!isToken(tokenValue)) return new Response('Invalid link', { status: 404 });
  const row = await env.DB.prepare('SELECT user_id FROM alert_optins WHERE unsubscribe_token=?').bind(tokenValue).first();
  const header = { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer', 'X-Robots-Tag': 'noindex', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'" };
  if (request.method === 'POST') {
    if (row) {
      await env.DB.batch([
        env.DB.prepare('UPDATE alert_preferences SET enabled=0,updated_at=CURRENT_TIMESTAMP WHERE user_id=?').bind(row.user_id),
        env.DB.prepare('DELETE FROM alert_optins WHERE user_id=?').bind(row.user_id)
      ]);
    }
    return new Response('<!doctype html><html><meta charset="utf-8"><title>CVEHarbor alerts</title><body style="font-family:Arial;padding:40px;background:#eef4f7;color:#13283d"><h1>Unsubscribed</h1><p>CVEHarbor vulnerability emails are now disabled for this subscription.</p><p><a href="' + SITE + '">Visit CVEHarbor</a></p></body></html>', { headers: header });
  }
  if (request.method !== 'GET') return new Response('Method not allowed', { status: 405, headers: { Allow: 'GET, POST' } });
  if (!row) return new Response('<!doctype html><html><body style="font-family:Arial;padding:40px"><h1>This unsubscribe link has expired.</h1></body></html>', { status: 404, headers: header });
  return new Response('<!doctype html><html><meta charset="utf-8"><title>Unsubscribe from CVEHarbor</title><body style="font-family:Arial;padding:40px;background:#eef4f7;color:#13283d"><h1>Stop CVEHarbor emails?</h1><p>You can turn off the personalized vulnerability email digest. Your account data will remain available.</p><form method="post"><button type="submit" style="background:#147e7c;border:0;border-radius:6px;padding:14px 24px;color:white;font-size:16px;cursor:pointer">Unsubscribe</button></form></body></html>', { headers: header });
}
