// Personalized CVEHarbor vulnerability digest. No emails or remote calls at import time.
export const MAX_DIGEST_ITEMS = 30;
export const LOOKBACK_DAYS = 30;
export const DATA_URL = 'https://cveharbor.com/data.js';
export const HEALTH_URL = 'https://cveharbor.com/feed-health.json';

function text(v, limit = 500) { return String(v == null ? '' : v).trim().slice(0, limit); }
function esc(v) { return text(v, 1500).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }
function https(v) { try { const url = new URL(String(v)); return url.protocol === 'https:' ? url.href : ''; } catch (_) { return ''; } }
function recent(record, minDate) {
  const dates = [record.published, record.updated, record.first_seen_at, record.source_updated_at].map(x => String(x || '').slice(0, 10));
  return dates.some(x => /^\d{4}-\d{2}-\d{2}$/.test(x) && x >= minDate);
}
export function revisionOf(record) {
  return text(record.source_updated_at || record.updated || record.published || record.first_seen_at, 64);
}
function falseWordPressMatch(record) {
  const affected = String(record.affected || '').toLowerCase();
  const summary = String(record.title || '') + ' ' + String(record.summary || '');
  return /\bcpanel\b/i.test(summary) && /\bwp_squared\b/i.test(affected) && !/\bwordpress\s+(?:core|plugin|theme)\b/i.test(summary);
}
export function selectDigest(records, selectedTechnologies, severityPreference, lastSent = new Map(), now = Date.now(), max = MAX_DIGEST_ITEMS) {
  const selected = new Set((Array.isArray(selectedTechnologies) ? selectedTechnologies : []).filter(x => typeof x === 'string'));
  const minDate = new Date(now - LOOKBACK_DAYS * 86400000).toISOString().slice(0, 10);
  const seen = new Map();
  if (!Array.isArray(records) || !selected.size) return { items: [], pending: 0, selected: [...selected] };
  for (const record of records) {
    if (!record || !/^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$/i.test(String(record.id || ''))) continue;
    if (!['critical', 'high'].includes(record.severity)) continue;
    if (severityPreference !== 'high' && record.severity !== 'critical') continue;
    if (!recent(record, minDate)) continue;
    const matches = (record.categories || []).filter(x => selected.has(x) && !(x === 'WordPress / Plugins' && falseWordPressMatch(record)));
    if (!matches.length) continue;
    const revision = revisionOf(record);
    if (lastSent.has(record.id) && lastSent.get(record.id) >= revision) continue;
    const prior = seen.get(record.id);
    if (!prior || revision > revisionOf(prior)) seen.set(record.id, { ...record, matchingCategories: matches });
  }
  const ranked = [...seen.values()].sort((a, b) =>
    Number(!!b.known_exploited) - Number(!!a.known_exploited) ||
    Number(b.severity === 'critical') - Number(a.severity === 'critical') ||
    Number(b.epss || 0) - Number(a.epss || 0) ||
    String(b.updated || b.published || '').localeCompare(String(a.updated || a.published || '')) ||
    String(a.id).localeCompare(String(b.id)));
  return { items: ranked.slice(0, Math.min(60, Math.max(1, max))), pending: Math.max(0, ranked.length - max), selected: [...selected] };
}

export function renderDigest({ items = [], selected = [], cadence = 'daily', date = new Date(), unsubscribeUrl = '', test = false, pending = 0, degraded = false, coverageLimited = false }) {
  const day = new Date(date).toLocaleDateString('en-CA', { timeZone: 'America/Toronto', year: 'numeric', month: 'long', day: 'numeric' });
  const critical = items.filter(x => x.severity === 'critical').length;
  const high = items.filter(x => x.severity === 'high').length;
  const kev = items.filter(x => x.known_exploited).length;
  const subject = (test ? '[TEST] ' : '') + 'CVEHarbor ' + (cadence === 'hourly' ? 'Security Alert' : 'Daily Security Brief') + ' | ' + items.length + ' advisories | ' + day;
  const footerUrl = https(unsubscribeUrl);
  const groups = new Map();
  for (const item of items) {
    const name = (item.matchingCategories || []).find(x => selected.includes(x)) || 'Selected technologies';
    if (!groups.has(name)) groups.set(name, []);
    groups.get(name).push(item);
  }
  const title = test ? 'Your sample security brief' : (cadence === 'hourly' ? 'Your vulnerability alert' : 'Your daily security brief');
  const meta = '<span style="display:inline-block;padding:7px 10px;margin:0 6px 8px 0;border:1px solid #d9e3eb;border-radius:7px;color:#334155;font-size:12px;">' +
    esc(selected.length) + ' tracked technologies</span>';
  const score = (count, label, color) => '<td width="33%" style="padding:13px 6px;text-align:center;background:#f0f7f9;border:1px solid #e1ecef;"><strong style="display:block;font-size:29px;line-height:1.3;color:' + color + ';">' + count + '</strong><span style="font-size:11px;color:#64748b;">' + label + '</span></td>';
  const blocks = [];
  for (const [category, entries] of groups) {
    blocks.push('<h2 style="margin:30px 0 14px;font-size:17px;letter-spacing:-0.3px;color:#14283c;border-bottom:2px solid #c9e7e5;padding-bottom:10px;">' + esc(category) + ' <span style="font-weight:normal;color:#64748b;">(' + entries.length + ')</span></h2>');
    for (const item of entries) {
      const priorityColor = item.severity === 'critical' ? '#be123c' : '#b45309';
      const link = (item.sources || []).map(s => https(s.url)).find(Boolean) || 'https://cveharbor.com/#advisories';
      const label = item.known_exploited ? '<span style="margin-left:8px;color:#be123c;font-size:11px;font-weight:bold;">CISA KEV LISTED</span>' : '';
      const details = [
        item.published ? 'Published ' + esc(String(item.published).slice(0, 10)) : '',
        item.updated ? 'Updated ' + esc(String(item.updated).slice(0, 10)) : '',
        item.cvss ? 'CVSS ' + esc(item.cvss) : '',
      ].filter(Boolean).join(' &nbsp;·&nbsp; ');
      blocks.push('<table width="100%" role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 14px;border:1px solid #d9e7ee;border-left:4px solid #19a6a0;border-radius:10px;background:#ffffff;"><tr><td style="padding:21px 22px;">' +
        '<div style="margin-bottom:8px;"><span style="background:' + priorityColor + ';color:#ffffff;border-radius:4px;padding:5px 9px;font-size:10px;font-weight:bold;letter-spacing:1px;">' + esc(item.severity.toUpperCase()) + '</span>' + label + '</div>' +
        '<div style="font-size:12px;font-weight:bold;color:#087b89;margin:0 0 6px;">' + esc(item.id) + '</div>' +
        '<div style="font-size:17px;font-weight:bold;line-height:1.45;letter-spacing:-0.2px;color:#13293e;">' + esc(text(item.title || item.summary || item.id, 190)) + '</div>' +
        '<p style="font-size:12px;color:#64748b;line-height:1.7;margin:8px 0;">' + details + '</p>' +
        '<p style="font-size:13px;color:#415568;line-height:1.75;margin:9px 0;"><strong>Affected:</strong> ' + esc(text(item.affected || 'Check the linked advisory for affected versions.', 190)) + '</p>' +
        '<p style="font-size:13px;color:#415568;line-height:1.75;margin:9px 0;"><strong>Recommended review:</strong> ' + esc(text(item.action || item.remediation || 'Verify your version and vendor guidance.', 240)) + '</p>' +
        '<a href="' + esc(link) + '" style="font-size:13px;color:#087b89;text-decoration:none;font-weight:bold;border-bottom:1px solid #087b89;padding-bottom:2px;">Review original advisory</a>' +
        '</td></tr></table>');
    }
  }
  const note = (degraded ? 'One or more advisory sources reported a degraded refresh. ' : '') +
    (coverageLimited ? 'The public index is capacity limited, so some disclosures may be missing. ' : '') +
    'CVEs are matched to your selected technology categories. This does not establish that your installed systems or versions are affected. Verify original vendor advisories before patching.';
  const intro = test ? 'This is a requested test email. It does not activate scheduled delivery.' :
    'Recent matching advisories first published, updated, or indexed within the last 30 days. Subsequent briefs avoid repeating unchanged records.';
  const more = pending > 0 ? '<p style="padding:12px;background:#eaf5f6;border-radius:7px;color:#195e68;font-size:13px;">' +
      esc(pending) + ' additional matching advisories are pending for future digests. Review the website for the full available index.</p>' : '';
  const unsubscribe = footerUrl ? '<a href="' + esc(footerUrl) + '" style="color:#64748b;text-decoration:underline;">Unsubscribe</a>' : '';
  const html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + esc(subject) + '</title></head>' +
    '<body style="margin:0;padding:0;background:#eef4f7;font-family:Arial,Helvetica,sans-serif;color:#14283c;">' +
    '<table width="100%" role="presentation" cellspacing="0" cellpadding="0" style="background:#eef4f7;"><tr><td align="center" style="padding:32px 12px;">' +
    '<table width="100%" role="presentation" cellpadding="0" cellspacing="0" style="max-width:680px;background:#ffffff;border-radius:16px;overflow:hidden;border:1px solid #dbe7ed;">' +
    '<tr><td style="background:#0b1b30;padding:38px 36px 34px;color:#ffffff;border-bottom:5px solid #4fd7ca;"><div style="color:#66e0d4;letter-spacing:2.2px;font-weight:bold;font-size:12px;">CVEHARBOR / VULNERABILITY INTELLIGENCE</div>' +
    '<div style="margin-top:22px;color:#ffffff;font-size:13px;letter-spacing:1.5px;font-weight:bold;">SECURITY INTELLIGENCE REPORT</div>' +
    '<h1 style="font-size:32px;line-height:1.2;margin:12px 0 10px;letter-spacing:-0.6px;color:#ffffff;">' + esc(title) + '</h1>' +
    '<p style="color:#b8ccd9;font-size:13px;margin:0;">' + esc(day) + ' &nbsp;·&nbsp; Personalized ' + esc(cadence) + ' report</p></td></tr>' +
    '<tr><td style="padding:34px 36px 14px;"><p style="font-size:15px;color:#425466;line-height:1.7;margin:0 0 16px;">' + esc(intro) + '</p>' + meta +
    '<table width="100%" cellpadding="0" cellspacing="6" role="presentation" style="margin:15px 0 22px;"><tr>' +
    score(critical, 'CRITICAL', '#be123c') + score(high, 'HIGH', '#b45309') + score(kev, 'CISA KEV', '#087b89') +
    '</tr></table>' +
    (items.length ? blocks.join('') : '<p style="color:#64748b;">No matching advisories were found in the current reporting window.</p>') +
    more + '<p style="margin:25px 0;text-align:center;"><a href="https://cveharbor.com/#securityWorkspace" style="display:inline-block;background:#147e7c;padding:15px 28px;border-radius:8px;color:#ffffff;text-decoration:none;font-size:14px;font-weight:bold;">Open my CVEHarbor watchlist</a></p>' +
    '<div style="border-top:1px solid #e4edf3;padding-top:17px;color:#64748b;font-size:12px;line-height:1.8;">' + esc(note) + '</div></td></tr>' +
    '<tr><td style="background:#f4f8fb;padding:24px 36px;color:#64748b;font-size:12px;line-height:1.9;">' +
    '<strong style="color:#14283c;">CVEHarbor</strong> &nbsp;·&nbsp; Independent vulnerability intelligence<br>' +
    '<a style="color:#087b89;" href="https://cveharbor.com/#accountWorkspace">Manage alert preferences</a>' +
    (unsubscribe ? ' &nbsp;·&nbsp; ' + unsubscribe : '') +
    '<br>Sent because you requested CVEHarbor security notifications. <a href="https://cveharbor.com" style="color:#087b89;">cveharbor.com</a></td></tr>' +
    '</table></td></tr></table></body></html>';
  const plain = [
    title, day, '', intro, '',
    critical + ' critical | ' + high + ' high | ' + kev + ' CISA KEV listed',
    'Selected technologies: ' + selected.join(', '), ''
  ];
  for (const [cat, rows] of groups) {
    plain.push(cat.toUpperCase());
    for (const x of rows) {
      const link = (x.sources || []).map(s => https(s.url)).find(Boolean) || 'https://cveharbor.com/#advisories';
      plain.push(x.severity.toUpperCase() + ' ' + x.id + (x.known_exploited ? ' [CISA KEV]' : ''), text(x.title || x.summary, 190),
        'Published: ' + text(x.published, 10) + ' Updated: ' + text(x.updated, 10) + ' CVSS: ' + text(x.cvss, 10),
        'Affected: ' + text(x.affected, 240), 'Review: ' + text(x.action || x.remediation, 260), link, '');
    }
  }
  if (pending) plain.push(pending + ' additional matching advisories remain. Check CVEHarbor.', '');
  plain.push(note, '', 'My watchlist: https://cveharbor.com/#securityWorkspace',
    'Manage preferences: https://cveharbor.com/#accountWorkspace');
  if (footerUrl) plain.push('Unsubscribe: ' + footerUrl);
  return { subject, html, text: plain.join('\n') };
}

export async function loadPublicFeed(fetcher = fetch) {
  const [dataResponse, healthResponse] = await Promise.all([
    fetcher(DATA_URL, { headers: { 'Accept': 'text/javascript' } }),
    fetcher(HEALTH_URL, { headers: { 'Accept': 'application/json' } })
  ]);
  if (!dataResponse.ok || !healthResponse.ok) throw Error('Vulnerability feed unavailable');
  const raw = await dataResponse.text();
  if (raw.length > 8000000) throw Error('Vulnerability feed too large');
  const match = /window\.CVEHARBOR_DATA\s*=\s*(\{[\s\S]*\})\s*;\s*$/.exec(raw);
  if (!match) throw Error('Unexpected vulnerability feed format');
  const parsed = JSON.parse(match[1]);
  const health = await healthResponse.json();
  if (!Array.isArray(parsed.advisories) || !health.last_successful_update) throw Error('Invalid vulnerability feed');
  const lastOk = Date.parse(health.last_successful_update);
  if (!Number.isFinite(lastOk) || Date.now() - lastOk > 8 * 3600000) throw Error('Vulnerability feed is stale');
  if (health.mode === 'degraded') throw Error('All vulnerability feeds are unavailable');
  return { records: parsed.advisories, degraded: health.mode !== 'live', coverageLimited: !!health.coverage_limited, health };
}
