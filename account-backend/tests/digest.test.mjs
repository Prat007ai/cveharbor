import test from 'node:test';
import assert from 'node:assert/strict';
import { selectDigest, renderDigest, loadPublicFeed, revisionOf } from '../src/digest.js';
import { digestSlot, localClock, sendEmail } from '../src/delivery.js';

const reference = Date.parse('2026-10-28T14:00:00Z');
const example = (id = 'CVE-2026-12345', fields = {}) => ({
  id, severity: 'critical', title: 'WordPress plugin remote code execution',
  summary: 'Example data, not a real advisory', categories: ['WordPress / Plugins'],
  published: '2026-10-24', updated: '2026-10-27',
  affected: 'Example WordPress plugin before 2.0',
  action: 'Review the vendor security bulletin',
  sources: [{ label: 'Example', url: 'https://example.com/advisory' }],
  known_exploited: false, ...fields
});

test('filters by saved technologies, preferred severity and recent reporting window', () => {
  const records = [
    example(),
    example('CVE-2026-12346', { severity: 'high' }),
    example('CVE-2026-12347', { categories: ['Python / PyPI'] }),
    example('CVE-2024-12345', { published: '2024-01-01', updated: '2024-01-03' })
  ];
  const criticalOnly = selectDigest(records, ['WordPress / Plugins'], 'critical', new Map(), reference);
  assert.deepEqual(criticalOnly.items.map(x => x.id), ['CVE-2026-12345']);
  const both = selectDigest(records, ['WordPress / Plugins'], 'high', new Map(), reference);
  assert.deepEqual(both.items.map(x => x.id), ['CVE-2026-12345', 'CVE-2026-12346']);
});
test('prioritizes CISA KEV and prevents duplicate unchanged advisories', () => {
  const exploited = example('CVE-2026-12346', { severity: 'high', known_exploited: true });
  const matches = selectDigest([example(), exploited, exploited], ['WordPress / Plugins'], 'high', new Map(), reference);
  assert.deepEqual(matches.items.map(x => x.id), ['CVE-2026-12346', 'CVE-2026-12345']);
  const sent = new Map([[exploited.id, revisionOf(exploited)]]);
  assert.deepEqual(selectDigest([exploited], ['WordPress / Plugins'], 'high', sent, reference).items, []);
  const newer = { ...exploited, source_updated_at: '2026-10-28T14:15:00Z' };
  assert.equal(selectDigest([newer], ['WordPress / Plugins'], 'high', sent, reference).items.length, 1);
});
test('excludes cPanel WP Squared false category matches from WordPress reports', () => {
  const record = example('CVE-2026-41940', {
    title: 'cPanel and WHM authentication bypass',
    affected: 'cpanel cpanel; cpanel whm; cpanel wp_squared',
    categories: ['WordPress / Plugins']
  });
  assert.equal(selectDigest([record], ['WordPress / Plugins'], 'high', new Map(), reference).items.length, 0);
});
test('source discussion does not falsely alert Fortinet or React subscribers about PHP', () => {
  const php = example('CVE-2026-109618', {
    source_type: 'php_upstream', title: 'RCE via OOM corruption',
    affected: 'php: php-src (< 8.4.27)',
    categories: ['Fortinet','PHP','React / Next.js'],
    known_exploited: true
  });
  assert.equal(selectDigest([php], ['Fortinet'], 'high', new Map(), reference).items.length, 0);
  assert.equal(selectDigest([php], ['React / Next.js'], 'high', new Map(), reference).items.length, 0);
  const actual = selectDigest([php], ['PHP','Fortinet'], 'high', new Map(), reference);
  assert.equal(actual.items.length, 1);
  assert.deepEqual(actual.items[0].matchingCategories, ['PHP']);
});
test('the .NET Brotli CVE may concern PHP but not Fortinet or unrelated categories', () => {
  const record = example('CVE-2026-111497', {
    source_type: 'vendor_baseline', title: '.NET Brotli decompression out of bounds write',
    categories: ['.NET / ASP.NET', '.NET Core', 'PHP', 'Fortinet','Linux','Windows'],
    affected: 'Affected .NET runtime versions and Windows PHP cURL builds'
  });
  assert.deepEqual(
    selectDigest([record], ['Fortinet'], 'critical', new Map(), reference).items, []);
  assert.equal(selectDigest([record], ['PHP'], 'critical', new Map(), reference).items.length, 1);
  assert.equal(selectDigest([record], ['.NET Core'], 'critical', new Map(), reference).items.length, 1);
});

test('caps email size and keeps the remaining unsent records eligible', () => {
  const records = Array.from({length: 45}, (_, i) => example('CVE-2026-' + (10000 + i)));
  const report = selectDigest(records, ['WordPress / Plugins'], 'high', new Map(), reference, 30);
  assert.equal(report.items.length, 30);
  assert.equal(report.pending, 15);
  const sent = new Map(report.items.map(x => [x.id, revisionOf(x)]));
  assert.equal(selectDigest(records, ['WordPress / Plugins'], 'high', sent, reference).items.length, 15);
});
test('renders safe branded HTML and plain text with unsubscribe and original source link', () => {
  const record = example('CVE-2026-12345', { title: '<img src=x onerror=alert(1)>', known_exploited: true });
  const selection = selectDigest([record], ['WordPress / Plugins'], 'high', new Map(), reference);
  const output = renderDigest({ ...selection, test:true, cadence:'daily', date:new Date(reference),
    unsubscribeUrl:'https://api.cveharbor.com/v1/unsubscribe/' + 'a'.repeat(64), coverageLimited:true });
  assert.match(output.subject, /^\[TEST\] CVEHarbor Daily Security Brief/);
  assert.match(output.html, /CVEHARBOR \/ VULNERABILITY INTELLIGENCE/);
  assert.match(output.html, /CISA KEV LISTED/);
  assert.match(output.html, /https:\/\/example.com\/advisory/);
  assert.match(output.html, /Unsubscribe/);
  assert.match(output.text, /https:\/\/api\.cveharbor\.com\/v1\/unsubscribe\//);
  assert.ok(output.html.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.ok(!output.html.includes('<img src=x onerror=alert(1)>'));
  assert.match(output.text, /capacity limited/);
});
test('Toronto digest slot handles daylight saving for morning deliveries', () => {
  assert.deepEqual(localClock(new Date('2026-10-28T12:05:00Z')), { day:'20261028', hour:8 });
  assert.deepEqual(localClock(new Date('2026-12-01T13:05:00Z')), { day:'20261201', hour:8 });
  assert.equal(digestSlot('daily', new Date('2026-10-28T12:05:00Z')), 'daily:20261028');
  assert.equal(digestSlot('hourly', new Date('2026-10-28T12:05:00Z')), 'hourly:20261028:08');
});
test('loads the public JavaScript advisory feed and requires recent source health', async () => {
  const fixture = { advisories:[example()], mode:'live' };
  const fetcher = async url => ({ ok:true, text:async ()=>'/* feed */\nwindow.CVEHARBOR_DATA = '+JSON.stringify(fixture)+';\n',
    json:async () => ({ mode:'live', last_successful_update:new Date().toISOString(), coverage_limited:true }) });
  const data = await loadPublicFeed(fetcher);
  assert.equal(data.records.length, 1);
  assert.equal(data.coverageLimited, true);
  await assert.rejects(loadPublicFeed(async url=>({ok:true,text:async()=>'{broken',json:async()=>({last_successful_update:new Date().toISOString()})})), /Unexpected/);
});
test('SMTP2GO sender checks provider acknowledgement and adds unsubscribe headers', async () => {
  const original = globalThis.fetch;
  let payload;
  try {
    globalThis.fetch = async (url, options) => {
      assert.equal(url, 'https://api.smtp2go.com/v3/email/send');
      payload=JSON.parse(options.body);
      return { ok:true, json:async()=>({data:{succeeded:1,failed:0,email_id:'abc'}}) };
    };
    const unsubscribeUrl='https://api.cveharbor.com/v1/unsubscribe/'+'f'.repeat(64);
    const result = await sendEmail({SMTP2GO_API_KEY:'not-a-real-key',EMAIL_FROM:'alerts@cveharbor.com'},
      'test@example.com',{subject:'Test',html:'<p>Hi</p>',text:'Hi'},unsubscribeUrl);
    assert.equal(result,'abc');
    assert.equal(payload.html_body,'<p>Hi</p>');
    assert.equal(payload.to[0],'test@example.com');
    assert.equal(payload.custom_headers.length,2);
    globalThis.fetch = async () => ({ok:true,json:async()=>({data:{succeeded:0,failed:1}})});
    await assert.rejects(sendEmail({SMTP2GO_API_KEY:'fake',EMAIL_FROM:'alerts@cveharbor.com'},
      'test@example.com',{subject:'Test',html:'test',text:'test'}), /did not accept/);
  } finally {globalThis.fetch=original;}
});
