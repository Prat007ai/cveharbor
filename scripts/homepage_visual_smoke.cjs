// Run against a local public/ build. Install Playwright separately; no production requests.
// CVEHARBOR_PLAYWRIGHT_MODULE can point to an external Playwright installation.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.CVEHARBOR_PLAYWRIGHT_MODULE || 'playwright');
const base = process.env.CVEHARBOR_TEST_URL || 'http://127.0.0.1:8080';
const out = process.env.CVEHARBOR_SCREENSHOTS || '/tmp/cveharbor-homepage-review';
if (!['127.0.0.1', 'localhost'].includes(new URL(base).hostname)) throw new Error('Use a local test server');
(async () => {
  fs.mkdirSync(out, { recursive: true });
  const browser = await chromium.launch({
    ...(process.env.CVEHARBOR_CHROMIUM ? { executablePath: process.env.CVEHARBOR_CHROMIUM } : {}),
    args: ['--no-sandbox'],
  });
  try {
    for (const [width, height] of [[1366,768], [1920,1080], [2560,1440], [390,844]]) {
      const page = await browser.newPage({ viewport: { width, height }, deviceScaleFactor: 1, reducedMotion: 'reduce' });
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      // Isolate visual regression checks from remote authentication, maps and feed providers.
      await page.route('**/*', route => new URL(route.request().url()).origin === new URL(base).origin ? route.continue() : route.abort());
      await page.goto(base, { waitUntil: 'networkidle' });
      await page.evaluate(() => document.fonts.ready);
      assert.equal(await page.locator('#heroTitle').innerText(), 'Know the risk.\nFind the fix.');
      assert.equal(await page.locator('.hero-capability').count(), 6);
      assert.equal(await page.locator('.hero-trust-pill').count(), 5);
      const layout = await page.evaluate(() => {
        const rect = selector => document.querySelector(selector).getBoundingClientRect().toJSON();
        const hero = rect('.hero'), card = rect('.hero-priority-card');
        const capabilities = [...document.querySelectorAll('.hero-capability')].map(el => el.getBoundingClientRect().toJSON());
        const labels = [...document.querySelectorAll('.hero-trust-pill')].map(el => el.getBoundingClientRect().toJSON());
        return { hero, card, capabilities, labels, scrollWidth: document.documentElement.scrollWidth,
          animation: getComputedStyle(document.querySelector('.hero-hologram')).animationName,
          labelAnimations: [...document.querySelectorAll('.hero-trust-pill')].map(el => getComputedStyle(el).animationName),
          buttons: [...document.querySelectorAll('.hero-actions a')].map(el => el.getBoundingClientRect().toJSON()),
          sidebar: rect('.command-sidebar') };
      });
      assert.ok(layout.scrollWidth <= width, `no horizontal overflow at ${width}`);
      assert.equal(layout.animation, 'none');
      assert.ok(layout.labelAnimations.every(a => a === 'none'));
      assert.ok(layout.card.left >= layout.hero.left && layout.card.right <= width, `card stays inside hero at ${width}`);
      assert.ok(layout.card.bottom < layout.capabilities[0].top, `card does not overlap capabilities at ${width}`);
      for (const label of layout.labels) {
        assert.ok(label.left >= layout.hero.left && label.right <= width, `labels stay on screen at ${width}`);
        assert.ok(label.right <= layout.card.left || label.bottom <= layout.card.top || label.top >= layout.card.bottom,
          `labels do not obscure the card at ${width}`);
      }
      if (width >= 1366) {
        assert.ok(layout.capabilities.every(r => Math.abs(r.top - layout.capabilities[0].top) < 1), 'six desktop columns');
        assert.ok(Math.abs(layout.buttons[0].top - layout.buttons[1].top) < 12, 'desktop buttons share a row');
        assert.equal(layout.sidebar.width, 74, 'existing collapsed sidebar width retained');
      }
      assert.deepEqual(errors, [], `no uncaught application errors at ${width}`);
      for (const asset of ['home-security-illustration.svg', 'home-intelligence-wave.svg']) {
        const response = await page.request.get(`${base}/assets/${asset}`);
        assert.equal(response.status(), 200);
        assert.match(await response.text(), /<svg/);
      }
      await page.screenshot({ path: path.join(out, `home-${width}.png`), fullPage: width < 600 });
      // All severity links and both authentication links retain their destinations.
      assert.deepEqual(await page.locator('.hero-priority-line').evaluateAll(els => els.map(el => el.getAttribute('href'))), Array(4).fill('/vulnerabilities/'));
      assert.equal(await page.locator('.header-account-login').getAttribute('href'), '/account/?mode=login');
      assert.equal(await page.locator('.header-account-primary').getAttribute('href'), '/account/?mode=register');
      await page.emulateMedia({ reducedMotion: 'no-preference' });
      assert.equal(await page.locator('.hero-hologram').evaluate(el => getComputedStyle(el).animationName), 'hero-shield-hover');
      if (width === 1920) {
        await page.locator('.hero-priority-line').first().click();
        await page.waitForURL('**/vulnerabilities/');
        assert.equal(await page.locator('.hero').isVisible(), false, 'hero remains hidden on other routes');
        assert.equal(await page.locator('#technology').isVisible(), true);
        await page.goto(base, { waitUntil: 'networkidle' });
        await page.locator('.hero-actions .primary-btn').click();
        await page.waitForURL('**/vulnerabilities/#advisories');
        assert.equal(await page.locator('#advisories').isVisible(), true, 'Explore advisories still opens the advisory list');
        await page.goto(base, { waitUntil: 'networkidle' });
        await page.locator('.hero-actions .ghost-btn').click();
        await page.waitForURL('**/vulnerabilities/#technology');
        assert.equal(await page.locator('#technology').isVisible(), true, 'Browse technologies still opens the catalogue');

      }
      console.log(`PASS ${width}×${height}: layout, links, artwork, reduced motion, application errors`);
      await page.close();
    }
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
