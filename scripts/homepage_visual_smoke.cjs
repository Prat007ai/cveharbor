// Local brochure/overview regression checks. No production authentication or writes.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {chromium}=require(process.env.CVEHARBOR_PLAYWRIGHT_MODULE||'playwright');
const base=process.env.CVEHARBOR_TEST_URL||'http://127.0.0.1:8080';
const out=process.env.CVEHARBOR_SCREENSHOTS||'/tmp/cveharbor-homepage-review';
if(!['127.0.0.1','localhost'].includes(new URL(base).hostname))throw Error('Use a local test server');
(async()=>{
 fs.mkdirSync(out,{recursive:true});
 const browser=await chromium.launch({...(process.env.CVEHARBOR_CHROMIUM?{executablePath:process.env.CVEHARBOR_CHROMIUM}:{}),args:['--no-sandbox']});
 try{
  for(const [width,height]of [[1366,768],[1920,1080],[2560,1440],[390,844]]){
   const page=await browser.newPage({viewport:{width,height},deviceScaleFactor:1,reducedMotion:'reduce',timezoneId:'America/Toronto'});
   const errors=[],writes=[];page.on('pageerror',e=>errors.push(e.message));
   await page.route('**/*',r=>{
    const u=new URL(r.request().url());
    if(u.origin===new URL(base).origin)return r.continue();
    if(!['GET','HEAD'].includes(r.request().method()))writes.push(u.pathname);
    if(u.hostname==='api.cveharbor.com'&&u.pathname==='/v1/me')return r.fulfill({status:200,contentType:'application/json',body:'{"authenticated":false}'});
    return r.abort();
   });
   await page.goto(base,{waitUntil:'networkidle'});
   assert.equal(await page.locator('#heroTitle').innerText(),'Know the risk.\nFind the fix.');
   assert.equal(await page.locator('.mosaic>.product-panel').count(),4);
   assert.equal(await page.locator('.findings-table th').count(),7);
   assert.equal(await page.locator('.findings-table tbody tr').count(),3);
   assert.equal(await page.locator('.asset-import-paths article').count(),3);
   assert.equal(await page.locator('#dashboard').isVisible(),false);
   assert.equal(await page.locator('.footer-status').isVisible(),false);
   assert.equal(await page.locator('.marketing-story').isVisible(),true);
   assert.equal(await page.locator('.hero .product-panel').first().evaluate(el=>getComputedStyle(el).animationName),'none');
   assert.ok(await page.locator('.findings-table').evaluate(el=>[...el.querySelectorAll('select,input,button')].every(c=>c.disabled)));
   assert.equal(await page.locator('.header-account-login').getAttribute('href'),'/account/?mode=login');
   assert.equal(await page.locator('.header-account-primary').getAttribute('href'),'/account/?mode=register');
   for(const image of await page.locator('.hero img').all()){
    await image.scrollIntoViewIfNeeded();await image.evaluate(el=>el.decode());
    assert.ok(await image.evaluate(el=>el.naturalWidth>0));
   }
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'no page overflow');
   assert.ok(await page.locator('.findings-table').evaluate(el=>el.scrollWidth<=el.clientWidth+1),'table fits');
   if(width>=1366){
    assert.ok(await page.locator('.findings-table th').evaluateAll(els=>els.every(el=>el.getBoundingClientRect().width>0)));
    assert.equal((await page.locator('.command-sidebar').boundingBox()).width,74);
   }
   await page.evaluate(()=>scrollTo(0,0));
   // Keep the fixed header at the document top in full-page review screenshots.
   await page.addStyleTag({content:'.site-header{position:absolute!important;top:0!important}'});
   await page.screenshot({path:path.join(out,`home-${width}.png`),fullPage:true});
   await page.emulateMedia({reducedMotion:'no-preference'});
   assert.equal(await page.locator('.hero .product-panel').first().evaluate(el=>getComputedStyle(el).animationName),'homepage-arrive');
   if(width===1920){
    await page.locator('.command-nav-link[aria-label="Intelligence Overview"]').click();
    await page.waitForURL('**/intelligence/');
    assert.equal(await page.locator('#dashboard').isVisible(),true);
    assert.equal(await page.locator('.footer-status').isVisible(),true);
    assert.equal(await page.locator('.hero').isVisible(),false);
    assert.equal(await page.locator('.marketing-story').isVisible(),false);
    assert.ok(Number(await page.locator('#statTotal').innerText())>0,'overview renders real local records');
    await page.screenshot({path:path.join(out,'intelligence-1920.png'),fullPage:true});
    await page.locator('[data-metric="critical"]').click();
    await page.waitForURL('**/vulnerabilities/?**');
    assert.equal(new URL(page.url()).searchParams.get('scope'),'critical','critical filter survives navigation');
    assert.equal(await page.locator('#advisories').isVisible(),true);
    assert.equal(await page.locator('.marketing-story').isVisible(),false);
    await page.goto(base+'/intelligence/',{waitUntil:'networkidle'});
    await page.locator('[data-chart-period="published30"]').click();
    const first=page.locator('.tech-chart-link').first();
    const name=await first.locator('span').first().innerText();
    await first.click();await page.waitForURL('**/vulnerabilities/?**');
    assert.equal(new URL(page.url()).searchParams.get('technology'),name);
    assert.equal(new URL(page.url()).searchParams.get('period'),'published30');
    assert.equal(await page.locator('#technologyFilter').inputValue(),name);
    await page.goto(base+'/#dashboard',{waitUntil:'networkidle'});
    await page.waitForURL('**/intelligence/#dashboard');
    assert.equal(await page.locator('#dashboard').isVisible(),true);
    await page.goto(base+'/#methodology',{waitUntil:'networkidle'});
    await page.waitForURL('**/intelligence/#methodology');
    await page.goto(base,{waitUntil:'networkidle'});
    await page.locator('.hero-actions .primary-btn').click();await page.waitForURL('**/vulnerabilities/#advisories');
    await page.goto(base,{waitUntil:'networkidle'});
    await page.locator('.hero-actions .ghost-btn').click();await page.waitForURL('**/vulnerabilities/#technology');
   }
   assert.deepEqual(errors,[],`no uncaught errors at ${width}`);
   assert.deepEqual(writes,[],`public demo sends no writes at ${width}`);
   console.log(`PASS ${width}×${height}: brochure, overview routes, images, sample controls, reduced motion, links and no private writes`);
   await page.close();
  }
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exit(1)});
