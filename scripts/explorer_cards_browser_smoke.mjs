// Local Chromium checks using the built public snapshot; no external services.
import fs from 'node:fs';
import assert from 'node:assert/strict';
const {chromium}=await import(process.env.CVIE_PLAYWRIGHT_MODULE||'playwright');
const directory=process.env.EXPLORER_SCREENSHOTS||'/workspace/explorer-cards-review';fs.mkdirSync(directory,{recursive:true});
const browser=await chromium.launch({headless:true,executablePath:process.env.CVIE_CHROMIUM_PATH||undefined,args:['--no-sandbox']});
try{
 const context=await browser.newContext({viewport:{width:1920,height:1080},reducedMotion:'reduce',serviceWorkers:'block'});
 const routing=route=>{const url=new URL(route.request().url());return ['127.0.0.1','localhost'].includes(url.hostname)?route.continue():url.hostname==='api.cveharbor.com'?route.fulfill({status:401,contentType:'application/json',headers:{'Access-Control-Allow-Origin':'http://127.0.0.1:8080','Access-Control-Allow-Credentials':'true'},body:'{"error":"Sign in required"}'}):route.abort();};
 await context.route('**/*',routing);
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto((process.env.CVIE_BASE_URL||'http://127.0.0.1:8080')+'/vulnerabilities/',{waitUntil:'domcontentloaded'});
 const cards=page.locator('.technology-kpis'),card=key=>page.locator('[data-technology-metric="'+key+'"]');
 await page.waitForFunction(()=>document.querySelectorAll('.technology-kpis .kpi-chart svg').length===4);
 const sum=async(key,selector)=>card(key).locator(selector).evaluateAll(nodes=>nodes.reduce((sum,n)=>sum+Number(n.dataset.chartValue),0));
 assert.equal(await sum('technologies','.kpi-bar'),Number(await page.locator('#technologyTotal').innerText()));
 assert.equal(await sum('recent','.kpi-bar'),Number(await page.locator('#technologyRecentMetric').innerText()));
 assert.equal(await sum('indexed','.kpi-severity'),Number(await page.locator('#technologyIndexedMetric').innerText()));
 const recentChart=card('recent').locator('svg');
 await page.locator('#technologySearch').fill('PHP');await page.locator('#technologySearch').dispatchEvent('input');
 assert.equal(await sum('technologies','.kpi-bar'),1);
 await card('technologies').click();assert.equal(await page.locator('#technologySearch').inputValue(),'');
 assert.ok(await page.locator('#categoryGrid').evaluate(el=>el===document.activeElement));
 for(const key of ['recent','indexed','critical']){
  await card(key).click();assert.equal(await page.locator('#dateRange').inputValue(),key==='recent'?'published30':'all');
  assert.equal(await page.locator('#severity').inputValue(),key==='critical'?'critical':'all');
  const total=Number(await card(key).locator('strong').innerText());
  assert.match(await page.locator('#resultCount').innerText(),new RegExp('^'+total+' of '));
 }
 const hit=card('recent').locator('.kpi-hit').last();await hit.hover();
 assert.equal(await card('recent').locator('.kpi-insight').innerText(),await hit.getAttribute('data-chart-label'));
 await page.mouse.move(5,5);
 assert.equal(await recentChart.locator('.kpi-bar').first().evaluate(el=>getComputedStyle(el).animationName),'none');
 await page.emulateMedia({reducedMotion:'no-preference'});await card('critical').hover();
 assert.notEqual(await card('critical').locator('.kpi-line').evaluate(el=>getComputedStyle(el).animationName),'none');
 await page.emulateMedia({reducedMotion:'reduce'});
 assert.equal(await card('critical').locator('.kpi-line').evaluate(el=>getComputedStyle(el).animationName),'none');
 await card('critical').focus();await page.keyboard.press('Enter');assert.equal(await page.locator('#severity').inputValue(),'critical');
 const widths=[1366,1920,2560,390];
 for(const width of widths){
  await page.setViewportSize({width,height:width===2560?1440:1080});await page.evaluate(()=>scrollTo(0,0));await page.mouse.move(5,5);
  await cards.screenshot({path:directory+'/explorer-cards-'+width+'.png'});
  await page.screenshot({path:directory+'/explorer-page-'+width+'.png'});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'no page overflow at '+width);
  assert.equal(await cards.locator('button').evaluateAll(nodes=>nodes.every(el=>el.scrollWidth<=el.clientWidth+1)),true,'no card content overflow at '+width);
 }
 assert.deepEqual(errors,[]);
 // A short actual browser recording lets reviewers see motion rather than a still.
 const recording=await browser.newContext({viewport:{width:1366,height:768},reducedMotion:'no-preference',serviceWorkers:'block',recordVideo:{dir:directory,size:{width:1366,height:768}}});
 await recording.route('**/*',routing);const preview=await recording.newPage();
 await preview.goto((process.env.CVIE_BASE_URL||'http://127.0.0.1:8080')+'/vulnerabilities/',{waitUntil:'domcontentloaded'});
 await preview.waitForFunction(()=>document.querySelectorAll('.technology-kpis .kpi-chart svg').length===4);
 fs.writeFileSync(directory+'/card-bounds.json',JSON.stringify(await preview.locator('.technology-kpis').boundingBox()));
 for(const key of ['technologies','recent','indexed','critical']){await preview.locator('[data-technology-metric="'+key+'"]').hover();await preview.waitForTimeout(1200);}
 const video=preview.video();await recording.close();await video.saveAs(directory+'/explorer-cards-motion.webm');
 fs.writeFileSync(directory+'/verification.json',JSON.stringify({ok:true,data:'Built public snapshot; signed-out account responses simulated',widths,checks:['charts reconcile to counters','all four drill-downs','hover date/count','keyboard activation','reduced motion','responsive overflow']},null,2));
 console.log('PASS explorer cards: real chart counts, drill-downs, hover, keyboard, reduced motion and 390/1366/1920/2560 widths.');
 await context.close();
}finally{await browser.close();}
