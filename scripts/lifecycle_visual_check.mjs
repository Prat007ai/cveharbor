// Local fixture account + the actual published directory. No production account mutations.
import {chromium} from 'playwright-core';
import {spawn} from 'node:child_process';
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
const server=spawn('python',['-m','http.server','8767','--bind','127.0.0.1','--directory','public'],{stdio:'ignore'});
let browser;
try{
 const executablePath=(await Promise.all(['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].map(async p=>await fs.access(p).then(()=>p,()=>null)))).find(Boolean);
 browser=await chromium.launch({executablePath,headless:true,args:['--no-sandbox']});
 const page=await browser.newPage();
 await page.route('**/*',async route=>{
  const url=new URL(route.request().url());
  if(url.hostname==='127.0.0.1')return route.continue();
  if(url.hostname==='api.cveharbor.com'){
   const path=url.pathname;
   if(path==='/v1/me')return route.fulfill({json:{authenticated:true,email:'visual-fixture@example.test'}});
   if(path==='/v1/monitoring/status')return route.fulfill({json:{ready:false}});
   if(path==='/v1/lifecycle/status')return route.fulfill({json:{ready:true}});
   if(path==='/v1/lifecycle')return route.fulfill({json:{watches:[{id:'visual-fixture',product:'WordPress',slug:'wordpress',cycle:'6.6',installed_version:''}],preferences:{email_enabled:0,lead_days:90},email_delivery_active:false}});
   return route.fulfill({json:{}});
  }
  return route.fulfill({status:204,body:''});
 });
 for(const [name,width,height] of [['reference',1672,941],['wide',3700,1800],['mobile',390,844]]){
  await page.setViewportSize({width,height});await page.goto('http://127.0.0.1:8767/lifecycle/');
  await page.waitForFunction(()=>document.querySelector('.lifecycle-source-row')&&document.body.classList.contains('command-center-app'));
  await page.evaluate(()=>window.dispatchEvent(new CustomEvent('cveharbor:account-state',{detail:{authenticated:true,email:'visual-fixture@example.test'}})));
  await page.waitForFunction(()=>document.getElementById('lifecycleWatches').textContent.includes('WordPress'));
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),name+' must not overflow horizontally');
  if(width>1050){const box=await page.locator('#lifecycleMonitor').boundingBox();assert.ok(box.width<=1541,'bounded workspace width');assert.ok(await page.locator('.lifecycle-hero-art img').evaluate(img=>img.complete&&img.naturalWidth>0),'hero asset must load');}
  await fs.mkdir('work',{recursive:true});await page.screenshot({path:'work/lifecycle-'+name+'.png',fullPage:true});
 }
 console.log('PASS: lifecycle reference/wide/mobile layouts; bounded width, no horizontal overflow, real published directory and explicit test account.');
}finally{await browser?.close();server.kill();}
