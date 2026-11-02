// Local fixture account + the actual published directory. No production account mutations.
let chromium;try{({chromium}=await import('playwright-core'));}catch{({chromium}=await import('/opt/codex/cua_node/lib/node_modules/playwright/index.mjs'));}
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
 await page.setViewportSize({width:1672,height:941});await page.goto('http://127.0.0.1:8767/lifecycle/');
 await page.waitForFunction(()=>document.querySelector('.lifecycle-source-row')&&document.body.classList.contains('command-center-app'));
 await page.evaluate(()=>window.dispatchEvent(new CustomEvent('cveharbor:account-state',{detail:{authenticated:true,email:'visual-fixture@example.test'}})));
 await page.waitForFunction(()=>document.getElementById('lifecycleWatches').textContent.includes('WordPress'));
 await page.locator('#lifecycleInstalled').fill('resize-preserves-input');
 const cases=[['reference',1672,941],['desktop',1920,1080],['qhd',2560,1440],['ultrawide',3440,1440],['wide',3840,2160],['five-k',5120,2160],['laptop',1280,800],['tablet',1024,768],['mobile',390,844],['small-mobile',320,740],['return-desktop',1920,1080],... [650,760,761,820,821,1050,1051,1100,1101,1400,1401,1700,2299,2300,3099,3100,4100].map(w=>['boundary-'+w,w,1000])];
 const measurements=[];
 for(const [name,width,height] of cases){
  await page.setViewportSize({width,height});await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
  const layout=await page.evaluate(()=>{
   const rect=selector=>document.querySelector(selector).getBoundingClientRect().toJSON();
   const root=rect('#lifecycleMonitor'),nav=rect('.command-sidebar');
   const cards=[...document.querySelectorAll('.lifecycle-source-row')];
   return {viewport:document.documentElement.clientWidth,pageWidth:document.documentElement.scrollWidth,root,header:rect('.topbar'),footer:rect('.footer-status'),sidebar:innerWidth>760?nav.right:0,
    panels:[...document.querySelectorAll('.lifecycle-grid > .data-panel')].map(panel=>panel.getBoundingClientRect().toJSON()),
    cards:cards.slice(0,2).map(card=>card.getBoundingClientRect().toJSON()),
    overflowingCards:cards.filter(card=>card.scrollWidth>card.clientWidth+1).length,
    installed:document.getElementById('lifecycleInstalled').value};
  });
  assert.ok(layout.pageWidth<=layout.viewport+1,name+' must not overflow horizontally');
  assert.ok(layout.root.left-layout.sidebar<=41&&layout.viewport-layout.root.right<=41,name+' must use the available width with small gutters');
  assert.ok(Math.abs(layout.header.left-layout.root.left)<=1&&Math.abs(layout.header.width-layout.root.width)<=1,name+' header aligns with workspace');
  assert.ok(Math.abs(layout.footer.width-layout.root.width)<=1,name+' footer uses available width');
  assert.equal(layout.overflowingCards,0,name+' product card content must fit');
  if(width>760)assert.ok(layout.header.top<1,name+' desktop sidebar must not occupy a horizontal row');
  assert.equal(layout.installed,'resize-preserves-input',name+' preserves in-progress form while resizing');
  if(width>1050){assert.equal(layout.panels.length,2,name+' has two workspace panels');assert.ok(Math.abs(layout.panels[0].width-layout.panels[1].width)<=1,name+' workspace panels split equally');assert.ok(Math.abs(layout.panels[0].top-layout.panels[1].top)<=1,name+' workspace panels sit side by side');}
  if(width>=3100)assert.ok(layout.cards[1].left>layout.cards[0].left+layout.cards[0].width,name+' uses two product columns');
  if(width>1050)assert.ok(await page.locator('.lifecycle-hero-art img').evaluate(img=>img.complete&&img.naturalWidth>0),'hero asset must load');
  measurements.push({name,width,contentWidth:layout.root.width,leftGutter:layout.root.left-layout.sidebar,rightGutter:layout.viewport-layout.root.right});
  if(!name.startsWith('boundary-')){await fs.mkdir('work',{recursive:true});await page.screenshot({path:'work/lifecycle-'+name+'.png',fullPage:true});}
 }
 await fs.writeFile('work/lifecycle-responsive-measurements.json',JSON.stringify(measurements,null,2));

 console.log('PASS: lifecycle 28 live resize layouts from 320px to 5120px; small gutters, aligned header/footer, fitting cards, input preserved, and two product columns on wide monitors.');
}finally{await browser?.close();server.kill();}
