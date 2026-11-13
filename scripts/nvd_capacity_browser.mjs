// Actual serving website, real authenticated test backend. No production requests.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fixtureId} from '../account-backend/tests/helpers/capacity-db.mjs';
const require=createRequire(new URL('../staging/package.json',import.meta.url));
export async function outageBrowser(base,token,site,phase){
 const {chromium}=require('playwright-core'),root=path.resolve(site),results=[];
 const browser=await chromium.launch({headless:true,env:Object.fromEntries(['PATH','HOME','TMPDIR','TEMP','SystemRoot','LOCALAPPDATA'].filter(k=>process.env[k]).map(k=>[k,process.env[k]])),executablePath:process.env.CVEHARBOR_CHROMIUM_PATH||(process.platform==='win32'?'C:/Program Files/Google/Chrome/Application/chrome.exe':'/usr/bin/google-chrome')});
 try{for(const section of ['customer-reports','customer-dashboard','workspace']){
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],requests=[];
  page.on('pageerror',e=>errors.push(e.message));page.on('crash',()=>errors.push('Browser crashed'));
  await page.addInitScript(()=>{window.outageTasks=[];new PerformanceObserver(l=>window.outageTasks.push(...l.getEntries().map(e=>e.duration))).observe({type:'longtask',buffered:true});});
  await page.route('**/*',async route=>{
   const req=route.request(),u=new URL(req.url());
   if(u.hostname==='api.cveharbor.com'){
    // Sync is disabled: the harness explicitly starts the real background job
    // with its injected outage provider. All data reads use the real Worker.
    if(req.method()!=='GET')return route.fulfill({status:405,json:{error:'Rehearsal is read only'}});
    const start=performance.now(),r=await fetch(base+u.pathname+u.search,{headers:{Cookie:'cvh_session='+token,Origin:'https://cveharbor.com'},signal:AbortSignal.timeout(15000)});
    requests.push({path:u.pathname,status:r.status,ms:Math.round(performance.now()-start)});
    return route.fulfill({status:r.status,body:await r.text(),contentType:'application/json'});
   }
   if(u.hostname!=='cveharbor.com')return route.abort();
   const file=path.resolve(root,'.'+u.pathname+(u.pathname.endsWith('/')?'index.html':''));assert.ok(file.startsWith(root+path.sep));
   try{return route.fulfill({body:await fs.readFile(file),contentType:({'.html':'text/html','.js':'text/javascript','.css':'text/css','.json':'application/json','.svg':'image/svg+xml'})[path.extname(file)]||'application/octet-stream'});}catch{return route.fulfill({status:404,body:''});}
  });
  const start=Date.now();await page.goto('https://cveharbor.com/'+section+'/');
  const interactions=[];let menuReady;
  if(section==='workspace'){
   await page.waitForSelector('body.workspace-authenticated');
   await page.getByRole('button',{name:'Review customer priorities',exact:true}).click();
   const chooser=page.locator('#workspaceAccess > .finding-ai select');await chooser.waitFor();menuReady=Date.now()-start;
   await page.evaluate(()=>window.outageTasks=[]);
   const at=Date.now();await chooser.selectOption(fixtureId(1));interactions.push({control:'customer',ms:Date.now()-at});
   await page.locator('#workspaceAccess > .finding-ai').getByText(/1000 saved software entries/).waitFor({timeout:30000});
   const tabAt=Date.now();await page.locator('#ws-environments-tab').click();await page.locator('#wsActivityPanel').getByText('Environment 0',{exact:true}).waitFor();interactions.push({control:'environment tab',ms:Date.now()-tabAt});
  }else{
   await page.waitForFunction(()=>document.querySelector('#customerDashFilter')?.options.length>=2&&document.querySelector('#customerDashStatus')?.dataset.ready==='true');menuReady=Date.now()-start;
   await page.waitForFunction(()=>window.CVEHARBOR_CVIE?.ready&&window.CVEHARBOR_CVIE.products.length===1&&!window.CVEHARBOR_CVIE.loading);
   const settled=()=>page.waitForFunction(()=>document.querySelector('#customerDashStatus').dataset.assessing==='false');await settled();
   await page.evaluate(()=>window.outageTasks=[]);
   for(const [control,value] of [['customerDashFilter',fixtureId(1)],['customerDashEnvironment',fixtureId(1000)],['customerDashEnvironment','']]){
    const at=Date.now();await page.selectOption('#'+control,value);interactions.push({control,ms:Date.now()-at});await settled();
   }
  }
  const maxTask=await page.evaluate(()=>Math.round(Math.max(0,...window.outageTasks)));
  results.push({phase,section,width:1440,menu_ready_ms:menuReady,interactions,max_long_task_ms:maxTask,errors,requests});
  console.log(JSON.stringify({phase,section,menu_ready_ms:menuReady,interactions,max_long_task_ms:maxTask,errors}));
  assert.deepEqual(errors,[]);assert.ok(interactions.every(i=>i.ms<1200),'Menu interaction exceeds 1.2 seconds');assert.ok(maxTask<500,'Browser main thread blocked for 500 ms');
  await page.close();
 }}finally{await browser.close();}
 return results;
}
