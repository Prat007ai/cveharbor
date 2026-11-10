import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
const {chromium}=await import(pathToFileURL(resolve(process.env.CVEHARBOR_PLAYWRIGHT_MODULE)));
const products=JSON.parse(await readFile('site-gate/version-products.json','utf8'));
const releases=JSON.parse(await readFile('site-gate/version-releases.json','utf8'));
const module=await readFile(join(process.env.CVEHARBOR_CATALOGUE_PUBLIC||'.','technology-version-picker.mjs'));
const browser=await chromium.launch({executablePath:process.env.CVEHARBOR_CHROMIUM_PATH,headless:true});
try {
  const page=await browser.newPage();
  await page.route('https://picker.test/**',route=>{
    const path=new URL(route.request().url()).pathname;
    if(path==='/technology-version-picker.mjs')return route.fulfill({contentType:'text/javascript',body:module});
    return route.fulfill({contentType:'text/html',body:'<!doctype html><title>Scan coverage</title>'});
  });
  await page.goto('https://picker.test/');
  const checks=await page.evaluate(async({products,releases})=>{
    const {openPicker,dismiss}=await import('/technology-version-picker.mjs');
    let scenario;
    window.fetch=async input=>{
      const url=new URL(input,location.href);
      if(url.pathname.endsWith('/catalogue'))return Response.json({...products,releases,
        formats:Object.fromEntries(Object.values(products.products).map(p=>[p.format,'.+']))});
      const q=Number(url.searchParams.get('quarter')),months=Number(url.searchParams.get('months'));
      const paged=url.searchParams.get('cursor')==='second';
      if(scenario==='denied'&&paged)return new Response(null,{status:403});
      const gaps=scenario==='restricted'&&!paged?['Customer portal requires sign-in.']:[];
      const rows=scenario==='denied'&&!paged?[{id:'CVE-2099-1234'}]:[];
      return Response.json({rows,coverageGaps:gaps,next:paged?null:'second',nextQuarter:q+1<months/3?q+1:null});
    };
    let paths=0;
    for(const [card,ids] of Object.entries(products.cards)){
      for(const id of ids){
        let cardWarning;
        await openPicker(card,{saved:()=>'',save:async()=>{},detail:()=>{},
          reportCoverage:(p,v,m,incomplete)=>{cardWarning=incomplete;}});
        const panel=document.querySelector('dialog[open]');
        const product=panel.querySelector('[aria-label="Installed product"]');
        product.value=id;product.onchange();
        const release=panel.querySelector('[aria-label="Release"]');release.selectedIndex=1;release.onchange();
        const [scan,more,retry]=panel.querySelectorAll('.cvie-identity-actions button');
        const status=panel.querySelectorAll('[role=status]')[1];
        function expect(fragment){
          if(!status.textContent.includes(fragment))throw Error(card+' / '+id+': '+status.textContent);
        }
        async function waitForResult(){
          for(let attempt=0;attempt<100 && status.textContent.startsWith('Checking ');attempt++)
            await new Promise(resolve=>setTimeout(resolve,10));
        }
        scenario='complete';await scan.onclick();expect('No matching public advisories');
        scenario='restricted';await scan.onclick();expect('Coverage incomplete');expect('Customer portal');
        if(cardWarning!==true)throw Error('Missing card warning: '+id);
        more.click();
        await waitForResult();
        expect('last 12 months');expect('Customer portal');
        scenario='denied';await scan.onclick();expect('Coverage incomplete');
        if(retry.hidden||!panel.querySelector('.version-result'))throw Error('Missing retry or partial finding: '+id);
        scenario='complete';retry.click();await waitForResult();
        expect('1 direct product advisor');
        if(cardWarning!==false)throw Error('Card warning survived recovery: '+id);
        dismiss();paths++;
      }
    }
    return paths;
  },{products,releases});
  assert.equal(checks,Object.values(products.cards).flat().length);
  console.log(Object.keys(products.cards).length+' cards, '+checks+' product selections: complete, restricted, extended, failure and recovery passed.');
} finally {await browser.close();}
