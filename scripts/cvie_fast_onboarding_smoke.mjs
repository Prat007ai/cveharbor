import assert from 'node:assert/strict';import fs from 'node:fs';import {JSDOM} from 'jsdom';
const dom=new JSDOM('<div id="cvieExplorer"></div><input id="technologyAddName"><input id="technologyAddVendor"><input id="technologyAddCpe">',{url:'https://cveharbor.com/vulnerabilities/',runScripts:'outside-only'});
const w=dom.window;w.AbortSignal=globalThis.AbortSignal;let pages=0,legacy=0;
const id='11111111-1111-4111-8111-111111111111';
w.fetch=async url=>{const u=new URL(url);
 if(u.pathname.endsWith('/sync'))return Response.json({ready:true,status:'unchanged'});
 if(u.pathname.endsWith('/directory'))return Response.json({status:'unresolved',guidance:'Choose a suggestion; no automatic correction.',candidates:[{id:'php',name:'PHP',vendor:'php',kind:'product',cpe:'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*',match:'suggestion'}]});
 if(u.pathname==='/v1/cvie'||u.pathname.endsWith('/progress'))return Response.json({ready:true,fast_evidence:true,account_id:'a',products:[{id,name:'PHP',cpe:'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*',status:'ready',progress:{}}],withdrawn_ids:['CVE-2026-99999'],evidence:{sources:[]}});
 if(u.pathname.endsWith('/evidence')){pages++;return Response.json({account_id:'a',scanned:100,coverage:'indexed_partial',advisories:[{id:pages===1?'CVE-2026-12345':'CVE-2026-12346',categories:['PHP'],cvie_products:['PHP']}],next:pages===1?'CVE-2026-12345':null,excluded_product_cves:[]});}
 if(u.pathname.endsWith('/advisories')){legacy++;throw Error('Full reconciliation must not run');}throw Error('Unexpected request');};
const until=async f=>{const end=Date.now()+4000;while(!f()){if(Date.now()>end)throw Error('UI did not settle');await new Promise(r=>setTimeout(r,10));}};
try{
 w.eval(fs.readFileSync('cvie.js','utf8'));const client=w.CVEHARBOR_CVIE;await until(()=>client.ready&&!client.loading);
 assert.equal(pages,1);assert.equal(legacy,0);assert.equal(client.records.length,1);assert.equal(client.coverageLimited,true);assert.equal(client.hasMore,true);
 assert.equal(client.merge([{id:'CVE-2026-99999'}]).some(r=>r.id==='CVE-2026-99999'),false);
 const more=[...w.document.querySelectorAll('button')].find(b=>b.textContent==='Load more stored CVEs');more.click();await until(()=>!client.loading&&!client.hasMore);assert.equal(client.records.length,2);
 const input=w.document.getElementById('technologyAddName');input.value='PHH';input.dispatchEvent(new w.Event('input'));await until(()=>w.document.querySelector('.cvie-registry-options button'));assert.equal(input.value,'PHH');
 w.document.querySelector('.cvie-registry-options button').click();assert.equal(input.value,'PHP');assert.equal(w.document.getElementById('technologyAddVendor').value,'php');
 w.dispatchEvent(new w.CustomEvent('cveharbor:account-state',{detail:{authenticated:false}}));assert.equal(client.records.length,0);assert.equal(client.hasMore,false);
 console.log('PASS bounded onboarding: immediate stored page, explicit pagination, no legacy reconciliation, typo confirmation, rejection and logout isolation.');
}finally{dom.window.close();}
