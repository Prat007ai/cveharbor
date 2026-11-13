import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {performance} from 'node:perf_hooks';
import {JSDOM} from 'jsdom';
const source=fs.readFileSync(new URL('../cvie.js',import.meta.url),'utf8');
function merger(extra={}){const c=vm.createContext({records:[],excluded:[],products:[],withdrawn:new Set(),normalize:x=>String(x||'').normalize('NFKC').trim().toLowerCase().replace(/\s+/g,' '),...extra});vm.runInContext(source.slice(source.indexOf('function merge(base=[]){'),source.indexOf('function clearPrivate'))+';this.merge=merge;',c);return c;}
test('indexed exclusions preserve per-product corrections, withdrawals and original CNA rows',()=>{
 const c=merger({products:[{name:'.NET Runtime',component_scope:true},{name:'ASP.NET Core',component_scope:true}],records:[{id:'CVE-2026-12345',cvie_products:['.NET Runtime'],categories:['.NET Runtime'],cna_affected:[{product:'.NET 10'}],sources:[{url:'https://example.test/runtime'}]}],excluded:[{id:'CVE-2026-12345',product:'Other'},{id:'CVE-2026-99999',product:'.NET Runtime'}],withdrawn:new Set(['CVE-2026-77777'])});
 const base=[{id:'CVE-2026-12345',categories:['ASP.NET Core','Other'],cna_affected:[{product:'ASP.NET Core 10'}],sources:[{url:'https://example.test/cna'}]},{id:'CVE-2026-77777'}];
 const rows=c.merge(base);assert.equal(rows.length,1);assert.deepEqual(Array.from(rows[0].categories),['.NET Runtime']);assert.deepEqual(Array.from(rows[0].cvie_excluded_products),['Other','ASP.NET Core']);assert.equal(rows[0].cna_affected.length,2);assert.equal(rows[0].sources.length,2);assert.equal(c.merge(base),rows);
 c.records=[{...c.records[0],verification_pending:true}];assert.notEqual(c.merge(base),rows);assert.equal(c.merge(base)[0].verification_pending,true);
 c.excluded.push({id:'CVE-2026-12345',product:'.NET Runtime'});assert.equal(c.merge(base)[0].categories.length,0,'new exclusions invalidate even when the array is appended');
 c.products=[];assert.ok(!c.merge(base)[0].cvie_excluded_products.includes('ASP.NET Core'),'scope changes invalidate cached exclusions');
});
test('large exclusion snapshots avoid repeated scans and reuse unchanged merge results',()=>{
 const records=Array.from({length:10000},(_,i)=>({id:'CVE-2026-'+(100000+i),cvie_products:['PHP'],categories:['PHP']}));
 const excluded=Array.from({length:30000},(_,i)=>({id:records[i%10000].id,product:'Other'+i%3}));
 const c=merger({records,excluded}),start=performance.now(),rows=c.merge(),duration=performance.now()-start;
 assert.equal(rows.length,10000);assert.ok(rows.every(r=>r.cvie_excluded_products.length===3));assert.equal(c.merge(),rows);
 assert.ok(duration<2000,'representative merge should not monopolize the UI for seconds');console.log(JSON.stringify({records:10000,exclusions:30000,mergeMs:Math.round(duration)}));
});
test('progress redraw keeps the focused History control and lazily renders collapsed product details',async()=>{
 const dom=new JSDOM('<div id="cvieExplorer"></div>',{url:'https://cveharbor.com/vulnerabilities/',runScripts:'outside-only',pretendToBeVisual:true});const w=dom.window;w.AbortSignal=globalThis.AbortSignal;
 let last=1,owner='a',unauthorized=false;
 const products=()=>Array.from({length:132},(_,i)=>({id:owner+i,name:'Product '+i,cpe:'cpe:2.3:a:example:product:*:*:*:*:*:*:*:*',status:'scanning',last_success_at:last,progress:{windows_complete:last,windows_total:10},coverage:{identities:[{label:'Product '+i}],notes:['Limited fixture']}}));
 w.fetch=async url=>unauthorized?Response.json({error:'Sign in'},{status:401}):Response.json(new URL(url).pathname.endsWith('/advisories')?{account_id:owner,advisories:[],next:null}:{account_id:owner,ready:true,products:products(),evidence:{sources:[]}});
 const until=async fn=>{const end=Date.now()+3000;while(!fn()){if(Date.now()>end)throw Error('Client did not settle');await new Promise(r=>setTimeout(r,1));}};
 try{w.eval(source);const client=w.CVEHARBOR_CVIE;await until(()=>client.ready&&!client.loading);
  const select=w.document.querySelector('select[aria-label="CVIE vulnerability history"]');select.focus();assert.equal(w.document.querySelectorAll('.cvie-product-status').length,0);
  last++;await client.refresh(false,true);assert.equal(w.document.querySelector('select[aria-label="CVIE vulnerability history"]'),select);assert.equal(w.document.activeElement,select);
  const details=w.document.querySelector('.cvie-scan-details');details.open=true;await until(()=>w.document.querySelectorAll('.cvie-product-status').length===132);
  w.document.querySelector('.cvie-coverage-details').open=true;last++;await client.refresh(false,true);assert.equal(w.document.querySelector('.cvie-scan-details').open,true);assert.equal(w.document.querySelector('.cvie-coverage-details').open,true);
  unauthorized=true;await client.refresh();assert.equal(w.document.querySelectorAll('.cvie-product-status').length,0);assert.equal(client.records.length,0);assert.equal(w.localStorage.length,0);
 }finally{dom.window.close();}
});
