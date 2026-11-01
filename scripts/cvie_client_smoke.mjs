// Exercise session races and correction propagation without customer data or network.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {JSDOM} from 'jsdom';
const dom=new JSDOM('<div id="cvieExplorer"></div>',{url:'https://cveharbor.com/vulnerabilities/',runScripts:'outside-only'});
const w=dom.window;w.AbortSignal=globalThis.AbortSignal;
let owner='a',held=null,holdNext=false,failPages=false,wrongPage=false,cycle=false,excluded=[],componentProducts=[],extraRecords=[];
const record=who=>({id:who==='a'?'CVE-2026-12345':'CVE-2026-54321',summary:'Synthetic private '+who,categories:['Apache Tomcat'],cvie_products:['Apache Tomcat'],source_type:'cvie_combined'});
w.fetch=async url=>{
 const parsed=new URL(url),who=owner;
 if(parsed.pathname.endsWith('/sync'))return Response.json({ready:true}, {status:202});
 if(parsed.pathname==='/v1/cvie')return Response.json({ready:true,account_id:who,products:[{id:who,name:'Apache Tomcat',status:'ready',progress:{},recent_count:1,history_count:1},...componentProducts],evidence:{sources:[]},excluded_product_cves:excluded});
 if(parsed.pathname.endsWith('/advisories')){
  if(failPages)throw Error('Simulated page failure');
  const body={account_id:wrongPage?'a':who,advisories:[record(who),...extraRecords],next:cycle?(parsed.searchParams.get('after')==='A'?'B':'A'):null};wrongPage=false;
  if(holdNext){holdNext=false;return new Promise(resolve=>{held=()=>resolve(Response.json(body));});}
  return Response.json(body);
 }
 throw Error('Unexpected test request');
};
const until=async condition=>{const end=Date.now()+3000;while(!condition()){if(Date.now()>end)throw Error('Client did not settle');await new Promise(resolve=>setTimeout(resolve,10));}};
const auth=(authenticated,email='')=>w.dispatchEvent(new w.CustomEvent('cveharbor:account-state',{detail:{authenticated,email}}));
try{
 w.eval(fs.readFileSync('cvie.js','utf8'));const client=w.CVEHARBOR_CVIE;
 await until(()=>client.ready&&!client.loading&&client.records.length===1);
 assert.equal(client.records[0].id,record('a').id);
 holdNext=true;const inFlight=client.refresh();await until(()=>held);
 owner='b';auth(true,'b@example.test');assert.equal(client.records.length,0,'account changes clear old private results synchronously');
 const seen=[];w.addEventListener('cvie:updated',()=>seen.push(client.records.map(r=>r.id)));
 held();held=null;await inFlight;await until(()=>!client.loading&&client.records[0]?.id===record('b').id);
 assert.ok(seen.every(ids=>!ids.includes(record('a').id)),'a late response from the previous session never restores its records');
 holdNext=true;const beforeLogout=client.refresh();await until(()=>held);
 auth(false);assert.equal(client.signedIn,false);assert.equal(client.records.length,0);
 held();held=null;await beforeLogout;assert.equal(client.signedIn,false);assert.equal(client.records.length,0,'logout survives a late successful response');
 owner='a';auth(true,'a@example.test');await until(()=>!client.loading&&client.records.length===1);
 owner='b';failPages=true;await client.refresh();assert.equal(client.records.length,0,'an account switch followed by a page failure never retains the old account cache');
 failPages=false;await client.refresh();assert.equal(client.records[0].id,record('b').id);
 wrongPage=true;await client.refresh();assert.equal(client.records.length,0,'state/page account identity mismatches fail closed');
 await until(()=>!client.loading&&client.records[0]?.id===record('b').id);
 cycle=true;await client.refresh();assert.match(w.document.querySelector('.cvie-status').textContent,/pagination stalled/,'multi-cursor loops are detected');cycle=false;
 const stale={id:'CVE-2026-88888',categories:['WordPress / Plugins'],title:'WordPress core before 6.0',affected:'WordPress core before 6.0'};
 excluded=[{id:stale.id,product:'WordPress'}];await client.refresh();
 const merged=client.merge([stale]);w.eval(fs.readFileSync('inventory-matching.js','utf8'));
 assert.equal(w.CVEHARBOR_INVENTORY_MATCH.candidate({id:'asset',technology:'WordPress',version:'5.0'},merged.find(r=>r.id===stale.id)),null,'a product correction suppresses stale public-snapshot findings');
 assert.equal(client.merge([stale]).length,2,'a product-specific correction does not erase the whole global CVE record');
 componentProducts=[{id:'h',name:'HyperV',component_scope:'windows_hyperv',status:'needs_identity'}];
 await client.refresh();
 const broad={id:'CVE-2026-77777',categories:['HyperV','Linux'],title:'Linux Hyper-V guest driver advisory'};
 let scoped=client.merge([broad]).find(r=>r.id===broad.id);
 assert.deepEqual([...scoped.categories],['Linux'],'the shared index cannot supply an unverified Windows host match');
 assert.equal(w.CVEHARBOR_INVENTORY_MATCH.candidate({id:'h',technology:'HyperV',version:'10.0'},scoped),null);
 extraRecords=[{...broad,categories:['HyperV'],cvie_products:['HyperV'],source_type:'cvie_combined',title:'Windows Hyper-V verified source fixture'}];
 await client.refresh();scoped=client.merge([broad]).find(r=>r.id===broad.id);
 assert.ok(scoped.categories.includes('HyperV'),'verified host-scoped evidence restores its category');
 console.log('PASS CVIE client: late responses, logout, account changes, failed pagination, cyclic cursors and product-specific public-snapshot corrections.');
}finally{dom.window.close();}
