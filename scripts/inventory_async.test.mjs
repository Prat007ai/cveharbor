import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
function engine(){const c=vm.createContext({setTimeout,clearTimeout});c.window=c;for(const file of ['inventory-matching.js','inventory-assessment.js'])vm.runInContext(fs.readFileSync(new URL('../'+file,import.meta.url),'utf8'),c);return c.CVEHARBOR_INVENTORY_MATCH;}
const records=Array.from({length:1500},(_,i)=>({id:'CVE-2026-'+(100000+i),categories:['PHP'],affected:'PHP before 8.4.2',severity:i%2?'high':'critical',known_exploited:i%7===0}));
const assets=Array.from({length:25},(_,i)=>({id:'a'+i,environment_id:'e',name:'HOST'+i,technology:'PHP',version:'8.4.'+(i%4)}));
test('cooperative and synchronous assessments preserve findings, ordering, counts and limits',async()=>{
 const expected=engine().evaluate(assets,records,250),actual=await engine().evaluateAsync(assets,records,250);
 assert.deepEqual(JSON.parse(JSON.stringify(actual)),JSON.parse(JSON.stringify(expected)));
 assert.equal(actual.limited,true);
});
test('cooperative assessment yields and cancels without publishing stale results',async()=>{
 const e=engine();let cancelled=false,heartbeat=0;
 const timer=setInterval(()=>heartbeat++,1);
 try{
  const pending=e.evaluateAsync(assets,records,250,{cancelled:()=>cancelled});
  setTimeout(()=>{cancelled=true;},5);
  await assert.rejects(pending,{name:'AbortError'});assert.ok(heartbeat>0);
  const replacement=await e.evaluateAsync([{id:'safe',technology:'PHP',version:'8.4.9'}],records,250);
  assert.equal(replacement.total,0);
 }finally{clearInterval(timer);}
});
test('Windows host inference and account-independent asset IDs remain identical',async()=>{
 const rows=[{id:'CVE-2026-99999',categories:['.NET Runtime'],cvie_products:['.NET Runtime'],cna_affected:[{vendor:'Microsoft',product:'.NET 8.0',platforms:['Windows'],versions:[{status:'affected',version:'8.0.0',lessThan:'8.0.33',versionType:'custom'}]}]}];
 const input=[{id:'os',environment_id:'a',name:'WEB',technology:'Windows Server',version:'2022'},{id:'runtime',environment_id:'a',name:'WEB',technology:'.NET Runtime',version:'8.0.1'},{id:'other',environment_id:'b',name:'WEB',technology:'.NET Runtime',version:'8.0.1'}];
 assert.deepEqual(JSON.parse(JSON.stringify(await engine().evaluateAsync(input,rows))),JSON.parse(JSON.stringify(engine().evaluate(input,rows))));
});
