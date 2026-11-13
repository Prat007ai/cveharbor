import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const context=vm.createContext({URL,setTimeout});context.window=context;
for(const file of ['inventory-matching.js','inventory-assessment.js'])vm.runInContext(fs.readFileSync(new URL('../'+file,import.meta.url),'utf8'),context);
const engine=context.CVEHARBOR_INVENTORY_MATCH;
const records=Array.from({length:41},(_,i)=>({id:'CVE-2026-'+(10000+i%37),categories:[i%2?'PHP':'MySQL'],affected:i%2?'PHP before 8.4.2':'MySQL before 8.4.2',severity:['critical','high','medium','low','unknown'][i%5],known_exploited:i%7===0,sources:[{url:'https://example.test/'+i}]}));
const assets=Array.from({length:90},(_,i)=>({id:'a'+i,name:'HOST-'+i,environment_id:'e'+i%3,technology:i%3?'PHP':'MySQL',version:i%5?'8.4.1':'8.4.3'}));
assets.push({...assets[1]},{...assets[0],technology:'PHP',version:'8.4.1'});
function fullResult(rows,advisories){
 const items=[],seen=new Set(),rank={critical:4,high:3,medium:2,low:1};
 for(const asset of rows)for(const record of advisories){const finding=engine.candidate(asset,record);if(!finding)continue;const key=asset.id+'|'+finding.id;if(seen.has(key))continue;seen.add(key);items.push(finding);}
 items.sort((a,b)=>Number(b.known_exploited)-Number(a.known_exploited)||(rank[b.severity]||0)-(rank[a.severity]||0)||a.id.localeCompare(b.id));return items;
}
const plain=value=>JSON.parse(JSON.stringify(value));
test('bounded report ranking preserves every count, tie, deduplication and limit',()=>{
 const all=fullResult(assets,records);
 for(const limit of [0,1,17,150,5000,-1,1.5,Infinity]){
  const result=engine.evaluate(assets,records,limit);
  assert.deepEqual(plain(result.items),plain(all.slice(0,limit)));
  assert.equal(result.total,all.length);assert.equal(result.limited,all.length>limit);
 }
 const changed=records.map(r=>({...r,known_exploited:!r.known_exploited}));
 assert.deepEqual(plain(engine.evaluate(assets,changed,50).items),plain(fullResult(assets,changed).slice(0,50)));
});
test('large repeated products retain exact totals without materializing all pairs',async()=>{
 const many=Array.from({length:10000},(_,i)=>({...assets[1],id:'large'+i}));
 const perAsset=fullResult([many[0]],records).length;
 const result=await engine.evaluateAsync(many,records,150);
 assert.equal(result.total,10000*perAsset);assert.equal(result.items.length,150);assert.equal(result.limited,true);
 let cancel=false;setTimeout(()=>{cancel=true;},0);
 await assert.rejects(engine.evaluateAsync(many,records,5000,{cancelled:()=>cancel}),{name:'AbortError'});
 assert.deepEqual(plain((await engine.evaluateAsync(assets,records,25)).items),plain(fullResult(assets,records).slice(0,25)));
});
test('repeated versions reuse current matches after the retained cache fills',()=>{
 const rows=Array.from({length:250},(_,i)=>({...records[1],id:'CVE-2026-'+(20000+i)}));
 const hosts=Array.from({length:120},(_,i)=>({id:'repeat'+i,technology:'PHP',version:'8.1.'+(i%60)}));
 const candidate=engine.candidate;let calls=0;
 engine.candidate=(...args)=>{calls++;return candidate(...args);};
 try{
  const result=engine.evaluate(hosts,rows,150);
  assert.equal(result.total,30000);assert.equal(result.items.length,150);
  assert.equal(calls,60*250,'Each unique version is assessed once even beyond the 10,000-finding retained cache');
 }finally{engine.candidate=candidate;}
});
