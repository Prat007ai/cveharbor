// Deterministic browser clock: verify freshness and request reduction without
// customer data, real timers or external services.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {JSDOM} from 'jsdom';
const dom=new JSDOM('<div id="cvieExplorer"></div>',{url:'https://cveharbor.com/vulnerabilities/',runScripts:'outside-only',pretendToBeVisual:true});
const w=dom.window;w.AbortSignal=globalThis.AbortSignal;let now=Date.now(),visibility='visible',owner='a',lastSuccess=1,summary='Initial source text',unauthorized=false;
const timers=new Map();let sequence=0;
w.Date.now=()=>now;Object.defineProperty(w.document,'visibilityState',{get:()=>visibility});
w.setTimeout=(fn,delay)=>{const id=++sequence;timers.set(id,{fn,delay});return id;};w.clearTimeout=id=>timers.delete(id);
const calls={sync:0,state:0,progress:0,advisories:0};
const product=()=>({id:owner,name:'Apache Tomcat',vendor:'apache',cpe:'cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*',status:'scanning',last_success_at:lastSuccess,progress:{windows_complete:1,windows_total:10}});
const evidence={sources:[{id:'nvd',status:'scanning'},{id:'cve_program',status:'current'},{id:'cisa_kev',status:'current'}]};
w.fetch=async url=>{
 const path=new URL(url).pathname;
 if(unauthorized)return Response.json({error:'Sign in'},{status:401});
 if(path.endsWith('/sync')){calls.sync++;return Response.json({ready:true,status:'unchanged'});}
 if(path==='/v1/cvie'){calls.state++;return Response.json({ready:true,account_id:owner,products:[{...product(),recent_count:1,history_count:1}],evidence});}
 if(path.endsWith('/progress')){calls.progress++;return Response.json({ready:true,account_id:owner,products:[product()],evidence});}
 if(path.endsWith('/advisories')){calls.advisories++;return Response.json({account_id:owner,advisories:[{id:'CVE-2026-'+(owner==='a'?'12345':'54321'),summary,categories:['Apache Tomcat']}],next:null});}
 throw Error('Unexpected request '+path);
};
const until=async fn=>{const end=Date.now()+2000;while(!fn()){if(Date.now()>end)throw Error('Client did not settle');await new Promise(r=>setTimeout(r,1));}};
let client;
async function tick(){const entry=[...timers.entries()].find(([,value])=>value.delay===30000||value.delay===60000);assert.ok(entry,'visible page schedules a bounded poll');timers.delete(entry[0]);now+=entry[1].delay;entry[1].fn();await until(()=>!client.loading);}
try{
 w.eval(fs.readFileSync('cvie.js','utf8'));client=w.CVEHARBOR_CVIE;await until(()=>client.ready&&!client.loading);
 assert.equal(calls.state,1);assert.equal(calls.advisories,1);
 await tick();assert.equal(calls.progress,1);assert.equal(calls.state,1);assert.equal(calls.advisories,1,'unchanged progress does not reload results');
 summary='Corrected original source text';await tick();
 assert.equal(calls.advisories,2);assert.equal(client.records[0].summary,summary,'CNA-only changes are checked within the sixty-second result interval');
 assert.equal(calls.progress,1,'a full refresh that is already due skips the redundant progress request');
 lastSuccess++;await tick();assert.equal(calls.advisories,3,'a saved scan page refreshes results at the next progress poll');
 const queued=[...timers.values()][0];visibility='hidden';w.document.dispatchEvent(new w.Event('visibilitychange'));
 assert.equal(timers.size,0);const before=JSON.stringify(calls);queued.fn();await Promise.resolve();assert.equal(JSON.stringify(calls),before,'a hidden-tab race does not issue another request');
 visibility='visible';w.document.dispatchEvent(new w.Event('visibilitychange'));await until(()=>!client.loading);assert.equal(calls.progress,3);
 owner='b';await tick();assert.equal(client.records.length,1);assert.equal(client.records[0].id,'CVE-2026-54321','progress responses cannot retain another account cache');
 unauthorized=true;await tick();assert.equal(client.signedIn,false);assert.equal(client.records.length,0);assert.equal(timers.size,0,'revoked sessions stop all polling');
 assert.equal(w.localStorage.length,0);assert.equal(w.sessionStorage.length,0,'private findings are never persisted in browser storage');
 console.log('PASS CVIE polling: lightweight reads, sixty-second result freshness, advancing scans, hidden tabs, account changes and revoked sessions.');
}finally{dom.window.close();}
