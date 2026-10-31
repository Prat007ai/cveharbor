import test from 'node:test';
import assert from 'node:assert/strict';
import {lookupWebsiteThreat,assessHttpHeaders} from '../src/website-threat.js';
test('unconfigured threat intelligence is never called clean',async()=>{
 const result=await lookupWebsiteThreat('https://example.com/',{},()=>{throw Error('should not fetch')});
 assert.equal(result.status,'not_configured');
});
test('Web Risk lookup maps confirmed listings and absence separately',async()=>{
 const db={count:0,prepare(sql){return {bind:()=>({run:async()=>{if(sql.includes('SET reserved=reserved+1'))db.count++;return {meta:{changes:1}}},first:async()=>({reserved:db.count})})}}};
 const seen=[];
 const fetcher=async url=>{seen.push(url);return new Response(JSON.stringify({threat:{threatTypes:['MALWARE'],expireTime:'2026-11-01T00:00:00Z'}}),{status:200})};
 const result=await lookupWebsiteThreat('https://example.com/',{GOOGLE_WEB_RISK_API_KEY:'test-key',DB:db},fetcher);
 assert.equal(result.status,'listed');assert.deepEqual(result.threats,['MALWARE']);
 assert.ok(seen[0].includes('threatTypes=MALWARE'));
 const empty=await lookupWebsiteThreat('https://example.com/',{GOOGLE_WEB_RISK_API_KEY:'test-key',DB:db},async()=>new Response('{}',{status:200}));
 assert.equal(empty.status,'no_known_listing');
});
test('missing headers are informational not a malware verdict',()=>{
 const findings=assessHttpHeaders({},200);
 assert.ok(findings.some(x=>x.id==='hsts'));
 assert.ok(findings.every(x=>x.severity==='informational'));
});
