import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeWebsite,scanDue} from '../src/website-monitor.js';
test('website origin requires HTTPS and a public DNS hostname',()=>{
 assert.equal(normalizeWebsite('https://Example.com/'),'https://example.com/');
 for(const url of ['http://example.com/','https://localhost/','https://127.0.0.1/','https://site.local/','https://example.com:8443/','https://example.com/private','https://user:pass@example.com/','https://example.com/?token=x'])assert.throws(()=>normalizeWebsite(url));
});
test('scheduled checks are disabled until explicitly enabled',async()=>{
 const result=await scanDue({WEBSITE_MONITOR_ENABLED:'false'},()=>{throw Error('Network should not run')});
 assert.deepEqual(result,{checked:0});
});
