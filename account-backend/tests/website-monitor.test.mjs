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

test('single HEAD request captures an HTTP response without following redirects',async()=>{
 const queries=[];
 const db={prepare(sql){return {bind(...params){return {
  async first(){return null},
  async run(){queries.push({sql,params});return {meta:{changes:1}}}
 }}}}};
 const {checkSite}=await import('../src/website-monitor.js');
 const calls=[];
 const fetcher=async(url,options)=>{calls.push({url,options});return new Response(null,{status:302,headers:{location:'https://example.net/other','strict-transport-security':'max-age=31536000'}})};
 const result=await checkSite({DB:db},{id:'site-1',user_id:'owner-1',url:'https://example.com/'},fetcher);
 assert.equal(result.http_status,302);
 assert.equal(result.security_headers.location,'https://example.net/other');
 assert.equal(calls.length,1);
 assert.equal(calls[0].options.method,'HEAD');
 assert.equal(calls[0].options.redirect,'manual');
 assert.ok(queries.some(x=>x.sql.includes('INSERT INTO website_monitor_checks')));
});
