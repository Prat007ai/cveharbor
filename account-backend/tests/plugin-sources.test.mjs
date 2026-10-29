import test from 'node:test';
import assert from 'node:assert/strict';
import {wordpressSlug,safeSourceUrl,sourceRoute} from '../src/plugin-sources.js';

test('only exact official WordPress.org plugin paths yield trusted slugs',()=>{
 assert.equal(wordpressSlug('https://wordpress.org/plugins/autoptimize/'),'autoptimize');
 assert.equal(wordpressSlug('https://wordpress.org/plugins/wordpress-seo/'),'wordpress-seo');
 assert.equal(wordpressSlug('https://attacker.example/plugins/autoptimize/'),'');
 assert.equal(wordpressSlug('https://wordpress.org.evil.example/plugins/autoptimize/'),'');
 assert.equal(wordpressSlug('https://wordpress.org/plugins/../../private'),'');
});
test('rejects unsafe URL strings before persistence',()=>{
 for(const value of ['http://example.org/','https://127.0.0.1/internal','https://localhost/','https://user:password@example.com/','https://192.168.1.1/','not a URL'])
  assert.throws(()=>safeSourceUrl(value));
 assert.equal(safeSourceUrl('https://vendor.example/releases'),'https://vendor.example/releases');
 assert.equal(safeSourceUrl(''),'');
});
test('source endpoint requires existing owned plugin before writing',async()=>{
 const asset='11111111-1111-4111-8111-111111111111';
 const env={DB:{prepare(sql){
  if(sql.includes('LIMIT 1'))return {first:async()=>null};
  if(sql.includes('SELECT id,technology FROM inventory_assets'))return {bind(){return {first:async()=>null}}};
  throw Error('Unexpected query');
 }}};
 const request={method:'PUT'};
 const result=await sourceRoute(request,env,{id:'user1'},'/v1/plugin-sources/'+asset,{vendor_url:'https://wordpress.org/plugins/autoptimize/'});
 assert.equal(result.status,404);
});
