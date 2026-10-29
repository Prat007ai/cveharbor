import test from 'node:test';
import assert from 'node:assert/strict';
import {slugOf,scanDue,monitorRoute} from '../src/plugin-monitor.js';

test('known WordPress plugin names resolve to canonical slugs',()=>{
 assert.equal(slugOf('WordPress Plugin: Yoast SEO'),'wordpress-seo');
 assert.equal(slugOf('WordPress Plugin: WP File Manager'),'wp-file-manager');
 assert.equal(slugOf('WordPress Plugin: Broadcast'),'broadcast');
});
test('pending migration is explicitly reported and never assumed checked',async()=>{
 const env={DB:{prepare(){return {async first(){throw Error('table missing')}}}}};
 const list=await monitorRoute({method:'GET'},env,{id:'account'},'/v1/plugin-monitor');
 assert.deepEqual(await list.json(),{ready:false,checks:[],message:'Plugin monitor D1 migration is required'});
 assert.deepEqual(await scanDue(env),{processed:0,ready:false});
});
test('monitor rejects missing identifiers before modifying inventory',async()=>{
 const env={DB:{prepare(sql){
  if(sql.includes('LIMIT 1'))return {async first(){return null}};
  throw Error('unexpected statement');
 }}};
 const res=await monitorRoute({method:'POST'},env,{id:'account'},'/v1/plugin-monitor/refresh',{asset_id:'invalid'});
 assert.equal(res.status,400);
});
