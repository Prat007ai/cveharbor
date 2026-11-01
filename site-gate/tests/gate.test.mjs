import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import gate from '../worker.mjs';

const password='fixture-only-strong-password';
const basic=(username='cveharbor',value=password)=>'Basic '+Buffer.from(username+':'+value).toString('base64');
function environment(extra={}){
  let calls=0,received;
  const env={SITE_GATE_ENABLED:'true',SITE_GATE_USERNAME:'cveharbor',SITE_GATE_PASSWORD:password,
    ASSETS:{fetch:async request=>{calls++;received=request;return new Response('private asset',{headers:{'Cache-Control':'public, max-age=3600'}})}},...extra};
  return {env,calls:()=>calls,request:()=>received};
}

test('all pages, scripts, data, downloads and unknown paths require credentials',async()=>{
  for(const path of ['/','/account/','/workspace/','/styles.css','/app.js','/threat-data.js','/attack-scanning-current.txt','/attack-scanning-current.csv','/robots.txt','/unknown']){
    const state=environment(),response=await gate.fetch(new Request('https://cveharbor.com'+path),state.env);
    assert.equal(response.status,401,path);assert.equal(state.calls(),0);
    assert.match(response.headers.get('WWW-Authenticate'),/^Basic realm="CVEHarbor development"/);
    assert.match(response.headers.get('Cache-Control'),/no-store/);
    assert.match(response.headers.get('X-Robots-Tag'),/noindex/);
    assert.doesNotMatch(await response.text(),/private asset/);
  }
});

test('correct credentials serve the requested asset and preserve query, cookies and response headers',async()=>{
  const state=environment();
  const response=await gate.fetch(new Request('https://cveharbor.com/threat-data.js?v=release',{headers:{Authorization:basic(),Cookie:'test-cookie=preserved'}}),state.env);
  assert.equal(response.status,200);assert.equal(await response.text(),'private asset');assert.equal(state.calls(),1);
  assert.equal(state.request().url,'https://cveharbor.com/threat-data.js?v=release');
  assert.equal(state.request().headers.get('Authorization'),null);
  assert.equal(state.request().headers.get('Cookie'),'test-cookie=preserved');
  assert.match(response.headers.get('Cache-Control'),/private, no-store/);
});

test('incorrect, malformed and other authentication schemes cannot reach assets',async()=>{
  for(const header of [basic('wrong'),basic('cveharbor','incorrect'),basic('cveharbor',''),basic('CVEHarbor'), 'Bearer app-token','Basic !!!','Basic '+Buffer.from(':password').toString('base64'),'Basic '+Buffer.from([255,254,58]).toString('base64'),'Basic '+'A'.repeat(5000)]){
    const state=environment();const response=await gate.fetch(new Request('https://cveharbor.com/',{headers:{Authorization:header}}),state.env);
    assert.equal(response.status,401);assert.equal(state.calls(),0);
  }
});

test('passwords containing colons and Unicode are compared in full',async()=>{
  const value='fixture-only:Unicode-秘密-password',state=environment({SITE_GATE_PASSWORD:value});
  const response=await gate.fetch(new Request('https://cveharbor.com/',{headers:{Authorization:basic('cveharbor',value)}}),state.env);
  assert.equal(response.status,200);
});

test('missing or weak configuration fails closed rather than publishing assets',async()=>{
  for(const extra of [{SITE_GATE_PASSWORD:undefined},{SITE_GATE_PASSWORD:'short'},{SITE_GATE_USERNAME:''},{ASSETS:undefined}]){
    const state=environment(extra),response=await gate.fetch(new Request('https://cveharbor.com/',{headers:{Authorization:basic()}}),state.env);
    assert.equal(response.status,503);assert.equal(state.calls(),0);
  }
});

test('HEAD cannot disclose assets without authentication and returns no body',async()=>{
  const state=environment(),response=await gate.fetch(new Request('https://cveharbor.com/attack-scanning-current.txt',{method:'HEAD'}),state.env);
  assert.equal(response.status,401);assert.equal(await response.text(),'');assert.equal(state.calls(),0);
});

test('POST cannot bypass the gate and authorized requests preserve method and body',async()=>{
  const denied=environment(),blocked=await gate.fetch(new Request('https://cveharbor.com/account/',{method:'POST',body:'data'}),denied.env);
  assert.equal(blocked.status,401);assert.equal(denied.calls(),0);
  const allowed=environment();await gate.fetch(new Request('https://cveharbor.com/account/',{method:'POST',body:'data',headers:{Authorization:basic()}}),allowed.env);
  assert.equal(allowed.request().method,'POST');assert.equal(await allowed.request().text(),'data');
});

test('www canonicalizes to the protected apex without serving content',async()=>{
  const state=environment(),response=await gate.fetch(new Request('https://www.cveharbor.com/threats/?source=test'),state.env);
  assert.equal(response.status,301);assert.equal(response.headers.get('Location'),'https://cveharbor.com/threats/?source=test');assert.equal(state.calls(),0);
});

test('HTTP redirects to HTTPS before requesting a password',async()=>{
  const state=environment(),response=await gate.fetch(new Request('http://cveharbor.com/account/?mode=login'),state.env);
  assert.equal(response.status,301);assert.equal(response.headers.get('Location'),'https://cveharbor.com/account/?mode=login');
  assert.equal(response.headers.get('WWW-Authenticate'),null);assert.equal(state.calls(),0);
});

test('only explicit false disables the temporary gate',async()=>{
  for(const value of [undefined,'',false,'FALSE']){
    const state=environment({SITE_GATE_ENABLED:value});assert.equal((await gate.fetch(new Request('https://cveharbor.com/'),state.env)).status,401);
  }
  const state=environment({SITE_GATE_ENABLED:'false',SITE_GATE_PASSWORD:undefined});
  const response=await gate.fetch(new Request('https://cveharbor.com/'),state.env);
  assert.equal(response.status,200);assert.equal(response.headers.get('X-Robots-Tag'),null);
});

test('asset routing cannot bypass authentication and API/customer database routes are untouched',()=>{
  const config=JSON.parse(fs.readFileSync(new URL('../wrangler.json',import.meta.url)));
  assert.equal(config.assets.run_worker_first,true);assert.equal(config.workers_dev,false);assert.equal(config.preview_urls,false);
  assert.ok(['true','false'].includes(config.vars.SITE_GATE_ENABLED));assert.equal(config.vars.SITE_GATE_PASSWORD,undefined);
  assert.deepEqual(config.routes.map(route=>route.pattern),['cveharbor.com/*','www.cveharbor.com/*']);
  assert.equal(config.d1_databases,undefined);
});
