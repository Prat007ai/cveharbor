import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const original=fs.readFileSync('account-page.js','utf8');
const staging=fs.readFileSync('staging/.build/public/account-page.js','utf8');
async function boot(source,status,payload,{network=false}={}){
 const nodes=new Map(),events=[];let requests=0;
 const node=id=>{if(!nodes.has(id))nodes.set(id,{hidden:false,textContent:'',value:'',innerHTML:'',addEventListener(){},focus(){}});return nodes.get(id);};
 const document={getElementById:node,body:{classList:{contains:name=>name==='workspace-redesign',add(){},remove(){}}}};
 vm.runInNewContext(source,{document,location:{search:''},URLSearchParams,CustomEvent:class{constructor(type,options){this.type=type;this.detail=options.detail;}},window:{dispatchEvent:e=>events.push(e)},fetch:async(url,init)=>{requests++;assert.ok(url.endsWith('/v1/me'));assert.equal(init.method,'GET');assert.equal(init.credentials,'include');if(network)throw Error('offline');return Response.json(payload,{status});},QRCode:undefined});
 await new Promise(setImmediate);
 return {node,events,requests};
}
test('pinned account page reproduces the false outage on an unauthenticated 401',async()=>{
 const r=await boot(original,401,{authenticated:false});assert.match(r.node('accountPageMessage').textContent,/Account service unavailable/);
});
test('staging-only account page treats every initial 401 as signed out without an outage',async()=>{
 for(const payload of [{authenticated:false},{error:'Sign in required'},{}]){
  const r=await boot(staging,401,payload);assert.equal(r.node('accountPageSignedOut').hidden,false);assert.equal(r.node('accountPageSignedIn').hidden,true);assert.equal(r.node('accountPageMessage').textContent,'');assert.equal(r.events.at(-1).detail.authenticated,false);assert.equal(r.requests,1);
 }
 assert.equal(fs.readFileSync('account-page.js','utf8'),original);
});
test('authenticated users still sign in; server failures and network errors still report unavailability',async()=>{
 const yes=await boot(staging,200,{authenticated:true,email:'synthetic@example.invalid'});assert.equal(yes.node('accountPageSignedIn').hidden,false);assert.equal(yes.events.at(-1).detail.authenticated,true);
 for(const [status,payload,options] of [[503,{},{}],[403,{},{}],[200,{}, {network:true}]]){
  const r=await boot(staging,status,payload,options);assert.match(r.node('accountPageMessage').textContent,/Account service unavailable/);assert.equal(r.node('accountPageSignedOut').hidden,false);
 }
});
