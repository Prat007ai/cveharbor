import test from 'node:test';
import assert from 'node:assert/strict';
import {probeAccess} from '../scripts/probe-access.mjs';
import {TARGET,LEGACY_ORIGIN} from '../target.mjs';
const issuer='https://synthetic.cloudflareaccess.com',env={CF_STAGING_ACCESS_ISSUER:issuer,CF_STAGING_ACCESS_AUD:'a'.repeat(64),CF_STAGING_ACCESS_CLIENT_ID:'private-client',CF_STAGING_ACCESS_CLIENT_SECRET:'private-secret'};
const headers={'X-Robots-Tag':'noindex, nofollow, noarchive','Cache-Control':'private, no-store'};
function transport({anonymous=302,location=issuer+'/cdn-cgi/access/login/'+new URL(LEGACY_ORIGIN).hostname+'?private=secret',service=403,guard=true,body='Unknown staging host',customOpen=false}={}){
 return async(url,init)=>{
  assert.equal(init.method,'GET');assert.equal(init.redirect,'manual');const u=new URL(url),auth=!!init.headers['CF-Access-Client-Id'];
  if(u.origin===LEGACY_ORIGIN)return auth?new Response(body,{status:service,headers:guard?headers:{}}):new Response('',{status:anonymous,headers:anonymous>=300&&anonymous<400?{Location:location}:{}});
  if(u.origin!==TARGET.origin)return new Response('',{status:404});
  if(!auth)return new Response('',{status:customOpen?200:403});
  if(init.headers.Origin)return new Response('Forbidden origin',{status:403,headers});
  if(u.pathname==='/v1/me')return Response.json({authenticated:false},{status:401,headers});
  const type=u.pathname.endsWith('.css')?'text/css':u.pathname.endsWith('.js')?'text/javascript':u.pathname.endsWith('.svg')?'image/svg+xml':'text/html';
  return new Response('CVEHarbor',{headers:{...headers,'Content-Type':type}});
 };
}
test('anonymous legacy Access login redirects pass while authenticated legacy routes must be Worker-denied',async()=>{
 for(const anonymous of [401,403,302,303,307,308]){
  const result=await probeAccess(env,transport({anonymous}));assert.equal(result.passed,true);assert.equal(result.requests,38);
  const checks=result.checks.filter(c=>c.name==='legacy_application_disabled');assert.equal(checks.length,10);assert.equal(checks.filter(c=>c.login_redirect_verified).length,anonymous>=300&&anonymous<400?5:0);
  assert.doesNotMatch(JSON.stringify(result),/private-client|private-secret|private=secret/);
 }
});
test('wrong issuer/path, successful legacy pages and service denials without Worker proof fail closed',async()=>{
 for(const patch of [{location:'https://evil.invalid/cdn-cgi/access/login'},{location:issuer+'/cdn-cgi/access/login-not-a-login'}, {location:issuer+'/cdn-cgi/access/login/'+new URL(TARGET.origin).hostname}, {anonymous:200},{service:200},{service:302},{guard:false},{body:'Cloudflare Access authentication required'},{customOpen:true}]){
  const report=await probeAccess(env,transport(patch));assert.equal(report.passed,false,JSON.stringify(patch));
 }
});
