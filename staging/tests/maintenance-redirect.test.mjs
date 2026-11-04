import test from 'node:test';
import assert from 'node:assert/strict';
import {probeMaintenanceAccess} from '../scripts/probe-access.mjs';
import {TARGET} from '../target.mjs';
const issuer='https://synthetic.cloudflareaccess.com';
const hostname=new URL(TARGET.origin).hostname;
const env={CF_STAGING_PROVISION_ACTION:'migrate',CF_STAGING_ACCESS_ISSUER:issuer,CF_STAGING_ACCESS_AUD:'a'.repeat(64),CF_STAGING_ACCESS_CLIENT_ID:'private-service-id',CF_STAGING_ACCESS_CLIENT_SECRET:'private-service-secret'};
async function probe(location,status=302,{backend=404,service=403}={}){
 const calls=[];
 const report=await probeMaintenanceAccess(env,async(url,init)=>{
  calls.push(url);assert.equal(init.method,'GET');assert.equal(init.redirect,'manual');
  assert.ok(url.startsWith(TARGET.origin+'/')||url==='https://cveharbor-accounts-staging.cveharbor-staging.workers.dev/v1/me');
  const code=url.includes('accounts-staging')?backend:init.headers['CF-Access-Client-Id']?service:status;
  return new Response(null,{status:code,headers:location===undefined?{}:{Location:location}});
 });
 assert.equal(calls.length,22);assert.doesNotMatch(JSON.stringify(report),/private-service|private-query|private-user|Location|cloudflareaccess/);
 return report;
}
test('only exact configured Access login endpoints verify browser denials; redirects are never followed',async()=>{
 for(const path of ['/cdn-cgi/access/login','/cdn-cgi/access/login/'+hostname]){
  const r=await probe(issuer+path+'?kid=private-query&redirect_url=%2Fworkspace%2F');
  assert.equal(r.passed,true);assert.equal(r.checks.filter(c=>c.login_redirect_verified).length,14);
  assert.ok(r.checks.filter(c=>c.name.startsWith('service_token:')).every(c=>c.status===403&&!c.login_redirect_verified));
 }
});
test('wrong origin, lookalike endpoints, credentials, relative/malformed URLs and missing Location remain failures',async()=>{
 for(const location of [undefined,'not-a-url','/cdn-cgi/access/login','//synthetic.cloudflareaccess.com/cdn-cgi/access/login',
  'https://evil.example/cdn-cgi/access/login','https://synthetic.cloudflareaccess.com.evil.example/cdn-cgi/access/login',
  'http://synthetic.cloudflareaccess.com/cdn-cgi/access/login',issuer+':8443/cdn-cgi/access/login',
  issuer+'/cdn-cgi/access/login-evil',issuer+'/cdn-cgi/access/login/other.example',issuer+'/cdn-cgi/access/login/'+hostname+'/extra',
  issuer+'/cdn-cgi/access/login%2F'+hostname,issuer+'/cdn-cgi/access/login#fragment',
  'https://private-user:private-query@synthetic.cloudflareaccess.com/cdn-cgi/access/login',
  'https://synthetic.cloudflareaccess.com@evil.example/cdn-cgi/access/login']){
   const r=await probe(location);assert.equal(r.passed,false,location);assert.ok(r.checks.filter(c=>c.status===302).every(c=>!c.login_redirect_verified&&!c.passed));
 }
});
test('successful responses and other redirect statuses cannot qualify as maintenance denial',async()=>{
 for(const status of [200,204,301,303,307,308,401,500])assert.equal((await probe(issuer+'/cdn-cgi/access/login',status)).passed,false);
 assert.equal((await probe(undefined,403)).passed,true);
});
test('service tokens still require 403 and backend still requires 404, even for trusted login redirects',async()=>{
 const login=issuer+'/cdn-cgi/access/login/'+hostname;
 for(const service of [200,302,401])assert.equal((await probe(login,302,{service})).passed,false);
 for(const backend of [200,302,403])assert.equal((await probe(login,302,{backend})).passed,false);
});
test('issuer and audience must be configured before any maintenance request',async()=>{
 for(const patch of [{CF_STAGING_ACCESS_ISSUER:'https://evil.example'},{CF_STAGING_ACCESS_AUD:''}])
  await assert.rejects(probeMaintenanceAccess({...env,...patch},()=>assert.fail('No network before valid configuration')));
});
