import assert from 'node:assert/strict';
const origin='https://confirm.cveharbor.com',legacy='https://api.cveharbor.com';
// The all-zero token is synthetic. Never use a real recipient's link in release checks.
export async function verifyConfirmationDomain(fetcher=fetch){
 const read=(url,options={})=>fetcher(url,{redirect:'error',signal:AbortSignal.timeout(20000),...options});
 for(const host of [origin,legacy]){
  const url=host+(host===origin?'/acknowledge/':'/v1/acknowledge/')+'0'.repeat(64);
  const result=await read(url);
  assert.equal(result.status,404,'Synthetic invalid link must return 404 on '+host);
  assert.match(result.headers.get('content-type')||'',/text\/html/);
  assert.match(result.headers.get('cache-control')||'',/no-store/);
  assert.equal(result.headers.get('referrer-policy'),'no-referrer');
  assert.match(result.headers.get('content-security-policy')||'',/frame-ancestors 'none'/);
  assert.match(result.headers.get('x-robots-tag')||'',/noindex/);
  assert.match(await result.text(),/CVEHarbor/);
  const post=await read(url,{method:'POST',headers:{Origin:'https://invalid.example','Content-Type':'application/x-www-form-urlencoded'},body:'confirm=receipt'});
  assert.equal(post.status,403,'Cross-origin confirmation must be rejected');
 }
 for(const path of ['/','/v1/me','/v1/remediations','/v1/remediations/CVE-2000-0000/status-history']){
  const result=await read(origin+path,{headers:{Origin:'https://cveharbor.com'}});
  assert.equal(result.status,404,'Private API must not be served on confirmation host');
  assert.equal(result.headers.get('access-control-allow-origin'),null);
  assert.match(result.headers.get('cache-control')||'',/no-store/);
 }
 for(const method of ['POST','OPTIONS'])assert.equal((await read(origin+'/v1/remediations',{method,headers:{Origin:'https://cveharbor.com'}})).status,404);
 assert.equal((await read(legacy+'/v1/remediations')).status,401);
 return {https_ready:true,guest_routes_ready:true,legacy_links_preserved:true,private_routes_isolated:true};
}
export async function verifyConfirmationSetting(account,token,fetcher=fetch){
 assert.ok(account&&token,'Cloudflare deployment credentials required');
 const result=await fetcher(`https://api.cloudflare.com/client/v4/accounts/${account}/workers/scripts/cveharbor-accounts/settings`,{headers:{Authorization:'Bearer '+token},redirect:'error',signal:AbortSignal.timeout(20000)});
 assert.ok(result.ok,'Unable to verify Worker settings');const data=await result.json();assert.equal(data.success,true);
 const binding=data.result?.bindings?.find(x=>x.name==='ASSIGNMENT_CONFIRM_ORIGIN');
 assert.ok(binding?.type==='plain_text'&&binding.text===origin,'Confirmation email origin not active');
 // Do not print or persist the settings response; it includes unrelated binding metadata.
 return {email_confirmation_origin:origin};
}
if(process.argv[1]&&new URL(import.meta.url).pathname===process.argv[1]){
 const result=await verifyConfirmationDomain();
 if(process.argv.includes('--runtime'))Object.assign(result,await verifyConfirmationSetting(process.env.CLOUDFLARE_ACCOUNT_ID,process.env.CLOUDFLARE_API_TOKEN));
 console.log(JSON.stringify(result));
}
