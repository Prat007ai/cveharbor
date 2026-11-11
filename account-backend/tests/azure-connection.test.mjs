import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import {azureConnectionProbe, probePath, probeMessage} from '../src/azure-connection.js';
import {recoveryProtected} from '../src/recovery-control.js';

const now = 1794360000000, seconds = now / 1000, release = 'a'.repeat(64), key = 'b'.repeat(64);
const config = {
  CVEHARBOR_AZURE_OPENAI_ENDPOINT: 'https://cvie-prod.openai.azure.com/',
  CVEHARBOR_AZURE_OPENAI_DEPLOYMENT: 'gpt-5.4-mini',
  CVEHARBOR_AZURE_OPENAI_TENANT_ID: 'f95d3766-898f-4e4d-a0ad-9b5efa394592',
  CVEHARBOR_AZURE_OPENAI_CLIENT_ID: 'dec0de99-1e60-461f-bfb2-aa518b40036a',
  CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET: 'fictional-secret',
};
const proof = (changes={}) => ({key, release, created: seconds-10, expires: seconds+890, ...changes});
const env = (changes={}) => ({...config, CVEHARBOR_AZURE_CONNECTION_PROBE: JSON.stringify(proof()), ...changes});
function request({stamp=String(seconds), nonce='c'.repeat(64), signingKey=key, method='POST', suffix='', host='api.cveharbor.com', body}={}) {
  const signature = createHmac('sha256', Buffer.from(signingKey,'hex')).update(probeMessage(stamp,nonce,release)).digest('hex');
  return new Request('https://'+host+probePath+suffix,{method,body,headers:{'X-CVH-Timestamp':stamp,'X-CVH-Nonce':nonce,'X-CVH-Signature':signature}});
}
test('deployment access probe authenticates from runtime without inference or private data', async()=>{
  const calls=[];
  const fetcher=async(url,options)=>{
    calls.push(url);
    assert.equal(options.redirect,'error');
    if(calls.length===1){assert.match(url,/login.microsoftonline.com/);return Response.json({access_token:'fictional-token',token_type:'Bearer',expires_in:3600});}
    assert.equal(url,'https://cvie-prod.openai.azure.com/openai/v1/models');
    assert.equal(options.headers.Authorization,'Bearer fictional-token');
    return Response.json({data:[]});
  };
  const response=await azureConnectionProbe(request(),env(),release,{fetcher,now});
  assert.equal(response.status,200);
  assert.deepEqual(await response.json(),{release,authentication_verified:true,resource_access_verified:true,inference_attempted:false,customer_ai_enabled:false,status:'passed'});
  assert.equal(calls.length,2);
});
test('unsigned, wrong, expired, replay-stale, cross-host and prompt-bearing checks never call Azure',async()=>{
  const cases=[
    [new Request('https://api.cveharbor.com'+probePath,{method:'POST'}),env()],
    [request({signingKey:'d'.repeat(64)}),env()],
    [request({stamp:String(seconds-61)}),env()],
    [request({method:'GET'}),env()],
    [request({suffix:'?prompt=secret'}),env()],
    [request({host:'confirm.cveharbor.com'}),env()],
    [request({body:'customer data'}),env()],
    [request(),env({CVEHARBOR_AZURE_CONNECTION_PROBE:undefined})],
    [request(),env({CVEHARBOR_AZURE_CONNECTION_PROBE:JSON.stringify(proof({created:seconds-901,expires:seconds-1}))})],
    [request(),env({CVEHARBOR_AZURE_CONNECTION_PROBE:JSON.stringify(proof({expires:seconds+99999}))})],
    [request(),env({CVEHARBOR_AZURE_CONNECTION_PROBE:JSON.stringify(proof({release:'e'.repeat(64)}))})],
  ];
  for(const [req,settings] of cases){
    const response=await azureConnectionProbe(req,settings,release,{now,fetcher:()=>{assert.fail('Unexpected Azure call');}});
    assert.equal(response.status,404);
  }
});
test('provider failures are redacted and do not expose tokens or secret values',async()=>{
  const result=await azureConnectionProbe(request(),env(),release,{now,fetcher:async()=>new Response('private upstream error fictional-secret',{status:401})});
  assert.equal(result.status,503);
  const value=await result.text();
  assert.match(value,/authentication_http_error/);
  assert.doesNotMatch(value,/fictional-secret|private upstream/);
});
test('unreviewed Azure destination is refused before credentials leave runtime',async()=>{
  const response=await azureConnectionProbe(request(),env({CVEHARBOR_AZURE_OPENAI_ENDPOINT:'https://other.openai.azure.com/'}),release,{now,fetcher:()=>assert.fail('Unexpected Azure call')});
  assert.equal(response.status,503);
  assert.equal((await response.json()).error,'invalid_configuration');
});
test('existing recovery hold blocks the deployment probe',async()=>{
  const app=recoveryProtected({fetch:()=>assert.fail('Must not enter handler')});
  const DB={prepare:()=>({first:async()=>({write_hold:1,revision:1})})};
  const response=await app.fetch(request(),{DB,RECOVERY_CONTROL_REQUIRED:'true'},{});
  assert.equal(response.status,503);
});
