// Exercise native workerd incoming and outgoing requests, without network access
// to Azure. All outbound requests are routed to a second local fixture Worker.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {createHmac} from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {probeMessage} from '../account-backend/src/azure-connection.js';

const require=createRequire(path.resolve(process.argv[2],'node_modules/wrangler/package.json'));
const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const {build}=require('esbuild');
const root=fileURLToPath(new URL('..',import.meta.url));
const dir=await fs.mkdtemp(path.join(os.tmpdir(),'cvh-azure-runtime-'));
const release='a'.repeat(64),key='b'.repeat(64),nonce='c'.repeat(64);
const created=Math.floor(Date.now()/1000);
const worker=`import {azureConnectionProbe} from './account-backend/src/azure-connection.js';
export default {fetch(req,env){return azureConnectionProbe(req,env,'${release}');}};`;
const fixture=`let calls=0;export default{async fetch(req,env){
  const url=new URL(req.url);
  if(url.hostname==='counts.test')return Response.json({calls});
  calls++;
  if(env.MODE==='redirect')return new Response(null,{status:302,headers:{Location:'https://untrusted.example/collect'}});
  if(url.hostname==='login.microsoftonline.com'&&url.pathname.endsWith('/oauth2/v2.0/token')){
    const body=new URLSearchParams(await req.text());
    if(body.get('client_secret')!=='fictional-secret')throw Error('Unexpected test credential');
    return Response.json({access_token:'fictional-token',token_type:'Bearer',expires_in:3600});
  }
  if(url.hostname==='cvie-prod.openai.azure.com'&&url.pathname==='/openai/v1/models'&&req.headers.get('Authorization')==='Bearer fictional-token')return Response.json({data:[]});
  throw Error('Unexpected outbound destination');
}};`;
try {
  const bundled=await build({stdin:{contents:worker,resolveDir:root},bundle:true,format:'esm',write:false});
  for(const mode of ['success','redirect']){
    const mf=new Miniflare(convertV4MiniflareOptions({workers:[{
      name:'probe',modules:true,script:bundled.outputFiles[0].text,
      compatibilityDate:'2026-10-28',outboundService:'azure-fixture',bindings:{
        CVEHARBOR_AZURE_OPENAI_ENDPOINT:'https://cvie-prod.openai.azure.com/',
        CVEHARBOR_AZURE_OPENAI_DEPLOYMENT:'gpt-5.4-mini',
        CVEHARBOR_AZURE_OPENAI_TENANT_ID:'f95d3766-898f-4e4d-a0ad-9b5efa394592',
        CVEHARBOR_AZURE_OPENAI_CLIENT_ID:'dec0de99-1e60-461f-bfb2-aa518b40036a',
        CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET:'fictional-secret',
        CVEHARBOR_AZURE_CONNECTION_PROBE:JSON.stringify({key,release,created,expires:created+900}),
      }},{name:'azure-fixture',modules:true,script:fixture,compatibilityDate:'2026-10-28',bindings:{MODE:mode}}]}));
    try {
      const stamp=String(created),signature=createHmac('sha256',Buffer.from(key,'hex')).update(probeMessage(stamp,nonce,release)).digest('hex');
      const options={method:'POST',headers:{'X-CVH-Timestamp':stamp,'X-CVH-Nonce':nonce,'X-CVH-Signature':signature}};
      const url='https://api.cveharbor.com/v1/ops/azure-connection';
      const response=await mf.dispatchFetch(url,options),result=await response.json();
      assert.equal(response.status,mode==='success'?200:503,JSON.stringify(result));
      assert.equal(result.authentication_verified,mode==='success');
      assert.equal(result.resource_access_verified,mode==='success');
      assert.equal(result.inference_attempted,false);
      if(mode==='redirect')assert.equal(result.error,'authentication_http_error');
      for(const body of [' ','fictional prompt'])assert.equal((await mf.dispatchFetch(url,{...options,body})).status,404);
      assert.equal((await mf.dispatchFetch(url,{method:'POST'})).status,404);
      const service=await mf.getWorker('azure-fixture');
      assert.equal((await (await service.fetch('https://counts.test/')).json()).calls,mode==='success'?2:1);
      console.log('Native Cloudflare Azure '+mode+' case passed; nonempty/unsigned requests blocked.');
    }finally{await mf.dispose();}
  }
}finally{await fs.rm(dir,{recursive:true,force:true});}
