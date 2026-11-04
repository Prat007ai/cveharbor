// Small SigV4 client: exact staging recovery bucket, PUT/GET immutable objects only.
import {createHmac} from 'node:crypto';
import {hash,requireThat} from './crypto.mjs';
const hmac=(key,value)=>createHmac('sha256',key).update(value).digest();
export function recoveryStore(env,transport=fetch){
 const bucket=env.CF_STAGING_RECOVERY_BUCKET;
 requireThat(/^[a-z0-9][a-z0-9-]{2,62}$/.test(bucket||'')&&bucket!=='cveharbor-intelligence-staging','recovery_bucket');
 requireThat(env.CF_STAGING_RECOVERY_R2_ACCESS_KEY_ID&&env.CF_STAGING_RECOVERY_R2_SECRET_ACCESS_KEY,'recovery_credentials');
 const host='9706b4d98ad72884e67fd1eb875c8a61.r2.cloudflarestorage.com';
 return async(method,key,body)=>{
  requireThat(['GET','PUT'].includes(method)&&/^recovery\/v1\/[a-f0-9]{40}\/[0-9]+-[0-9]+\/(snapshot|checkpoint29)\.cms$/.test(key),'object_boundary');
  const url=new URL('https://'+host+'/'+bucket+'/'+key),stamp=new Date().toISOString().replace(/[:-]|\.\d{3}/g,''),day=stamp.slice(0,8),payload=body||Buffer.alloc(0);
  const headers={'host':host,'x-amz-content-sha256':hash(payload),'x-amz-date':stamp,...(method==='PUT'?{'if-none-match':'*'}:{})};
  const names=Object.keys(headers).sort(),signed=names.join(';'),canonical=names.map(k=>k+':'+headers[k]+'\n').join('');
  const request=[method,url.pathname,'',canonical,signed,hash(payload)].join('\n'),scope=day+'/auto/s3/aws4_request';
  const signing=hmac(hmac(hmac(hmac('AWS4'+env.CF_STAGING_RECOVERY_R2_SECRET_ACCESS_KEY,day),'auto'),'s3'),'aws4_request');
  headers.Authorization='AWS4-HMAC-SHA256 Credential='+env.CF_STAGING_RECOVERY_R2_ACCESS_KEY_ID+'/'+scope+', SignedHeaders='+signed+', Signature='+createHmac('sha256',signing).update('AWS4-HMAC-SHA256\n'+stamp+'\n'+scope+'\n'+hash(request)).digest('hex');
  const r=await transport(url,{method,headers,redirect:'error',signal:AbortSignal.timeout(60000),...(method==='PUT'?{body:payload}:{})});
  requireThat(r.ok,'object_'+method.toLowerCase()+'_failed');
  if(method==='PUT'){requireThat(r.headers.get('etag'),'object_put_receipt');return;}
  return boundedBytes(r);
 };
}
export async function boundedBytes(r,limit=110000000){
 const declared=r.headers.get('content-length');if(declared)requireThat(Number(declared)<=limit,'download_limit');
 const chunks=[];let size=0;for await(const chunk of r.body){size+=chunk.length;requireThat(size<=limit,'download_limit');chunks.push(chunk);}return Buffer.concat(chunks);
}
