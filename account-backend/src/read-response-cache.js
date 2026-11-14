// Private dashboard snapshots live only in bounded Worker memory. Every lookup
// requires a newly validated primary session/MFA/hold and the exact D1 bookmark.
// No cross-request authentication, promises, errors or unbounded inventory reads.
const databases=new WeakMap();
export const RESPONSE_TTL=5000,RESPONSE_BYTES=32*1024*1024,RESPONSE_ENTRY_BYTES=512*1024;
const routes=new Set(['/v1/workspace/summary','/v1/cvie','/v1/cvie/advisories']);
const flags=['AGENT_INVENTORY_SCHEMA','CVIE_SHARED_SCANS_ENABLED','CVIE_REGISTRY_ENABLED','CVIE_FAST_EVIDENCE_ENABLED','CVIE_TOPIC_HISTORY_ENABLED','CVIE_METRICS_ENABLED'];
const partial=value=>value&&typeof value==='object'&&(value.available===false||value.ready===false||Object.values(value).some(partial));
export function responseCacheKey(req,env,user){
 const url=new URL(req.url),origin=req.headers.get('origin');
 if(req.method!=='GET'||!user?.id||origin&&origin!=='https://cveharbor.com'||url.hostname==='confirm.cveharbor.com')return null;
 const metadata=url.pathname==='/v1/inventory/page'&&['customers','environments','assets'].includes(url.searchParams.get('resource'));
 if(!routes.has(url.pathname)&&!metadata)return null;
 return JSON.stringify([user.id,url.origin,url.pathname,url.search,flags.map(k=>env[k]??null)]);
}
function state(identity){let s=databases.get(identity);if(!s){s={rows:new Map(),bytes:0};databases.set(identity,s);}return s;}
function remove(s,key,row){s.rows.delete(key);s.bytes-=row.bytes;}
export function cachedResponse(identity,bookmark,key,now=Date.now()){
 if(!identity||typeof bookmark!=='string'||!bookmark||!key)return null;
 const s=state(identity),id=JSON.stringify([bookmark,key]),row=s.rows.get(id);
 if(!row)return null;
 if(now<row.at||now-row.at>=RESPONSE_TTL){remove(s,id,row);return null;}
 s.rows.delete(id);s.rows.set(id,row);
 return new Response(row.body,{status:200,headers:row.headers});
}
export async function rememberResponse(identity,bookmark,key,response,stillCurrent,now=Date.now()){
 if(!identity||typeof bookmark!=='string'||!bookmark||!key||response.status!==200||response.headers.has('Set-Cookie')||!response.headers.get('Content-Type')?.includes('application/json'))return;
 const body=new Uint8Array(await response.clone().arrayBuffer());
 if(body.byteLength>RESPONSE_ENTRY_BYTES||!stillCurrent())return;
 let data;try{data=JSON.parse(new TextDecoder().decode(body));}catch{return;}
 if(data?.error||partial(data))return;
 const s=state(identity),id=JSON.stringify([bookmark,key]),bytes=body.byteLength+2*id.length;
 const old=s.rows.get(id);if(old)remove(s,id,old);
 for(const [k,row] of s.rows)if(now<row.at||now-row.at>=RESPONSE_TTL)remove(s,k,row);
 while(s.rows.size>=512||s.bytes+bytes>RESPONSE_BYTES){const [k,row]=s.rows.entries().next().value;remove(s,k,row);}
 const headers=[...response.headers];headers.push(['X-CVEHarbor-Read-At',new Date(now).toISOString()]);
 s.rows.set(id,{body,headers,at:now,bytes});s.bytes+=bytes;
 response.headers.set('X-CVEHarbor-Read-At',new Date(now).toISOString());
}
