// Shared data-only R2 reader. The legacy path remains the default until cutover.
export const FEED_GLOBALS = Object.freeze({
 'data.js':'CVEHARBOR_DATA','malware-data.js':'CVEHARBOR_MALWARE',
 'threat-data.js':'CVEHARBOR_THREATS','lifecycle.js':'CVEHARBOR_LIFECYCLE',
 'patch-notes.js':'CVEHARBOR_PATCH_NOTES'
});
export const PUBLIC_FEEDS = Object.freeze({
 ...Object.fromEntries(Object.keys(FEED_GLOBALS).map(x=>['/'+x,x])),
 '/feed-health.json':'data/feed-health.json','/workspace-intelligence.json':'workspace-intelligence.json',
 ...Object.fromEntries(['attack-scanning-current.txt','attack-scanning-current.csv','attack-scanning-current.json',
 'fortigate-threat-ip-objects.txt','sophos-threat-ip-api.txt','fortigate-suspicious-ip-initial.txt',
 'fortigate-suspicious-ip-incremental.txt','sophos-suspicious-ip-initial.txt',
 'sophos-suspicious-ip-incremental.txt'].map(x=>['/'+x,x]))
});
const HASH=/^[a-f0-9]{64}$/;
const MAX=32*1024*1024;
export function useIntelligenceStore(env={}) {
 if (!env.INTELLIGENCE_SOURCE || env.INTELLIGENCE_SOURCE==='legacy') return false;
 if (env.INTELLIGENCE_SOURCE!=='r2') throw Error('Unknown intelligence source');
 if (!env.INTELLIGENCE_BUCKET?.get) throw Error('Intelligence bucket is not configured');
 return true;
}
async function sha(raw) {
 return [...new Uint8Array(await crypto.subtle.digest('SHA-256',raw))].map(x=>x.toString(16).padStart(2,'0')).join('');
}
async function object(bucket,key,max=MAX) {
 const result=await bucket.get(key);
 if (!result || result.size>max) throw Error('Missing/oversized intelligence object');
 const raw=await result.arrayBuffer();
 if (raw.byteLength>max) throw Error('Oversized intelligence object');
 return raw;
}
export async function openIntelligenceSnapshot(env,version=null) {
 if (!useIntelligenceStore(env)) throw Error('R2 source is not enabled');
 let key;
 if (version!==null) {
  if (!HASH.test(version)) throw Error('Invalid feed version');
  key='manifests/'+version+'.json';
 } else {
  const p=JSON.parse(new TextDecoder().decode(await object(env.INTELLIGENCE_BUCKET,'current.json',4096)));
  if(p.schema!==1 || !/^manifests\/[a-f0-9]{64}\.json$/.test(p.manifest)) throw Error('Invalid intelligence pointer');
  key=p.manifest;
 }
 const raw=await object(env.INTELLIGENCE_BUCKET,key,100000);
 const versionHash=key.slice(10,-5);
 if(await sha(raw)!==versionHash) throw Error('Corrupt intelligence manifest');
 const manifest=JSON.parse(new TextDecoder().decode(raw));
 if(manifest.schema!==1 || !manifest.files || typeof manifest.files!=='object') throw Error('Invalid intelligence manifest');
 return {version:versionHash,manifest,async read(name) {
  const e=manifest.files[name];
  if(!e || !HASH.test(e.sha256) || e.key!=='objects/'+e.sha256 || !Number.isInteger(e.bytes) || e.bytes<0 || e.bytes>MAX) throw Error('Invalid intelligence entry');
  const body=await object(env.INTELLIGENCE_BUCKET,e.key);
  if(body.byteLength!==e.bytes || await sha(body)!==e.sha256) throw Error('Corrupt intelligence object');
  return new TextDecoder('utf-8',{fatal:true}).decode(body);
 },async json(name) {return JSON.parse(await this.read(name));}};
}
export async function intelligenceResponse(request,env) {
 const url=new URL(request.url),name=PUBLIC_FEEDS[url.pathname];
 if(!name || !useIntelligenceStore(env)) return null;
 if(!['GET','HEAD'].includes(request.method)) return new Response('Method not allowed',{status:405});
 const snapshot=await openIntelligenceSnapshot(env,url.searchParams.get('feed_version'));
 let body=await snapshot.read(name),type='text/plain; charset=utf-8';
 if(FEED_GLOBALS[name]) {
  const data=JSON.parse(body);
  if(!data || typeof data!=='object' || Array.isArray(data)) throw Error('Invalid feed data');
  // Stored bytes can never select a global or become executable application code.
  body='window.'+FEED_GLOBALS[name]+' = '+body.replace(/</g,'\\u003c').replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029')+';\n';
  type='application/javascript; charset=utf-8';
 } else if(name.endsWith('.json')) {JSON.parse(body);type='application/json; charset=utf-8';}
 else if(name.endsWith('.csv')) type='text/csv; charset=utf-8';
 return new Response(request.method==='HEAD'?null:body,{headers:{'Content-Type':type,
  'Cache-Control':url.searchParams.has('feed_version')?'public, max-age=31536000, immutable':'no-store',
  'X-Content-Type-Options':'nosniff','X-CVEHarbor-Feed-Version':snapshot.version}});
}
// Pin a page's executable data wrappers to one immutable manifest. Source files
// and UI stay unchanged; only the reviewed serving adapter adds version queries.
export function pinIntelligenceScripts(html,version) {
 if(!HASH.test(version)) throw Error('Invalid version');
 return html.replace(/src="\/(data\.js|malware-data\.js|threat-data\.js|lifecycle\.js|patch-notes\.js)(\?[^"<>]*)?"/g,
  (_,name,query)=>'src="/'+name+(query?query+'&':'?')+'feed_version='+version+'"');
}
