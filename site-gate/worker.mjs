import { intelligenceResponse, useIntelligenceStore, openIntelligenceSnapshot, pinIntelligenceScripts } from '../account-backend/src/intelligence-store.js';
const realm='Basic realm="CVEHarbor development", charset="UTF-8"';

function privateHeaders(){
  return {'Cache-Control':'private, no-store, max-age=0','Pragma':'no-cache','X-Robots-Tag':'noindex, nofollow, noarchive'};
}

function unavailable(request){
  return new Response(request.method==='HEAD'?null:'CVEHarbor is temporarily unavailable.',{
    status:503,headers:{...privateHeaders(),'Content-Type':'text/plain; charset=utf-8'}
  });
}

async function matchesSecret(candidate,expected){
  const encode=new TextEncoder();
  const [a,b]=await Promise.all([candidate,expected].map(value=>crypto.subtle.digest('SHA-256',encode.encode(value))));
  const left=new Uint8Array(a),right=new Uint8Array(b);
  let difference=0;for(let i=0;i<left.length;i++)difference|=left[i]^right[i];
  return difference===0;
}

async function authorized(request,env){
  const header=request.headers.get('Authorization')||'';
  if(header.length>4096)return false;
  const match=/^Basic\s+([A-Za-z0-9+/]+={0,2})$/i.exec(header);
  if(!match)return false;
  try{
    const raw=atob(match[1]);
    const value=new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(raw,c=>c.charCodeAt(0)));
    const colon=value.indexOf(':');
    if(colon<=0||value.slice(0,colon)!==env.SITE_GATE_USERNAME)return false;
    return await matchesSecret(value.slice(colon+1),env.SITE_GATE_PASSWORD);
  }catch{return false;}
}

export default {
  async fetch(request,env){
    const gated=env.SITE_GATE_ENABLED!=='false';
    const url=new URL(request.url);
    if(url.hostname==='www.cveharbor.com'||url.hostname==='cveharbor.com'&&url.protocol!=='https:'){
      url.hostname='cveharbor.com';url.protocol='https:';
      return new Response(null,{status:301,headers:{Location:url.toString(),...(gated?privateHeaders():{})}});
    }
    if(gated){
      if(!env.SITE_GATE_USERNAME||typeof env.SITE_GATE_PASSWORD!=='string'||env.SITE_GATE_PASSWORD.length<16)return unavailable(request);
      if(!await authorized(request,env)){
        return new Response(request.method==='HEAD'?null:'CVEHarbor is in private development. Sign in to continue.',{
          status:401,headers:{...privateHeaders(),'WWW-Authenticate':realm,'Content-Type':'text/plain; charset=utf-8'}
        });
      }
    }
    try {
      const feed=await intelligenceResponse(request,env);
      if(feed){
        if(gated)for(const [name,value] of Object.entries(privateHeaders()))feed.headers.set(name,value);
        return feed;
      }
    } catch { return unavailable(request); }
    if(!env.ASSETS?.fetch)return unavailable(request);
    // Credentials must never be forwarded to an asset origin or embedded in a page.
    const headers=new Headers(request.headers);headers.delete('Authorization');headers.delete('Proxy-Authorization');
    let response=await env.ASSETS.fetch(new Request(request,{headers}));
    if(request.method==='GET' && response.ok && (response.headers.get('Content-Type')||'').includes('text/html')){
      const html=await response.text();
      const h=new Headers(response.headers);h.delete('Content-Length');
      let rendered=html;
      try {
        if(useIntelligenceStore(env) && /src="\/(data\.js|malware-data\.js|threat-data\.js|lifecycle\.js|patch-notes\.js)/.test(html)){
          const snapshot=await openIntelligenceSnapshot(env);
          rendered=pinIntelligenceScripts(html,snapshot.version);
          h.delete('ETag');h.set('Cache-Control','no-store');
        }
      } catch {
        // A feed outage must not remove account/login/remediation HTML. Data
        // routes still fail visibly; never silently serve stale embedded assets.
        h.set('Cache-Control','no-store');
      }
      response=new Response(rendered,{status:response.status,headers:h});
    }
    if(!gated)return response;
    const protectedHeaders=new Headers(response.headers);
    for(const [name,value] of Object.entries(privateHeaders()))protectedHeaders.set(name,value);
    return new Response(response.body,{status:response.status,statusText:response.statusText,headers:protectedHeaders});
  }
};
