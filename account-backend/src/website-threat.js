// Commercial Web Risk lookup. Optional: configure GOOGLE_WEB_RISK_API_KEY as a secret.
// Never represent unavailable intelligence as a clean scan.
export async function lookupWebsiteThreat(url,env,fetcher=fetch){
 if(!env.GOOGLE_WEB_RISK_API_KEY)return {provider:'Google Web Risk',status:'not_configured',threats:[]};
 const endpoint=new URL('https://webrisk.googleapis.com/v1/uris:search');
 endpoint.searchParams.set('uri',url);
 for(const type of ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE'])endpoint.searchParams.append('threatTypes',type);
 endpoint.searchParams.set('key',env.GOOGLE_WEB_RISK_API_KEY);
 try{
  const response=await fetcher(endpoint.toString(),{method:'GET',signal:AbortSignal.timeout(6000),redirect:'manual'});
  if(!response.ok)return {provider:'Google Web Risk',status:'unavailable',threats:[]};
  const payload=await response.json();
  const threats=Array.isArray(payload.threat?.threatTypes)?payload.threat.threatTypes.filter(x=>['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE'].includes(x)):[];
  return {provider:'Google Web Risk',status:threats.length?'listed':'no_known_listing',threats,cache_expires:payload.threat?.expireTime||null};
 }catch{return {provider:'Google Web Risk',status:'unavailable',threats:[]}}
}
export function assessHttpHeaders(headers,status){
 const findings=[];
 if(status!==null&&(status>=500||status<200))findings.push({id:'http_status',severity:'warning',description:'HTTP response requires review'});
 if(!headers['strict-transport-security'])findings.push({id:'hsts',severity:'informational',description:'HSTS header was not observed'});
 if(!headers['content-security-policy'])findings.push({id:'csp',severity:'informational',description:'Content Security Policy header was not observed'});
 if(!headers['x-content-type-options'])findings.push({id:'content_type_options',severity:'informational',description:'X-Content-Type-Options header was not observed'});
 if(status>=300&&status<400&&headers.location) findings.push({id:'redirect',severity:'review',description:'Redirect response was observed without following the destination'});
 return findings;
}
