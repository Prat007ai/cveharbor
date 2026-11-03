// Only bundled into staging. No native fetch fallback exists.
import {AsyncLocalStorage} from 'node:async_hooks';
import {TARGET} from './target.mjs';
import {PUBLIC_FEEDS,openIntelligenceSnapshot} from '../account-backend/src/intelligence-store.js';
const context=new AsyncLocalStorage();
export const SCENARIOS=Object.freeze(['synthetic','provider-failure','mail-failure']);
export function withStagingTransport(env,operation,scenario='synthetic',stats={}){
 if(env.STAGING_MODE!=='true'||!SCENARIOS.includes(scenario))throw Error('Invalid staging transport');
 return context.run({env,scenario,stats},operation);
}
export async function fetch(input,init){
 const scope=context.getStore();if(!scope)throw Error('Outbound providers are disabled outside staging context');
 // Workers cannot construct redirect:error Requests. Fixture responses never redirect.
 const req=new Request(input,init?.redirect==='error'?{...init,redirect:'manual'}:init),url=new URL(req.url),{env,scenario,stats}=scope;
 if(url.href==='https://api.smtp2go.com/v3/email/send'&&req.method==='POST'){
  if(env.STAGING_EMAIL_CAPTURE_ENABLED!=='true'||!env.DB)throw Error('Staging email capture unavailable');
  if(req.headers.get('X-Smtp2go-Api-Key')!=='staging-capture-only')throw Error('Real provider credentials forbidden');
  const raw=await req.text();if(raw.length>4000000)throw Error('Captured message too large');
  const p=JSON.parse(raw),recipients=[...(p.to||[]),...(p.cc||[]),...(p.bcc||[])];
  if(!Array.isArray(p.to)||!p.to.length||recipients.length>100||recipients.some(x=>typeof x!=='string'||x.length>320)||typeof p.subject!=='string')throw Error('Invalid message');
  if(scenario==='mail-failure'){stats.failed=(stats.failed||0)+1;return Response.json({data:{succeeded:0,failed:1}},{status:503});}
  const id=crypto.randomUUID(),provider='staging_'+id.replaceAll('-','');
  // Never persist request headers/provider keys. Existing templates and recipients are unchanged.
  const payload={sender:p.sender,to:p.to,cc:p.cc||[],bcc:p.bcc||[],subject:p.subject,html_body:p.html_body||'',text_body:p.text_body||'',custom_headers:p.custom_headers||[],attachments:p.attachments||[],inlines:p.inlines||[]};
  const chunks=[];
  payload.attachments=payload.attachments.map((attachment,index)=>{
   const blob=attachment.fileblob;if(typeof blob!=='string'||!/^[A-Za-z0-9+/]*={0,2}$/.test(blob))throw Error('Invalid synthetic attachment');
   for(let offset=0;offset<blob.length;offset+=64000)chunks.push(env.DB.prepare('INSERT INTO staging_mail_attachment_chunks(mail_id,attachment_index,chunk_index,body) VALUES(?,?,?,?)').bind(id,index,offset/64000,blob.slice(offset,offset+64000)));
   return {filename:attachment.filename,mimetype:attachment.mimetype,base64_length:blob.length,capture_url:'/__staging/mail/'+id+'/attachment/'+index};
  });
  const encoded=JSON.stringify(payload);if(encoded.length>1000000)throw Error('Captured message body too large');
  await env.DB.batch([env.DB.prepare('INSERT INTO staging_mail(id,created_at,subject,recipients_json,payload_json,scenario,provider_id) VALUES(?,?,?,?,?,?,?)').bind(id,Date.now(),p.subject,JSON.stringify(recipients),encoded,scenario,provider),...chunks]);
  stats.captured=(stats.captured||0)+1;
  return Response.json({request_id:id,data:{succeeded:1,failed:0,failures:[],email_id:provider}});
 }
 if(!['GET','HEAD'].includes(req.method))throw Error('Staging provider writes blocked');
 if(scenario==='provider-failure'){stats.failed=(stats.failed||0)+1;return new Response('Synthetic provider unavailable',{status:503});}
 // Legacy application fetch consumers still read the same immutable staging snapshot.
 if(url.origin===TARGET.origin&&PUBLIC_FEEDS[url.pathname]){
  const snapshot=await openIntelligenceSnapshot(env,url.searchParams.get('feed_version'));
  const name=PUBLIC_FEEDS[url.pathname],raw=await snapshot.read(name);
  const globals={'data.js':'CVEHARBOR_DATA','malware-data.js':'CVEHARBOR_MALWARE','threat-data.js':'CVEHARBOR_THREATS','lifecycle.js':'CVEHARBOR_LIFECYCLE','patch-notes.js':'CVEHARBOR_PATCH_NOTES'};
  return new Response(globals[name]?'window.'+globals[name]+' = '+raw+';':raw);
 }
 if(url.hostname==='services.nvd.nist.gov'&&url.pathname==='/rest/json/cves/2.0')return Response.json({resultsPerPage:0,startIndex:0,totalResults:0,format:'NVD_CVE',version:'2.0',timestamp:new Date().toISOString(),vulnerabilities:[]});
 if(url.hostname==='api.github.com'&&url.pathname==='/advisories')return Response.json([]);
 const cve=/(CVE-[0-9]{4}-[0-9]{4,})(?:\.json)?$/.exec(url.pathname)?.[1];
 if(cve&&((url.hostname==='cveawg.mitre.org'&&url.pathname.startsWith('/api/cve/'))||(url.hostname==='raw.githubusercontent.com'&&url.pathname.startsWith('/CVEProject/cvelistV5/main/cves/'))))return Response.json({dataType:'CVE_RECORD',cveMetadata:{cveId:cve,state:'PUBLISHED',datePublished:'2026-01-01T00:00:00Z',dateUpdated:'2026-01-01T00:00:00Z'},containers:{cna:{title:'Synthetic staging advisory',descriptions:[{lang:'en',value:'Synthetic fixture, not a real security finding.'}],affected:[{vendor:'Example',product:'Review service',versions:[{version:'1.0',lessThan:'1.2',status:'affected'}]}],metrics:[{cvssV3_1:{baseScore:8.8,baseSeverity:'HIGH'}}],references:[]}}});
 if(url.href==='https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json')return Response.json([{fetchTime:new Date().toISOString(),numberOfChanges:0,new:[],updated:[],error:[]}]);
 if(url.href==='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')return Response.json({dateReleased:new Date().toISOString(),count:1,vulnerabilities:[{cveID:'CVE-2099-12345',vendorProject:'Synthetic',product:'Staging fixture',vulnerabilityName:'Synthetic advisory',dateAdded:new Date().toISOString().slice(0,10),shortDescription:'Synthetic only',requiredAction:'Test only',dueDate:'2099-12-31',knownRansomwareCampaignUse:'Unknown'}]});
 if(url.hostname==='endoflife.date'&&/^\/api\/[a-z0-9.-]+\.json$/.test(url.pathname))return Response.json([]);
 if(url.hostname==='cloudflare-dns.com'&&url.pathname==='/dns-query'&&(String(url.searchParams.get('name')).endsWith('.invalid')||url.searchParams.get('name')==='synthetic-monitor.example.org'))return Response.json({Status:0,Answer:url.searchParams.get('type')==='A'?[{type:1,data:'1.1.1.1'}]:[]});
 if(url.hostname==='webrisk.googleapis.com'&&url.pathname==='/v1/uris:search'&&url.searchParams.get('key')==='staging-fixture-only')return Response.json({});
 if(url.hostname==='api.wordpress.org'&&url.pathname==='/plugins/info/1.2/')return Response.json({slug:url.searchParams.get('request[slug]'),version:'1.2.0',last_updated:'2026-01-01',sections:{changelog:'Synthetic release'},download_link:'https://example.invalid/plugin.zip'});
 if(url.hostname==='www.wpvulnerability.net'&&/^\/plugin\/[a-z0-9-]+\/$/.test(url.pathname))return Response.json({error:0,data:{vulnerability:[]}});
 if(url.hostname==='api.wordpress.org'&&url.pathname==='/core/stable-check/1.0/')return Response.json({'6.6.2':'latest'});
 if(url.hostname==='www.php.net'&&url.pathname==='/releases/')return Response.json({'8.3.10':{date:'01 Jan 2026',source:[]}});
 if(url.href==='https://raw.githubusercontent.com/dotnet/core/main/release-notes/releases-index.json')return Response.json({'releases-index':[{'channel-version':'8.0','latest-release':'8.0.11','latest-release-date':'2026-10-20','support-phase':'active','security':true,'eol-date':'2026-11-10'}]});
 if(url.hostname.endsWith('.invalid')||url.hostname==='synthetic-monitor.example.org')return new Response('<!doctype html><title>Synthetic staging monitor</title>',{headers:{'Content-Type':'text/html','X-Staging-Fixture':'true'}});
 stats.blocked=(stats.blocked||0)+1;throw Error('No reviewed synthetic provider response for this request');
}
