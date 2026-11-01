// Only fixed vendor-owned endpoints are fetched. Custom URLs are reference-only
// until a reviewed adapter exists; user-provided URLs never become fetch targets.
export const DAY=86400000;
export const SOURCE_REGISTRY={
 dotnet:{vendor:'Microsoft',name:'.NET',adapter:'dotnet',url:'https://raw.githubusercontent.com/dotnet/core/main/release-notes/releases-index.json',official:'https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core'},
 wordpress:{vendor:'WordPress',name:'WordPress',adapter:'wordpress',url:'https://api.wordpress.org/core/stable-check/1.0/',official:'https://wordpress.org/download/releases/'},
 php:{vendor:'PHP',name:'PHP',adapter:'php',url:'https://www.php.net/releases/?json&version={branch}&max=1',official:'https://www.php.net/supported-versions.php'},
};
export function sourceFor(slug,branch){
 const source=SOURCE_REGISTRY[slug];if(!source)return null;
 if(slug==='php')return /^\d{1,2}\.\d{1,2}$/.test(branch)?{...source,id:'php:'+branch,url:source.url.replace('{branch}',branch)}:null;
 return {...source,id:slug};
}
export function approvedSource(source){const base=source.adapter==='php'?sourceFor('php',source.id.slice(4)):sourceFor(source.id,'');return base&&base.id===source.id&&base.url===source.url&&base.adapter===source.adapter;}
const stable=value=>typeof value==='string'&&/^\d+(?:\.\d+){1,3}$/.test(value)&&value.split('.').every(n=>Number.isSafeInteger(Number(n)));
export function compareVersions(a,b){
 if(!stable(a)||!stable(b))return null;
 const x=a.split('.').map(Number),y=b.split('.').map(Number);
 for(let i=0;i<Math.max(x.length,y.length);i++)if((x[i]||0)!==(y[i]||0))return (x[i]||0)>(y[i]||0)?1:-1;
 return 0;
}
export const sameBranch=(version,branch)=>stable(version)&&/^\d+\.\d+$/.test(branch)&&version.split('.').slice(0,2).join('.')===branch;
const isoDate=value=>{if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(value)||!Number.isFinite(Date.parse(value))||new Date(value+'T00:00:00Z').toISOString().slice(0,10)!==value)throw Error('Vendor date format changed');return value;};
export function monitorIdentity(watch){
 const slug=String(watch.slug||'').toLowerCase(),branch=String(watch.cycle||'').trim(),source=watch.edition?null:sourceFor(slug,branch);
 if(source&&!/^\d+\.\d+$/.test(branch))throw Error('Choose a specific major.minor release branch');
 return {id:JSON.stringify([slug||'custom',branch,watch.edition||'']),source_id:source?.id||null,slug,name:source?.name||'Unverified product',vendor:source?.vendor||'Unverified',branch,edition:watch.edition||'',official_url:source?.official||'',source};
}
export function normalizeVendor(adapter,raw,product){
 let version='',published=null,security=false,milestones={};
 if(adapter==='dotnet'){
  if(!Array.isArray(raw?.['releases-index'])||raw['releases-index'].length>100)throw Error('Invalid Microsoft release index');
  const rows=raw['releases-index'].filter(r=>r['channel-version']===product.branch);
  if(rows.length!==1)throw Error('Microsoft release branch missing or ambiguous');
  const row=rows[0];version=row['latest-release'];
  if(!['active','maintenance','eol'].includes(row['support-phase']))throw Error('Preview or unrecognized Microsoft release phase');
  published=isoDate(row['latest-release-date']);
  if(typeof row.security!=='boolean')throw Error('Microsoft security classification missing');security=row.security;
  if(row['eol-date'])milestones.security=isoDate(row['eol-date']);
 }else if(adapter==='wordpress'){
  if(!raw||Array.isArray(raw)||typeof raw!=='object'||Object.keys(raw).length>5000)throw Error('Invalid WordPress release data');
  const versions=Object.entries(raw).filter(([v,status])=>sameBranch(v,product.branch)&&['latest','outdated','insecure'].includes(status)).map(([v])=>v).sort((a,b)=>compareVersions(b,a));
  version=versions[0];
  // No precise support deadline, release date or security-fix classification
  // is invented from a WordPress stable-check response.
 }else if(adapter==='php'){
  if(!raw||Array.isArray(raw)||typeof raw!=='object')throw Error('Invalid PHP release data');
  const versions=Object.keys(raw).filter(v=>sameBranch(v,product.branch)).sort((a,b)=>compareVersions(b,a));version=versions[0];
  const row=raw[version];if(!row||!Array.isArray(row.source)||!row.source.length)throw Error('Incomplete PHP release record');
  const stamp=Date.parse(row.date);if(!Number.isFinite(stamp))throw Error('Invalid PHP publication date');published=new Date(stamp).toISOString().slice(0,10);
  security=Array.isArray(row.tags)&&row.tags.includes('security');
 }else throw Error('No verified official source adapter');
 if(!sameBranch(version,product.branch))throw Error('No verified stable release in the subscribed branch');
 return {product:product.name,vendor:product.vendor,branch:product.branch,edition:product.edition||'',version,published,security,milestones,source_url:sourceFor(product.slug,product.branch).url,release_source_url:sourceFor(product.slug,product.branch).url,lifecycle_source_url:SOURCE_REGISTRY[product.slug].official,reliability:'official_structured'};
}
export async function fetchVendor(source,fetcher=fetch){
 const response=await fetcher(source.url,{headers:{Accept:'application/json','User-Agent':'CVEHarbor-ProductMonitor/1.0'},redirect:'error',signal:AbortSignal.timeout(15000)});
 if(!response.ok){const error=Error('Official source unavailable (HTTP '+response.status+')'),header=response.headers.get('Retry-After');const retry=/^\d+$/.test(header||'')?Number(header)*1000:Date.parse(header||'')-Date.now();error.delay=response.status===429&&Number.isFinite(retry)?Math.min(DAY,Math.max(60000,retry)):null;throw error;}
 if(Number(response.headers.get('Content-Length'))>2000000)throw Error('Official source response exceeds size limit');
 const reader=response.body?.getReader();if(!reader)throw Error('Official source response has no body');
 const chunks=[];let size=0;
 while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>2000000){await reader.cancel();throw Error('Official source response exceeds size limit');}chunks.push(value);}
 const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
 return JSON.parse(new TextDecoder().decode(bytes));
}
