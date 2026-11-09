import catalogue from './version-products.json' with {type:'json'};
import seed from './version-releases.json' with {type:'json'};

const patterns = {
  maria: /^\d+\.\d+\.\d+(?:-[A-Za-z0-9][A-Za-z0-9.~+-]{0,25})?$/, sql2022: /^16\.0\.\d+\.\d+$/,
  kendo: /^20\d{2}\.[1-4]\.\d{2,4}$/,
  triple: /^\d+\.\d+\.\d+$/, twoThree: /^\d+\.\d+(?:\.\d+)?$/, four: /^\d+\.\d+\.\d+\.\d+$/,
  sdk: /^\d+\.\d+\.[1-9]\d{2}$/, win: /^(?:10\.0\.)?\d{5}\.\d+$/, build: /^\d{6,9}$/,
  android: /^\d+(?:\.\d+){0,2}$/, sfos: /^\d+\.\d+ (?:GA|MR\d+) Build \d+$/
};
export function validVersion(product, value) {
  return typeof value==='string' && value.length<=48 && patterns[product.format].test(value);
}
function monthsBefore(date, count) {
  const result=new Date(date), day=result.getUTCDate();
  result.setUTCDate(1);
  result.setUTCMonth(result.getUTCMonth()-count);
  const last=new Date(Date.UTC(result.getUTCFullYear(),result.getUTCMonth()+1,0)).getUTCDate();
  result.setUTCDate(Math.min(day,last));
  return result;
}
export function windowFor(anchor, quarter) {
  return {start:monthsBefore(anchor,3*(quarter+1)).toISOString(),
    end:new Date(monthsBefore(anchor,3*quarter).getTime()-(quarter?1:0)).toISOString()};
}
async function upstream(url,options={}) {
  const response=await fetch(url,{...options,redirect:'error',signal:AbortSignal.timeout(18000),
    headers:{'User-Agent':'CVEHarbor version checks','Accept':'application/json',...options.headers}});
  if(!response.ok)throw Error('Advisory source returned '+response.status);
  return response.json();
}
const numeric = s => /^\d+(?:\.\d+){1,3}$/.test(s);
function compare(a,b) {
  const x=a.split('.').map(Number), y=b.split('.').map(Number);
  for(let i=0;i<Math.max(x.length,y.length);i++) if((x[i]||0)!==(y[i]||0))return (x[i]||0)-(y[i]||0);
  return 0;
}
// A family search alone is never proof of applicability. Compare a CNA range
// only on the same product line and only for supported numeric version schemes.
export function buildMatch(id,installed,affected) {
  const product=catalogue.products[id];
  const family=product.match.slice(7).toLowerCase();
  const version=['win11','server','hyperv'].includes(id)&&!installed.startsWith('10.0.')?'10.0.'+installed:installed;
  if(!numeric(version))return 'Product lead · verify the vendor build';
  const rows=affected.filter(row=>String(row.product||'').toLowerCase().includes(family)
    && ['microsoft','microsoft corporation'].includes(String(row.vendor||'').toLowerCase()));
  for(const row of rows)for(const rule of row.versions||[]){
    if(rule.status!=='affected'||rule.changes?.length||!numeric(rule.version))continue;
    const upper=rule.lessThan||rule.lessThanOrEqual;
    if(upper && (!numeric(upper)|| !['custom','semver'].includes(rule.versionType)))continue;
    if(product.format==='win' && upper && upper.split('.').slice(0,3).join('.')!==version.split('.').slice(0,3).join('.'))continue;
    if(compare(version,rule.version)>=0 && (upper?(rule.lessThan?compare(version,upper)<0:compare(version,upper)<=0):compare(version,rule.version)===0))
      return 'Vendor affected range · confirm edition';
  }
  return 'Product lead · verify the vendor build';
}
async function nvdPage(id,product,version,range,offset) {
  const url=new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
  const family=product.match.startsWith('family:');
  if(family)url.searchParams.set('keywordSearch',product.match.slice(7));
  else {
    url.searchParams.set('cpeName','cpe:2.3:'+product.match.slice(4)+':'+(product.format==='maria'?version.split('-')[0]:version)+':*:*:*:*:*:*:*');
    url.searchParams.set('isVulnerable','');
  }
  const size=family?12:100;
  for(const [key,val] of Object.entries({pubStartDate:range.start,pubEndDate:range.end,resultsPerPage:size,startIndex:offset,noRejected:''}))url.searchParams.set(key,String(val));
  const data=await upstream(url);
  if(!Array.isArray(data.vulnerabilities)||data.startIndex!==offset||!Number.isSafeInteger(data.totalResults))throw Error('Incomplete NVD page');
  const rows=await Promise.all(data.vulnerabilities.map(async ({cve})=>{
    if(!/^CVE-\d{4}-\d{4,}$/.test(cve.id))throw Error('Invalid advisory');
    let evidence=product.format==='maria'&&version.includes('-')?'Upstream version match � verify distributor backports':'NVD vulnerable product/version match';
    if(family){
      evidence='Product lead · verify the vendor build';
      if(product.vendor==='Microsoft'){
        const [,year,serial]=cve.id.split('-');
        try {
          const record=await upstream('https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/'+year+'/'+serial.slice(0,-3)+'xxx/'+cve.id+'.json');
          evidence=buildMatch(id,version,record.containers?.cna?.affected||[]);
        } catch { /* The NVD lead remains usable without a verified build range. */ }
      }
    }
    return {id:cve.id,title:cve.descriptions?.find(d=>d.lang==='en')?.value||cve.id,published:cve.published,
      url:'https://nvd.nist.gov/vuln/detail/'+cve.id,evidence};
  }));
  const more=offset+rows.length<data.totalResults;
  if(more&&!rows.length)throw Error('Incomplete NVD page');
  return {rows,next:more?String(offset+rows.length):null};
}
async function osvPage(product,version,range,cursor) {
  const [,ecosystem,name]=product.match.split(':');
  const data=await upstream('https://api.osv.dev/v1/query',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({package:{ecosystem,name},version,...(cursor?{page_token:cursor}:{})})});
  if(data.vulns!==undefined&&!Array.isArray(data.vulns))throw Error('Incomplete OSV page');
  const start=Date.parse(range.start),end=Date.parse(range.end);
  const rows=(data.vulns||[]).filter(v=>!v.withdrawn&&Date.parse(v.published)>=start&&Date.parse(v.published)<=end)
    .map(v=>({id:v.aliases?.find(a=>/^CVE-\d{4}-\d+$/.test(a))||v.id,title:v.summary||v.details||v.id,
      published:v.published,url:'https://osv.dev/vulnerability/'+encodeURIComponent(v.id),evidence:'OSV package/version match'}));
  return {rows,next:data.next_page_token||null};
}
export async function versionResponse(request,env) {
  const url=new URL(request.url);
  if(!url.pathname.startsWith('/v1/version-picker/'))return null;
  const json=(body,status=200)=>Response.json(body,{status,headers:{'Cache-Control':'private, no-store'}});
  if(request.method!=='GET')return json({error:'GET required'},405);
  const route=url.pathname.slice('/v1/version-picker/'.length);
  if(route==='catalogue'){
    let releases=seed;
    try {const object=await env.INTELLIGENCE_BUCKET?.get('picker/releases-v1.json');if(object)releases={...seed,...await object.json()};}catch{}
    return json({cards:catalogue.cards,products:catalogue.products,releases,formats:Object.fromEntries(Object.entries(patterns).map(([k,v])=>[k,v.source]))});
  }
  if(route!=='scan')return json({error:'Unknown route'},404);
  const id=url.searchParams.get('product'), version=url.searchParams.get('version');
  if(!Object.hasOwn(catalogue.products,id))return json({error:'Select a listed product.'},400);
  const product=catalogue.products[id];
  if(!validVersion(product,version))return json({error:'Enter a '+product.name+' version such as '+product.example+'.'},400);
  const months=Number(url.searchParams.get('months')), q=Number(url.searchParams.get('quarter')||0);
  const date=url.searchParams.get('day'),cursor=url.searchParams.get('cursor')||'';
  const anchor=new Date(date+'T23:59:59.999Z');
  if(![3,12].includes(months)||!Number.isInteger(q)||q<0||q>=months/3||!/^\d{4}-\d\d-\d\d$/.test(date)||!Number.isFinite(anchor.getTime())||
      Math.abs(Date.now()-anchor.getTime())>2*86400000||cursor.length>2048)return json({error:'Invalid scan window.'},400);
  const osv=product.match.startsWith('osv:');
  if(!osv&&cursor&&!/^\d{1,7}$/.test(cursor))return json({error:'Invalid page.'},400);
  const range=osv?{start:monthsBefore(anchor,months).toISOString(),end:anchor.toISOString()}:windowFor(anchor,q);
  // Cache only public product queries; do not include gate credentials or account identifiers.
  const key=new Request(url.origin+'/__version_scan_cache/'+[id,version,date,months,q,cursor].map(encodeURIComponent).join('/'));
  const cache=globalThis.caches?.default;
  try{
    const hit=await cache?.match(key);
    if(hit)return json(await hit.json());
    const page=osv?await osvPage(product,version,range,cursor):await nvdPage(id,product,version,range,Number(cursor));
    const body={...page,nextQuarter:!osv&&q+1<months/3?q+1:null,range};
    if(cache)await cache.put(key,Response.json(body,{headers:{'Cache-Control':'public, max-age=1800'}})).catch(()=>{});
    return json(body);
  }catch{return json({error:'The advisory source could not finish this check. Retry to continue.'},503);}
}
