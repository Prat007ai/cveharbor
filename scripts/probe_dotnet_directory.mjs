// Public source identity evidence only; no customer accounts or production writes.
import fs from 'node:fs';
const report={checked_at:new Date().toISOString(),ok:false,directories:[],cves:[]};
const headers={Accept:'application/json',...(process.env.NVD_API_KEY?{apiKey:process.env.NVD_API_KEY}:{})};
async function nvd(path,params){
 const url=new URL('https://services.nvd.nist.gov/rest/json/'+path+'/2.0');
 for(const [key,value] of Object.entries(params))url.searchParams.set(key,value);
 const response=await fetch(url,{headers,signal:AbortSignal.timeout(45000)});
 if(!response.ok)throw Error('NVD '+path+' HTTP '+response.status);
 const data=await response.json();await new Promise(resolve=>setTimeout(resolve,6700));return data;
}
try{
 for(const keyword of ['.NET Core','Microsoft .NET','ASP.NET Core']){
  const data=await nvd('cpes',{keywordSearch:keyword,resultsPerPage:'500'}),families=new Map();
  for(const {cpe} of data.products||[]){
   if(cpe.deprecated)continue;const parts=cpe.cpeName.split(':'),family=parts.slice(0,5).join(':');
   if(!families.has(family))families.set(family,{family,title:cpe.titles?.find(x=>x.lang==='en')?.title,versions:[]});
   families.get(family).versions.push(parts[5]);
  }
  report.directories.push({keyword,total:data.totalResults,returned:data.products?.length,families:[...families.values()].map(f=>({...f,versions:[...new Set(f.versions)].slice(-35)}))});
 }
 for(const id of ['CVE-2026-114148','CVE-2026-109468','CVE-2026-70161','CVE-2026-111497']){
  const data=await nvd('cves',{cveId:id});report.cves.push(...(data.vulnerabilities||[]).map(({cve})=>cve));
 }
 report.ok=true;
}catch(error){report.error=error.message;}
fs.writeFileSync('data/cvie-dotnet-directory-check.json',JSON.stringify(report,null,2)+'\n');
console.log('Public .NET identity check: '+(report.ok?'complete':'failed'));
