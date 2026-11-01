// Public NVD directory evidence only. No customer accounts or production writes.
import fs from 'node:fs';
const report={checked_at:new Date().toISOString(),ok:false,queries:[]};
const headers={Accept:'application/json',...(process.env.NVD_API_KEY?{apiKey:process.env.NVD_API_KEY}:{})};
try{
 for(const keyword of ['Microsoft Hyper-V','Microsoft Hyper V','HyperV']){
  const url=new URL('https://services.nvd.nist.gov/rest/json/cpes/2.0');
  url.searchParams.set('keywordSearch',keyword);url.searchParams.set('resultsPerPage','500');
  const response=await fetch(url,{headers,signal:AbortSignal.timeout(45000)});
  if(!response.ok)throw Error('NVD product directory HTTP '+response.status);
  const data=await response.json(),families=new Map();
  for(const {cpe} of data.products||[]){
   if(cpe.deprecated)continue;
   const family=cpe.cpeName.split(':').slice(0,5).join(':');
   if(!families.has(family))families.set(family,{family,title:cpe.titles?.find(x=>x.lang==='en')?.title,example:cpe.cpeName});
  }
  report.queries.push({keyword,total:data.totalResults,returned:data.products?.length,families:[...families.values()]});
  await new Promise(resolve=>setTimeout(resolve,6700));
 }
 const url=new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
 url.searchParams.set('keywordSearch','Hyper-V');url.searchParams.set('resultsPerPage','10');
 url.searchParams.set('pubStartDate',new Date(Date.now()-90*86400000).toISOString());url.searchParams.set('pubEndDate',new Date().toISOString());
 const response=await fetch(url,{headers,signal:AbortSignal.timeout(45000)});
 if(!response.ok)throw Error('NVD CVE query HTTP '+response.status);
 const data=await response.json();
 report.cves={total:data.totalResults,records:(data.vulnerabilities||[]).map(({cve})=>({id:cve.id,summary:cve.descriptions?.find(x=>x.lang==='en')?.value,configurations:cve.configurations}))};
 report.ok=true;
}catch(error){report.error=error.message;}
fs.writeFileSync('data/cvie-hyperv-directory-check.json',JSON.stringify(report,null,2)+'\n');
console.log('Public Hyper-V directory check: '+(report.ok?'complete':'failed'));
