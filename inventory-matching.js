(function(root){
'use strict';
const categories={
 'php':['PHP'],'wordpress':['WordPress / Plugins'],'mysql':['MySQL'],
 'mariadb':['MariaDB'],'sql server':['SQL Server'],'microsoft sql server':['SQL Server'],
 'iis':['IIS / Web Server'],'.net':['.NET Core','.NET / ASP.NET'],
 'asp.net':['.NET / ASP.NET'],'python':['Python / PyPI'],
 'azure':['Azure'],'windows server':['Windows'],'fortigate':['Fortinet'],
 'fortios':['Fortinet'],'docker':['Docker / Kubernetes'],
 'kubernetes':['Docker / Kubernetes'],'linux':['Linux'],
 'ubuntu':['Linux'],'debian':['Linux'],'sitefinity':['Progress Sitefinity']
};
const norm=x=>String(x||'').trim().toLowerCase().replace(/\s+/g,' ');
const numeric=x=>/^\d+(?:\.\d+){1,3}$/.test(x);
function compare(a,b){
 if(!numeric(a)||!numeric(b))return null;
 const x=a.split('.').map(Number),y=b.split('.').map(Number);
 for(let i=0;i<Math.max(x.length,y.length);i++){
  if((x[i]||0)!==(y[i]||0))return(x[i]||0)>(y[i]||0)?1:-1;
 }
 return 0;
}
function candidate(asset,cve){
 const product=norm(asset.technology);
 if(!product||!/^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+)$/i.test(String(cve.id||'')))return null;
 if(/rejected|withdrawn/i.test(String(cve.status||'')))return null;
 const tags=(cve.categories||[]).map(norm);
 if(!(categories[product]||[product]).some(t=>tags.includes(norm(t))))return null;
 const affected=String(cve.affected||''),version=String(asset.version||'').trim();
 let level='category',evidence='Category match only. Product identity and affected versions have not been verified.';
 let comparisonDetail='No reliable version comparison available from this advisory text.';
 // Only evaluate a single unambiguous numeric range associated with the named product.
 // Any qualifiers or complex ranges remain category-only candidates.
 const mentions=affected.toLowerCase().includes(product);
 if(mentions&&numeric(version)&&!/\b(except|unless|only when|requires|if configured)\b/i.test(affected)){
  const ranges=[...affected.matchAll(/\b(before|prior to|earlier than|through|up to)\s+(?:version\s+)?(\d+(?:\.\d+){1,3})\b/gi)];
  if(ranges.length===1){
   const comparison=compare(version,ranges[0][2]);
   if(comparison!==null){
    const inclusive=/through|up to/i.test(ranges[0][1]);
    if(inclusive?comparison>0:comparison>=0){
     return null; // Explicit single before/through range: installed numeric version is outside it.
    }else{
     level='version_review';
     evidence='Installed version falls within one stated numeric affected range. Confirm exact product, package and exposure.';
    }
    comparisonDetail='Installed '+version+' compared with '+ranges[0][1]+' '+ranges[0][2]+' (single range extracted from advisory text; may not cover other branches).';
   }
  }
 }
 return {id:String(cve.id),title:String(cve.title||cve.summary||cve.id),
 severity:String(cve.severity||'unknown'),known_exploited:!!cve.known_exploited,
 asset_id:asset.id,technology:asset.technology,version,level,evidence,
 affected,comparison_detail:comparisonDetail,
 summary:String(cve.summary||cve.title||''),remediation:String(cve.remediation||''),
 published:String(cve.published||''),updated:String(cve.updated||''),
 source_label:String((cve.sources||[]).find(s=>String(s.url||'').startsWith('https://'))?.label||'Original advisory'),
 source_url:(cve.sources||[]).map(s=>String(s.url||'')).find(url=>url.startsWith('https://'))||''};
}
function evaluate(assets,advisories,limit=150){
 const items=[],seen=new Set();
 for(const asset of assets||[])for(const advisory of advisories||[]){
  const match=candidate(asset,advisory);if(!match)continue;
  const key=asset.id+'|'+match.id;if(seen.has(key))continue;seen.add(key);
  items.push(match);
 }
 items.sort((a,b)=>Number(b.known_exploited)-Number(a.known_exploited)||
  Number(b.severity==='critical')-Number(a.severity==='critical')||
  Number(b.level==='version_review')-Number(a.level==='version_review')||a.id.localeCompare(b.id));
 return {items:items.slice(0,limit),total:items.length,limited:items.length>limit};
}
root.CVEHARBOR_INVENTORY_MATCH={candidate,evaluate,compare};
})(window);
