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
 'ubuntu':['Linux'],'ubuntu linux':['Linux'],'debian':['Linux'],'debian linux':['Linux'],'sitefinity':['Progress Sitefinity']
};
const norm=x=>String(x||'').normalize('NFKC').trim().toLowerCase().replace(/\s+/g,' ');
const numeric=x=>/^\d+(?:\.\d+){1,3}$/.test(x);
function compare(a,b){
 if(!numeric(a)||!numeric(b))return null;
 const x=a.split('.').map(Number),y=b.split('.').map(Number);
 for(let i=0;i<Math.max(x.length,y.length);i++){
  if((x[i]||0)!==(y[i]||0))return(x[i]||0)>(y[i]||0)?1:-1;
 }
 return 0;
}
// Fixed PHP release versions published by the PHP project on 21 October 2026.
// Keep this narrowly scoped; an arbitrary bulletin must not inherit this evidence.
const phpVendorFixes={
 'CVE-2026-109618':{'8.2':'8.2.35','8.3':'8.3.36','8.4':'8.4.27','8.5':'8.5.12'},
 'CVE-2026-109619':{'8.2':'8.2.35','8.3':'8.3.36','8.4':'8.4.27','8.5':'8.5.12'}
};
function phpVendorAssessment(product,version,cve){
 if(product!=='php'||!phpVendorFixes[cve.id])return null;
 const branch=String(version).match(/^(\d+\.\d+)\.(\d+)$/);
 if(!branch)return {level:'category',evidence:'PHP vendor advisory found. Exact installed PHP version is required.',comparison_detail:'Official PHP security releases: https://www.php.net/'};
 const fixed=phpVendorFixes[cve.id][branch[1]];
 if(!fixed)return {level:'category',evidence:'PHP version branch not covered by this release table; consult official PHP security and support information.',comparison_detail:'https://www.php.net/'};
 const comparison=compare(version,fixed);
 if(comparison>=0)return {exclude:true};
 return {level:'version_review',evidence:'Official PHP release advisory: the installed branch version predates the fixed release. Validate packaging, deployment and patch provenance.',comparison_detail:'PHP '+version+' predates fixed PHP '+fixed+' for '+cve.id+'. Source: https://www.php.net/'};
}
function preciseProductMatch(asset,cve){
 const product=norm(asset.technology);
 const detail=norm([cve.title,cve.summary,cve.affected].filter(Boolean).join(' '));
 const affected=norm(cve.affected);
 const plugin=product.startsWith('wordpress plugin:');
 // Plugin advisories require the actual product name and cannot be assigned
 // to WordPress core, PHP, or a different installed plugin.
 if(plugin){
  const name=product.slice('wordpress plugin:'.length).trim();
  return name.length>=3&&(affected.includes(name)||detail.includes(name))&&
   !(!affected.includes(name)&&/wordpress core|wordpress itself/i.test(detail));
 }
 if(product==='wordpress'){
  // Core inventory must not inherit vulnerabilities in plugins, hosting panels,
  // themes or other WordPress ecosystem products.
  if(/\b(cpanel|whm|wp2|woocommerce|plugin|theme|appointment-booking|geo my wordpress|wpbakery|extension)\b/i.test(detail))return false;
  return /\bwordpress (?:core|versions?|itself)\b/i.test(detail)||/\bwordpress\b[^.]{0,55}\b(?:core|before|through)\b/i.test(affected);
 }
 if(product==='php'){
  // Requiring runtime identity prevents PHP applications and vendor appliances
  // from being reported against the installed PHP interpreter.
  const foreign=/\b(phpmailer|phpmyadmin|zimbra|junos|juniper|cpanel|whm|wp2|vbulletin|joomla|drupal|dedecms|wordpress|woocommerce|widgetconfig|roundcube|magento|laravel|symfony)\b/i;
  if(foreign.test(detail))return false;
  const core=/\bphp\s*(?:runtime|interpreter|core|engine|versions?|8\.\d+|7\.\d+|cgi|fpm)\b|\bphp\s+(?:before|prior to|through|up to|earlier than)\s+\d|\b(?:php\.net|php-src)\b/i;
  return core.test(affected)||core.test(detail);
 }
 if(['debian','debian linux','ubuntu','ubuntu linux'].includes(product)){
  const distro=product.startsWith('debian')?'debian':'ubuntu';
  // Linux is a category, not proof that the affected package exists on
  // this distribution. Generic Linux kernel notices need kernel inventory.
  const explicit=new RegExp('\\b'+distro+'\\b','i');
  const vendor=(cve.sources||[]).some(s=>{try{const host=new URL(s.url).hostname;return distro==='debian'?host==='security-tracker.debian.org'||host==='debian.org'||host.endsWith('.debian.org'):host==='ubuntu.com'||host.endsWith('.ubuntu.com')}catch(_){return false}});
  if(!explicit.test(detail)&&!vendor)return false;
  if(distro==='debian'&&/\bubuntu\b/i.test(detail)&&!/\bdebian\b/i.test(detail))return false;
  if(distro==='ubuntu'&&/\bdebian\b/i.test(detail)&&!/\bubuntu\b/i.test(detail))return false;
  if(/\b(juniper|junos|zimbra|cpanel|whm|windows server)\b/i.test(detail))return false;
  return true;
 }
 return true;
}
function candidate(asset,cve){
 const product=norm(asset.technology);
 if(!product||!/^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+)$/i.test(String(cve.id||'')))return null;
 if((cve.cvie_excluded_products||[]).some(name=>norm(name)===product))return null;
 if(/rejected|withdrawn/i.test(String(cve.status||'')))return null;
 const cvie=/^cvie_/.test(cve.source_type||'')&&(cve.cvie_products||[]).some(name=>norm(name)===product);
 const tags=(cve.categories||[]).map(norm);
 if(!cvie&&!(product.startsWith('wordpress plugin:')?tags.includes('wordpress / plugins'):(categories[product]||[product]).some(t=>tags.includes(norm(t)))))return null;
 if(!cvie&&!preciseProductMatch(asset,cve))return null;
 // An OS release alone cannot establish exposure to arbitrary application
 // packages (Redis, curl, OpenSSL, etc). Require actual package inventory.
 if(['debian','debian linux','ubuntu','ubuntu linux'].includes(product))return null;
 const affected=String(cve.affected||''),version=String(asset.version||'').trim();
 let level='category',evidence='Category match only. Product identity and affected versions have not been verified.';
 let comparisonDetail='No reliable version comparison available from this advisory text.';
 // Generic PHP category advisories with no runtime fixed-version evidence
 // remain research leads, not customer-specific vulnerability findings.
 if(!cvie&&product==='php'&&!phpVendorFixes[cve.id]){
  const text=String(cve.affected||'');
  if(!/\bphp\s+(?:before|prior to|earlier than|through|up to)\s+(?:version\s+)?\d+\.\d+/i.test(text))return null;
 }
 const vendorAssessment=cvie?null:phpVendorAssessment(product,version,cve);
 if(vendorAssessment?.exclude)return null;
 if(vendorAssessment){level=vendorAssessment.level;evidence=vendorAssessment.evidence;comparisonDetail=vendorAssessment.comparison_detail;}
 if(cvie){
  const families=(cve.cvie_identities||[]).filter(x=>norm(x.name)===product).map(x=>x.cpe.split(':').slice(0,5).join(':'));
  const result=cvieVersionAssessment(version,(cve.affected_cpes||[]).filter(x=>x.cvie_product_key?norm(x.cvie_product_key)===product:families.includes(String(x.criteria).split(':').slice(0,5).join(':'))));
  if(result==='outside')return null;
  level=result==='within'?'version_review':'category';
  evidence=result==='within'?'CVIE product identity and a published numeric version range match. Verify vendor prerequisites and deployment before treating this as exposure.':'CVIE matched the affected product identity. Installed-version applicability still needs verification.';
  comparisonDetail=result==='within'?'Installed '+version+' is within a structured affected-version range. Complex configuration prerequisites are not evaluated.':'No unambiguous supported numeric comparison is available. Review the original advisory.';
 }
 const distroAsset=['debian','debian linux','ubuntu','ubuntu linux'].includes(product);
 if(distroAsset){
  evidence='Distribution advisory candidate only. OS release does not identify the installed source package or Debian backported revision. Verify package name, Debian suite and installed package version in the security tracker.';
  comparisonDetail='Review https://security-tracker.debian.org/tracker/'+encodeURIComponent(cve.id)+' and compare the exact installed source package revision; no OS-version comparison was attempted.';
 }

 // Only evaluate a single unambiguous numeric range associated with the named product.
 // Any qualifiers or complex ranges remain category-only candidates.
 // Inventory prefixes plugin names; publisher ranges usually omit that prefix.
 const rangeProduct=product.replace(/^wordpress plugin:\s*/, '');
 const mentions=norm(affected).includes(rangeProduct);
 if(!cvie&&!vendorAssessment&&!distroAsset&&mentions&&numeric(version)&&!/\b(except|unless|only when|requires|if configured)\b/i.test(affected)){
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
 if(cve.verification_pending)evidence+=' A newer source record is still being verified.';
 if(cve.disclosure_verification_stale)evidence+=' The original disclosure feed is pending or overdue; verify the latest vendor information.';
 if(cve.exploitation_verification_stale&&cve.known_exploited)evidence+=' Current CISA verification is pending or overdue.';
 return {id:String(cve.id),title:String(cve.title||cve.summary||cve.id),
 severity:String(cve.severity||'unknown'),known_exploited:!!cve.known_exploited,
 asset_id:asset.id,technology:asset.technology,version,level,evidence,
 affected,comparison_detail:comparisonDetail,
 summary:String(cve.summary||cve.title||''),remediation:String(cve.remediation||''),
 published:String(cve.published||''),updated:String(cve.updated||''),
 provenance:cve.provenance||[],kev_added:cve.kev_added||'',kev_verified_at:cve.kev_verified_at||null,
 evidence_status:cve.evidence_status||'Original advisory verification required',
 source_label:String((cve.sources||[]).find(s=>String(s.url||'').startsWith('https://'))?.label||'Original advisory'),
 source_url:(cve.sources||[]).map(s=>String(s.url||'')).find(url=>url.startsWith('https://'))||''};
}
function cvieVersionAssessment(version,ranges){
 if(!numeric(version)||!ranges.length)return 'unknown';
 let unknown=false;
 for(const range of ranges){
  if(range.comparison_unsupported){unknown=true;continue;}
  let outside=false,uncertain=false,hasBound=false;
  const exact=String(range.criteria||'').split(':')[5];
  if(exact&&exact!=='*'&&exact!=='-'){
   hasBound=true;const c=compare(version,exact);if(c===null)uncertain=true;else if(c!==0)outside=true;
  }
  for(const [field,kind] of [['versionStartIncluding','>='],['versionStartExcluding','>'],['versionEndIncluding','<='],['versionEndExcluding','<']]){
   if(!range[field])continue;hasBound=true;
   const c=compare(version,range[field]);if(c===null){uncertain=true;continue;}
   if(kind==='>='&&c<0||kind==='>'&&c<=0||kind==='<='&&c>0||kind==='<'&&c>=0)outside=true;
  }
  if(!outside&&!uncertain&&hasBound)return 'within';
  if(!outside&&(uncertain||!hasBound))unknown=true;
 }
 return unknown?'unknown':'outside';
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
root.CVEHARBOR_INVENTORY_MATCH={candidate,evaluate,compare,cvieVersionAssessment};
})(window);
