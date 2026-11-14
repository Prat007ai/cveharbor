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
// Product and exclusion names repeat across thousands of candidate comparisons.
// Cache short immutable strings only; each matcher retains its original normalization.
const normalizedNames=new Map();
function norm(value){
 const text=String(value||'');
 if(normalizedNames.has(text))return normalizedNames.get(text);
 const result=text.normalize('NFKC').trim().toLowerCase().replace(/\s+/g,' ');
 if(text.length<=256){if(normalizedNames.size>=2048)normalizedNames.clear();normalizedNames.set(text,result);}
 return result;
}
const numeric=x=>/^\d+(?:\.\d+){1,3}$/.test(x);
const sourcePending=record=>!!(record.verification_pending||record.disclosure_verification_stale);
function applicability(finding){
 const pending=sourcePending(finding),product=norm(finding.technology);
 const serviced=['windows','windows server','iis','.net framework'].includes(product);
 const versionMatch=finding.level==='version_review'&&!pending&&!serviced;
 const missing=pending?'A source update is pending verification. Recheck the latest vendor advisory.':
  !String(finding.version||'').trim()||/^(unknown|n\/a|-)$/i.test(finding.version)?'Collect the exact installed product and version.':
  serviced?'Check the OS release, installed security updates and component build; a product or CLR version alone is insufficient.':
  versionMatch?'Verify platform, package provenance, installed patches and application prerequisites before deciding exposure.':
  'Verify the exact product, affected release and vendor conditions; the available evidence does not establish a version match.';
 return {code:versionMatch?'affected_version':'needs_verification',label:versionMatch?'Affected version detected':'Needs verification',reason:missing};
}
function summarize(findings){
 const matched=findings.filter(f=>applicability(f).code==='affected_version').length;
 return {total:findings.length,affected_version:matched,needs_verification:findings.length-matched};
}
function assessFinding(finding,record=finding){
 const result={...finding,verification_pending:!!record.verification_pending,disclosure_verification_stale:!!record.disclosure_verification_stale};
 if(sourcePending(record))result.level='category';
 const state=applicability(result);
 return {...result,applicability_status:state.code,applicability_label:state.label,verification_required:state.reason};
}
function structuredAssessment(asset,record){
 const product=norm(asset.technology);
 if(!/^cvie_/.test(record.source_type||'')||!(record.cvie_products||[]).some(p=>norm(p)===product))return null;
 if(sourcePending(record)||['windows','windows server','iis','.net framework'].includes(product))return 'unknown';
 const families=(record.cvie_identities||[]).filter(x=>norm(x.name)===product).map(x=>String(x.cpe).split(':').slice(0,5).join(':'));
 const ranges=(record.affected_cpes||[]).filter(x=>x.cvie_product_key?norm(x.cvie_product_key)===product:families.includes(String(x.criteria).split(':').slice(0,5).join(':')));
 // Explicit non-Windows CPE targets cannot establish exposure on a Windows agent.
 const compatible=ranges.filter(x=>asset.assessment_os!=='windows'||!['android','iphone_os','ios','mac_os','mac_os_x','macos','linux'].includes(String(x.criteria).split(':')[10]));
 if(ranges.length&&!compatible.length)return 'outside';
 const python=/^python (\d+\.\d+\.\d+) core interpreter \((?:64|32)-bit\)$/i.exec(asset.technology||'');
 if(python){
  const [major,minor,patch]=python[1].split('.').map(Number),msi=major+'.'+minor+'.'+(patch*1000+150)+'.0';
  // CPython final-release MSI encoding (PCbuild/python.props). Contradictory
  // display-name and package versions require review, never a guessed exclusion.
  if(asset.version!==python[1]&&asset.version!==msi)return 'unknown';
 }
 return cvieVersionAssessment(python?python[1]:String(asset.version||''),compatible);
}
function productAssessment(asset,product,{count=0,limited=false,available=true,months=3}={}){
 const finding=count?' · '+count+' candidate CVE'+(count===1?'':'s'):'';
 let code,label;
 if(!String(asset.version||'').trim()||/^(?:unknown|version unknown|n\/a|-)$/i.test(asset.version)){code='version_missing';label='Version unavailable — assessment incomplete';}
 else if(!available){code='unavailable';label='Assessment status unavailable';}
 else if(!product){code='unregistered';label='Waiting for product registration';}
 else if(product.status==='retrying'){code='retrying';label='Source unavailable — retry scheduled';}
 else if(!product.cpe){code=product.status==='needs_identity'?'unmapped':'resolving';label=code==='unmapped'?'Product mapping needs review':'Resolving product identity';}
 else if(['queued','scanning'].includes(product.status)){code=product.status;label=code==='queued'?'CVE check queued':'CVE check in progress';}
 else if(product.stale){code='stale';label='Saved assessment — source check overdue';}
 else if(limited||product.coverage?.limited){code='partial';label='Partial coverage — review required';}
 else if(product.status!=='ready'||!(months===12?product.history_complete_at:product.recent_complete_at)){code='pending';label='Assessment incomplete';}
 else if(count){code='candidates';label='Potential vulnerabilities — verify applicability';}
 else {code='no_match';label='No applicable matches in loaded '+months+'-month results';}
 return {code,label:label+finding};
}
// Release identity is separate from patch applicability. Never compare a Windows
// build number numerically with a marketing year. Source: Microsoft Server release info.
const serverBuildFamilies={'6.0.6001':'2008','6.0.6002':'2008','6.1.7600':'2008 R2','6.1.7601':'2008 R2','6.2.9200':'2012','6.3.9600':'2012 R2','10.0.14393':'2016','10.0.17763':'2019','10.0.20348':'2022','10.0.26100':'2025'};
function serverFamily(value){
 const text=String(value||'').trim();
 const sac=/^(?:Windows Server\s*[:,]?\s*)?version\s+(1709|1803|1809|1903|1909|2004|20H2)(?:\s+\((?:Server )?Core installation\))?$/i.exec(text);
 if(sac)return 'version '+sac[1].toUpperCase();
 const build=/^(\d+\.\d+\.\d+)(?:\.\d+)?$/.exec(text);
 if(build)return serverBuildFamilies[build[1]]||null;
 // Accept only complete product labels, not prose, ranges or future releases.
 const label=/^(?:Microsoft\s+)?(?:Windows Server\s*:?\s*)?(2003|2008|2012|2016|2019|2022|2025)(\s+R2)?((?:\s+(?:for\s+(?:x64-based|32-bit|Itanium-based)\s+Systems|Service Pack\s+[12]|Standard|Datacenter|Essentials|Enterprise|Web|Foundation|\(Core installation\)|\(Server Core installation\)))*)$/i.exec(text);
 if(!label||label[2]&&!['2003','2008','2012'].includes(label[1]))return null;
 return label[1]+(label[2]?' R2':'');
}
function windowsServerApplicability(asset,record){
 if(norm(asset.technology)!=='windows server')return 'unknown';
 const installed=serverFamily(asset.version);if(!installed)return 'unknown';
 if(sourcePending(record))return 'unknown';
 let families=[];
 const rows=(record.cna_affected||[]).filter(r=>/^(?:Microsoft\s+)?Windows Server\b/i.test(String(r.product||'')));
 if(record.cna_affected?.length&&!rows.length)return 'unknown';
 if(rows.length){
  for(const row of rows){
   const productFamily=serverFamily(row.product);
   if(productFamily===installed)return 'possible';
   if(row.defaultStatus==='affected'&&!productFamily)return 'unknown';
   if(!row.versions?.length){if(productFamily)families.push(productFamily);else return 'unknown';}
   for(const v of row.versions||[]){
    if(v.status==='unaffected')continue;
    if(v.status!=='affected'||v.changes?.length)return 'unknown';
    // An explicitly named OS family remains distinct even when its patch range
    // is complex. Generic Server labels need a complete release identity.
    const family=productFamily||(!v.lessThan&&!v.lessThanOrEqual&&serverFamily(v.version));
    if(!family)return 'unknown';families.push(family);
   }
  }
 }else{
  const raw=String(record.affected||''),text=raw.trim();
  if(!text||raw.length>=4000)return 'unknown';
  const entries=text.split(/[;\n]/).map(x=>x.trim());
  if(!/^Windows Server\b/i.test(entries[0]))return 'unknown';
  families=entries.map(serverFamily);
 }
 if(families.includes(installed))return 'possible';
 if(!families.length||families.some(x=>!x))return 'unknown';
 // Merged records may carry additional structured evidence not present in the
// display text. Never discard a candidate when that evidence is contradictory.
 for(const range of record.affected_cpes||[]){
  // CNA ranges are synthesized using the monitored product's CPE, which can
  // represent a different Server release. Check their original CNA rows below.
  if(record.cna_affected?.length&&range.cvie_product_key)continue;
  const p=String(range.criteria||'').split(':');
  if(p[3]!=='microsoft')continue;
  const named=/^windows_server_(2003|2008|2012|2016|2019|2022|2025)(_r2)?$/.exec(p[4]||'');
  if(named&&named[1]+(named[2]?' R2':'')===installed)return 'possible';
 }
 return 'outside';
}
function compare(a,b){
 if(!numeric(a)||!numeric(b))return null;
 const x=a.split('.').map(Number),y=b.split('.').map(Number);
 for(let i=0;i<Math.max(x.length,y.length);i++){
  if((x[i]||0)!==(y[i]||0))return(x[i]||0)>(y[i]||0)?1:-1;
 }
 return 0;
}
function dotnetKind(value){
 const name=norm(value).replace(/^microsoft\s+/,'');
 if(name==='.net')return 'runtime';
 if(/^\.net (?:core )?sdk\b/.test(name))return 'sdk';
 if(/^asp\.net core\b/.test(name))return 'aspnet';
 if(/^\.net (?:desktop runtime|windows desktop runtime|runtime|core runtime|core(?:\s|$)|\d|$)/.test(name))return 'runtime';
 return null;
}
// Microsoft uses "custom" for ordinary numeric .NET ranges as well as complex
// servicing statements. Interpret only explicit numeric ranges, preserving the
// original product/branch/platform; never compare SDK builds as runtime patches.
function dotnetAssessment(asset,record){
 const kind=dotnetKind(asset.technology);if(!kind)return null;
 if(sourcePending(record))return {state:'unknown',detail:'Current vendor evidence is pending verification.'};
 const rows=record.cna_affected;if(!Array.isArray(rows)||!rows.length){
  if(!/^cvie_/.test(record.source_type||''))return null;
  const product=norm(asset.technology),families=(record.cvie_identities||[]).filter(x=>norm(x.name)===product).map(x=>String(x.cpe).split(':').slice(0,5).join(':'));
  const ranges=(record.affected_cpes||[]).filter(x=>x.cvie_product_key?norm(x.cvie_product_key)===product:families.includes(String(x.criteria).split(':').slice(0,5).join(':')));
  return cvieVersionAssessment(String(asset.version||''),ranges)==='outside'?{state:'outside',detail:'Installed version is outside the structured affected ranges.'}:null;
 }
 const microsoft=rows.filter(r=>/^microsoft(?: corporation)?$/i.test(String(r.vendor||'').trim()));
 const modern=microsoft.filter(r=>dotnetKind(r.product));if(!modern.length)return null;
 const version=String(asset.version||'').trim(),installed=/^(\d+)\.(\d+)(?:\.(\d+))?$/.exec(version);
 if(!installed||sourcePending(record))return {state:'unknown',detail:'Exact installed .NET version and current vendor evidence are required.'};
 let unknown=false,within=false;const evidence=[];
 for(const row of modern){
  const product=String(row.product||''),rowKind=dotnetKind(product);
  const branch=/\b(\d+)\.(\d+)\b/.exec(product);
  const sdkStyle=(row.versions||[]).some(v=>[v.lessThan,v.lessThanOrEqual].some(x=>/^\d+\.\d+\.\d+$/.test(x||'')&&Number(x.split('.')[2])>=100));
  const ambiguousSdk=rowKind==='runtime'&&sdkStyle&&!/\bruntime\b/i.test(product);
  if(rowKind!==kind&&!(kind==='sdk'&&ambiguousSdk))continue;
  if(asset.assessment_os==='windows'){
   const platform=[product,...(row.platforms||[])].join(' ');
   if(/\blinux\b|\bmac\s*os\b/i.test(platform)&&!/\bwindows\b/i.test(platform))continue;
  }
  if(branch&&(Number(branch[1])!==Number(installed[1])||Number(branch[2])!==Number(installed[2])))continue;
  if(ambiguousSdk){unknown=true;continue;}
  if(!row.versions?.length||row.defaultStatus==='affected')unknown=true;
  for(const range of row.versions||[]){
   if(range.status==='unaffected'){unknown=true;continue;}
   if(range.status!=='affected'||range.changes?.length){unknown=true;continue;}
   const lower=String(range.version||''),upper=range.lessThan||range.lessThanOrEqual;
   if(!numeric(lower)||upper&&!numeric(upper)){unknown=true;continue;}
   const start=compare(version,lower),end=upper?compare(version,upper):null;
   if(upper&&compare(lower,upper)>=0){unknown=true;continue;}
   const matches=upper?start>=0&&(range.lessThan?end<0:end<=0):start===0;
   if(matches){within=true;evidence.push(product+': '+(upper?'>= '+lower+', '+(range.lessThan?'< ':'<= ')+upper:lower));}
  }
 }
 return within&&!unknown?{state:'within',detail:'Installed '+version+' matches the original Microsoft affected range: '+[...new Set(evidence)].join('; ')+'. Verify platform, installed component and deployment prerequisites; this is not confirmed exposure.'}:
  unknown?{state:'unknown',detail:'Original Microsoft evidence needs component or servicing verification. SDK-style versions, prereleases and complex conditions are not treated as runtime patch versions.'}:
  {state:'outside',detail:'Installed .NET component/release is outside the original Microsoft affected-product ranges.'};
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
 if(windowsServerApplicability(asset,cve)==='outside')return null;
 const dotnet=dotnetAssessment(asset,cve);if(dotnet?.state==='outside')return null;
 if(!product||!/^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+)$/i.test(String(cve.id||'')))return null;
 if((cve.cvie_excluded_products||[]).some(name=>norm(name)===product))return null;
 if(/rejected|withdrawn/i.test(String(cve.status||'')))return null;
 const cvie=/^cvie_/.test(cve.source_type||'')&&(cve.cvie_products||[]).some(name=>norm(name)===product);
 const tags=(cve.categories||[]).map(norm);
 if(!cvie&&!dotnet&&!(product.startsWith('wordpress plugin:')?tags.includes('wordpress / plugins'):(categories[product]||[product]).some(t=>tags.includes(norm(t)))))return null;
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
 const vendorAssessment=cvie||sourcePending(cve)?null:phpVendorAssessment(product,version,cve);
 if(vendorAssessment?.exclude)return null;
 if(vendorAssessment){level=vendorAssessment.level;evidence=vendorAssessment.evidence;comparisonDetail=vendorAssessment.comparison_detail;}
 if(cvie&&!dotnet){
  const result=structuredAssessment(asset,cve);
  if(result==='outside'&&!sourcePending(cve))return null;
  level=result==='within'?'version_review':'category';
  evidence=result==='within'?'CVIE product identity and a published numeric version range match. Verify vendor prerequisites and deployment before treating this as exposure.':'CVIE matched the affected product identity. Installed-version applicability still needs verification.';
  comparisonDetail=result==='within'?'Installed '+version+' is within a structured affected-version range. Complex configuration prerequisites are not evaluated.':'No unambiguous supported numeric comparison is available. Review the original advisory.';
 }
 if(dotnet){level=dotnet.state==='within'?'version_review':'category';evidence=dotnet.state==='within'?'Microsoft component and affected-version range match; deployment verification required.':'Microsoft .NET applicability requires verification.';comparisonDetail=dotnet.detail;}
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
 // Only a complete, single-product sentence is eligible for text comparison.
 // A range for a dependency or one release branch cannot establish applicability
 // for another product or branch mentioned elsewhere in the same advisory.
 const escapedProduct=rangeProduct.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
 const simpleRange=new RegExp('^(?:Microsoft\\s+)?'+escapedProduct+'(?:\\s+(?:core|runtime|versions?))?\\s+(before|prior to|earlier than|through|up to)\\s+(?:version\\s+)?(\\d+(?:\\.\\d+){1,3})\\.?$','i').test(affected.trim());
 if(!cvie&&!dotnet&&!vendorAssessment&&!distroAsset&&!['windows','windows server','iis','.net framework'].includes(product)&&!sourcePending(cve)&&simpleRange&&mentions&&numeric(version)){
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
 return assessFinding({id:String(cve.id),title:String(cve.title||cve.summary||cve.id),
 severity:String(cve.severity||'unknown'),known_exploited:!!cve.known_exploited,
 asset_id:asset.id,technology:asset.technology,version,level,evidence,
 affected,comparison_detail:comparisonDetail,
 summary:String(cve.summary||cve.title||''),remediation:String(cve.remediation||''),
 published:String(cve.published||''),updated:String(cve.updated||''),
 provenance:cve.provenance||[],kev_added:cve.kev_added||'',kev_verified_at:cve.kev_verified_at||null,
 evidence_status:cve.evidence_status||'Original advisory verification required',
 source_label:String((cve.sources||[]).find(s=>String(s.url||'').startsWith('https://'))?.label||'Original advisory'),
 source_url:(cve.sources||[]).map(s=>String(s.url||'')).find(url=>url.startsWith('https://'))||''},cve);
}
function cvieVersionAssessment(version,ranges){
 if(!numeric(version)||!ranges.length)return 'unknown';
 let unknown=false;
 for(const range of ranges){
  if(range.comparison_unsupported||range.vulnerable===false){unknown=true;continue;}
  let outside=false,uncertain=false,hasBound=false;
  const exact=String(range.criteria||'').split(':')[5];
  if(exact==='-'){unknown=true;continue;}
  const lower=range.versionStartIncluding||range.versionStartExcluding,upper=range.versionEndIncluding||range.versionEndExcluding;
  if(lower&&upper&&(compare(lower,upper)>0||compare(lower,upper)===0&&(range.versionStartExcluding||range.versionEndExcluding))){unknown=true;continue;}
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
root.CVEHARBOR_INVENTORY_MATCH={candidate,evaluate,compare,cvieVersionAssessment,windowsServerApplicability,dotnetAssessment,structuredAssessment,applicability,summarize,assessFinding,productAssessment};
})(window);
