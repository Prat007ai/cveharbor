(function(root){
'use strict';
const norm=v=>String(v||'').trim().toLowerCase();
const escape=v=>v.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
const names={'.net runtime':['.NET Runtime','.NET Core Runtime'],'.net desktop runtime':['.NET Desktop Runtime','Windows Desktop Runtime'],'asp.net core runtime':['ASP.NET Core'],'.net sdk':['.NET SDK'],'.net framework':['.NET Framework'],'windows server':['Windows Server'],'windows':['Windows 10','Windows 11'],'iis':['Internet Information Services','Microsoft IIS']};
const legacy=new Set(['php','wordpress','mysql','mariadb','sql server','microsoft sql server','asp.net','.net','python','azure','fortigate','fortios','docker','kubernetes','linux','ubuntu','ubuntu linux','debian','debian linux','sitefinity']);
const sourceCache=new WeakMap();
function source(record){
 if(!sourceCache.has(record))sourceCache.set(record,(record.sources||[]).find(s=>{try{return new URL(s.url).protocol==='https:';}catch{return false;}}));
 return sourceCache.get(record);
}
const productPatterns=new Map();
// Marketing releases mapped from Microsoft's Windows Server release information.
// This is a family mismatch warning, never a claim about installed KBs or exposure.
const serverBuilds={'14393':'2016','17763':'2019','20348':'2022','26100':'2025'};
function familyWarning(asset,record){
 if(norm(asset.technology)!=='windows server')return '';
 const build=/^10\.0\.(\d+)(?:\.\d+)?$/.exec(String(asset.version||'').trim()),release=build&&serverBuilds[build[1]];
 if(!release)return '';
 const affected=String(record.affected||''),families=[...affected.matchAll(/\bWindows Server\s*:?\s*(2003|2008|2012|2016|2019|2022|2025)\b/gi)].map(m=>m[1]);
 // Grouped affected-product lists may omit the product name after a semicolon.
 if(!families.length||new RegExp('\\b'+release+'\\b').test(affected))return '';
 return 'Version family mismatch: installed build '+asset.version+' identifies Windows Server '+release+', while the indexed affected text names Windows Server '+[...new Set(families)].join(', ')+'. Verify the complete vendor affected-product list before treating this as a vulnerability or recommending a patch. Build mapping: https://learn.microsoft.com/en-us/windows-server/get-started/windows-server-release-info';
}
function patterns(technology){
 if(!productPatterns.has(technology)){
  if(productPatterns.size>=1000)productPatterns.clear();
  productPatterns.set(technology,(names[norm(technology)]||[technology]).map(name=>new RegExp('(?:^|[^a-z0-9])'+escape(name)+'(?:$|[^a-z0-9])','i')));
 }
 return productPatterns.get(technology);
}
function candidate(asset,record,base){
 const product=norm(asset.technology),special=Object.hasOwn(names,product);
 // Respect exclusions before the broad affected-product fallback can recreate them.
 if(base.windowsServerApplicability(asset,record)==='outside')return null;
 const original=base.candidate(asset,record);
 if(!special&&(legacy.has(product)||product.startsWith('wordpress plugin:')))return original;
 if(!special&&original)return original;
 if(!/^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+)$/i.test(record.id||'')||/rejected|withdrawn/i.test(record.status||''))return null;
 if((record.cvie_excluded_products||[]).some(p=>norm(p)===product))return null;

 // Explicit reviewed CVIE identities retain the existing structured CPE rules.
 // OS/.NET Framework/IIS builds still require patch evidence, not a generic numeric comparison.
 if(original&&/^cvie_/.test(record.source_type||'')&&!['windows','windows server','.net framework','iis'].includes(product))return source(record)?original:null;
 const affected=String(record.affected||'');
 const aliases=patterns(asset.technology);
 if((!special&&product.length<4)||!aliases.some(pattern=>pattern.test(affected)))return null;
 const reference=source(record);if(!reference)return null;
 // Installer marketing names are not guessed into another product family.
 return {id:record.id,title:record.title||record.summary||record.id,severity:record.severity||'unknown',known_exploited:!!record.known_exploited,
  asset_id:asset.id,technology:asset.technology,version:asset.version||'',level:'category',
  evidence:'Potential product match in advisory affected-product text. Installed-version and patch applicability need verification.',
  affected,comparison_detail:familyWarning(asset,record)||'No automatic affected-version conclusion was made for this installed-product entry.',
  summary:record.summary||'',remediation:record.remediation||'',published:record.published||'',updated:record.updated||'',sources:record.sources||[],source_url:reference.url,source_label:reference.label||'Advisory source'};
}
function install(){
 const base=root.CVEHARBOR_INVENTORY_MATCH;if(!base||base.inventoryAssessment)return;
 const original={...base};
 // CVIE replaces advisory snapshots when evidence changes. Reuse product/version
 // work within a snapshot while assigning every finding to its current asset.
 const assessments=new WeakMap();
 base.candidate=(a,r)=>candidate(a,r,original);
 base.evaluate=(assets,records,limit=150)=>{
  const items=[],seen=new Set();
  const advisoryRecords=records||[];
  let cached=assessments.get(advisoryRecords);
  if(!cached||cached.length!==advisoryRecords.length){
   cached={products:new Map(),findings:0,length:advisoryRecords.length};
   assessments.set(advisoryRecords,cached);
  }
  const byProduct=cached.products;
  for(const asset of assets||[]){
   const key=JSON.stringify([asset.technology,asset.version]);
   let matches=byProduct.get(key);
   if(!matches){
    matches=[];
    for(const record of advisoryRecords){const finding=base.candidate(asset,record);if(finding)matches.push(finding);}
    // Bound retained results even for unusually broad advisory matches.
    if(byProduct.size<1000&&cached.findings+matches.length<=10000){
     byProduct.set(key,matches);cached.findings+=matches.length;
    }
   }
   for(const finding of matches){
    const identity=asset.id+'|'+finding.id;
    if(seen.has(identity))continue;
    seen.add(identity);items.push({...finding,asset_id:asset.id});
   }
  }
  const rank={critical:4,high:3,medium:2,low:1};items.sort((a,b)=>Number(b.known_exploited)-Number(a.known_exploited)||(rank[norm(b.severity)]||0)-(rank[norm(a.severity)]||0)||a.id.localeCompare(b.id));
  return {items:items.slice(0,limit),total:items.length,limited:items.length>limit};
 };base.inventoryAssessment=true;
}
const el=(tag,text='',cls='')=>{const x=document.createElement(tag);x.textContent=text;if(cls)x.className=cls;return x;};
function summary(assets,records){
 install();const engine=root.CVEHARBOR_INVENTORY_MATCH;
 if(!engine||!Array.isArray(records)||!records.length)return el('p','Assessment unavailable: the advisory index could not be loaded or is empty. Inventory remains saved; retry when the index is available.','ops-note');
 const result=engine.evaluate(assets,records,5000),matched=new Set(result.items.map(f=>f.asset_id));
 const panel=el('section','','data-panel ops-panel');panel.append(el('h2','Imported inventory assessment'),el('p',assets.length+' software entries assessed against '+records.length+' indexed advisory records. '+result.total+' potential asset/advisory matches. Checked '+new Date().toLocaleString()+'.','ops-note'),el('p','Inventory-based assessment only; no endpoint scan or AI request. No indexed match does not mean secure. Windows, IIS and .NET Framework require patch/build verification.','ops-note'));
 const review=assets.filter(a=>!a.version||!matched.has(a.id));
 if(review.length){const details=el('details'),title=el('summary',review.length+' entries need version or coverage review');details.append(title);
  for(const a of review)details.append(el('p',a.name+' · '+a.technology+' '+(a.version||'Unknown version')+' — '+(!a.version?'Installed version required.':'No indexed match; product mapping and source coverage remain unverified.')));panel.append(details);}
 if(result.limited)panel.append(el('p','Results exceed the 5,000 finding limit. Narrow the environment scope.','ops-note'));
 return panel;
}
root.CVEHARBOR_ASSESSMENT={install,summary};install();
})(typeof window==='undefined'?globalThis:window);
