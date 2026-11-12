(function(root){
'use strict';
const norm=v=>String(v||'').trim().toLowerCase();
const escape=v=>v.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
const names={'.net runtime':['.NET Runtime','.NET Core Runtime'],'.net desktop runtime':['.NET Desktop Runtime','Windows Desktop Runtime'],'asp.net core runtime':['ASP.NET Core'],'.net sdk':['.NET SDK'],'.net framework':['.NET Framework'],'windows server':['Windows Server'],'windows':['Windows 10','Windows 11'],'iis':['Internet Information Services','Microsoft IIS']};
function source(record){return (record.sources||[]).find(s=>{try{return new URL(s.url).protocol==='https:';}catch{return false;}});}
function candidate(asset,record,base){
 const product=norm(asset.technology),special=Object.hasOwn(names,product);
 const original=base.candidate(asset,record);
 const legacy=new Set(['php','wordpress','mysql','mariadb','sql server','microsoft sql server','asp.net','.net','python','azure','fortigate','fortios','docker','kubernetes','linux','ubuntu','ubuntu linux','debian','debian linux','sitefinity']);
 if(!special&&(legacy.has(product)||product.startsWith('wordpress plugin:')))return original;
 if(!special&&original)return original;
 if(!/^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+)$/i.test(record.id||'')||/rejected|withdrawn/i.test(record.status||''))return null;
 if((record.cvie_excluded_products||[]).some(p=>norm(p)===product))return null;
 const reference=source(record);if(!reference)return null;
 // Explicit reviewed CVIE identities retain the existing structured CPE rules.
 // OS/.NET Framework/IIS builds still require patch evidence, not a generic numeric comparison.
 if(original&&/^cvie_/.test(record.source_type||'')&&!['windows','windows server','.net framework','iis'].includes(product))return original;
 const affected=String(record.affected||'');
 const aliases=names[product]||[asset.technology];
 if((!special&&product.length<4)||!aliases.some(name=>new RegExp('(?:^|[^a-z0-9])'+escape(name)+'(?:$|[^a-z0-9])','i').test(affected)))return null;
 // Installer marketing names are not guessed into another product family.
 return {id:record.id,title:record.title||record.summary||record.id,severity:record.severity||'unknown',known_exploited:!!record.known_exploited,
  asset_id:asset.id,technology:asset.technology,version:asset.version||'',level:'category',
  evidence:'Potential product match in advisory affected-product text. Installed-version and patch applicability need verification.',
  affected,comparison_detail:'No automatic affected-version conclusion was made for this installed-product entry.',
  summary:record.summary||'',remediation:record.remediation||'',published:record.published||'',updated:record.updated||'',sources:record.sources||[],source_url:reference.url,source_label:reference.label||'Advisory source'};
}
function install(){
 const base=root.CVEHARBOR_INVENTORY_MATCH;if(!base||base.inventoryAssessment)return;
 const original={...base};
 base.candidate=(a,r)=>candidate(a,r,original);
 base.evaluate=(assets,records,limit=150)=>{
  const items=[],seen=new Set();for(const a of assets||[])for(const r of records||[]){const f=base.candidate(a,r);if(!f)continue;const k=a.id+'|'+f.id;if(seen.has(k))continue;seen.add(k);items.push(f);}
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
