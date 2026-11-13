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
 const dotnet=base.dotnetAssessment(asset,record);
 if(dotnet?.state==='outside')return null;
 if(!dotnet&&base.structuredAssessment(asset,record)==='outside')return null;
 const original=base.candidate(asset,record);
 if(dotnet&&original)return source(record)?original:null;
 if(!special&&(legacy.has(product)||product.startsWith('wordpress plugin:')))return original;
 if(!special&&original)return original;
 if(!/^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+)$/i.test(record.id||'')||/rejected|withdrawn/i.test(record.status||''))return null;
 if((record.cvie_excluded_products||[]).some(p=>norm(p)===product))return null;

 // Explicit reviewed CVIE identities retain the existing structured CPE rules.
 // OS/.NET Framework/IIS builds still require patch evidence, not a generic numeric comparison.
 if(original&&/^cvie_/.test(record.source_type||''))return source(record)?original:null;
 const affected=String(record.affected||'');
 const aliases=patterns(asset.technology);
 if((!special&&product.length<4)||!aliases.some(pattern=>pattern.test(affected)))return null;
 const reference=source(record);if(!reference)return null;
 // Installer marketing names are not guessed into another product family.
 return {id:record.id,title:record.title||record.summary||record.id,severity:record.severity||'unknown',known_exploited:!!record.known_exploited,
  asset_id:asset.id,technology:asset.technology,version:asset.version||'',level:'category',
  evidence:'Potential product match in advisory affected-product text. Installed-version and patch applicability need verification.',
  affected,comparison_detail:dotnet?.detail||familyWarning(asset,record)||(product==='.net framework'?'Windows-serviced .NET Framework requires the installed Release registry value and applicable Windows/.NET update evidence. CLR compatibility versions alone cannot establish exposure.':'No automatic affected-version conclusion was made for this installed-product entry.'),
  summary:record.summary||'',remediation:record.remediation||'',published:record.published||'',updated:record.updated||'',verification_pending:!!record.verification_pending,disclosure_verification_stale:!!record.disclosure_verification_stale,sources:record.sources||[],source_url:reference.url,source_label:reference.label||'Advisory source'};
}
function install(){
 const base=root.CVEHARBOR_INVENTORY_MATCH;if(!base||base.inventoryAssessment)return;
 const original={...base};
 // CVIE replaces advisory snapshots when evidence changes. Reuse product/version
 // work within a snapshot while assigning every finding to its current asset.
 const assessments=new WeakMap();
 base.candidate=(a,r)=>{const finding=candidate(a,r,original);return finding?base.assessFinding(finding,r):null;};
 function* evaluate(assets,records,limit=150){
  let work=0;
  const items=[],streams=[],duplicateIds=new Map(),assetCounts=new Map();
  const rank={critical:4,high:3,medium:2,low:1};
  const compare=(a,b)=>b.priority-a.priority||a.finding.id.localeCompare(b.finding.id);
  // Rank each product/version once, then merge only the requested result window.
  // Do not allocate and sort the full asset x advisory Cartesian product.
  for(const asset of assets||[]){assetCounts.set(asset.id,(assetCounts.get(asset.id)||0)+1);if(++work%128===0)yield;}
  const advisoryRecords=records||[];
  let cached=assessments.get(advisoryRecords);
  if(!cached||cached.length!==advisoryRecords.length){
   cached={products:new Map(),findings:0,length:advisoryRecords.length};
   assessments.set(advisoryRecords,cached);
  }
  const byProduct=cached.products,requestProducts=new Map();
  const windowsHosts=new Set((assets||[]).filter(a=>a.name&&a.environment_id&&norm(a.technology)==='windows server').map(a=>JSON.stringify([a.environment_id,a.name])));
  for(const rawAsset of assets||[]){
   const asset=windowsHosts.has(JSON.stringify([rawAsset.environment_id,rawAsset.name]))?{...rawAsset,assessment_os:'windows'}:rawAsset;
   const key=JSON.stringify([asset.technology,asset.version,asset.assessment_os]);
   let matches=byProduct.get(key)||requestProducts.get(key);
   if(!matches){
    matches=[];const ids=new Set();
    for(const record of advisoryRecords){
     const finding=base.candidate(asset,record);
     if(finding&&!ids.has(finding.id)){ids.add(finding.id);matches.push({finding,priority:Number(!!finding.known_exploited)*5+(rank[norm(finding.severity)]||0)});}
     if(++work%128===0)yield;
    }
    matches.sort(compare);
    // Reuse repeated products within this assessment even when the retained
    // cross-render cache is full; streams must not duplicate their match lists.
    requestProducts.set(key,matches);
    // Bound retained results even for unusually broad advisory matches.
    if(byProduct.size<1000&&cached.findings+matches.length<=10000){
     byProduct.set(key,matches);cached.findings+=matches.length;
    }
   }
   if(assetCounts.get(asset.id)>1){
    let seen=duplicateIds.get(asset.id);if(!seen){seen=new Set();duplicateIds.set(asset.id,seen);}
    const unique=[];
    for(const match of matches){if(!seen.has(match.finding.id)){seen.add(match.finding.id);unique.push(match);}if(++work%128===0)yield;}
    matches=unique;
   }
   if(matches.length)streams.push({matches,assetId:asset.id,index:0,order:streams.length});
   if(++work%128===0)yield;
  }
  const total=streams.reduce((n,s)=>n+s.matches.length,0),heap=[];
  const before=(a,b)=>compare(a.matches[a.index],b.matches[b.index])||a.order-b.order;
  const push=stream=>{let i=heap.length;heap.push(stream);while(i){const parent=(i-1)>>1;if(before(heap[parent],stream)<=0)break;heap[i]=heap[parent];i=parent;}heap[i]=stream;};
  const pop=()=>{const first=heap[0],last=heap.pop();if(heap.length){let i=0;while(i*2+1<heap.length){let child=i*2+1;if(child+1<heap.length&&before(heap[child+1],heap[child])<0)child++;if(before(last,heap[child])<=0)break;heap[i]=heap[child];i=child;}heap[i]=last;}return first;};
  for(const stream of streams){push(stream);if(++work%128===0)yield;}
  // Match Array.slice's previous handling of negative limits as well.
  const end=Math.trunc(Number(limit)),count=Number.isNaN(end)?0:end<0?Math.max(0,total+end):Math.min(total,end);
  while(items.length<count&&heap.length){
   const stream=pop();items.push({...stream.matches[stream.index].finding,asset_id:stream.assetId});
   if(++stream.index<stream.matches.length)push(stream);
   if(++work%128===0)yield;
  }
  return {items,total,limited:total>limit};
 }
 base.evaluate=(...args)=>{const task=evaluate(...args);let step;do{step=task.next();}while(!step.done);return step.value;};
 base.evaluateAsync=async(assets,records,limit=150,{cancelled=()=>false}={})=>{
  const task=evaluate(assets,records,limit);
  const pause=()=>root.scheduler?.yield?root.scheduler.yield():new Promise(resolve=>setTimeout(resolve,0));
  try{
   await pause();let started=Date.now();
   for(;;){
    if(cancelled()){const error=new Error('Assessment cancelled');error.name='AbortError';throw error;}
    const step=task.next();if(step.done)return step.value;
    if(Date.now()-started>=8){await pause();started=Date.now();}
   }
  }finally{task.return();}
 };
 base.inventoryAssessment=true;
}
const el=(tag,text='',cls='')=>{const x=document.createElement(tag);x.textContent=text;if(cls)x.className=cls;return x;};
function summary(assets,records,assessment){
 install();const engine=root.CVEHARBOR_INVENTORY_MATCH;
 if(!engine||!Array.isArray(records)||!records.length)return el('p','Assessment unavailable: the advisory index could not be loaded or is empty. Inventory remains saved; retry when the index is available.','ops-note');
 const result=assessment||engine.evaluate(assets,records,5000),matched=new Set(result.items.map(f=>f.asset_id));
 const panel=el('section','','data-panel ops-panel');panel.append(el('h2','Imported inventory assessment'),el('p',assets.length+' software entries assessed against '+records.length+' indexed advisory records. '+result.total+' potential asset/advisory matches. Checked '+new Date().toLocaleString()+'.','ops-note'),el('p','Inventory-based assessment only; no endpoint scan or AI request. No indexed match does not mean secure. Windows, IIS and .NET Framework require patch/build verification.','ops-note'));
 const states=engine.summarize(result.items);panel.append(el('p',states.affected_version+' affected version detected · '+states.needs_verification+' need verification'+(result.limited?' (available results only)':'')+'. Applicability is separate from saved remediation status.','applicability-summary'));
 const review=assets.filter(a=>!a.version||!matched.has(a.id));
 if(review.length){const details=el('details'),title=el('summary',review.length+' entries need version or coverage review');details.append(title);
  const body=el('div'),pager=el('div'),previous=el('button','Previous entries'),next=el('button','Next entries'),count=el('span');let page=0,built=false;
  previous.type=next.type='button';pager.append(previous,count,next);details.append(body,pager);pager.hidden=true;
  function draw(){body.replaceChildren();for(const a of review.slice(page*50,(page+1)*50))body.append(el('p',a.name+' · '+a.technology+' '+(a.version||'Unknown version')+' — '+(!a.version?'Installed version required.':'No indexed match; product mapping and source coverage remain unverified.')));count.textContent=' '+(page*50+1)+'–'+Math.min((page+1)*50,review.length)+' of '+review.length+' ';previous.disabled=page===0;next.disabled=(page+1)*50>=review.length;pager.hidden=review.length<=50;built=true;}
  previous.onclick=()=>{page--;draw()};next.onclick=()=>{page++;draw()};details.addEventListener('toggle',()=>{if(details.open&&!built)draw()});panel.append(details);}
 if(result.limited)panel.append(el('p','Results exceed the 5,000 finding limit. Narrow the environment scope.','ops-note'));
 return panel;
}
root.CVEHARBOR_ASSESSMENT={install,summary};install();
})(typeof window==='undefined'?globalThis:window);
