// Supplemental product history includes fixes issued during the requested window.
const distributionIds = new Set(['ubuntu','debian','rhel','almalinux','rocky-linux','oracle-linux','sles','opensuse','amazon-linux','fedora','centos-stream','alpine-linux','android']);
const majorOnly = new Set(['debian','almalinux','rocky-linux','oracle-linux','amazon-linux','fedora','android']);
export function scopes(id,version){
  const [major,minor]=version.split('.');
  const series=[major,minor].filter(Boolean).join('.');
  if(id==='rhel')return [...new Set([id+'@'+major,id+'@'+series])];
  if(distributionIds.has(id))return [id+'@'+(majorOnly.has(id)?major:series)];
  if(['sdk','runtime','aspnet'].includes(id))return [id,id+'@'+series];
  return [id];
}

function numeric(version){return /^\d+(?:\.\d+){0,3}$/.test(version);}
function compare(a,b){
  const left=a.split('.').map(Number),right=b.split('.').map(Number);
  for(let i=0;i<Math.max(left.length,right.length);i++)if((left[i]||0)!==(right[i]||0))return (left[i]||0)-(right[i]||0);
  return 0;
}
export function label(row,id,version) {
  if(row.vendorFixes?.[version])return {...row,evidence:'Fix included in this vendor build · '+row.vendorFixes[version]};
  if(!row.ranges?.length)return row;
  const {ranges,...item}=row;
  // These products use vendor servicing tracks, downstream backports or build IDs.
  // A numeric comparison across those tracks would overstate applicability.
  if(['esxi','linux','maria','forti','sophos','sql','sql2025','sql2017','sql2016','sql2014'].includes(id))return item;
  const windows=['server','win11','hyperv'].includes(id);
  const installed=windows&&!version.startsWith('10.0.')?'10.0.'+version:version;
  if(!numeric(installed))return item;
  const matches=ranges.some(([lo,hi,inclusive])=>numeric(lo)&&numeric(hi)
    && (!windows||installed.split('.')[2]===hi.split('.')[2])
    && compare(installed,lo)>=0 && (inclusive?compare(installed,hi)<=0:compare(installed,hi)<0));
  if(matches)item.evidence='Installed version falls in a published affected range · verify configuration';
  return item;
}

export async function cataloguePage(bucket,id,version,range,cursor) {
  async function read(name) {
    const object=await bucket.get('picker/history-v1/'+name+'.json');
    if(!object)throw Error('Missing vendor history');
    return object.json();
  }
  const [snapshot,offset]=cursor?cursor.split('.'):[null,'0'];
  const index=await read(snapshot||'current');
  if(!index.audited?.includes(id)||!/^[a-f0-9]{64}$/.test(index.snapshot)||!/^\d{4}-\d{2}-\d{2}$/.test(index.from)||index.from>range.start.slice(0,10)||
    !(Math.abs(Date.now()-Date.parse(index.checked))<72*3600000))throw Error('Vendor history is incomplete');
  const keys=scopes(id,version);
  const componentKey=id==='npm' ? 'npm@'+version+'~components' : id+'~components';
  const hasComponents=Object.hasOwn(index.products,componentKey);
  const hasReleaseHistory=keys.some(k=>Object.hasOwn(index.products,k));
  if(hasComponents)keys.push(componentKey);
  const pages=keys.flatMap(k=>index.products[k]||[]).filter(([first,last])=>
    first<=range.end.slice(0,10)&&last>=range.start.slice(0,10)).sort((a,b)=>b[1].localeCompare(a[1]));
  const pos=Number(offset);
  let rows=[];
  if(pages.length){
    const hash=pages[pos]?.[2];
    if(!/^[a-f0-9]{64}$/.test(hash||''))throw Error('Invalid history page');
    const start=Date.parse(range.start),end=Date.parse(range.end);
    const records=await read(hash);
    if(!Array.isArray(records)||records.some(r=>!r?.id||!Number.isFinite(Date.parse(r.published))))throw Error('Unverified history rows');
    rows=records.filter(r=>Date.parse(r.published)>=start&&Date.parse(r.published)<=end).map(r=>label(r,id,version));
  }
  let coverage='Includes published product advisories. Check the evidence for applicability to your installed version.';
  if(distributionIds.has(id))coverage=hasReleaseHistory
    ? 'Distribution notices cover packages for this release. Verify the installed package and patch level.'
    : 'Package-notice coverage is unverified for this release. Check the distribution’s security records.';
  if(id==='sophos')coverage='Includes reviewed Sophos Firewall bulletins and indexed CVEs. Check the vendor for additional hotfix notices.';
  if(['sql2014','sql2016'].includes(id))coverage='Public Microsoft bulletins checked. Extended Security Updates may depend on your ESU entitlement. Check the updates offered for your enrolled instance.';
  if(id==='npm')coverage=hasComponents?'Includes a separate check of the dependencies shipped in this exact npm release.':'Bundled dependencies have not been verified for this npm build.';
  if(id==='react'||id==='sitefinity')coverage=hasComponents?'Review optional component notices against the separately installed component version.':'Optional component coverage is unavailable.';
  const componentRows=rows.filter(r=>r.scope==='bundled'||r.scope==='optional');
  const coverageGaps=[];
  if(distributionIds.has(id)&&!hasReleaseHistory)coverageGaps.push(coverage);
  if(['npm','sitefinity','react'].includes(id)&&!hasComponents)coverageGaps.push(coverage);
  if(id==='sophos')coverageGaps.push('Check the Sophos Firewall console for hotfixes offered to this device.');
  return {rows:rows.filter(r=>!r.scope),componentRows,coverage,coverageGaps,next:pos+1<pages.length?index.snapshot+'.'+(pos+1):'source:'};
}
