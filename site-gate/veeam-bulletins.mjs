// Veeam publishes fixes under both the backup product and its deployed components.
// Read the public product release notes; a support login is only needed for some payloads.
const releaseUrl='https://www.veeam.com/kb4738';
const clean=s=>s.replace(/<[^>]*>/g,' ').replace(/&nbsp;|&#160;/gi,' ').replace(/&amp;/gi,'&').replace(/\s+/g,' ').trim();

async function read(url,format){
  const response=await fetch(url,{redirect:'follow',signal:AbortSignal.timeout(12000),cf:{cacheEverything:true,cacheTtl:1800}});
  if(!response.ok)throw Error('Public Veeam evidence unavailable');
  return format==='json'?response.json():response.text();
}
export function securityIds(html){
  const releases=html.split(/<h3\b[^>]*>\s*(?:<b>)?13\.\d+\.\d+\.\d+(?:<\/b>)?\s*<\/h3>/i).slice(1);
  const ids=new Set();
  for(const release of releases){
    for(const section of release.matchAll(/<h4\b[^>]*>\s*(?:<b>)?Security(?:<\/b>)?\s*<\/h4>([\s\S]*?)(?=<h[234]\b|$)/gi)){
      for(const id of clean(section[1]).match(/\bCVE-\d{4}-\d{4,}\b/g)||[])ids.add(id);
    }
  }
  if(!releases.length||!ids.size)throw Error('Unrecognized Veeam security history');
  return [...ids].sort();
}
const impactNotices=[
  {id:'CVE-2026-98432',kb:'4966',published:'2026-11-06',lines:['12.3','13.1'],
   expected:'Linux-based helper appliances',title:'Linux kernel vulnerability in Veeam appliances',
   affected:'Linux-based helper appliances on Windows backup deployments and affected Linux appliances. Check the deployment type and kernel update.',
   remediation:'Follow KB4966 for the appropriate appliance update or private fix.'},
  {id:'KB4879',kb:'4879',published:'2026-07-14',lines:['13'],
   expected:'12.3.0.65',title:'Privilege escalation in the Veeam Updater component',
   affected:'Veeam Software Appliance and Infrastructure Appliance deployments. Check the Updater component version.',
   remediation:'Veeam identifies Updater 12.3.0.65 as the first fixed component version.'}
];
const inWindow=(date,range)=>Date.parse(date)>=Date.parse(range.start)&&Date.parse(date)<=Date.parse(range.end);
export async function veeamBulletins(version,range,after=''){
  const componentRows=[];
  let next='source:';
  if(version.startsWith('13.')){
    const ids=securityIds(await read(releaseUrl,'html'));
    const remaining=ids.filter(id=>id>after), page=remaining.slice(0,8);
    if(remaining.length>page.length)next='veeam:'+page.at(-1);
    for(let index=0;index<page.length;index+=4){
      const rows=await Promise.all(page.slice(index,index+4).map(async id=>{
        const number=id.split('-')[2],year=id.split('-')[1];
        const record=await read('https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/'+year+'/'+number.slice(0,-3)+'xxx/'+id+'.json','json');
        const metadata=record.cveMetadata;
        if(metadata?.cveId!==id)throw Error('Unexpected CVE record');
        if(metadata.state==='REJECTED')return;
        if(metadata.state!=='PUBLISHED'||!Number.isFinite(Date.parse(metadata.datePublished)))throw Error('Unverified CVE');
        if(!inWindow(metadata.datePublished,range))return;
        const cna=record.containers.cna, products=cna.affected.map(a=>a.product);
        // The catalogue already ingests records that name Backup & Replication directly.
        if(cna.affected.some(a=>/^veeam(?: software)?$/i.test(a.vendor)&&/^(?:veeam )?backup (?:and|&) replication/i.test(a.product)))return;
        const url='https://www.cve.org/CVERecord?id='+id;
        return {id,published:metadata.datePublished,title:cna.title||id,summary:cna.descriptions.find(d=>d.lang==='en')?.value,
          affected:products.join(', '),url:releaseUrl,status:'Veeam release notes · KB4738',
          evidence:'Deployment or component advisory · check component, build and configuration',scope:'optional',
          sources:[{url:releaseUrl,label:'Veeam 13 release history'},{url,label:'CVE Program record'}]};
      }));
      componentRows.push(...rows.filter(Boolean));
    }
  }
  for(const notice of after?[]:impactNotices){
    const published=notice.published+'T00:00:00Z';
    if(!notice.lines.some(line=>version.startsWith(line+'.'))||!inWindow(published,range))continue;
    const url='https://www.veeam.com/kb'+notice.kb;
    const body=clean(await read(url,'html'));
    if(!body.includes(notice.expected)||!body.includes(notice.published)||!body.includes(notice.id==='KB4879'?'Veeam Updater':notice.id))
      throw Error('Veeam impact statement could not be verified');
    componentRows.push({id:notice.id,published,title:notice.title,affected:notice.affected,remediation:notice.remediation,url,
      scope:'optional',status:'Veeam impact statement · KB'+notice.kb,evidence:'Deployment-specific · verify appliance or helper components',
      sources:[{url,label:'Veeam impact statement'}]});
  }
  return {rows:[],componentRows,next};
}
