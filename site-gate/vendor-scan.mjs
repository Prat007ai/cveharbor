// Microsoft tracks SQL servicing branches separately. An Ubuntu installation
// release identifies the vendor notice series; exposure depends on its packages.
function sqlAdvisory(row, version) {
  const build = Number(version.split('.')[2]);
  const branch = build >= 4000 && build < 5000 ? 'CU' : build >= 2000 && build < 3000 ? 'GDR' : null;
  const available = row.fixes.filter(f => branch && f.branch.startsWith(branch));
  const compare = (a,b) => {
    const x = a.split('.').map(Number), y = b.split('.').map(Number);
    return x[2]-y[2] || x[3]-y[3];
  };
  const fixed = available.sort((a,b) => compare(b.build,a.build))[0];
  let evidence = 'SQL Server 2019 advisory · verify servicing branch and build';
  if (fixed) evidence = compare(version, fixed.build) >= 0
    ? 'Fix included in this build · '+fixed.branch
    : 'Build predates the '+fixed.branch+' fix · check affected components';
  const url = 'https://msrc.microsoft.com/update-guide/vulnerability/'+row.id;
  return {...row, url, evidence, status:'Microsoft Security Response Center',
    severity:row.cvss == null ? 'unrated' : row.cvss >= 9 ? 'critical' : row.cvss >= 7 ? 'high' : row.cvss >= 4 ? 'medium' : 'low',
    affected:'Microsoft SQL Server 2019 for x64-based systems',
    remediation:row.fixes.map(f => f.branch+' fixed build '+f.build+(f.kb?' (KB'+f.kb+')':'')).join('\n'),
    sources:[{url,label:'Microsoft Security Update Guide'}, ...row.fixes.filter(f=>/^\d{7}$/.test(f.kb))
      .map(f=>({url:'https://support.microsoft.com/help/'+f.kb,label:f.branch+' · KB'+f.kb}))]};
}

function ubuntuNotice(row) {
  const url = 'https://ubuntu.com/security/notices/'+row.id;
  const packages = Object.entries(row.packages);
  return {id:row.id, title:row.title, published:row.published, summary:row.summary,
    evidence:'Ubuntu 24.04 package notice · verify installed packages', url, status:'Canonical Ubuntu Security Notice',
    affected:['Ubuntu 24.04 LTS (Noble)', ...packages.map(([name])=>name), row.cves.join(', ')].filter(Boolean).join('\n'),
    remediation:Object.entries(row.binaries).map(([name,version])=>name+(version?' · '+version:'')).join('\n')
      || packages.map(([name,version])=>name+(version?' · '+version:'')).join('\n'),
    sources:[{url,label:'Canonical security notice'},...row.cves.map(id=>({url:'https://ubuntu.com/security/'+id,label:id}))]};
}

export async function vendorPage(bucket, product, version, range, cursor) {
  const prefix = 'picker/vendor-v1/'+product+'/';
  async function read(key) {
    const object = await bucket.get(prefix+key+'.json');
    if (!object) throw Error('Vendor evidence is unavailable');
    return object.json();
  }
  // Pin the directory throughout pagination so a refresh cannot skip a notice.
  const [snapshot,position] = cursor ? cursor.split('.') : [null,'0'];
  const directory = await read(snapshot || 'current');
  if (directory.product !== product || !/^[a-f0-9]{64}$/.test(directory.snapshot)
      || !/^\d{4}-\d{2}-\d{2}$/.test(directory.from) || directory.from > range.start.slice(0,10) || !(Math.abs(Date.now()-Date.parse(directory.checked)) < 48*3600000))
    throw Error('Vendor evidence is incomplete or out of date');
  const months = Object.keys(directory.months).filter(m=>m >= range.start.slice(0,7) && m <= range.end.slice(0,7)).sort().reverse();
  const offset = Number(position), index = Math.floor(offset/100000);
  const start = offset%100000;
  if (!months.length) return {rows:[],next:null};
  if (index >= months.length) throw Error('Invalid vendor page');
  const hash = directory.months[months[index]];
  if (!/^[a-f0-9]{64}$/.test(hash)) throw Error('Invalid vendor month');
  const source = await read(hash);
  if (!Array.isArray(source) || source.some(r=>!r?.id || !Number.isFinite(Date.parse(r.published))))
    throw Error('Unverified vendor records');
  const records = source.filter(r=>Date.parse(r.published)>=Date.parse(range.start) && Date.parse(r.published)<=Date.parse(range.end));
  const page = records.slice(start,start+35);
  const next = start+page.length < records.length ? offset+page.length : index+1 < months.length ? (index+1)*100000 : null;
  return {rows:page.map(r=>product==='sql2019'?sqlAdvisory(r,version):ubuntuNotice(r)),
    next:next===null?null:directory.snapshot+'.'+next};
}
