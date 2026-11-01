// Explicit identities avoid inventing a vendor/product from descriptive text.
import brands from './brand-registry.js';
export const normalizeName=value=>String(value||'').normalize('NFKC').trim().toLowerCase().replace(/\s+/g,' ');
export function vendorKey(value){
 const key=normalizeName(value).replace(/[^a-z0-9]/g,'');
 const aliases={apachesoftwarefoundation:'apache',theapachesoftwarefoundation:'apache',microsoftcorporation:'microsoft',thephpgroup:'php',phpgroup:'php',postgresqlglobaldevelopmentgroup:'postgresql'};
 return aliases[key]||key;
}
export function productCpe(value){
 const parts=String(value||'').split(':');
 if(parts.length!==13||parts[0]!=='cpe'||parts[1]!=='2.3'||!['a','o','h'].includes(parts[2])||
    !parts.slice(3,5).every(x=>/^[a-z0-9_~.-]{1,100}$/i.test(x))||!parts.slice(5).every(x=>x==='*'))return null;
 return parts.join(':').toLowerCase();
}
export function cpeFamily(value){
 const parts=String(value||'').split(':');
 return parts.length===13?productCpe([...parts.slice(0,5),...Array(8).fill('*')].join(':')):null;
}
const known=[
 [/^(?:microsoft\s+)?(?:\.net|dotnet)\s+core$/,'a','microsoft','.net','dotnet'],
 [/^apache tomcat$|^tomcat$/,'a','apache','tomcat','apachetomcat'],
 [/^apache http server$|^apache httpd$/,'a','apache','http_server','apache'],
 [/^windows server 2022$/,'o','microsoft','windows_server_2022',''],
 [/^windows server 2019$/,'o','microsoft','windows_server_2019',''],
 [/^windows server 2016$/,'o','microsoft','windows_server_2016',''],
 [/^php$/,'a','php','php','php'],[/^wordpress(?: core)?$/,'a','wordpress','wordpress','wordpress'],
 [/^postgresql$/,'a','postgresql','postgresql','postgresql'],
 [/^mysql$/,'a','oracle','mysql','mysql'],[/^mariadb$/,'a','mariadb','mariadb','mariadb'],
 [/^redis$/,'a','redis','redis','redis'],[/^openssl$/,'a','openssl','openssl','openssl'],
 [/^gitlab$/,'a','gitlab','gitlab','gitlab'],[/^jenkins$/,'a','jenkins','jenkins','jenkins'],
 [/^fortios$|^fortinet fortios$/,'o','fortinet','fortios','fortinet'],
 [/^node\.js$|^nodejs$/,'a','nodejs','node.js','nodedotjs'],
 [/^python$/,'a','python','python','python'],[/^drupal$/,'a','drupal','drupal','drupal'],
 [/^linux kernel$/,'o','linux','linux_kernel','linux'],
];
export function knownIdentity(name,vendor=''){
 const found=known.find(([pattern])=>pattern.test(normalizeName(name)));
 if(found&&vendor&&vendorKey(vendor)!==vendorKey(found[2]))return null;
 return found?{cpe:['cpe','2.3',found[1],found[2],found[3],...Array(8).fill('*')].join(':'),icon:found[4]}:null;
}
export function curatedProductFamily(cpe){return known.some(([,part,vendor,product])=>cpe===['cpe','2.3',part,vendor,product,...Array(8).fill('*')].join(':'));}
export function logoFor(name,cpe=''){
 const known=knownIdentity(name);
 if(known?.icon)return known.icon;
 // Only curated brand identifiers; no customer-supplied image URLs or favicon requests.
 const identities=[['apache:tomcat','apachetomcat'],['apache:http_server','apache'],['microsoft:dotnet','dotnet'],
 ['wordpress:wordpress','wordpress'],['oracle:mysql','mysql'],['postgresql:postgresql','postgresql'],
 ['f5:nginx','nginx'],['nginx:nginx','nginx'],['fortinet:fortios','fortinet'],['python:python','python'],
 ['nodejs:node.js','nodedotjs'],['gitlab:gitlab','gitlab'],['jenkins:jenkins','jenkins']];
 const parts=cpe.split(':');
 const curated=identities.find(([id])=>id===parts.slice(3,5).join(':'))?.[1];
 const key=value=>String(value||'').normalize('NFKD').replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/[^a-z0-9]/g,'');
 return curated||brands[key(name)]||brands[key(parts[4])]||brands[key(parts[3])]||'';
}
export const windowsServerGroup=product=>/^(?:microsoft )?windows server(?: os)?$/.test(normalizeName(product.name));
export function directorySearch(product){
 const name=windowsServerGroup(product)?'Windows Server':normalizeName(product.name)==='maria db'?'MariaDB':product.name;
 return [product.vendor||(windowsServerGroup(product)?'Microsoft':''),name].filter(Boolean).join(' ');
}
export function identityCandidates(data,product={}){
 const options=new Map();
 for(const item of data.products||[]){
  if(item.cpe?.deprecated)continue;
  const cpe=cpeFamily(item.cpe?.cpeName);if(!cpe)continue;
  if(product.vendor&&vendorKey(cpe.split(':')[3])!==vendorKey(product.vendor))continue;
  if(windowsServerGroup(product)&&!(cpe.startsWith('cpe:2.3:o:microsoft:')&&/^windows_server(?:_|$)/.test(cpe.split(':')[4])))continue;
  if(!options.has(cpe))options.set(cpe,{cpe,label:windowsServerGroup(product)?'Microsoft '+cpe.split(':')[4].replace(/^windows_server/,'Windows Server').replaceAll('_',' ').replace(/\br2\b/ig,'R2'):cpe.split(':').slice(3,5).join(' / ').replaceAll('_',' ')});
 }
 return [...options.values()].sort((a,b)=>a.label.localeCompare(b.label));
}
