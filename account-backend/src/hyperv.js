// Hyper-V is a Windows component, not an independent NVD CPE family.
// Host families below are verified in the public NVD Hyper-V compatibility report.
import {normalizeName,vendorKey,productCpe} from './product-identity.js';
const hosts=[
 ['windows_server_2025','Windows Server 2025'],['windows_server_2022','Windows Server 2022'],
 ['windows_server_2019','Windows Server 2019'],['windows_server_2016','Windows Server 2016'],
 ['windows_11_26h2','Windows 11 26H2'],['windows_11_26h1','Windows 11 26H1'],
 ['windows_11_25h2','Windows 11 25H2'],['windows_11_24h2','Windows 11 24H2'],['windows_11_23h2','Windows 11 23H2'],
 ['windows_10_22h2','Windows 10 22H2'],['windows_10_21h2','Windows 10 21H2'],
 ['windows_10_1809','Windows 10 1809'],['windows_10_1607','Windows 10 1607'],
];
export function isHyperV(product){
 return /^(?:(?:microsoft(?: windows)?|windows)\s+)?hyper[\s-]?v$/.test(normalizeName(product.name))&&
  (!product.vendor||vendorKey(product.vendor)==='microsoft');
}
export const hyperVHosts=()=>hosts.map(([key,title])=>({
 cpe:['cpe','2.3','o','microsoft',key,...Array(8).fill('*')].join(':'),
 label:'Microsoft '+title+' · Hyper-V',
}));
export function hyperVHost(cpe){return productCpe(cpe)?hyperVHosts().find(h=>h.cpe===cpe):undefined;}
export function hyperVHostNames(cpe){
 const host=hyperVHost(cpe);if(!host)return [];
 const name=host.label.replace(/^Microsoft /,'').replace(/ · Hyper-V$/,'');
 return [name,...(/^Windows (?:10|11) /.test(name)?[name.replace(/^(Windows (?:10|11)) /,'$1 Version ')]:[name+' (Server Core installation)'])];
}
export const hyperVHelp='Windows Hyper-V advisories are indexed under the Windows host. Select the Windows Server or Windows edition running Hyper-V; CVIE will check Hyper-V advisories for that host. Review the vendor advisory for required features and affected builds.';
export function hyperVStatement(record){return /\bwindows[\s-]+hyper[\s-]?v\b/i.test([record.title,record.summary].filter(Boolean).join(' '));}
// Fixed SQL expressions only; never interpolate user input into a query.
export function hyperVStatementSql(record){
 let text=`COALESCE(json_extract(${record},'$.title'),'')||' '||COALESCE(json_extract(${record},'$.summary'),'')`;
 for(const code of [45,95,46,44,58,59,40,41,9,10,13])text=`replace(${text},char(${code}),' ')`;
 text=`' '||lower(${text})||' '`;
 return `(instr(${text},' windows hyper v ')>0 OR instr(${text},' windows hyperv ')>0)`;
}
