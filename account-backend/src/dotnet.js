// The explorer's .NET Core category explicitly covers modern .NET and SDKs.
// These distinct Microsoft CPE families are verified by the live directory probe.
import {normalizeName,vendorKey,productCpe} from './product-identity.js';
const cpe=name=>['cpe','2.3','a','microsoft',name,...Array(8).fill('*')].join(':');
const families=['.net','asp.net_core','.net_core','.net_core_sdk'].map(cpe);
export const DOTNET_PROFILE='microsoft-modern-dotnet-v1';
export const DOTNET_FAMILY='profile:microsoft:modern_dotnet';
export function dotnetProfile(product){
 if(!/^(?:microsoft\s+)?(?:\.net|dotnet)\s+core$/.test(normalizeName(product.name))||
  product.vendor&&vendorKey(product.vendor)!=='microsoft'||product.cpe&&!families.includes(productCpe(product.cpe)))return null;
 return {key:DOTNET_PROFILE,families:[...families],primary:families[0],label:'Microsoft .NET (5+), ASP.NET Core, legacy .NET Core and SDKs'};
}
export function dotnetFamilies(product){return dotnetProfile(product)?.families||[product.cpe].filter(Boolean);}
// Use only original Microsoft affected-product labels, never summary keywords.
// SQLite's GLOB keeps the original product text and version/platform conditions.
export function dotnetAffectedSql(row){
 const product=`lower(trim(json_extract(${row},'$.product')))`;
 const vendor=`lower(replace(replace(trim(json_extract(${row},'$.vendor')),' ',''),'.',''))`;
 return `(${vendor} IN('microsoft','microsoftcorporation') AND (
  ${product} IN('.net','.net core','.net core sdk','asp.net core','.net sdk','.net runtime')
  OR ${product} GLOB '.net [5-9].*' OR ${product} GLOB '.net [1-9][0-9].*'
  OR ${product} GLOB '.net core [0-9]*' OR ${product} GLOB '.net core sdk [0-9]*'
  OR ${product} GLOB 'asp.net core [0-9]*' OR ${product} GLOB 'asp.net core runtime*'
  OR ${product} GLOB '.net source-build linux tarballs*'))`;
}
