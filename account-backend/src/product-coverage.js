// Shared coverage contract for every registered product. Provider-specific naming
// belongs in reviewed adapters; the scanner consumes the same plan for all of them.
import {normalizeName,productCpe,vendorKey} from './product-identity.js';
import {dotnetProfile,dotnetFamilyLabel,DOTNET_FAMILY,dotnetAffectedSql} from './dotnet.js';
import {isHyperV,hyperVHost} from './hyperv.js';
export const COVERAGE_VERSION='cvie-product-coverage-v1';
export const DISCOVERY_PAGES=3;
export const catalogueNames=[
 'Windows Server OS','Windows 11 OS','.NET / ASP.NET','.NET Core','WordPress / Plugins','Linux','PHP','Python / PyPI','Azure','Microsoft 365','Exchange SE','SQL Server','MySQL / MariaDB','Fortinet','Sophos Firewall','VMware','Veeam Backup & Replication','HyperV','Docker / Kubernetes','Progress Telerik','Sitefinity','Angular','React / Next.js','JavaScript / TypeScript','jQuery / Bootstrap','Kendo UI','SharePoint / SharePoint Server','Microsoft Power Platform','Dynamics 365','Microsoft Fabric / Power BI','Azure AI / AI SDK','NoSQL / MongoDB','AWS','iOS / Android','Node.js / npm','Drupal / CMS','Application dependencies','Windows',
];
const collections=new Set(catalogueNames.filter(n=>!['PHP','.NET Core','HyperV'].includes(n)).map(normalizeName));
export const catalogueKind=name=>normalizeName(name)==='.net core'?'reviewed_group':normalizeName(name)==='hyperv'?'host_component':collections.has(normalizeName(name))?'collection':'product';
export function familyLabel(value){const parts=String(value).split(':');return parts.slice(3,5).join(' / ').replaceAll('_',' ');}
export function rawProductLabels(product){
 const parts=String(product.cpe||'').split(':');
 const labels=parts.length===13?[parts[4].replaceAll('_',' '),(parts[3]+' '+parts[4]).replaceAll('_',' ')]:[product.name];
 if(parts[3]==='microsoft'){
  const name=parts[4].replaceAll('_',' ');
  if(/^windows server 20\d{2}(?: r2)?$/.test(name))labels.push(name+' (Server Core installation)');
  if(/^windows (?:10|11) /.test(name))labels.push(name.replace(/^(windows (?:10|11)) /,'$1 version '));
 }
 return [...new Set(labels.map(normalizeName))];
}
export function coveragePlan(product){
 const dotnet=dotnetProfile(product),hyperv=isHyperV(product),selected=productCpe(product.cpe),kind=catalogueKind(product.name);
 const conflict=Boolean(selected&&product.vendor&&vendorKey(product.vendor)!==vendorKey(selected.split(':')[3]));
 const families=dotnet?dotnet.families:selected&&(!hyperv||hyperVHost(selected))?[selected]:[];
 const type=conflict?'identity_conflict':!families.length?'unresolved':dotnet?'reviewed_group':hyperv?'host_component':['collection','reviewed_group'].includes(kind)?'selected_member':'product';
 const terms=dotnet?['.NET','ASP.NET Core']:hyperv?['Windows Hyper-V']:families.length?[families[0].split(':')[4].replaceAll('_',' ')]:[];
 const label=dotnet?.label||hyperVHost(selected)?.label||families.map(familyLabel).join('; ')||'Exact vendor and product not confirmed';
 const key=dotnet?.key||type;
 const signature=JSON.stringify([COVERAGE_VERSION,key,families,terms,hyperv?'windows_hyperv':'']);
 return {key,signature,type,families,terms,label,primary:dotnet?.primary||selected||'',profile:dotnet?.key||null,
  component:hyperv?'windows_hyperv':'',familyLabel:dotnet?dotnetFamilyLabel:familyLabel,
  notes:conflict?['The selected product identity conflicts with its vendor. Confirm the vendor/product before using the results.']:
   type==='selected_member'?['This is a broad catalogue category. Only the selected product is checked; related products, services and dependencies require their own verified identities.']:
   !families.length?['Choose an exact vendor/product identity before CVIE can establish product coverage.']:
   ['Coverage is limited to the listed source identities. Related products and future renames require verified mappings.']};
}
export function coverageMetadata(plan,cursor={}){return {coverage_signature:plan.signature,...(plan.profile?{profile:plan.profile}:{}),...(cursor.discovery_limited?{discovery_limited:true}:{})};}
export function sourceWorkTypes(plan){return [...plan.families.map(cpe=>({cpe})),...plan.terms.map(disclosures=>({disclosures}))];}
export function coverageSummary(product){
 const plan=coveragePlan(product),cursor=JSON.parse(product.cursor_json||'{}');
 return {kind:plan.type,label:plan.label,families:plan.families,identities:plan.families.map(cpe=>({cpe,label:plan.familyLabel(cpe)})),discovery_terms:plan.terms,notes:[...plan.notes,
  ...(cursor.discovery_limited?['Additional disclosure discovery reached its per-window limit. Saved matches remain available; original disclosure history is not exhaustive.']:[])],
  limited:plan.type==='selected_member'||plan.type==='unresolved'||plan.type==='identity_conflict'||Boolean(cursor.discovery_limited),
  version:COVERAGE_VERSION,discovery_limited:Boolean(cursor.discovery_limited)};
}
// A source may append a release number to an exact product label. Keep the
// boundary and punctuation: AB is not A.B; MySQL is not MySQL Connector.
export function versionedLabelSql(row,labels){
 // D1 limits expression depth to 100. Materialize each transformation so SQLite
 // cannot inline repeated release parsing into every version-bound comparison.
 return `EXISTS(WITH product_label AS MATERIALIZED (
   SELECT lower(trim(replace(json_extract(${row},'$.product'),'_',' '))) AS product_text
  ), label_suffixes AS MATERIALIZED (
   SELECT label.value AS label,product_text,ltrim(substr(product_text,length(label.value)+1)) AS suffix
   FROM product_label,json_each(${labels}) label
  ), label_releases AS MATERIALIZED (
   SELECT *,substr(suffix,1,instr(suffix||' ',' ')-1) AS release FROM label_suffixes
  ) SELECT 1 FROM label_releases WHERE product_text=label OR (
   substr(product_text,1,length(label))=label AND substr(product_text,length(label)+1,1)=' '
   AND substr(suffix,1,1) GLOB '[0-9]' AND EXISTS(
    SELECT 1 FROM json_each(json_extract(${row},'$.versions')) v,json_each(v.value) bound
    WHERE bound.key IN('version','lessThan','lessThanOrEqual') AND (
     lower(bound.value)=release OR lower(substr(bound.value,1,length(release)+1)) IN(release||'.',release||'-')))))`;
}
export const cnaCoverageAdapters=[{key:DOTNET_FAMILY,matchSql:dotnetAffectedSql}];
