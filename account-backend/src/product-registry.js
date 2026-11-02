// Compact reviewed dictionary: no customer aliases, versions or keystrokes are persisted.
import seed from '../data/cvie-identities.json' with {type:'json'};
import {normalizeName,vendorKey,productCpe} from './product-identity.js';
export const registryRevision=seed.revision;
export const registryEnabled=env=>env.CVIE_REGISTRY_ENABLED==='true';
const keys=p=>[p.name,...p.aliases].map(normalizeName);
export function registryIdentity(id){return seed.identities.find(p=>p.id===id)||null;}
export function registryCpe(cpe){return seed.identities.find(p=>p.cpe&&p.cpe===cpe)||null;}
function distance(a,b){
 if(Math.abs(a.length-b.length)>2)return 3;
 let row=Array.from({length:b.length+1},(_,i)=>i);
 for(let i=1;i<=a.length;i++){const next=[i];for(let j=1;j<=b.length;j++)next[j]=Math.min(next[j-1]+1,row[j]+1,row[j-1]+(a[i-1]===b[j-1]?0:1));row=next;}
 return row[b.length];
}
export function searchRegistry({q='',vendor='',ecosystem='',identifier='',scheme=''}={}){
 if([q,vendor,ecosystem,identifier,scheme].some(s=>typeof s!=='string'||s.length>200||/[\u0000-\u001f]/.test(s)))throw Error('Invalid product search');
 const term=normalizeName(q),candidates=seed.identities.filter(p=>(!vendor||vendorKey(vendor)===vendorKey(p.vendor))&&(!ecosystem||p.ecosystem===ecosystem));
 const ranked=candidates.map(p=>{
  const names=keys(p),exact=identifier?scheme==='cpe'?p.cpe===identifier:p.identifiers.some(i=>i.scheme===scheme&&i.value===identifier):names.includes(term);
  const rank=exact?0:identifier?9:!term||names.some(n=>n.startsWith(term))?1:term.length>=4&&names.some(n=>distance(term,n)<=2)?2:9;
  return {...p,match:rank===0?'exact':rank===1?'prefix':'suggestion',rank};
 }).filter(p=>p.rank<9).sort((a,b)=>a.rank-b.rank||a.name.localeCompare(b.name));
 const exact=ranked.filter(p=>p.rank===0);
 return {revision:seed.revision,status:exact.length===1?'resolved':exact.length>1?'ambiguous':'unresolved',identity:exact.length===1?exact[0]:null,candidates:ranked.slice(0,20),
  guidance:exact.length>1?'Choose the vendor and exact product or component.':exact.length===1?'Add the installed version to evaluate applicability.':'Save the product as unresolved, or choose a verified suggestion. No match does not establish safety.'};
}
export function resolveRegistry(item){
 const found=item.identity_id?registryIdentity(item.identity_id):item.cpe?registryCpe(item.cpe):searchRegistry({q:item.name||item.technology||'',vendor:item.vendor||''}).identity;
 if(!found||item.vendor&&vendorKey(item.vendor)!==vendorKey(found.vendor)||item.cpe&&item.cpe!==found.cpe)return null;
 return found;
}
export function registrySeed(){return seed;}
export async function storedRegistryIdentity(env,{id,cpe}){
 const common=id?registryIdentity(id):registryCpe(cpe);if(common)return common;
 return await env.DB.prepare(`SELECT p.identity_id AS id,p.name,p.vendor,p.kind,p.ecosystem,p.version_scheme,p.revision,i.value AS cpe
  FROM cvie_identity_identifiers i JOIN cvie_identities p ON p.identity_id=i.identity_id
  WHERE i.scheme='cpe' AND ${id?'p.identity_id=?':'i.value=?'} LIMIT 1`).bind(id||cpe).first();
}
export async function registerVerifiedCpe(env,cpe){
 if(!productCpe(cpe))throw Error('Invalid source product identity');
 const saved=await storedRegistryIdentity(env,{cpe});if(saved)return saved;
 const parts=cpe.split(':'),vendor=parts[3],name=vendor+' '+parts[4].replaceAll('_',' ');
 const id='cpe-'+[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(cpe)))].map(b=>b.toString(16).padStart(2,'0')).join('');
 const provenance='https://services.nvd.nist.gov/rest/json/cpes/2.0';
 const families=['cpe:'+cpe,'name:'+vendorKey(vendor)+':'+parts[4].replace(/[^a-z0-9]/g,'')];
 await env.DB.batch([
  env.DB.prepare(`INSERT OR IGNORE INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES(?,?,?,'product','','vendor',1,?)`).bind(id,vendor,name,provenance),
  env.DB.prepare('INSERT OR IGNORE INTO cvie_identity_identifiers VALUES(?,?,?,?,1)').bind('cpe',cpe,id,provenance),
  env.DB.prepare('INSERT OR IGNORE INTO cvie_identity_aliases VALUES(?,?,?,1)').bind(normalizeName(name),id,provenance),
  ...families.map(f=>env.DB.prepare('INSERT OR IGNORE INTO cvie_identity_families VALUES(?,?)').bind(f,id))
 ]);
 return {id,name,vendor,cpe,kind:'product',ecosystem:'',version_scheme:'vendor',revision:1};
}
export async function searchDirectory(env,input){
 const result=searchRegistry(input),term=normalizeName(input.q||'');
 if(!term)return result;
 const rows=(await env.DB.prepare(`SELECT p.identity_id AS id,p.name,p.vendor,p.kind,p.ecosystem,p.version_scheme,p.revision,
  (SELECT value FROM cvie_identity_identifiers i WHERE i.identity_id=p.identity_id AND i.scheme='cpe' LIMIT 1) AS cpe,a.alias
  FROM cvie_identity_aliases a JOIN cvie_identities p ON p.identity_id=a.identity_id
  WHERE a.alias>=? AND a.alias<? ORDER BY a.alias LIMIT 21`).bind(term,term+'\uffff').all()).results||[];
 const combined=new Map(result.candidates.map(p=>[p.id,p]));
 for(const p of rows)if((!input.vendor||vendorKey(p.vendor)===vendorKey(input.vendor))&&(!input.ecosystem||p.ecosystem===input.ecosystem))combined.set(p.id,{...p,match:p.alias===term?'exact':'prefix',rank:p.alias===term?0:1});
 const candidates=[...combined.values()].sort((a,b)=>a.rank-b.rank||a.name.localeCompare(b.name)).slice(0,20),exact=candidates.filter(p=>p.match==='exact');
 return {...result,candidates,limited:rows.length>20,status:rows.length>20||exact.length>1?'ambiguous':exact.length===1?'resolved':'unresolved',identity:rows.length<=20&&exact.length===1?exact[0]:null};
}
