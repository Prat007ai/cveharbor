// Public directory reads only; never reads or changes customer catalogues or starts CVE history scans.
import assert from 'node:assert/strict';
import {directorySearch,identityCandidates} from '../account-backend/src/product-identity.js';
const product={name:'Windows Server OS'},choices=new Map();let index=0,total=Infinity,pages=0;
while(index<total&&index<10000){
 if(pages)await new Promise(resolve=>setTimeout(resolve,6600));
 const url=new URL('https://services.nvd.nist.gov/rest/json/cpes/2.0');
 url.search=new URLSearchParams({keywordSearch:directorySearch(product),resultsPerPage:'500',startIndex:String(index)});
 const response=await fetch(url,{headers:process.env.NVD_API_KEY?{apiKey:process.env.NVD_API_KEY}:{},signal:AbortSignal.timeout(45000)});
 assert.equal(response.status,200,'NVD directory request must succeed');const data=await response.json();
 assert.ok(Array.isArray(data.products)&&Number.isSafeInteger(data.totalResults)&&data.totalResults>=0);assert.equal(data.startIndex,index);
 for(const choice of identityCandidates(data,product))choices.set(choice.cpe,choice.label);
 total=data.totalResults;assert.ok(data.products.length||index>=total,'Directory page must advance');index+=data.products.length;pages++;
}
assert.ok(choices.size,'Windows Server lookup must return selectable identities');
console.log(JSON.stringify({read_only:true,source:'NVD CPE directory',query:directorySearch(product),pages,entries_checked:index,total_entries:total,complete:index>=total,choices:[...choices].map(([cpe,label])=>({cpe,label}))}));
