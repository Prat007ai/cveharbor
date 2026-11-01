// Live vendor contract probe only. No D1 access, subscriptions or email.
import {SOURCE_REGISTRY,sourceFor,fetchVendor,monitorIdentity,normalizeVendor} from '../account-backend/src/monitor-sources.js';
const report=[];
for(const [slug,branch] of [['dotnet','8.0'],['wordpress','6.8'],['php','8.4']]){
 try{const source=sourceFor(slug,branch),raw=await fetchVendor(source),record=normalizeVendor(source.adapter,raw,monitorIdentity({slug,product:source.name,cycle:branch}));report.push({slug,ok:true,record});}
 catch{report.push({slug,ok:false,state:'Source Verification Required'});}
}
console.log(JSON.stringify({checked_at:new Date().toISOString(),production_writes:0,report},null,2));if(report.some(r=>!r.ok))process.exitCode=1;
