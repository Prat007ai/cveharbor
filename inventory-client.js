// Shared complete reads for inventory, reports and Workspace. Partial pages
// never escape this module. No persistent private cache or cross-account reuse.
const origin='https://api.cveharbor.com/v1/';
const resources={inventory:['customers','environments','assets'],'finding-statuses':['statuses'],'finding-tickets':['tickets'],'plugin-sources':['sources'],'plugin-installation-status':['installations'],'plugin-monitor':['checks','releases'],'inventory/server-network':['networks'],'inventory/packages':['packages']};
export const pagedPath=path=>Object.hasOwn(resources,path.split('?')[0]);
async function json(url,options){
 const response=await fetch(url,{credentials:'include',cache:'no-store',...options});
 const data=await response.json();
 if(!response.ok){const error=Error(data.error||'Unable to load complete inventory.');error.status=response.status;throw error;}
 return data;
}
export async function readInventory(path='inventory',{signal,customer='',environment='',fetchPage,resourceList,metadataUnscoped=false}={}){
 const [base,query='']=path.split('?'),list=resourceList||resources[base];
 if(!list)throw Error('Unsupported inventory resource');
 const oldParams=new URLSearchParams(query);customer||=oldParams.get('customer_id')||'';environment||=oldParams.get('environment_id')||'';
 // Allows a website-first rollout while the protected backend release waits.
 const flags=fetchPage?{pagination:true}:await json(origin+'inventory/status',{signal});
 if(!flags.pagination)return json(origin+path,{signal});
 for(let attempt=0;attempt<3;attempt++){
  let revision=null;const result={ready:true,append_ready:true};
  try{
   async function readResource(resource,partitionEnvironment=''){
    const rows=[];let cursor=null;const seen=new Set();
    do{
     const params=new URLSearchParams({resource});
     const metadata=metadataUnscoped&&['customers','environments'].includes(resource);
     if(customer&&!metadata)params.set('customer_id',customer);if((partitionEnvironment||environment)&&!metadata)params.set('environment_id',partitionEnvironment||environment);
     if(cursor)params.set('cursor',cursor);if(revision!==null)params.set('revision',String(revision));
     const page=await (fetchPage?fetchPage(params,signal):json(origin+'inventory/page?'+params,{signal}));
     if(!Array.isArray(page.items)||page.resource!==resource||!Number.isSafeInteger(page.revision)||page.complete!==(page.next_cursor===null))throw Error('Incomplete inventory response. Refresh and retry.');
     if(revision!==null&&page.revision!==revision){const error=Error('Inventory changed while loading.');error.status=409;throw error;}
     revision=page.revision;rows.push(...page.items);cursor=page.next_cursor;
     if(cursor&&(seen.has(cursor)||seen.size>=4000))throw Error('Inventory paging did not complete.');
     if(cursor)seen.add(cursor);
    }while(cursor);
    return rows;
   }
   for(const resource of list){
    // Disjoint environment pages let a large workspace use four bounded reads
    // in flight. The environment list and every page share one revision; a
    // changed/missing partition discards the entire attempt.
    if(resource==='assets'&&!customer&&!environment&&result.environments?.length>4){
     const partitions=result.environments.map(e=>e.id),batches=new Array(partitions.length);let next=0,failure;
     await Promise.allSettled(Array.from({length:4},async()=>{while(!failure&&next<partitions.length){const i=next++;try{batches[i]=await readResource(resource,partitions[i]);}catch(error){failure=error;throw error;}}}));
     if(failure)throw failure;
     result[resource]=batches.flat();
    }else result[resource]=await readResource(resource);
   }
   if(base==='plugin-monitor'){
    const releases=new Map(result.releases.map(r=>[r.asset_id,r]));
    result.checks=result.checks.map(r=>({...r,release:releases.get(r.asset_id)||null}));delete result.releases;
   }
   if(base==='plugin-installation-status'){result.statuses=result.installations;delete result.installations;}
   for(const key of ['customers','environments'])result[key]?.sort((a,b)=>a.name.localeCompare(b.name));
   result.complete=true;result.revision=revision;return result;
  }catch(error){if(error.status!==409||attempt===2)throw error;}
 }
}

if(typeof window!=='undefined')window.CVEHARBOR_INVENTORY_CLIENT={readInventory,pagedPath};
