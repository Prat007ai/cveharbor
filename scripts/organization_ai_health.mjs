import {verifyService} from './production_service_health.mjs';

// Cloudflare can briefly serve the healthy predecessor after a successful upload.
// Retry only that exact state; recovery holds, schema failures and other builds fail immediately.
export async function verifyAfterDeployment({expectedRelease,predecessor,fetcher=fetch,wait=ms=>new Promise(r=>setTimeout(r,ms))}){
 for(let attempt=0;attempt<13;attempt++){
  let previous=false;
  const observed=async(url,options)=>{
   const response=await fetcher(url,options);
   if(url.endsWith('/release-readiness')){
    const state=await response.clone().json();
    previous=response.status===200&&state.ready===true&&state.held===false&&state.schema_ready===true&&state.release===predecessor;
   }
   return response;
  };
  try{return await verifyService({expectedRelease,fetcher:observed});}
  catch(error){
   if(!previous||error.code!=='ERR_ASSERTION'||error.message!=='Production is serving a different Worker build'||attempt===12)throw error;
   await wait(5000);
  }
 }
}
