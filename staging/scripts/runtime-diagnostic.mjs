// GET-only observation of the partially deployed staging pair. No deployments,
// migrations, R2 writes, mail generation or credential changes.
import {TARGET} from '../target.mjs';
import {configs} from './configure.mjs';
import {management,inspectWorker} from './diagnose.mjs';
import {probeBackend} from './release.mjs';
import {safeFailure} from './errors.mjs';

export async function runtimeDiagnostic(env,{get=management(env),transport=fetch,inspect=inspectWorker,record=()=>{}}={}){
 const expected=configs(env);
 const report={mutation_requests:0,production_requests:0,workers:[],runtime:null};
 for(const [name,config] of [[TARGET.api,expected.api],[TARGET.site,expected.site]]){
  // inspectWorker selects only version IDs and fixed booleans from metadata.
  const worker=await inspect(name,config,get,{allowLegacy:true,requireKey:true});
  report.workers.push(worker);record(report);
 }
 const settings=await get(`/workers/scripts/${TARGET.api}/settings`);
 const release=(settings.bindings||[]).find(b=>b.type==='plain_text'&&b.name==='STAGING_RELEASE')?.text;
 report.backend_release_configured=typeof release==='string'&&/^[a-f0-9]{40}$/.test(release);
 report.backend_release_matches_requested=release===env.CF_STAGING_APPROVED_COMMIT;
 if(!report.backend_release_configured){report.failure={operation:'release.backend_runtime',category:'validation',check:'configured_release'};record(report);return report;}
 // Compare the running backend to its installed release, not the new diagnostic
 // workflow's SHA. No backend upload is needed to observe an older deployment.
 try{
  report.runtime=await probeBackend({...env,CF_STAGING_APPROVED_COMMIT:release},transport,{bootstrap:true,record:e=>{report.runtime=e;record(report);}});
 }catch(error){report.failure=safeFailure(error);}
 const invalid=report.workers.find(w=>!w.verified);
 if(invalid&&!report.failure)report.failure={operation:'release.worker_metadata',category:'validation',check:invalid.name===TARGET.api?'backend_metadata':'frontend_metadata'};
 report.ready=!report.failure;
 record(report);return report;
}
