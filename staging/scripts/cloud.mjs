// Legacy initial-provisioning entrypoint retired: resources already exist.
import {diagnose} from './diagnose.mjs';
export async function runCloud(action='check',env=process.env,transport=fetch){
 if(action!=='check')throw Error('Initial provisioning retired; use the separately approved permanent release workflow.');
 return diagnose(env,transport);
}
