import {WorkflowError} from './remediation-workflow.js';
import {administrator,owner,adminRoute} from './ai-admin.js';
import {access,allowance,assist,enabled} from './ai-allowance.js';
export async function aiRoute(req,env,user,path,{response,body,limit},ctx){
 if(env.CVEHARBOR_AI_ACCOUNTING_ENABLED!=='true')return response(path==='/v1/ai/capabilities'?{admin:false,available:false}:{error:'AI assistance is unavailable.'},path==='/v1/ai/capabilities'?200:404);
 if(path==='/v1/ai/capabilities'&&req.method==='GET')return response({available:true,personal_available:env.CVEHARBOR_AI_PERSONAL_ENABLED==='true',admin:await administrator(env,user),platform_owner:owner(env,user)});
 if(path.startsWith('/v1/ai/admin/'))return response(await adminRoute(req,env,user,path.slice('/v1/ai/admin'.length),req.method==='GET'?{}:await body(req)));
 const personal=/^\/v1\/ai\/personal\/(allowance|assistance)$/.exec(path);
 if(personal&&env.CVEHARBOR_AI_PERSONAL_ENABLED!=='true')throw new WorkflowError('Personal AI assistance is unavailable.',404);
 const match=personal?[personal[0],user.id,personal[1]]:/^\/v1\/ai\/organizations\/([^/]+)\/(allowance|assistance)$/.exec(path);
 if(!match)throw new WorkflowError('Not found.',404);
 const [,org,action]=match;await access(env.DB,user,org,undefined,!!personal);
 if(action==='allowance'&&req.method==='GET')return response({...await allowance(env.DB,org,Date.now(),!!personal),enabled:await enabled(env.DB,env,org,!!personal),scope:personal?'personal':'organization'});
 if(action!=='assistance'||req.method!=='POST')throw new WorkflowError('Not found.',404);
 if(!await limit(env,'ai-user:'+user.id,60)||!await limit(env,'ai-org:'+org,300))throw new WorkflowError('AI request limit reached. Please try later.',429);
 const pending=assist(env,user,org,await body(req),fetch,!!personal);
 ctx?.waitUntil(pending.catch(()=>{}));
 const result=await pending;
 return response(result,result.state==='blocked'?402:result.state==='held'||result.state==='released'?503:200);
}
