// Staging-only compatibility for the audited production schema; never installed in production.
import baseline from '../release/baseline.json' with {type:'json'};
import {canonicalDDL} from '../scripts/sql_schema_tokens.mjs';
import {releaseReadiness} from '../account-backend/src/release-readiness.js';
const expected=typeof __STAGING_PRODUCTION_SCHEMA__==='undefined'?null:__STAGING_PRODUCTION_SCHEMA__;
export function productionEnvironment(safe){
 const result={...safe,STAGING_APPLICATION_PROFILE:'production-baseline',RECOVERY_CONTROL_REQUIRED:'false'};
 for(const [name,value] of Object.entries(baseline.runtime_flags.values)){
  if(name==='RECOVERY_CONTROL_REQUIRED'||/DELIVERY_ENABLED$/.test(name)||name==='ASSIGNMENT_EMAIL_ENABLED')continue;
  if(value===null)delete result[name];else result[name]=value;
 }
 return result;
}
export async function stagingReadiness(env){
 if(env.STAGING_APPLICATION_PROFILE!=='production-baseline')return releaseReadiness(env);
 let ready=false;
 try{
  const rows=(await env.DB.prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' AND name NOT GLOB '_cf_*' AND name NOT GLOB 'd1_*' ORDER BY type,name").all()).results;
  ready=env.RECOVERY_CONTROL_REQUIRED==='false'&&!!expected&&JSON.stringify(rows.map(r=>[r.type,r.name,r.tbl_name,canonicalDDL(r.sql)]))===JSON.stringify(expected)&&Number((await env.DB.prepare('SELECT COUNT(*) n FROM pragma_foreign_key_check').first()).n)===0;
 }catch{}
 return Response.json({ready,held:false,schema_ready:ready,schema:'production-baseline-209',release:baseline.backend.identity},{status:ready?200:503,headers:{'Cache-Control':'no-store'}});
}
