import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {TARGET,accessSettings} from '../target.mjs';
import {resourceManifest} from './inventory.mjs';
export const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const read=name=>JSON.parse(fs.readFileSync(path.join(root,name),'utf8'));
export function adminEmails(raw=''){
 const list=raw.split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);
 if(list.length>10||new Set(list).size!==list.length||list.some(x=>!/^[-a-z0-9._+]{1,64}@[-a-z0-9.]+\.[a-z]{2,}$/.test(x)))throw Error('Explicit administrator email list required');
 return list.join(',');
}
export function configs(env){
 const resources=resourceManifest();
 if(env.CF_STAGING_ACCOUNT_ID!==TARGET.account||env.CF_STAGING_D1_DATABASE_ID!==resources.permanent_database.uuid)throw Error('Approved permanent account/database required');
 const api=read('wrangler.api.json'),site=read('wrangler.site.json');
 const access=accessSettings(env.CF_STAGING_ACCESS_ISSUER,env.CF_STAGING_ACCESS_AUD);
 const admins=adminEmails(env.CF_STAGING_ADMIN_EMAILS||''),sha=env.CF_STAGING_APPROVED_COMMIT||'0'.repeat(40);
 if(!/^[a-f0-9]{40}$/.test(sha)||!['false','true'].includes(env.CF_STAGING_MANUAL_JOBS_ENABLED||'false'))throw Error('Invalid reviewed release configuration');
 api.vars={...api.vars,STAGING_ADMIN_EMAILS:admins,STAGING_RELEASE:sha,STAGING_MANUAL_JOBS_ENABLED:env.CF_STAGING_MANUAL_JOBS_ENABLED||'false'};
 site.vars={...site.vars,...access,STAGING_ADMIN_EMAILS:admins,STAGING_RELEASE:sha};
 api.main=path.join(root,'.build/api.mjs');api.d1_databases[0].migrations_dir=path.resolve(root,'../account-backend/migrations');
 site.main=path.join(root,'frontend.mjs');site.assets.directory=path.join(root,'.build/public');
 validate(api,site);return {api,site};
}
export function validate(api,site){
 const common=['$schema','name','account_id','main','compatibility_date','workers_dev','preview_urls','keep_vars','routes','triggers','vars','r2_buckets'];
 if(Object.keys(api).some(k=>![...common,'d1_databases','ratelimits','compatibility_flags'].includes(k))||Object.keys(site).some(k=>![...common,'assets','services'].includes(k)))throw Error('Unreviewed configuration');
 for(const [config,name] of [[api,TARGET.api],[site,TARGET.site]]){
  if(config.name!==name||config.account_id!==TARGET.account||config.compatibility_date!==TARGET.compatibility||config.keep_vars!==false||config.preview_urls!==false||config.routes?.length||config.triggers?.crons?.length)throw Error('Unexpected identity, exposure or schedules');
  if(JSON.stringify(config.r2_buckets)!==JSON.stringify([{binding:'INTELLIGENCE_BUCKET',bucket_name:resourceManifest().intelligence_bucket}]))throw Error('Unapproved staging bucket');
 }
 if(api.workers_dev!==false||site.workers_dev!==true||JSON.stringify(api.compatibility_flags)!=='["nodejs_compat"]')throw Error('Invalid runtime/exposure');
 if(api.main!==path.join(root,'.build/api.mjs')||site.main!==path.join(root,'frontend.mjs')||site.assets.directory!==path.join(root,'.build/public'))throw Error('Invalid build path');
 if(api.d1_databases?.length!==1||api.d1_databases[0].binding!=='DB'||api.d1_databases[0].database_name!==TARGET.database||api.d1_databases[0].database_id!==resourceManifest().permanent_database.uuid)throw Error('Permanent database mismatch');
 if(JSON.stringify(site.services)!==JSON.stringify([{binding:'STAGING_API',service:TARGET.api}])||site.assets.binding!=='ASSETS'||site.assets.run_worker_first!==true)throw Error('Access gate can be bypassed');
 accessSettings(site.vars.ACCESS_ISSUER,site.vars.ACCESS_AUD);
 const baseline=read('wrangler.api.json').vars;
 if(Object.keys(api.vars).length!==Object.keys(baseline).length)throw Error('Unexpected API variables');
 for(const [k,v] of Object.entries(baseline))if(!['STAGING_ADMIN_EMAILS','STAGING_RELEASE','STAGING_MANUAL_JOBS_ENABLED'].includes(k)&&api.vars[k]!==v)throw Error('Unsafe API variable');
 if(!['true','false'].includes(api.vars.STAGING_MANUAL_JOBS_ENABLED))throw Error('Invalid manual test flag');
 if(Object.keys(site.vars).sort().join(',')!==Object.keys(read('wrangler.site.json').vars).sort().join(',')||site.vars.INTELLIGENCE_SOURCE!=='r2')throw Error('Unsafe frontend variables');
 if(adminEmails(api.vars.STAGING_ADMIN_EMAILS)!==api.vars.STAGING_ADMIN_EMAILS||api.vars.STAGING_ADMIN_EMAILS!==site.vars.STAGING_ADMIN_EMAILS||api.vars.STAGING_RELEASE!==site.vars.STAGING_RELEASE||!/^[a-f0-9]{40}$/.test(api.vars.STAGING_RELEASE))throw Error('Release/admin configuration mismatch');
 if(JSON.stringify(api.ratelimits)!==JSON.stringify(read('wrangler.api.json').ratelimits))throw Error('Unexpected rate limiter');
}
export function writeConfigs(env){const out=configs(env);fs.mkdirSync(path.join(root,'.build'),{recursive:true});for(const [name,c] of Object.entries(out))fs.writeFileSync(path.join(root,'.build',name+'.json'),JSON.stringify(c,null,2)+'\n');return out;}
if(process.argv[1]===fileURLToPath(import.meta.url)){writeConfigs(process.env);console.log('Permanent staging configuration prepared locally.');}
