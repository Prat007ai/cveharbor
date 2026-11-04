import {TARGET,LEGACY_ORIGIN} from './target.mjs';
import {withStagingTransport} from './transport.mjs';
import {openIntelligenceSnapshot} from '../account-backend/src/intelligence-store.js';
import {productionEnvironment,stagingReadiness} from './production-runtime.mjs';
import {adminRoute} from './admin.mjs';
export function applicationEnvironment(env){
 const safe={DB:env.DB,ASSIGNMENT_ACK_RATE_LIMITER:env.ASSIGNMENT_ACK_RATE_LIMITER,TOTP_ENCRYPTION_KEY:env.STAGING_TOTP_ENCRYPTION_KEY,
  SMTP2GO_MONITOR_WEBHOOK_TOKEN:env.STAGING_MONITOR_WEBHOOK_TOKEN,GOOGLE_WEB_RISK_API_KEY:'staging-fixture-only',WEB_RISK_BILLING_ALERT_EMAIL:'billing@example.invalid',
  INTELLIGENCE_BUCKET:env.INTELLIGENCE_BUCKET,INTELLIGENCE_SOURCE:'r2',RECOVERY_CONTROL_REQUIRED:'true',
  REMEDIATION_WORKFLOW_ENABLED:'true',ASSIGNMENT_ACK_ENABLED:'true',ASSIGNMENT_PROGRESS_ENABLED:'true',ASSIGNMENT_FYI_ENABLED:'true',
  ASSIGNMENT_CONFIRM_ORIGIN:TARGET.origin,CVIE_METRICS_ENABLED:'true',CVIE_SHARED_SCANS_ENABLED:'true',
  CVIE_REGISTRY_ENABLED:'true',CVIE_FAST_EVIDENCE_ENABLED:'true',
  PRODUCT_MONITOR_CHECKS_ENABLED:'true',PLUGIN_MONITOR_ENABLED:'true',WEBSITE_MONITOR_ENABLED:'true',WEBSITE_MONITOR_MANUAL_ENABLED:'true',
  PRODUCT_MONITOR_TEST_ENABLED:'false',WEB_RISK_ALERT_TEST_ENABLED:'false'};
 const capture=env.STAGING_EMAIL_CAPTURE_ENABLED==='true';
 for(const k of ['ASSIGNMENT_EMAIL_ENABLED','ALERT_DELIVERY_ENABLED','LIFECYCLE_DELIVERY_ENABLED','PRODUCT_MONITOR_DELIVERY_ENABLED'])safe[k]=String(capture);
 if(capture){safe.EMAIL_FROM='CVEHarbor Staging <no-reply@cveharbor.invalid>';safe.SMTP2GO_API_KEY='staging-capture-only';safe.ALERT_SMTP2GO_API_KEY='staging-capture-only';safe.ASSIGNMENT_SMTP2GO_API_KEY='staging-capture-only';}
 return env.STAGING_APPLICATION_PROFILE==='production-baseline'?productionEnvironment(safe):safe;
}
export function createStagingAPI(application){return {
 async fetch(request,env,ctx){
  const url=new URL(request.url);
  if((url.origin!==TARGET.origin&&!(url.origin===LEGACY_ORIGIN&&url.pathname==='/v1/staging-readiness'&&request.method==='GET'))||env.STAGING_MODE!=='true')return new Response('Invalid staging target',{status:403});
  const safe=applicationEnvironment(env);
  if(new URL(request.url).pathname==='/v1/staging-readiness'){
   if(request.method!=='GET')return new Response('Method not allowed',{status:405});
   const schema=await (await stagingReadiness(safe)).json();let version=null;
   try{version=(await openIntelligenceSnapshot(safe)).version;}catch{}
   const ready=schema.schema_ready&&!!version&&env.STAGING_EMAIL_CAPTURE_ENABLED==='true'&&typeof env.STAGING_TOTP_ENCRYPTION_KEY==='string'&&env.STAGING_TOTP_ENCRYPTION_KEY.length>=32&&!!env.STAGING_MONITOR_WEBHOOK_TOKEN;
   return Response.json({ready,held:schema.held,schema_ready:schema.schema_ready,feed_version:version,release:env.STAGING_RELEASE||'unbuilt',application_profile:env.STAGING_APPLICATION_PROFILE||'candidate',mail_capture:env.STAGING_EMAIL_CAPTURE_ENABLED==='true',native_schedules:false},{status:ready?200:503,headers:{'Cache-Control':'private, no-store'}});
  }
  return withStagingTransport(env,()=>new URL(request.url).pathname.startsWith('/__staging/')?adminRoute(request,env,application,safe):application.fetch(request,safe,ctx));
 },
 async scheduled(){/* Native crons remain disabled even if someone changes a runtime flag. */}
};}
