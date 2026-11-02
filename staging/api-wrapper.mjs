import { TARGET } from './target.mjs';
const disabled = ['ASSIGNMENT_EMAIL_ENABLED', 'ALERT_DELIVERY_ENABLED', 'LIFECYCLE_DELIVERY_ENABLED', 'PRODUCT_MONITOR_DELIVERY_ENABLED', 'PRODUCT_MONITOR_TEST_ENABLED', 'PRODUCT_MONITOR_CHECKS_ENABLED', 'PLUGIN_MONITOR_ENABLED', 'WEBSITE_MONITOR_ENABLED', 'WEBSITE_MONITOR_MANUAL_ENABLED', 'WEB_RISK_ALERT_TEST_ENABLED'];
export function createStagingAPI(application) {
  return {
    async fetch(request, env, ctx) {
      if (new URL(request.url).origin !== TARGET.origin || env.STAGING_MODE !== 'true') return new Response('Invalid staging target', { status: 403 });
      // A positive allowlist prevents any accidental production/provider credentials reaching application code.
      const safe = { DB: env.DB, ASSIGNMENT_ACK_RATE_LIMITER: env.ASSIGNMENT_ACK_RATE_LIMITER, TOTP_ENCRYPTION_KEY: env.TOTP_ENCRYPTION_KEY,
        CVIE_METRICS_ENABLED: 'true', CVIE_SHARED_SCANS_ENABLED: 'true', REMEDIATION_WORKFLOW_ENABLED: 'true',
        ASSIGNMENT_ACK_ENABLED: 'true', ASSIGNMENT_PROGRESS_ENABLED: 'true', ASSIGNMENT_FYI_ENABLED: 'true',
        CVIE_REGISTRY_ENABLED: env.CVIE_REGISTRY_ENABLED === 'true' ? 'true' : 'false',
        CVIE_FAST_EVIDENCE_ENABLED: env.CVIE_REGISTRY_ENABLED === 'true' && env.CVIE_FAST_EVIDENCE_ENABLED === 'true' ? 'true' : 'false' };
      for (const name of disabled) safe[name] = 'false';
      return application.fetch(request, safe, ctx);
    },
    async scheduled() { /* Deliberately never invoke application.scheduled, regardless of cron/flags. */ },
  };
}
