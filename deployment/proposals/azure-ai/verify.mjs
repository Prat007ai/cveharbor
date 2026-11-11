import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { AzureConnectionError, azureConfiguration, azureAccessToken,
  verifyAzureAccess, azureCompletion } from './client.mjs';

export const fictionalPrompt = 'Northstar Demo is a fictional customer running PHP 8.2 on Ubuntu 24.04 with Apache. PHP was installed using apt. We have no CVE number, vendor advisory, or exact package version. In under 100 words, explain what an administrator should verify before deciding whether a patch is needed. Include checking which repository supplied PHP. Do not invent a vulnerability or a fixed version.';

// USD public retail rates checked on 2026-11-10 for East US Data Zone Standard.
// Nano-dollars per token preserve fractional micro-dollar charges exactly.
export function estimateUsdNano(usage) {
  return (usage.input_tokens - usage.cached_input_tokens) * 825 +
    usage.cached_input_tokens * 82.5 + usage.output_tokens * 4950;
}

export async function runVerification(env, fetcher = fetch) {
  const report = { schema_version: 1, status: 'failed', mode: env.AZURE_AI_VERIFY_MODE,
    usage_category: 'platform_verification', organization_id: null, user_id: null,
    started_at: new Date().toISOString(), authentication_verified: false,
    resource_access_verified: false, inference_attempted: false, usage: null,
    estimated_cost_usd: null, cost_status: 'no_inference_attempted' };
  try {
    if (!['access', 'inference'].includes(report.mode)) throw new AzureConnectionError('invalid_mode');
    const config = azureConfiguration(env);
    // Reviewed resource/model pin prevents accidental testing of another deployment.
    if (config.endpoint !== 'https://cvie-prod.openai.azure.com' ||
        config.deployment !== 'gpt-5.4-mini') throw new AzureConnectionError('unexpected_resource');
    const token = await azureAccessToken(config, fetcher);
    report.authentication_verified = true;
    Object.assign(report, await verifyAzureAccess(config, token, fetcher));
    if (report.mode === 'inference') {
      report.inference_attempted = true;
      report.cost_status = 'unknown_pending_reconciliation';
      const started = Date.now();
      const result = await azureCompletion(config, token, [
        { role: 'system', content: 'You are a helpful assistant. Use only the fictional scenario supplied.' },
        { role: 'user', content: fictionalPrompt },
      ], fetcher);
      report.duration_ms = Date.now() - started;
      report.usage = result.usage;
      if (!['gpt-5.4-mini', 'gpt-5.4-mini-2026-03-17'].includes(result.model)) {
        throw new AzureConnectionError('unreviewed_model_price');
      }
      report.estimated_cost_usd = estimateUsdNano(result.usage) / 1e9;
      report.price_basis = 'USD retail, East US Data Zone Standard, 2026-11-10';
      report.cost_status = 'estimated_from_reported_usage';
      report.finish_reason = ['stop', 'length', 'content_filter'].includes(result.finish_reason)
        ? result.finish_reason : 'other';
      report.response_received = result.text.trim().length > 0;
      if (!report.response_received || result.finish_reason !== 'stop') {
        throw new AzureConnectionError('inference_response_incomplete');
      }
    }
    report.status = 'passed';
  } catch (error) {
    report.error = error instanceof AzureConnectionError ? error.code : 'verification_failed';
    report.http_status = error instanceof AzureConnectionError ? error.status : null;
  }
  report.completed_at = new Date().toISOString();
  return report;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const report = await runVerification(process.env);
  // The report deliberately excludes credentials, tokens, prompts and model text.
  await writeFile('azure-ai-verification.json', JSON.stringify(report, null, 2) + '\n');
  console.log('Azure AI verification ' + report.status);
  if (report.error) console.log('Failure category: ' + report.error);
  process.exitCode = report.status === 'passed' ? 0 : 1;
}
