// Task 2C diagnostics only. Every remote request is GET; no deployment/migration imports.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TARGET, accessSettings, databaseId } from '../target.mjs';
import { createAccessVerifier } from '../access.mjs';

export async function preflight(env, transport = fetch, { existingDatabase = false } = {}) {
  const checks = [], requests = [], blockers = [], limitations = [];
  const report = { account: TARGET.account, origin: TARGET.origin, checked_at: new Date().toISOString(),
    operation: 'read-only staging preflight', checks, requests, blockers, limitations,
    mutation_requests: 0, production_requests: 0, ready_for_creation: false };
  const add = (name, passed, detail, required = true) => {
    checks.push({ name, status: passed ? 'pass' : required ? 'fail' : 'unverified', ...detail });
    if (!passed) (required ? blockers : limitations).push(name);
  };
  const value = name => String(env[name] || '').trim();
  const account = value('CF_STAGING_ACCOUNT_ID'), token = value('CF_STAGING_API_TOKEN');
  const issuer = value('CF_STAGING_ACCESS_ISSUER'), audience = value('CF_STAGING_ACCESS_AUD');
  add('configured_account', account === TARGET.account, { expected: TARGET.account });
  if (existingDatabase) {
    try { databaseId(value('CF_STAGING_D1_DATABASE_ID')); add('configured_database', true, {}); }
    catch { add('configured_database', false, {}); }
  }
  add('management_token_present', !!token, {});
  try { accessSettings(issuer, audience); add('access_settings_format', true, {}); }
  catch { add('access_settings_format', false, {}); }
  add('service_credentials_present', !!value('CF_STAGING_ACCESS_CLIENT_ID') && !!value('CF_STAGING_ACCESS_CLIENT_SECRET'), {});
  if (blockers.length) return report;
  const base = 'https://api.cloudflare.com/client/v4';
  async function get(url, label, headers = {}) {
    const u = new URL(url);
    if (!(u.origin === 'https://api.cloudflare.com' && (u.pathname === `/client/v4/accounts/${TARGET.account}` || u.pathname.startsWith(`/client/v4/accounts/${TARGET.account}/`) || /^\/client\/v4\/user\/tokens\/(?:verify|[a-f0-9]{32})$/.test(u.pathname))) &&
        !(u.origin === issuer && u.pathname === '/cdn-cgi/access/certs') && !(u.origin === TARGET.origin && u.pathname === '/')) throw Error('Preflight destination not allowed');
    try {
      const response = await transport(url, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(20000), headers });
      requests.push({ check: label, method: 'GET', status: response.status });
      return response;
    } catch { requests.push({ check: label, method: 'GET', status: 'network_error' }); return null; }
  }
  async function cf(route, label, user = false) {
    const response = await get(base + (user ? route : `/accounts/${TARGET.account}${route}`), label, { Authorization: 'Bearer ' + token });
    if (!response) return { ok: false, status: 'network_error' };
    let payload;
    try { payload = await response.json(); } catch { return { ok: false, status: response.status }; }
    return { ok: response.ok && payload.success === true, status: response.status, result: payload.result };
  }
  const identity = await cf('', 'account_identity');
  add('account_identity', identity.ok && identity.result?.id === TARGET.account,
    { http_status: identity.status, name_matches_owner_label: identity.result?.name === 'CVEHarbor Staging' });
  let verification = await cf('/tokens/verify', 'account_token_active'), accountOwned = verification.ok;
  if (!verification.ok) verification = await cf('/user/tokens/verify', 'user_token_active', true);
  add('token_active', verification.ok && verification.result?.status === 'active', { http_status: verification.status, verification_endpoint: accountOwned ? 'account' : 'user' });
  let grantsVerified = false, scopeVerified = false;
  if (verification.ok && /^[a-f0-9]{32}$/i.test(verification.result?.id || '')) {
    let detail = await cf(accountOwned ? `/tokens/${verification.result.id}` : `/user/tokens/${verification.result.id}`, 'token_permission_metadata', !accountOwned);
    // Account verification success alone does not prove token ownership/type. Try
    // the documented user-token metadata endpoint if account metadata is denied.
    if (!detail.ok && accountOwned) detail = await cf(`/user/tokens/${verification.result.id}`, 'user_token_permission_metadata', true);
    const policies = detail.ok && Array.isArray(detail.result?.policies) ? detail.result.policies : [];
    const allow = policies.filter(p => p.effect === 'allow');
    const names = allow.flatMap(p => (p.permission_groups || []).map(g => String(g.name || '')));
    const required = {
      workers_edit: names.some(n => /^(Workers Scripts (Write|Edit)|Workers Editor)$/.test(n)),
      d1_edit: names.some(n => /^D1 (Write|Edit)$/.test(n)),
      account_read: names.some(n => /^Account Settings (Read|Write|Edit)$/.test(n)),
      access_read: names.some(n => /^Access: Apps and Policies (Read|Write|Edit)$/.test(n)),
    };
    grantsVerified = allow.length > 0 && Object.values(required).every(Boolean);
    scopeVerified = allow.length > 0 && allow.every(p => {
      const resources = Object.keys(p.resources || {});
      return resources.length === 1 && resources[0] === `com.cloudflare.api.account.${TARGET.account}`;
    });
    add('token_permission_grants', grantsVerified, { http_status: detail.status, required_grants: detail.ok ? required : Object.fromEntries(Object.keys(required).map(k => [k, null])), metadata_available: detail.ok }, false);
    add('token_staging_only_scope', scopeVerified, { metadata_available: detail.ok, production_access_probe_performed: false }, false);
  } else {
    add('token_permission_grants', false, { reason: 'Token metadata unavailable; no write probe performed' }, false);
    add('token_staging_only_scope', false, { production_access_probe_performed: false }, false);
  }
  const subdomain = await cf('/workers/subdomain', 'workers_subdomain');
  add('workers_subdomain', subdomain.ok && subdomain.result?.subdomain === 'cveharbor-staging', { http_status: subdomain.status });
  const workers = await cf('/workers/scripts', 'workers_inventory');
  const workerRows = workers.ok && Array.isArray(workers.result) ? workers.result : null;
  add('workers_read_permission', !!workerRows, { http_status: workers.status });
  add('approved_worker_names_available', !!workerRows && !workerRows.some(w => [TARGET.api, TARGET.site].includes(w.id)), { worker_count: workerRows?.length ?? null });
  const databases = await cf('/d1/database?per_page=100', 'd1_inventory');
  const dbRows = databases.ok && Array.isArray(databases.result) && databases.result.length < 100 ? databases.result : null;
  add('d1_read_permission', !!dbRows, { http_status: databases.status, database_count: dbRows?.length ?? null });
  if (existingDatabase) add('approved_database_identity', !!dbRows && dbRows.length === 1 && dbRows[0].name === TARGET.database && dbRows[0].uuid === value('CF_STAGING_D1_DATABASE_ID'), {});
  else add('approved_database_name_available', !!dbRows && !dbRows.some(d => d.name === TARGET.database), {});
  add('production_resources_absent', !!dbRows && !!workerRows && !dbRows.some(d => d.uuid === TARGET.productionDatabase || d.name === 'cveharbor-accounts') && !workerRows.some(w => ['cveharbor-accounts', 'cveharbor-site'].includes(w.id)), {});
  const apps = await cf('/access/apps?per_page=100', 'access_applications');
  const app = apps.ok && Array.isArray(apps.result) && apps.result.length < 100 && apps.result.find(a => a.domain === new URL(TARGET.origin).hostname && a.aud === audience && a.type === 'self_hosted');
  add('exact_access_application', !!app, { http_status: apps.status, name_matches_owner_label: app?.name === 'CVEHarbor Staging' });
  let servicePolicy;
  if (app && /^[a-f0-9-]+$/i.test(app.id)) {
    const policyResult = await cf(`/access/apps/${app.id}/policies`, 'access_policies');
    const policies = policyResult.ok && Array.isArray(policyResult.result) ? policyResult.result : [];
    const human = policies.find(p => p.name === 'CVEHarbor staging reviewers' && p.decision === 'allow');
    servicePolicy = policies.find(p => p.name === 'CVEHarbor staging automated tests' && p.decision === 'non_identity');
    const narrow = selectors => Array.isArray(selectors) && selectors.length > 0 && selectors.every(s => Object.keys(s).length === 1 && typeof s.email?.email === 'string' && s.email.email.includes('@'));
    add('reviewer_email_allow_policy', !!human && narrow(human.include), { email_rule_count: human?.include?.length ?? 0 });
    add('service_auth_policy', !!servicePolicy && Array.isArray(servicePolicy.include) && servicePolicy.include.length > 0 && servicePolicy.include.every(s => Object.keys(s).length === 1 && /^[a-f0-9-]{36}$/i.test(s.service_token?.token_id || '')), {});
    add('no_access_bypass_or_additional_allow', policies.length === 2 && policies.every(p => p === human || p === servicePolicy) && !policies.some(p => p.decision === 'bypass' || (p.include || []).some(s => Object.hasOwn(s, 'everyone'))), { policy_count: policies.length });
  }
  const serviceTokens = await cf('/access/service_tokens?per_page=100', 'service_token_metadata');
  const tokenRows = serviceTokens.ok && Array.isArray(serviceTokens.result) ? [...serviceTokens.result] : [];
  const listedCount = tokenRows.length;
  const policyTokenIds = [...new Set((servicePolicy?.include || []).map(s => s.service_token?.token_id).filter(id => /^[a-f0-9-]{36}$/i.test(id || '')))];
  const detailStatuses = [];
  if (policyTokenIds.length <= 5) for (const id of policyTokenIds) {
    if (tokenRows.some(t => t.id === id)) continue;
    const detail = await cf(`/access/service_tokens/${id}`, 'policy_service_token_detail');
    detailStatuses.push(detail.status);
    if (detail.ok && detail.result?.id === id) tokenRows.push(detail.result);
  }
  const named = tokenRows.filter(s => s.name === 'cvie-staging-validation');
  const clientMatches = tokenRows.filter(s => s.client_id === value('CF_STAGING_ACCESS_CLIENT_ID'));
  const selected = named.find(s => s.client_id === value('CF_STAGING_ACCESS_CLIENT_ID'));
  const linked = selected && servicePolicy?.include?.some(s => s.service_token?.token_id === selected.id);
  const serviceMetadataVerified = !!linked && selected.enabled !== false && (!selected.expires_at || Date.parse(selected.expires_at) > Date.now());
  add('service_token_matches_policy_and_client', serviceMetadataVerified, {
    http_status: serviceTokens.status, metadata_available: serviceTokens.ok,
    metadata_is_array: Array.isArray(serviceTokens.result), listed_count: listedCount, record_count: tokenRows.length,
    policy_token_detail_statuses: detailStatuses,
    name_match_count: named.length, client_match_count: clientMatches.length,
    named_record_has_client_id: named.some(s => typeof s.client_id === 'string' && s.client_id.length > 0),
    named_record_policy_linked: named.some(s => servicePolicy?.include?.some(rule => rule.service_token?.token_id === s.id)),
    matching_client_policy_linked: clientMatches.some(s => servicePolicy?.include?.some(rule => rule.service_token?.token_id === s.id)),
    matched_enabled: selected ? selected.enabled !== false : null,
    matched_unexpired: selected ? !selected.expires_at || Date.parse(selected.expires_at) > Date.now() : null,
  }, false);
  const keys = await get(issuer + '/cdn-cgi/access/certs', 'access_issuer_keys');
  let jwks;
  try { jwks = keys?.ok ? await keys.json() : null; } catch {}
  add('access_issuer_signing_keys', Array.isArray(jwks?.keys) && jwks.keys.some(k => k.kty === 'RSA' && k.kid), { http_status: keys?.status ?? null });
  // No Worker exists yet. A GET can verify Access only if its edge issues a valid JWT;
  // an origin 404 alone is deliberately not evidence that a service secret is valid.
  const response = await get(TARGET.origin + '/', 'access_service_auth_probe', {
    'CF-Access-Client-Id': value('CF_STAGING_ACCESS_CLIENT_ID'), 'CF-Access-Client-Secret': value('CF_STAGING_ACCESS_CLIENT_SECRET'),
  });
  const jwt = response?.headers.get('set-cookie')?.match(/(?:^|[,;]\s*)CF_Authorization=([^;]+)/)?.[1];
  const verified = jwt && await createAccessVerifier(async () => Response.json(jwks))(jwt, issuer, audience);
  add('service_secret_end_to_end', !!verified, { http_status: response?.status ?? null, reason: verified ? 'Valid Access JWT for configured issuer/AUD' : 'No valid JWT returned; origin may not exist yet. HTTP status alone does not validate credentials.' }, false);
  report.read_only_checks_passed = blockers.length === 0;
  report.ready_for_creation = blockers.length === 0 && grantsVerified && scopeVerified && serviceMetadataVerified;
  report.write_permissions_exercised = false;
  return report;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = await preflight(process.env);
  const destination = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../artifacts');
  fs.mkdirSync(destination, { recursive: true });
  fs.writeFileSync(path.join(destination, 'preflight.json'), JSON.stringify(result, null, 2) + '\n');
  console.log('CVIE_STAGING_PREFLIGHT ' + JSON.stringify(result));
  if (result.blockers.length) process.exitCode = 1;
}
