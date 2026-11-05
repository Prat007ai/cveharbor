import test from 'node:test';
import assert from 'node:assert/strict';
import { preflight } from '../scripts/preflight.mjs';
import { probeMaintenanceAccess } from '../scripts/probe-access.mjs';
import { TARGET } from '../target.mjs';
const env = { CF_STAGING_ACCOUNT_ID: TARGET.account, CF_STAGING_API_TOKEN: 'private-management-token', CF_STAGING_ACCESS_ISSUER: 'https://synthetic-stage.cloudflareaccess.com', CF_STAGING_ACCESS_AUD: 'a'.repeat(64), CF_STAGING_ACCESS_CLIENT_ID: 'private-service-client', CF_STAGING_ACCESS_CLIENT_SECRET: 'private-service-secret' };
const sid = 'fac61562-fc31-426d-8032-550aba63b7f6';
function fixture({ metadataDenied = false, bypass = false, emptyList = false, missingDetail = false, database = null, workers = [], apps = null } = {}) {
  return async (url, init) => {
    assert.equal(init.method, 'GET'); assert.equal(init.redirect, 'manual');
    const u = new URL(url); let result;
    if (u.pathname.startsWith('/client/v4/user/tokens/')) return Response.json({ success: false }, { status: 403 });
    if (u.origin === TARGET.origin) { assert.equal(init.headers['CF-Access-Client-Secret'], env.CF_STAGING_ACCESS_CLIENT_SECRET); return new Response('', { status: 404 }); }
    if (u.origin === env.CF_STAGING_ACCESS_ISSUER) { assert.equal(init.headers.Authorization, undefined); return Response.json({ keys: [{ kty: 'RSA', kid: 'fixture' }] }); }
    assert.equal(u.origin, 'https://api.cloudflare.com');
    const base = '/client/v4/accounts/' + TARGET.account;
    assert.ok(u.pathname === base || u.pathname.startsWith(base + '/'));
    const route = u.pathname.slice(base.length);
    if (route === '') result = { id: TARGET.account, name: 'CVEHarbor Staging' };
    else if (route === '/tokens/verify') result = { id: 'f'.repeat(32), status: 'active' };
    else if (route === '/tokens/' + 'f'.repeat(32)) {
      if (metadataDenied) return Response.json({ success: false }, { status: 403 });
      result = { policies: [{ effect: 'allow', resources: { ['com.cloudflare.api.account.' + TARGET.account]: '*' }, permission_groups: ['Workers Scripts Write','D1 Write','Account Settings Read','Access: Apps and Policies Read'].map(name => ({ name })) }] };
    } else if (route === '/workers/subdomain') result = { subdomain: 'cveharbor-staging' };
    else if (route === '/workers/scripts') result = workers;
    else if (route === '/d1/database') result = database ? [database] : [];
    else if (route === '/access/apps') result = apps ?? [{ id: sid, domain: new URL(TARGET.origin).hostname, aud: env.CF_STAGING_ACCESS_AUD, type: 'self_hosted', name: 'CVEHarbor Staging' }];
    else if (route.endsWith('/policies')) result = [
      { name: 'CVEHarbor staging reviewers', decision: bypass ? 'bypass' : 'allow', include: [{ email: { email: 'private-reviewer@example.test' } }] },
      { name: 'CVEHarbor staging automated tests', decision: 'non_identity', include: [{ service_token: { token_id: sid } }] },
    ];
    else if (route === '/access/service_tokens') result = emptyList ? [] : [{ id: sid, name: 'cvie-staging-validation', client_id: env.CF_STAGING_ACCESS_CLIENT_ID, enabled: true }];
    else if (route === '/access/service_tokens/' + sid) {
      if (missingDetail) return Response.json({ success: false }, { status: 404 });
      result = { id: sid, name: 'cvie-staging-validation', client_id: env.CF_STAGING_ACCESS_CLIENT_ID, enabled: true };
    }
    else assert.fail('Unexpected route');
    return Response.json({ success: true, result });
  };
}
test('preflight is GET-only, reports safe evidence, and does not infer a valid service secret from 404', async () => {
  const result = await preflight(env, fixture());
  assert.equal(result.read_only_checks_passed, true); assert.equal(result.ready_for_creation, true);
  assert.equal(result.mutation_requests, 0); assert.equal(result.production_requests, 0);
  assert.equal(result.checks.find(c => c.name === 'access_cookie_jwt_observed').status, 'unverified');
  assert.doesNotMatch(JSON.stringify(result), /private-management-token|private-service-client|private-service-secret|private-reviewer/);
});
test('multi-domain Access app accepts exact staging host with the same AUD/type and policies', async () => {
  const host = new URL(TARGET.origin).hostname;
  const base = {id:sid,domain:'cveharbor-site-staging.cveharbor-staging.workers.dev',aud:env.CF_STAGING_ACCESS_AUD,type:'self_hosted'};
  for (const patch of [{self_hosted_domains:[base.domain,host]}, {destinations:[{type:'public',hostname:base.domain},{type:'public',hostname:host}]}]) {
    const report = await preflight(env, fixture({apps:[{...base,...patch}]}));
    assert.equal(report.read_only_checks_passed,true);
    const check = report.checks.find(c=>c.name==='exact_access_application');
    assert.equal(check.primary_domain_matches,false);assert.equal(check.matching_application_count,1);
    assert.equal(report.checks.find(c=>c.name==='service_auth_policy').status,'pass');
  }
  for (const patch of [{}, {self_hosted_domains:['*.'+host]}, {self_hosted_domains:[host+'/private']}, {self_hosted_domains:[host+'.evil.test']},
    {destinations:[{type:'private',hostname:host}]}, {self_hosted_domains:[host],aud:'b'.repeat(64)}, {self_hosted_domains:[host],type:'saas'}]) {
    const report = await preflight(env,fixture({apps:[{...base,...patch}]}));
    assert.ok(report.blockers.includes('exact_access_application'));
  }
  const matching = {...base,self_hosted_domains:[host]};
  const duplicate = await preflight(env,fixture({apps:[matching,{...matching,id:'abc-def'}]}));
  assert.ok(duplicate.blockers.includes('exact_access_application'));
  const bypass = await preflight(env,fixture({apps:[matching],bypass:true}));
  assert.ok(bypass.blockers.includes('no_access_bypass_or_additional_allow'));
});
test('unreadable token metadata is not called a confirmed write grant or isolation proof', async () => {
  const result = await preflight(env, fixture({ metadataDenied: true }));
  assert.equal(result.read_only_checks_passed, true); assert.equal(result.ready_for_creation, false);
  assert.ok(result.limitations.includes('token_permission_grants'));
});
test('wrong account, missing secret and Access bypass fail closed', async () => {
  const noNetwork = async () => assert.fail('No request allowed');
  assert.equal((await preflight({ ...env, CF_STAGING_ACCOUNT_ID: 'another' }, noNetwork)).ready_for_creation, false);
  assert.equal((await preflight({ ...env, CF_STAGING_ACCESS_CLIENT_SECRET: '' }, noNetwork)).ready_for_creation, false);
  const result = await preflight(env, fixture({ bypass: true }));
  assert.equal(result.ready_for_creation, false); assert.ok(result.blockers.includes('no_access_bypass_or_additional_allow'));
});
test('empty token lists use only bounded policy references and distinguish missing metadata', async () => {
  const good = await preflight(env, fixture({ emptyList: true }));
  assert.equal(good.checks.find(c => c.name === 'service_token_matches_policy_and_client').status, 'pass');
  const missing = await preflight(env, fixture({ emptyList: true, missingDetail: true }));
  const result = missing.checks.find(c => c.name === 'service_token_matches_policy_and_client');
  assert.equal(result.status, 'unverified'); assert.deepEqual(result.policy_token_detail_statuses, [404]);
  assert.equal(missing.ready_for_creation, false);
});

test('deployment preflight accepts only the recorded staging DB and keeps diagnostics GET-only', async () => {
  const settings = { ...env, CF_STAGING_D1_DATABASE_ID: sid };
  const result = await preflight(settings, fixture({ database: { name: TARGET.database, uuid: sid } }), { existingDatabase: true });
  assert.equal(result.read_only_checks_passed, true);
  assert.equal(result.checks.find(c => c.name === 'approved_database_identity').status, 'pass');
  const wrong = await preflight(settings, fixture({ database: { name: TARGET.database, uuid: TARGET.productionDatabase } }), { existingDatabase: true });
  assert.equal(wrong.read_only_checks_passed, false);
});


test('deployed diagnostic accepts only both expected Workers without weakening initial creation gates', async () => {
  const settings = { ...env, CF_STAGING_D1_DATABASE_ID: sid };
  const options = { existingDatabase: true, workerState: 'deployed' };
  const database = { name: TARGET.database, uuid: sid };
  const workers = [{ id: TARGET.api }, { id: TARGET.site }];
  const good = await preflight(settings, fixture({ database, workers }), options);
  assert.equal(good.read_only_checks_passed, true);
  assert.equal(good.ready_for_creation, false);
  assert.equal(good.checks.find(c => c.name === 'expected_staging_workers_present').status, 'pass');
  for (const rows of [[], [workers[0]], [...workers, { id: 'unexpected' }], [workers[0], workers[0]]]) {
    const bad = await preflight(settings, fixture({ database, workers: rows }), options);
    assert.ok(bad.blockers.includes('expected_staging_workers_present'));
  }
  const initial = await preflight(settings, fixture({ database, workers }), { existingDatabase: true });
  assert.ok(initial.blockers.includes('approved_worker_names_available'));
});


test('migration maintenance accepts a known zero-policy app; denied metadata is not an empty-policy proof', async () => {
  const settings = { ...env, CF_STAGING_D1_DATABASE_ID: sid, CF_STAGING_PROVISION_ACTION: 'migrate' };
  const options = { existingDatabase: true, workerState: 'deployed', maintenance: true };
  const original = fixture({ database: { name: TARGET.database, uuid: sid }, workers: [{ id: TARGET.api }, { id: TARGET.site }] });
  for (const mode of ['blocked','allow','metadata_denied','other_app']) {
    const transport = async (url, init) => {
      if (String(url).endsWith('/policies')) return Response.json(mode === 'metadata_denied' ? {success:false} : {success:true,result:mode==='allow'?[{decision:'allow'}]:[]}, {status:mode==='metadata_denied'?403:200});
      if (mode==='other_app' && String(url).includes('/access/apps?')) return Response.json({success:true,result:[{id:sid,domain:new URL(TARGET.origin).hostname,aud:env.CF_STAGING_ACCESS_AUD,type:'self_hosted'}, {id:'unexpected',domain:'other.invalid'}]});
      return original(url, init);
    };
    assert.equal((await preflight(settings, transport, options)).read_only_checks_passed, mode==='blocked');
    if(mode==='blocked') assert.equal((await preflight(settings, transport, {...options,maintenance:false})).read_only_checks_passed,false);
  }
  await assert.rejects(preflight({...settings,CF_STAGING_PROVISION_ACTION:'update'}, original, options));
});
test('maintenance probes require denial for anonymous, forged and service requests and keep backend private', async () => {
  const settings={...env,CF_STAGING_PROVISION_ACTION:'migrate'};
  for(const mode of ['blocked','service_open','api_open','login_redirect','browser_login_redirect','network']) {
    const calls=[];
    const result=await probeMaintenanceAccess(settings,async(url,init)=>{
      calls.push(String(url));assert.equal(init.method,'GET');assert.equal(init.redirect,'manual');
      if(mode==='network')throw Error('fixture');
      if(String(url).includes('accounts-staging'))return new Response('',{status:mode==='api_open'?200:404});
      if(mode==='login_redirect')return new Response('',{status:302,headers:{Location:env.CF_STAGING_ACCESS_ISSUER+'/cdn-cgi/access/login'}});
      if(mode==='browser_login_redirect'&&!init.headers['CF-Access-Client-Id'])return new Response('',{status:302,headers:{Location:env.CF_STAGING_ACCESS_ISSUER+'/cdn-cgi/access/login/'+new URL(TARGET.origin).hostname}});
      return new Response('',{status:mode==='service_open'&&init.headers['CF-Access-Client-Id']?200:403});
    });
    assert.equal(result.passed,mode==='blocked'||mode==='browser_login_redirect');assert.equal(calls.length,22);
    assert.doesNotMatch(JSON.stringify(result),/private-service/);
  }
  await assert.rejects(probeMaintenanceAccess({...settings,CF_STAGING_PROVISION_ACTION:'update'}));
});
