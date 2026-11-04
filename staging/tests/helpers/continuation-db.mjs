import assert from 'node:assert/strict';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {root} from '../../scripts/configure.mjs';
import {TARGET} from '../../target.mjs';
import {STAGING_DATABASE_ID} from '../../scripts/migrate.mjs';
export function harness(t, plan, env, hook = async () => undefined) {
  const child = spawn('python', ['-u', path.join(root, 'tests/sqlite-d1.py')], { stdio: ['pipe', 'pipe', 'inherit'] });
  t.after(() => { child.stdin.end(); child.kill(); });
  const lines = createInterface({ input: child.stdout });
  const waiters = [];
  lines.on('line', line => waiters.shift()(JSON.parse(line)));
  const execute = body => new Promise(resolve => { waiters.push(resolve); child.stdin.write(JSON.stringify(body) + '\n'); });
  let latest; const calls = [];
  let size = 0;
  const transport = async (url, init) => {
    assert.equal(new URL(url).origin, 'https://api.cloudflare.com');
    assert.ok(new URL(url).pathname.startsWith('/client/v4/accounts/' + TARGET.account));
    assert.equal(init.redirect, 'error');
    const route = new URL(url).pathname.split(TARGET.account)[1];
    calls.push({ route, method: init.method });
    if (init.method === 'POST') {
      assert.equal(route, `/d1/database/${STAGING_DATABASE_ID}/query`);
      const body = JSON.parse(init.body);
      const intercepted = await hook({ body, execute, calls });
      if (intercepted) return intercepted;
      const response = await execute(body);
      for (const result of response.result || []) size = result.meta?.size_after ?? size;
      return Response.json(response);
    }
    assert.equal(init.method, 'GET');
    if (route === '') return Response.json({ success: true, result: { id: TARGET.account } });
    if (route === `/d1/database/${STAGING_DATABASE_ID}`) {
      const stats = await execute({ sql: 'PRAGMA page_count' });
      size = stats.result[0].meta.size_after;
      return Response.json({ success: true, result: { uuid: STAGING_DATABASE_ID, name: TARGET.database, file_size: size } });
    }
    if (route.startsWith('/access/apps/')) return Response.json({ success: true, result: [] });
    if (route.startsWith('/access/apps')) return Response.json({ success: true, result: [{ id: 'abc-def', type: 'self_hosted', domain: new URL(TARGET.origin).hostname, aud: env.CF_STAGING_ACCESS_AUD }] });
    assert.match(route, /^\/workers\/scripts\/cveharbor-(accounts|site)-staging\/(settings|deployments|subdomain|schedules)$/);
    return Response.json({ success: true, result: { unchanged: true } });
  };
  const deps = { plan, transport, requestIntervalMs: 0, inventory: async () => ({ verified: true }), probe: async () => ({ passed: true }),
    record: (name, data) => { if (name === 'migration') latest = data; } };
  return { deps, calls, execute, final: () => latest };
}

