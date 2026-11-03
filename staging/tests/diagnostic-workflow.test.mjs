import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
const yaml = fs.readFileSync(new URL('../../.github/workflows/cvie-staging-diagnostics.yml', import.meta.url), 'utf8');
const development = fs.readFileSync(new URL('../../.github/workflows/cvie-staging.yml', import.meta.url), 'utf8');

test('diagnostic trigger rejects untrusted refs, repositories, forks and PR events', () => {
  const expression = yaml.match(/    if: >-\n((?:      .*\n)+)/)?.[1].trim();
  assert.ok(expression);
  const allow = new Function('github', `return Boolean(${expression});`);
  const base = { repository: 'Prat007ai/cveharbor', ref: 'refs/heads/main', event_name: 'workflow_run', event: { workflow_run: {
    head_repository: { full_name: 'Prat007ai/cveharbor' }, head_branch: 'codex/cvie-core-phase012', path: '.github/workflows/cvie-staging.yml', event: 'push',
  } } };
  assert.equal(allow(base), true);
  for (const conclusion of ['success', 'failure', 'cancelled']) assert.equal(allow({ ...base, event: { workflow_run: { ...base.event.workflow_run, conclusion } } }), true);
  assert.equal(allow({ ...base, event_name: 'workflow_dispatch', event: {} }), true);
  for (const mutate of [
    g => { g.ref = 'refs/heads/codex/cvie-core-phase012'; },
    g => { g.ref = 'refs/pull/243/merge'; },
    g => { g.repository = 'attacker/cveharbor'; },
    g => { g.event_name = 'pull_request_target'; },
    g => { g.event.workflow_run.head_repository.full_name = 'attacker/cveharbor'; },
    g => { g.event.workflow_run.head_branch = 'main'; },
    g => { g.event.workflow_run.path = '.github/workflows/untrusted.yml'; },
    g => { g.event.workflow_run.event = 'pull_request'; },
  ]) { const candidate = structuredClone(base); mutate(candidate); assert.equal(allow(candidate), false); }
});

test('secret job consumes only immutable reviewed code and one read-only credential', () => {
  assert.match(yaml, /environment: cloudflare-cvie-staging-readonly\n/);
  assert.match(yaml, /ref: d43139fdee1192a655e8103c85c14f1a892b2544\n/);
  assert.match(yaml, /persist-credentials: false/);
  const actionLines = yaml.split('\n').filter(l => /uses:/.test(l));
  assert.equal(actionLines.length, 3);
  for (const line of actionLines) assert.match(line, /uses: actions\/(checkout|setup-node|upload-artifact)@[a-f0-9]{40}$/);
  assert.deepEqual([...yaml.matchAll(/secrets\.([A-Z_]+)/g)].map(m => m[1]), ['CF_STAGING_READONLY_API_TOKEN']);
  assert.deepEqual([...yaml.matchAll(/^\s+run: (.+)$/gm)].map(m => m[1]), ['node trusted-diagnostics/staging/scripts/diagnose.mjs']);
  assert.doesNotMatch(yaml, /head_sha|download-artifact|actions\/cache|npm install|npx |pull_request_target|secrets: inherit/);
  assert.match(yaml, /permissions:\n  contents: read\n/);
  assert.match(yaml, /group: cvie-staging-readonly-243/);
  assert.doesNotMatch(development, /cloudflare-cvie-staging-readonly|CF_STAGING_READONLY_API_TOKEN|check-staging-credentials:/);
  assert.match(development, /environment: cloudflare-cvie-staging\n/);
  assert.match(development, /github.run_attempt > 1/);
  assert.match(development, /node staging\/scripts\/provision.mjs --check/);
});
