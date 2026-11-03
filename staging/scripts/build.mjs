import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { root } from './configure.mjs';
import { TARGET } from '../target.mjs';
const { build } = await import(process.env.CVIE_ESBUILD_MODULE || 'esbuild');
const backend = path.resolve(root, '../account-backend/src');
const out = path.join(root, '.build');
fs.mkdirSync(out, { recursive: true });
// Refuse newly introduced network mechanisms that bypass the injected fetch guard.
for (const name of fs.readdirSync(backend).filter(n => n.endsWith('.js'))) {
  const text = fs.readFileSync(path.join(backend, name), 'utf8');
  if (/\bglobalThis\s*(?:\.(?!caches\b)|\[)|\bself\s*(?:\.|\[)|\bwindow\s*(?:\.\s*fetch|\[)|\b(?:WebSocket|XMLHttpRequest|eval)\s*\(|cloudflare:sockets|node:(?:http|https|net|tls)/.test(text))
    throw Error('Review staging egress for backend module: ' + name);
}
await build({
  entryPoints: [path.join(root, 'api-entry.mjs')], bundle: true, format: 'esm', platform: 'browser',
  conditions: ['workerd', 'worker', 'browser'], external:['node:async_hooks'], outfile: path.join(out, 'api.mjs'),
  inject: [path.join(root, 'blocked-fetch.mjs')],
  plugins: [{ name: 'trusted-staging-origins', setup(b) {
    b.onLoad({ filter: /account-backend\/src\/.*\.js$/ }, async args => ({
      loader: 'js', contents: path.basename(args.path) === 'monitor-approved-test.js'
        ? 'export async function approvedTest() { return { inactive: true }; }'
        : fs.readFileSync(args.path, 'utf8').replace(/https:\/\/(?:api\.|confirm\.)?cveharbor\.com/g, TARGET.origin).replace("url.hostname==='confirm.cveharbor.com'", "(url.pathname.startsWith('/assignment/')||url.pathname.startsWith('/acknowledge/'))").replaceAll('confirm\\.cveharbor\\.com',new URL(TARGET.origin).hostname.replaceAll('.', '\\.')).replaceAll('api\\.cveharbor\\.com',new URL(TARGET.origin).hostname.replaceAll('.', '\\.')),
    }));
  } }],
});
const assets = spawnSync('python', [path.join(root, 'scripts/build-assets.py')], { stdio: 'inherit' });
if (assets.status !== 0) throw Error('Synthetic asset build failed');
const manifest = { account: TARGET.account, api: TARGET.api, site: TARGET.site, origin: TARGET.origin, providers: 'synthetic-only', schedules: 'disabled',
  commit: spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).stdout.trim(),
  api_sha256: createHash('sha256').update(fs.readFileSync(path.join(out, 'api.mjs'))).digest('hex') };
fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log('Staging bundle prepared locally; no deployment performed.');

