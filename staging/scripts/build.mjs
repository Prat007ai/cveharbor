import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { root } from './configure.mjs';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {backendIdentity} from '../../scripts/build_release_identity.mjs';
import {expectedBaseline,schemaSQL} from '../../scripts/production_schema_baseline.mjs';
import {canonicalDDL} from '../../scripts/sql_schema_tokens.mjs';
import { TARGET } from '../target.mjs';
import {verifyCandidateProfile} from './customer-remediation-profile.mjs';
const { build } = await import(process.env.CVIE_ESBUILD_MODULE || 'esbuild');
assert.ok([undefined,'production-baseline','customer-remediation-candidate'].includes(process.env.STAGING_BUILD_PROFILE),'Unknown staging build profile');
const candidate=process.env.STAGING_BUILD_PROFILE==='customer-remediation-candidate';
const candidateData=candidate?verifyCandidateProfile():null;
const production=process.env.STAGING_BUILD_PROFILE==='production-baseline';
const repository=path.resolve(root,'..');
const baseline=JSON.parse(fs.readFileSync(path.join(repository,'release/baseline.json')));
const releaseProfile=JSON.parse(fs.readFileSync(path.join(root,'application-release.json')));
assert.ok(['production-baseline','reviewed-main'].includes(releaseProfile.source_mode));
assert.equal(releaseProfile.schema_profile,'production-baseline-209');assert.equal(releaseProfile.origin,TARGET.origin);
const pinned=production&&releaseProfile.source_mode==='production-baseline';
const source=pinned?path.join(repository,'release/.build/production-source'):repository;
const frontend=pinned?path.join(repository,'release/.build/production-frontend'):repository;
const backend=path.join(source,'account-backend/src');
let expected=null;
if(production){
 if(pinned){const pins=JSON.parse(fs.readFileSync(path.join(repository,'release/.build/source-pins.json')));
 assert.deepEqual(pins,{backend:baseline.backend.source_sha,frontend:baseline.frontend.source_sha});
 expectedBaseline(source,repository);}
 for(const f of baseline.application_schema_files)assert.equal(createHash('sha256').update(fs.readFileSync(path.join(source,f.path))).digest('hex'),f.sha256,'Schema changes require a reviewed schema profile, never an implicit migration');
 const db=new DatabaseSync(':memory:');try{
  db.exec(fs.readFileSync(path.join(root,'schema.sql'),'utf8'));
  for(const f of baseline.application_schema_files)db.exec(fs.readFileSync(path.join(source,f.path),'utf8'));
  expected=db.prepare(schemaSQL).all().map(r=>[r.type,r.name,r.tbl_name,canonicalDDL(r.sql)]);
 }finally{db.close();}
}

if(candidate)expected=candidateData.rows.map(r=>[r.type,r.name,r.tbl_name,canonicalDDL(r.sql)]);
const out = path.join(root, '.build',...(candidate?['customer-remediation-candidate']:[]));
fs.mkdirSync(out, { recursive: true });
// Refuse newly introduced network mechanisms that bypass the injected fetch guard.
for (const name of fs.readdirSync(backend).filter(n => n.endsWith('.js'))) {
  const text = fs.readFileSync(path.join(backend, name), 'utf8');
  if (/\bglobalThis\s*(?:\.(?!caches\b)|\[)|\bself\s*(?:\.|\[)|\bwindow\s*(?:\.\s*fetch|\[)|\b(?:WebSocket|XMLHttpRequest|eval)\s*\(|cloudflare:sockets|node:(?:http|https|net|tls)/.test(text))
    throw Error('Review staging egress for backend module: ' + name);
}
await build({
  entryPoints: [path.join(root, 'api-entry.mjs')], bundle: true, format: 'esm', platform: 'browser',
  define:(production||candidate)?{__STAGING_PRODUCTION_SCHEMA__:JSON.stringify(expected),...(candidate?{__STAGING_CUSTOMER_PROFILE__:JSON.stringify(candidateData.profile)}:{})}:{},
  conditions: ['workerd', 'worker', 'browser'], external:['node:async_hooks'], outfile: path.join(out, 'api.mjs'),
  inject: [path.join(root, 'blocked-fetch.mjs')],
  plugins: [{ name: 'trusted-staging-origins', setup(b) {
    if(production||candidate)b.onResolve({filter:/account-backend\/src\//},args=>{
      const suffix=args.path.split('account-backend/src/')[1];return {path:path.join(backend,suffix)};
    });
    b.onLoad({ filter: /account-backend\/src\/.*\.js$/ }, async args => ({
      loader: 'js', contents: (production||candidate)&&path.basename(args.path)==='release-build.js'?`export const releaseIdentity=${JSON.stringify(backendIdentity(source))};`:path.basename(args.path) === 'monitor-approved-test.js'
        ? 'export async function approvedTest() { return { inactive: true }; }'
        : fs.readFileSync(args.path, 'utf8').replace(/https:\/\/(?:api\.|confirm\.)?cveharbor\.com/g, TARGET.origin).replace("url.hostname==='confirm.cveharbor.com'", "(url.pathname.startsWith('/assignment/')||url.pathname.startsWith('/acknowledge/'))").replaceAll('confirm\\.cveharbor\\.com',new URL(TARGET.origin).hostname.replaceAll('.', '\\.')).replaceAll('api\\.cveharbor\\.com',new URL(TARGET.origin).hostname.replaceAll('.', '\\.')),
    }));
  } }],
});
// The routine publisher uploads these two modules without bundling them again.
if(candidate) await build({entryPoints:[path.join(root,'frontend.mjs')], bundle:true,
  format:'esm', platform:'browser', conditions:['workerd','worker','browser'], outfile:path.join(out,'site.mjs')});
const assets = spawnSync('python', [path.join(root, 'scripts/build-assets.py')], { stdio: 'inherit',env:{...process.env,STAGING_ASSET_SOURCE:frontend,STAGING_ASSET_ORIGIN:TARGET.origin,...(candidate?{STAGING_ASSET_OUTPUT:path.join(out,'public')}:{})} });
if (assets.status !== 0) throw Error('Synthetic asset build failed');
const manifest = { account: TARGET.account, api: TARGET.api, site: TARGET.site, origin: TARGET.origin, providers: 'synthetic-only', schedules: 'disabled',
  application_profile:candidate?'customer-remediation-candidate':production?'production-baseline':'candidate',...(candidate?{candidate_profile:candidateData.profile,activation:'separate-approval-required'}:{}),source_mode:candidate?'reviewed-customer-candidate':releaseProfile.source_mode,backend_source_sha:(production||candidate)?(pinned?baseline.backend.source_sha:spawnSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).stdout.trim()):null,frontend_source_sha:(production||candidate)?(pinned?baseline.frontend.source_sha:spawnSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).stdout.trim()):null,backend_identity:backendIdentity(source),schema_sha256:candidate?candidateData.profile.schema_sha256:production?baseline.schema_sha256:null,
  commit: spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).stdout.trim(),
  api_sha256: createHash('sha256').update(fs.readFileSync(path.join(out, 'api.mjs'))).digest('hex') };
fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log('Staging bundle prepared locally; no deployment performed.');

