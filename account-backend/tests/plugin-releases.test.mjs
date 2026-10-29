import test from 'node:test';
import assert from 'node:assert/strict';
import {compareVersions,normalizeRelease,lookupRelease} from '../src/plugin-releases.js';
test('release comparisons preserve the installed version',()=>{
 assert.equal(compareVersions('2.9.5','2.10.0'),-1);
 assert.equal(compareVersions('8.0.1','8.0.1'),0);
 assert.equal(compareVersions('unknown','8.0.1'),null);
});
test('only verified exact WordPress.org slug reports newer release',()=>{
 const x=normalizeRelease('wordpress-seo','24.7',{slug:'wordpress-seo',version:'24.8',last_updated:'2026-10-29'});
 assert.equal(x.update_status,'Update Available');
 assert.equal(x.latest_version,'24.8');
 assert.equal(normalizeRelease('wordpress-seo','24.7',{slug:'other-plugin',version:'99.0'}).release_status,'unverified');
});
test('official API unavailability is not an up-to-date claim',async()=>{
 const x=await lookupRelease('gravity-forms','2.9.5',async()=>({ok:false,status:404}));
 assert.equal(x.release_status,'unavailable');
 assert.equal(x.update_status,'Unknown');
});
