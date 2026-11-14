import fs from 'node:fs';
import assert from 'node:assert/strict';
import {snapshot} from '../account-backend/src/agent-validation.js';
const actual=snapshot(JSON.parse(fs.readFileSync(new URL('./dist/fictional-payload.json',import.meta.url),'utf8')));
assert.equal(actual.hostname,'NORTHSTAR-WEB01');assert.equal(actual.products.length,6);assert.equal(actual.network.adapters.length,3);assert.equal(actual.complete,true);
assert.equal(actual.products.filter(p=>p.name==='.NET Runtime').length,2,'Side-by-side versions remain separate');
console.log('Compiled Windows agent payload accepted by the real backend validator.');
