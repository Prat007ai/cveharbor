import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeWatch,evaluate,dateValid } from '../src/lifecycle.js';

test('custom lifecycle watches require an explicit valid date and https evidence link',()=>{
 assert.throws(()=>normalizeWatch({product:'Custom database'}),/verified custom support date/);
 assert.throws(()=>normalizeWatch({product:'Custom database',custom_eol_date:'2026-02-30'}),/verified custom support date/);
 const x=normalizeWatch({product:'Vendor Platform',custom_eol_date:'2027-01-01',
 custom_source_url:'https://example.org/support'});
 assert.equal(x.product,'Vendor Platform');
 assert.ok(dateValid('2027-01-01'));
 assert.throws(()=>normalizeWatch({product:'Test',custom_eol_date:'2027-01-01',
 custom_source_url:'javascript:alert(1)'}),/verified custom support date/);
});
test('support dates produce lead window notice without inventing unknown dates',()=>{
 const now=new Date('2026-10-28T12:00:00Z');
 const watches=[{id:'w1',product:'SQL Server',slug:'mssqlserver',cycle:'2022'},
 {id:'w2',product:'Custom',custom_eol_date:'2026-11-10',custom_source_url:'https://example.com'},
 {id:'w3',product:'.NET',slug:'dotnet',cycle:'8'}];
 const cycles=[{slug:'mssqlserver',product:'SQL Server',cycle:'2022',eol_date:'2027-01-10',url:'https://endoflife.date/mssqlserver'},
 {slug:'dotnet',product:'.NET',cycle:'8',eol_date:null,url:'https://endoflife.date/dotnet'}];
 const items=evaluate(watches,cycles,90,now);
 assert.equal(items.length,2);
 assert.equal(items[0].product,'Custom');
 assert.equal(items[1].days,74);
 assert.equal(items[0].origin,'user');
 assert.equal(evaluate(watches,cycles,30,now).length,1);
});
