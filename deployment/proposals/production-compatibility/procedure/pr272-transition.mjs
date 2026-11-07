// Offline only. The separate trigger change is never submitted by execute.mjs.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {baselineDB} from '../rehearsal.mjs';
import {digest} from '../../../../scripts/production_schema_baseline.mjs';
import {allOf, folder, literal, noViolations, originalTables, quote, receiptTable, sqlFiles} from './build.mjs';

// Independently verified by production audit run 42337113564.
export const installed272 = Object.freeze({
 source: '18dadb0349f54b434a6bd78424345a256088338c',
 manifest: '23b78685f453e0719ffc87cbcbba0f087d8ac85d4e9467041e22297ac9b08b6d',
 run: '42336705578',
 receipt: '96979b3da359e11184780ed56604ce8fbc2251b9619173b06c89974677105c9d',
 journal: '5c24bd2d306ea5d63787ffbf805af2bac09ce78aee16c7ccee7c41d5738d4891'
});

export function triggerUpgradeTemplate() {
 const old = fs.readFileSync(path.join(folder,'pr272-installed-bootstrap.sql'),'utf8');
 assert.equal(digest(old),'842fe63920cb55bed339623ca55efeb2508eefb1ea5ce97a6ca80f373038dd91');
 const db = baselineDB();
 try {
  db.exec(old);
  const journal = db.prepare("SELECT name,sql FROM sqlite_schema WHERE name GLOB 'd1_*' AND sql IS NOT NULL").all();
  const originalJournal = journal.map(row =>
   `(SELECT sql FROM sqlite_schema WHERE name=${literal(row.name)})=${literal(row.sql)}`);
  const guards = [
   `(SELECT COUNT(*) FROM sqlite_schema WHERE name GLOB 'd1_*' AND sql IS NOT NULL)=${journal.length}`,
   ...originalJournal,
   `(SELECT COUNT(*) FROM ${receiptTable})=3`,
   `(SELECT COUNT(*) FROM ${receiptTable} WHERE id IN ('install-intent','install-started','installed') AND payload=expected.p)=3`,
   "EXISTS(SELECT 1 FROM operations_control WHERE id=1 AND write_hold=1 AND database_frozen=1 AND revision=0)",
   'NOT EXISTS(SELECT 1 FROM operations_leases)', 'NOT EXISTS(SELECT 1 FROM remediation_finding_write_context)',
   ...originalTables().map(t => `(SELECT COUNT(*) FROM ${quote(t)})=(c->>'${t}')`),
   noViolations()
  ];
  const sequence = receiptTable+'_sequence';
  const bootstrap = sqlFiles()['bootstrap.sql'];
  const start = bootstrap.indexOf('CREATE TRIGGER '+sequence+' ');
  assert.ok(start>0);
  return `WITH expected AS (SELECT ?1 AS p) SELECT json_extract(CASE WHEN COALESCE(${allOf(guards)},0) THEN 'true' ELSE 'Trigger upgrade rejected' END,'$') FROM (SELECT p,json_extract(p,'$.counts') AS c FROM expected) AS expected;\nDROP TRIGGER ${sequence};\n${bootstrap.slice(start)}`;
 } finally { db.close(); }
}

export function triggerUpgradeSQL(receipt) {
 assert.equal(digest(receipt), installed272.receipt, 'Expected exact verified installed payload bytes');
 const sql = triggerUpgradeTemplate().replace('(SELECT ?1 AS p)', () => '(SELECT '+literal(receipt)+' AS p)');
 assert.ok(Buffer.byteLength(JSON.stringify({sql,params:[]}))<=100000,'Trigger batch exceeds reviewed size limit');
 return sql;
}

if (process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
 const [receiptPath,output] = process.argv.slice(2);
 const sql = triggerUpgradeSQL(fs.readFileSync(receiptPath,'utf8'));
 fs.writeFileSync(output,sql,{flag:'wx'});
 console.log(JSON.stringify({trigger_upgrade_sha256:digest(sql),bytes:Buffer.byteLength(sql)}));
}
