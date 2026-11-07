// PR270 isolated development rehearsal only. This is a proposed boundary, not
// execution approval. The production executor does not import this module.
import assert from 'node:assert/strict';
export const developmentException=Object.freeze({
 id:'pr270-disposable-test-data-20261107',
 not_before:Date.parse('2026-11-06T23:25:00Z')/1000,
 expires_at:Date.parse('2026-11-07T03:25:00Z')/1000,
 resources:Object.freeze({
  success:'84dab6e9-9344-4e0f-a79a-4f0b43395754',
  schema:'9f106efd-f5ae-4401-8c50-a4c80c53b90e',
  count:'5d2e6500-350c-4228-9fe4-48c37f755e7d',
  expiry:'39adff8b-b689-45f6-ba3a-c6005ec86b3f',
  race:'b098f98c-bb9f-4e50-95fc-177ac7c2582f',
  rejected:'3ddd25d0-b5c7-4597-9a4c-02bb9ba1c697',
  interrupt:'477cb173-2f84-4786-baa1-6bba51fd7937',
  lost:'d7eb48ca-2023-420d-a5d3-c9cc0360b49c'
 })
});
export function verifyExternalWriterPolicy(p){
 if(p.external_writer_exception===undefined){
  assert.equal(p.external_writers_excluded,true,'External writer exclusion or exact development exception required');
  return;
 }
 // Accepted uncertainty must never be represented as verified exclusion.
 assert.equal(p.external_writers_excluded,false);
 const e=p.external_writer_exception;
 assert.match(e?.assessment_sha256||'',/^[a-f0-9]{64}$/);
 assert.deepEqual(e,{id:developmentException.id,accepted_uncertainty:true,inspected_workflows_do_not_target:true,assessment_sha256:e.assessment_sha256});
 assert.equal(p.not_before,developmentException.not_before);
 assert.equal(p.expires_at,developmentException.expires_at);
 assert.deepEqual(Object.fromEntries(Object.entries(p.resources).map(([c,r])=>[c,r.uuid])),developmentException.resources);
 // Account, names, creation receipts, source/manifest, approval pin, runtime
 // enablement, clock, live bindings, drift, custody and budget checks still run.
}
