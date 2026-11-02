// Explicit bounded maintenance, never called by reads or provider ingestion.
// Run against staging first; production backfill requires deployment approval.
export async function backfillEvidenceIndex(env,source,limit=100){
 if(!['nvd','cna'].includes(source)||!Number.isInteger(limit)||limit<1||limit>100)throw Error('Invalid index maintenance page');
 const db=env.DB,state=await db.prepare('SELECT * FROM cvie_index_state WHERE source=?').bind(source).first();
 if(!state)throw Error('Apply migration 0029 first');
 if(state.complete)return {complete:true,processed:0};
 const statements=[];let cursor=state.cursor,rows;
 if(source==='nvd'){
  const after=cursor?JSON.parse(cursor):['',''];
  rows=(await db.prepare('SELECT scope_id,cve_id FROM cvie_shared_advisories WHERE (scope_id,cve_id)>(?,?) ORDER BY scope_id,cve_id LIMIT ?').bind(...after,limit).all()).results||[];
  for(const row of rows)statements.push(db.prepare(`INSERT INTO cvie_identity_evidence(identity_id,cve_id,nvd_scope_id)
   SELECT i.identity_id,a.cve_id,a.scope_id FROM cvie_shared_advisories a JOIN cvie_shared_scopes s ON s.id=a.scope_id
   JOIN cvie_identity_identifiers i ON i.scheme='cpe' AND i.value=s.cpe
   WHERE a.scope_id=? AND a.cve_id=? AND json_array_length(json_extract(s.signature,'$[1]'))=1
   ON CONFLICT(identity_id,cve_id) DO UPDATE SET nvd_scope_id=excluded.nvd_scope_id WHERE nvd_scope_id IS NOT excluded.nvd_scope_id`).bind(row.scope_id,row.cve_id));
  if(rows.length)cursor=JSON.stringify([rows.at(-1).scope_id,rows.at(-1).cve_id]);
 }else{
  rows=(await db.prepare('SELECT cve_id FROM cvie_disclosures WHERE cve_id>? ORDER BY cve_id LIMIT ?').bind(cursor,limit).all()).results||[];
  // Current source assertions are read inside the same transaction as index writes.
  if(rows.length)statements.push(db.prepare(`INSERT INTO cvie_identity_evidence(identity_id,cve_id,cna_affected_json)
   SELECT f.identity_id,d.cve_id,json_group_array(json(a.value)) FROM cvie_disclosure_products d
   JOIN cvie_identity_families f ON f.family_key=d.family_key,json_each(d.affected_json) a
   WHERE d.cve_id IN(SELECT value FROM json_each(?)) GROUP BY f.identity_id,d.cve_id
   ON CONFLICT(identity_id,cve_id) DO UPDATE SET cna_affected_json=excluded.cna_affected_json WHERE cna_affected_json IS NOT excluded.cna_affected_json`).bind(JSON.stringify(rows.map(r=>r.cve_id))));
  if(rows.length)cursor=rows.at(-1).cve_id;
 }
 const complete=rows.length<limit;
 statements.push(db.prepare('UPDATE cvie_index_state SET cursor=?,complete=? WHERE source=? AND cursor=? AND complete=0').bind(cursor,Number(complete),source,state.cursor));
 await db.batch(statements);
 return {complete,processed:rows.length};
}
