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

// One source page per claim; concurrent customers share this durable public job.
export async function primeIdentityIndex(env,identityId){
 await env.DB.prepare('INSERT OR IGNORE INTO cvie_identity_index_jobs(identity_id) VALUES(?)').bind(identityId).run();
 let result;for(let page=0;page<3;page++){result=await runIdentityIndexWork(env,identityId,Date.now(),true);if(result.processed||result.complete||result.busy||result.failed)break;}return result;
}
export async function runIdentityIndexWork(env,identityId=null,now=Date.now(),urgent=false){
 if(env.CVIE_REGISTRY_ENABLED!=='true')return {processed:0};
 const db=env.DB,job=await db.prepare(`SELECT * FROM cvie_identity_index_jobs WHERE complete=0 ${urgent?'':'AND next_attempt_at<=?'} AND lease_until<? ${identityId?'AND identity_id=?':''} ORDER BY next_attempt_at,identity_id LIMIT 1`).bind(...(urgent?[]:[now]),now,...(identityId?[identityId]:[])).first();
 if(!job)return {processed:0};
 const token=crypto.randomUUID();
 const claimed=await db.prepare(`UPDATE cvie_identity_index_jobs SET lease_until=?,lease_token=?
  WHERE identity_id=? AND lease_until<? AND complete=0 AND cursor_json=? AND next_attempt_at=?`)
  .bind(now+120000,token,job.identity_id,now,job.cursor_json,job.next_attempt_at).run();
 if(!claimed.meta.changes)return {busy:true};
 const guard='EXISTS(SELECT 1 FROM cvie_identity_index_jobs j WHERE j.identity_id=? AND j.lease_token=?)';
 try{
  const state=JSON.parse(job.cursor_json),statements=[];let rows=[],complete=false;
  const identity=await db.prepare("SELECT value FROM cvie_identity_identifiers WHERE identity_id=? AND scheme='cpe' LIMIT 1").bind(job.identity_id).first();
  if(!identity)complete=true;
  else{
   if(!state.phase)state.phase='nvd';
   if(state.phase==='nvd'){
    const scope=await db.prepare('SELECT id FROM cvie_shared_scopes WHERE cpe=? AND id>? ORDER BY id LIMIT 1').bind(identity.value,state.scope_after||'').first();
    if(!scope){state.phase='cna';state.family_after='';state.after='';}
    else{
     rows=(await db.prepare('SELECT cve_id FROM cvie_shared_advisories WHERE scope_id=? AND cve_id>? ORDER BY cve_id LIMIT 100').bind(scope.id,state.after||'').all()).results||[];
     if(rows.length)statements.push(db.prepare(`INSERT INTO cvie_identity_evidence(identity_id,cve_id,nvd_scope_id)
      SELECT ?,a.cve_id,a.scope_id FROM cvie_shared_advisories a JOIN cvie_shared_scopes s ON s.id=a.scope_id
      WHERE a.scope_id=? AND a.cve_id IN(SELECT value FROM json_each(?)) AND json_array_length(json_extract(s.signature,'$[1]'))=1 AND ${guard}
      ON CONFLICT(identity_id,cve_id) DO UPDATE SET nvd_scope_id=excluded.nvd_scope_id WHERE nvd_scope_id IS NOT excluded.nvd_scope_id`).bind(job.identity_id,scope.id,JSON.stringify(rows.map(r=>r.cve_id)),job.identity_id,token));
     if(rows.length<100){state.scope_after=scope.id;state.after='';}else state.after=rows.at(-1).cve_id;
    }
   }
   if(state.phase==='cna'){
    const family=await db.prepare('SELECT family_key FROM cvie_identity_families WHERE identity_id=? AND family_key>? ORDER BY family_key LIMIT 1').bind(job.identity_id,state.family_after||'').first();
    if(!family)complete=true;
    else{
     rows=(await db.prepare('SELECT cve_id FROM cvie_disclosure_products WHERE family_key=? AND cve_id>? ORDER BY cve_id LIMIT 100').bind(family.family_key,state.after||'').all()).results||[];
     if(rows.length)statements.push(db.prepare(`INSERT INTO cvie_identity_evidence(identity_id,cve_id,cna_affected_json)
      SELECT f.identity_id,d.cve_id,json_group_array(json(a.value)) FROM cvie_disclosure_products d
      JOIN cvie_identity_families f ON f.family_key=d.family_key,json_each(d.affected_json) a
      WHERE f.identity_id=? AND d.cve_id IN(SELECT value FROM json_each(?)) AND ${guard} GROUP BY f.identity_id,d.cve_id
      ON CONFLICT(identity_id,cve_id) DO UPDATE SET cna_affected_json=excluded.cna_affected_json WHERE cna_affected_json IS NOT excluded.cna_affected_json`).bind(job.identity_id,JSON.stringify(rows.map(r=>r.cve_id)),job.identity_id,token));
     if(rows.length<100){state.family_after=family.family_key;state.after='';}else state.after=rows.at(-1).cve_id;
    }
   }
  }
  statements.push(db.prepare('UPDATE cvie_identity_index_jobs SET cursor_json=?,complete=?,lease_until=0,lease_token=\'\',next_attempt_at=?,failed=0 WHERE identity_id=? AND lease_token=?').bind(JSON.stringify(state),Number(complete),now+60000,job.identity_id,token));
  await db.batch(statements);return {processed:rows.length,complete};
 }catch{
  await db.prepare('UPDATE cvie_identity_index_jobs SET lease_until=0,lease_token=\'\',next_attempt_at=?,failed=1 WHERE identity_id=? AND lease_token=?').bind(now+60000,job.identity_id,token).run();
  return {failed:true};
 }
}
