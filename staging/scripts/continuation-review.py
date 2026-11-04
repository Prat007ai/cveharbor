"""Prove the two separately approved phases reconcile original checkpoint 29. No remote I/O."""
import importlib.util
import hashlib
import json
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'staging/.build/schema'
spec = importlib.util.spec_from_file_location('checkpoint_builder', Path(__file__).with_name('migration-plan.py'))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

def build():
    full, _ = builder.build()
    reference_bytes = (ROOT/'staging/schema-diagnostic.v1.json').read_bytes()
    reference = json.loads(reference_bytes)
    baseline = ROOT / reference['source_sql']
    if builder.digest(baseline.read_text()) != reference['source_sql_sha256'] or reference['expected_step'] != 29:
        raise ValueError('Original verified source changed')
    manifest = json.loads((ROOT/'staging/migrations.v1.json').read_text())
    if manifest['entries'][0]['path'] != 'staging/schema.sql' or manifest['entries'][1]['path'] != reference['source_sql']:
        raise ValueError('Review the staging adoption order')
    db = sqlite3.connect(':memory:')
    db.execute('PRAGMA foreign_keys=ON')
    builder.d1_limits(db)
    db.executescript(baseline.read_text())
    plan = {'format':1, 'profile':'original29-reconciliation-review-v1', 'manifest_version':1,
      'approved_manifest_sha256':full['approved_manifest_sha256'], 'reference_sha256':hashlib.sha256(reference_bytes).hexdigest(),
      'initial_step':29, 'schema_sql':full['schema_sql'], 'adoptions':[{'file':reference['source_sql'],
      'sha256':reference['source_sql_sha256'], 'verified_original_step':29, 'evidence_run':41707547474, 'evidence_attempt':2}],
      'files':[], 'checkpoints':reference['checkpoints'], 'schemas':dict(reference['schemas'])}
    def capture():
        objects = [list(r) for r in db.execute(plan['schema_sql'])]
        sh = builder.digest(builder.encoded(objects))
        tables=[]; counts=[]; rows=[]
        for _,name,_,_ in objects:
            if not any(o[0]=='table' and o[1]==name for o in objects) or any(t['name']==name for t in tables):continue
            columns=[r[1] for r in db.execute('PRAGMA table_info('+builder.identifier(name)+')')]
            tables.append({'name':name,'row_sql':builder.row_sql(name,columns)})
        tables.sort(key=lambda t:t['name'])
        for t in tables:
            values=[r[0] for r in db.execute(t['row_sql'])]
            counts.append([t['name'],len(values)]);rows.extend([[t['name'],v] for v in values])
        plan['schemas'][sh]={'objects':objects,'tables':tables}
        return {'schema_sha256':sh,'counts':counts,'rows_sha256':builder.digest(builder.encoded(rows))}
    if capture()!=reference['checkpoints'][29]:raise ValueError('Baseline does not reproduce verified original checkpoint 29')
    # The first new transaction creates staging bookkeeping and records BOTH the
    # newly applied staging file and the independently verified existing base.
    for index, item in enumerate(full['files']):
        if item['file']==reference['source_sql']:continue  # NEVER replay these 29 statements.
        pending=list(item['statements'])
        phase=item['phase']
        if index==0:
            pending.append(full['files'][1]['statements'][-1])
            phase='adopt-original29'
        start=len(plan['checkpoints'])-1
        for sql in pending:
            db.execute(sql)
            if db.execute('PRAGMA foreign_key_check').fetchall():raise ValueError('Forward plan violates foreign keys')
            plan['checkpoints'].append(capture())
        plan['files'].append({**item,'phase':phase,'start':start,'end':len(plan['checkpoints'])-1,'statements':pending})
    if plan['checkpoints'][-1]!=full['checkpoints'][-1]:raise ValueError('Continuation differs from clean integrated schema/data state')
    if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('Final integrity failed')
    rows=db.execute('SELECT path,sha256,manifest_version FROM staging_schema_history ORDER BY rowid').fetchall()
    if rows!=[(e['path'],e['sha256'],1) for e in manifest['entries']]:raise ValueError('Incorrect migration/adoption receipts')
    payload=builder.encoded(plan)+'\n';builder.write_atomic(OUT/'reconciliation-plan.json',payload)
    # Exact executable batches are separately reviewable and hashed; original
    # file digests remain alongside them (receipts are additional SQL).
    files=[]
    for i, item in enumerate(plan['files']):
        sql='\n'.join(item['statements'])+'\n'
        name=f'continuation-{i:02d}.sql';builder.write_atomic(OUT/name,sql)
        files.append({'file':item['file'],'source_sha256':item['sha256'],'phase':item['phase'],
          'from_step':item['start'],'to_step':item['end'],'statements':len(item['statements']),
          'execution_sql':name,'execution_sha256':builder.digest(sql)})
    phase_b_sql=''.join((OUT/f['execution_sql']).read_text() for f in files[1:])
    builder.write_atomic(OUT/'continuation-phase-b-review.sql',phase_b_sql)
    summary={'phase_b_sql_sha256':builder.digest(phase_b_sql),'profile':plan['profile'],'account':'9706b4d98ad72884e67fd1eb875c8a61',
      'database_id':'fac61562-fc31-426d-8032-550aba63b7f6','initial_original_step':29,
      'final_step':len(plan['checkpoints'])-1,'execution_plan_sha256':builder.digest((OUT/'execution-plan.json').read_text()),'reconciliation_sha256':builder.digest(payload),'adoption_spec_sha256':builder.digest((ROOT/'staging/adoption.v1.json').read_text()),'phase_b_start':37,'phase_b_statements':703,'phase_b_batches':34,
      'manifest_sha256':plan['approved_manifest_sha256'],'reference_sha256':plan['reference_sha256'],
      'adoptions':plan['adoptions'],'files':files,'application_tables':len(plan['checkpoints'][-1]['counts']),
      'receipt_rows':len(rows),'remote_executed':False}
    builder.write_atomic(OUT/'continuation-summary.json',json.dumps(summary,indent=2)+'\n')
    print('Integrated execution plan SHA-256: '+summary['execution_plan_sha256'])
    print(f"Original step 29 -> {summary['final_step']}; {len(files)} new batches; {sum(f['statements'] for f in files)} statements; {len(rows)} receipts")
    db.close()
    return plan,summary

if __name__=='__main__':build()
