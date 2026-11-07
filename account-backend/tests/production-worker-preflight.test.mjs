import test from 'node:test';
import assert from 'node:assert/strict';
import {baselineDB, applyLocally} from '../../deployment/proposals/production-compatibility/rehearsal.mjs';
import {preflight, verifySchema, verifyTarget} from '../../scripts/production_worker_preflight.mjs';
import {verifyService} from '../../scripts/production_service_health.mjs';

const account = 'aa99b9b15e0492302e4f6484b8d27bc2';
const name = 'cveharbor-accounts';
const database = '46710e51-7ca4-4571-b89c-921b9969de0b';
const config = {name, vars: {RECOVERY_CONTROL_REQUIRED:'true'}, d1_databases:[{binding:'DB', database_name:name, database_id:database}]};

function fixture(t) {
  const sqlite = baselineDB();
  t.after(() => sqlite.close());
  const DB = {prepare(sql) {
    assert.match(sql, /^SELECT /);
    const stmt = sqlite.prepare(sql);
    return {all: () => ({results: stmt.all()}), first: () => stmt.get()};
  }};
  return {sqlite, DB};
}

test('audited production schema from the outage is rejected before an upload', async t => {
  const {sqlite, DB} = fixture(t);
  sqlite.exec('PRAGMA query_only=ON');
  await assert.rejects(verifySchema(DB), /Missing required production table: operations_control/);
});

test('repaired database is accepted only in the correct release mode and with full coverage', async t => {
  const {sqlite, DB} = fixture(t);
  applyLocally(sqlite);
  await verifySchema(DB, {recovery:true});
  await assert.rejects(verifySchema(DB), /Recovery control row/);
  sqlite.exec('UPDATE operations_control SET write_hold=0,database_frozen=0,revision=1');
  await verifySchema(DB);
  await assert.rejects(verifySchema(DB, {migrations:[{name:'0001_required.sql'}]}), /receipt missing: 0001_required/);
  await assert.rejects(verifySchema(DB, {recovery:true}), /Recovery control row/);
  sqlite.exec('DROP TRIGGER recovery_hold_new_lease');
  await assert.rejects(verifySchema(DB), /Candidate readiness failed/);
});

test('candidate binding and live binding must identify production before D1 is queried', async () => {
  assert.throws(() => verifyTarget('0'.repeat(32),config),/account/);
  assert.throws(() => verifyTarget(account,{...config,d1_databases:[]}),/binding/);
  const requests = [];
  const fetcher = async (url, init) => {
    requests.push(url);
    assert.equal(init.method ?? 'GET','GET');
    return Response.json({success:true,result:url.endsWith('/settings') ? {bindings:[{name:'DB',type:'d1',id:'wrong'}]} : {uuid:database,name}});
  };
  await assert.rejects(preflight({CLOUDFLARE_ACCOUNT_ID:account,CLOUDFLARE_API_TOKEN:'test'},config,fetcher), /Live Worker DB binding/);
  assert.equal(requests.length,2);
});

test('monitor distinguishes healthy, confirmed hold and failed schema without reporting holds as healthy', async () => {
  for (const [state, status, failure] of [
    [{ready:true,held:false,schema_ready:true},200,null],
    [{ready:false,held:true,schema_ready:true},503,/active maintenance hold/],
    [{ready:false,held:true,schema_ready:false},503,/schema\/readiness query failed/]
  ]) {
    const result = verifyService({readinessOnly:true,fetcher:async url => {
      assert.ok(url.endsWith('/release-readiness')); return Response.json(state,{status});
    }});
    if (failure) await assert.rejects(result,failure); else await result;
  }
});
