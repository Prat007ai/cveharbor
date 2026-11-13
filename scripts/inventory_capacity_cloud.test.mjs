import test from 'node:test';
import assert from 'node:assert/strict';
import {validateCloudRun,validateRetainedDatabase,previewDiagnostics,enableRetainedReadReplication} from './inventory_capacity_cloud.mjs';
import {classifyDatabaseError,observeDatabase} from './capacity_db_observer.mjs';
const valid={GITHUB_REPOSITORY:'Prat007ai/cveharbor',GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_RUN_ATTEMPT:'1',GITHUB_WORKFLOW_REF:'Prat007ai/cveharbor/.github/workflows/inventory-capacity-cloud.yml@refs/heads/main',GITHUB_RUN_ID:'12345678901',GITHUB_SHA:'a'.repeat(40),CAPACITY_REVIEWED_COMMIT:'a'.repeat(40),CLOUDFLARE_ACCOUNT_ID:'9706b4d98ad72884e67fd1eb875c8a61',CLOUDFLARE_API_TOKEN:'fictional-only'};

test('replication configuration is restricted to the retained fictional database',async()=>{
 const database={uuid:'b4a226d7-35e8-469f-abfe-2a2eee0a96de',name:'cveharbor-capacity-43438175247',read_replication:{mode:'disabled'}},calls=[];
 const api=async(path,method,body)=>{calls.push({path,method,body});return {...database,read_replication:{mode:'auto'}};};
 assert.deepEqual(await enableRetainedReadReplication(api,database),{before:'disabled',after:'auto'});
 assert.deepEqual(calls,[{path:'/d1/database/'+database.uuid,method:'PUT',body:{read_replication:{mode:'auto'}}},{path:'/d1/database/'+database.uuid,method:undefined,body:undefined}]);
 calls.length=0;await enableRetainedReadReplication(api,{...database,read_replication:{mode:'auto'}});assert.equal(calls.length,1);assert.equal(calls[0].method,undefined);
 calls.length=0;
 await assert.rejects(enableRetainedReadReplication(api,{...database,uuid:'46710e51-7ca4-4571-b89c-921b9969de0b'}));
 await assert.rejects(enableRetainedReadReplication(api,{...database,read_replication:{}}));assert.equal(calls.length,0);
});

test('observer measures replica page results without exposing session bookmarks',async()=>{
 const result={results:[],meta:{served_by_primary:false,rows_read:3,duration:1}};
 const {binding,state}=observeDatabase({withSession(bookmark){assert.equal(bookmark,'fictional-private-bookmark');return {getBookmark:()=>bookmark,prepare:()=>({all:async()=>result})};}});
 const session=binding.withSession('fictional-private-bookmark');assert.equal(session.getBookmark(),'fictional-private-bookmark');
 assert.equal(await session.prepare('SELECT 1 AS packed').all(),result);
 assert.equal(state.replica_results,1);assert.equal(state.primary_results,0);assert.equal(state.calls,1);assert.equal(state.rows_read,3);
 assert.doesNotMatch(JSON.stringify(state),/fictional|bookmark/);
});
test('preview diagnostics retain only closed categories and provider codes',()=>{
 const result=previewDiagnostics('secret-value https://private.example/?token=private Authentication error [code: 10000]\nA request to the Cloudflare API failed');
 assert.deepEqual(result,{categories:['authentication','provider_api'],provider_codes:[10000]});
 assert.doesNotMatch(JSON.stringify(result),/secret|private|https|token/);
 assert.deepEqual(previewDiagnostics('unrecognized confidential output'),{categories:['unknown'],provider_codes:[]});
 assert.deepEqual(previewDiagnostics('Script startup exceeded CPU time limit [code: 10021]'),{categories:['startup_resource'],provider_codes:[10021]});
});
test('cloud rehearsal requires exact main, manual first attempt, reviewed commit, staging account and caller',()=>{
 assert.equal(validateCloudRun(valid),'cveharbor-capacity-12345678901');
 for(const [key,value] of [['GITHUB_REPOSITORY','other/repo'],['GITHUB_REF','refs/heads/feature'],['GITHUB_EVENT_NAME','push'],['GITHUB_RUN_ATTEMPT','2'],['GITHUB_WORKFLOW_REF','Prat007ai/cveharbor/.github/workflows/other.yml@refs/heads/main'],['GITHUB_RUN_ID','../../escape'],['CAPACITY_REVIEWED_COMMIT','b'.repeat(40)],['CLOUDFLARE_ACCOUNT_ID','aa99b9b15e0492302e4f6484b8d27bc2'],['CLOUDFLARE_API_TOKEN','']])assert.throws(()=>validateCloudRun({...valid,[key]:value}));
});
test('continued rehearsal can use only the exact retained fictional database',()=>{
 const database={uuid:'b4a226d7-35e8-469f-abfe-2a2eee0a96de',name:'cveharbor-capacity-43438175247'};
 assert.equal(validateRetainedDatabase(database),database);
 for(const uuid of ['46710e51-7ca4-4571-b89c-921b9969de0b','fac61562-fc31-426d-8032-550aba63b7f6','aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'])assert.throws(()=>validateRetainedDatabase({...database,uuid}));
 assert.throws(()=>validateRetainedDatabase({...database,name:'cveharbor-accounts-staging'}));
});
test('database observer retains native statements, bindings, results and failures without recording their content',async()=>{
 const statements=[],result={results:[{private_value:'fictional-private'}],meta:{rows_read:2,rows_written:1,duration:3}};
 const failure=new Error('D1_ERROR',{cause:new Error('D1 DB is overloaded. Requests queued for too long. private-value')});
 const db={prepare(sql){const s={bind(...args){this.args=args;return this;},async all(){return result;},async first(){throw failure;}};statements.push(s);return s;},async batch(rows){assert.equal(rows[0],statements[0]);assert.deepEqual(rows[0].args,['fictional-session']);return [result];}};
 const {binding,state}=observeDatabase(db),s=binding.prepare('SELECT private_value FROM sessions').bind('fictional-session');
 assert.equal(await s.all(),result);assert.deepEqual(await binding.batch([s]),[result]);
 await assert.rejects(s.first(),error=>error===failure);
 assert.deepEqual(state.errors,[{operation:'session_auth',category:'queue_wait'}]);assert.equal(state.calls,3);assert.equal(state.rows_read,4);assert.equal(state.rows_written,2);
 assert.doesNotMatch(JSON.stringify(state),/fictional|private|SELECT|D1_ERROR/);
});
test('database diagnostics use closed error classes and suppress unknown text',()=>{
 for(const [message,category]of [['D1 DB is overloaded. Too many resources consumed within a 10 second window','resource_window'],['D1 DB is overloaded. Too many requests queued','queue_full'],['D1 DB is overloaded. Requests queued for too long','queue_wait'],['D1 DB is overloaded','overloaded']])assert.equal(classifyDatabaseError(new Error('D1_ERROR',{cause:new Error(message)})),category);
 for(const [message,category]of [['daily usage limit exceeded','quota'],['Cannot resolve D1 DB due to transient issue on remote node.','transient'],['no such table: private','schema'],['UNIQUE constraint failed','constraint'],['fetch failed','transport'],['request timed out','timeout'],['secret text','unknown']])assert.equal(classifyDatabaseError(new Error(message)),category);
});
