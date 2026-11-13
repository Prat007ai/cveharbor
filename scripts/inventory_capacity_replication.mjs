import assert from 'node:assert/strict';
const account='aa99b9b15e0492302e4f6484b8d27bc2',database='46710e51-7ca4-4571-b89c-921b9969de0b';
export async function ensureCapacityReplication(db,{env=process.env,fetcher=fetch}={}){
 assert.equal(env.GITHUB_REF,'refs/heads/main');assert.match(env.GITHUB_SHA||'',/^[a-f0-9]{40}$/);
 assert.equal(env.CLOUDFLARE_ACCOUNT_ID,account);assert.ok(env.CLOUDFLARE_API_TOKEN);
 const before=await db.metadata();assert.equal(before.uuid,database);assert.equal(before.name,'cveharbor-accounts');
 const mode=before.read_replication?.mode;assert.ok(['auto','disabled'].includes(mode));
 if(mode!=='auto'){
  const response=await fetcher(`https://api.cloudflare.com/client/v4/accounts/${account}/d1/database/${database}`,{
   method:'PUT',headers:{Authorization:'Bearer '+env.CLOUDFLARE_API_TOKEN,'Content-Type':'application/json'},
   body:JSON.stringify({read_replication:{mode:'auto'}}),redirect:'error',signal:AbortSignal.timeout(30000)});
  const result=await response.json();assert.ok(response.ok&&result.success,'Capacity read replication configuration failed; inspect the recorded state before continuing');
 }
 const after=await db.metadata();assert.equal(after.uuid,database);assert.equal(after.name,before.name);assert.equal(after.read_replication?.mode,'auto');
 return {before:mode,after:'auto'};
}
