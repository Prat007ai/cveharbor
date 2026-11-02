// Public feed metadata only. Never cache account products, assets or findings.
// Each Worker isolate shares one bounded entry per database binding. Cold
// isolates read D1 normally; a cache miss never affects correctness.
const entries=new WeakMap();
export const PUBLIC_STATUS_TTL=30000;
export function invalidatePublicSourceStatus(env){entries.delete(env.CVIE_UNWRAPPED_DB||env.DB);}
export async function publicSourceStatus(env,now,load){
 const key=env.CVIE_UNWRAPPED_DB||env.DB;let entry=entries.get(key);
 if(!entry||now<entry.started||now>=entry.expires){
  entry={started:now,expires:now+PUBLIC_STATUS_TTL};
  entry.promise=Promise.resolve().then(load).then(JSON.stringify);
  entries.set(key,entry);
 }
 try{return JSON.parse(await entry.promise);}
 catch(error){if(entries.get(key)===entry)entries.delete(key);throw error;}
}
