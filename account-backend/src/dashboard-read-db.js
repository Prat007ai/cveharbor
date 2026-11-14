// Read capabilities for the explicitly audited dashboard endpoints only.
// No cached authority, private response cache, writes or background effects.
const paths=new Set(['/v1/me','/v1/cvie','/v1/cvie/progress','/v1/cvie/advisories','/v1/workspace/summary','/v1/workspace/items','/v1/workspace/trend','/v1/inventory/software-history','/v1/customer-score-history','/v1/finding-assignments','/v1/team/organizations']);
export const dashboardReadRequest=req=>req.method==='GET'&&new URL(req.url).hostname!=='confirm.cveharbor.com'&&paths.has(new URL(req.url).pathname);
function readSql(sql){
 if(typeof sql!=='string')throw Error('Dashboard capability accepts one read-only SELECT');
 // Remove literals/comments before checking SQL tokens. A CTE can otherwise
 // conceal UPDATE/DELETE even when its name starts with an innocent SELECT.
 const tokens=sql.replace(/'(?:''|[^'])*'|"(?:""|[^"])*"|`[^`]*`|\[[^\]]*\]|--[^\n]*|\/\*[\s\S]*?\*\//g,' ');
 if(!/^\s*(SELECT|WITH)\b/i.test(tokens)||/;|\b(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|PRAGMA|ATTACH|DETACH|VACUUM|REINDEX|ANALYZE|BEGIN|COMMIT|ROLLBACK)\b|\bREPLACE\b(?!\s*\()/i.test(tokens))throw Error('Dashboard capability accepts one read-only SELECT');
 return tokens;
}
export function dashboardReadDatabase(db,{sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms)),random=Math.random}={}){
 let bookmark=null;const statements=new WeakMap();
 const authority=sql=>/\b(operations_control|sessions|user_totp|users|team_\w+)\b/i.test(sql);
 const authentication=sql=>/\bFROM\s+sessions\b/i.test(sql)&&/\buser_totp\b/i.test(sql);
 const transient=e=>/overload|queued for too long|transient issue|object.*reset|7500/.test([e?.message,e?.cause?.message].join(' ').toLowerCase());
 async function execute(specs,method,options=[]){
  for(let attempt=0;;attempt++){
   const primary=!bookmark||specs.some(s=>authority(s.tokens));
   // Recreate the session on a transient failure so routing can recover. Fresh
   // primary maintenance, session/MFA and team checks are never bypassed.
   const session=typeof db.withSession==='function'?db.withSession(primary?'first-primary':bookmark):db;
   try{
    const native=specs.map(s=>{const p=session.prepare(s.sql);return s.args.length?p.bind(...s.args):p;});
    const result=method==='batch'?await session.batch(native):await native[0][method](...options);
    if(primary&&session!==db&&specs.some(s=>authentication(s.tokens))&&result)bookmark=session.getBookmark();
    return result;
   }catch(error){if(attempt===3||!transient(error))throw error;await sleep(50*3**attempt+Math.floor(random()*50));}
  }
 }
 function statement(sql,args=[],tokens=readSql(sql)){
  const spec={sql,args,tokens},result={bind:(...values)=>statement(sql,values,tokens)};
  for(const method of ['first','all','raw'])result[method]=(...options)=>execute([spec],method,options);
  statements.set(result,spec);return Object.freeze(result);
 }
 return Object.freeze({prepare:sql=>statement(sql),batch:rows=>{
  if(!Array.isArray(rows)||!rows.length||rows.some(r=>!statements.has(r)))throw Error('Dashboard batch requires read-only capabilities');
  return execute(rows.map(r=>statements.get(r)),'batch');
 }});
}
