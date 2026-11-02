// Only fixed SELECT/CTE/EXPLAIN statements are accepted by the diagnostic adapter.
// SQL REPLACE(text, old, new) is a read-only function, not REPLACE INTO.
export function assertReadOnlySql(sql){
 const code=sql.replace(/'(?:''|[^'])*'/g,"''");
 if(!/^\s*(SELECT|EXPLAIN QUERY PLAN|WITH)\b/i.test(code)||/;|\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|ATTACH|VACUUM)\b|\bREPLACE\b(?!\s*\()/i.test(code))throw Error('Read-only diagnostic rejected a mutating or unsupported statement');
}
