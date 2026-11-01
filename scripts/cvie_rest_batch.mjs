// REST /query supports transactional multi-statement SQL without parameters.
// Escape values as SQLite literals; never interpolate them with shell commands.
const literal=value=>{
 if(value===null)return 'NULL';
 if(typeof value==='number'&&Number.isFinite(value))return String(value);
 if(typeof value==='string'&&!value.includes('\0'))return "'"+value.replaceAll("'","''")+"'";
 throw Error('Unsupported REST batch value');
};
function render(statement){
 let index=0;
 const sql=statement.sql.replace(/'(?:''|[^'])*'|"(?:""|[^"])*"|--[^\n]*|\/\*[\s\S]*?\*\/|\?/g,token=>token==='?'?literal(statement.params[index++]):token);
 if(index!==statement.params.length)throw Error('Unsupported REST batch parameters');
 return sql;
}
export function restBatch(statements){
 const pending=[...statements],queries=[];
 while(pending.length){
  const s=pending.shift(),sql=render(s);
  if(Buffer.byteLength(sql)>90000){
   // Bulk import statements consume JSON arrays through json_each. Split only
   // that input, keeping all generated statements in the same transaction.
   let index=-1,values;
   for(let i=0;i<s.params.length;i++)if(typeof s.params[i]==='string'){try{const v=JSON.parse(s.params[i]);if(Array.isArray(v)&&v.length>1&&(!values||v.length>values.length)){index=i;values=v;}}catch{}}
   if(index<0)throw Error('REST migration statement exceeds the safe SQL size');
   const middle=Math.ceil(values.length/2);
   pending.unshift(...[values.slice(0,middle),values.slice(middle)].map(part=>({...s,params:s.params.map((v,i)=>i===index?JSON.stringify(part):v)})));
  }else queries.push(sql);
 }
 return {sql:queries.join(';\n')};
}
