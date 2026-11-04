// Compare SQL tokens, not formatting. Never collapse whitespace inside literals,
// quoted identifiers or comments; never merge identifiers/operators across gaps.
export function sqlTokens(sql){
 const text=String(sql),tokens=[];let i=0;
 while(i<text.length){
  if(/\s/u.test(text[i])){i++;continue;}
  const start=i,c=text[i];
  const blob=/^[xX]'(?:''|[^'])*'/.exec(text.slice(i));if(blob){tokens.push(blob[0]);i+=blob[0].length;continue;}
  if(text.startsWith('--',i)){i=text.indexOf('\n',i);if(i<0)i=text.length;tokens.push(text.slice(start,i));continue;}
  if(text.startsWith('/*',i)){const end=text.indexOf('*/',i+2);if(end<0)throw Error('Unterminated SQL comment');i=end+2;tokens.push(text.slice(start,i));continue;}
  if("'\"`[".includes(c)){
   const close=c==='['?']':c;i++;let ended=false;
   while(i<text.length){if(text[i++]===close){if(c!=='['&&text[i]===close){i++;continue;}ended=true;break;}}
   if(!ended)throw Error('Unterminated SQL quote');tokens.push(text.slice(start,i));continue;
  }
  const m=/^(?:0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?|[\p{L}_][\p{L}\p{N}_$]*|->>|->|\|\||<<|>>|<=|>=|==|!=|<>)/u.exec(text.slice(i));
  if(m){tokens.push(m[0]);i+=m[0].length;}else tokens.push(text[i++]);
 }
 if(tokens.at(-1)===';')tokens.pop();
 return tokens;
}
export const canonicalDDL=sql=>JSON.stringify(sqlTokens(sql));
