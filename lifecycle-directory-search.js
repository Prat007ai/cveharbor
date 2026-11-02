(() => {
'use strict';
const normalize=value=>String(value||'').normalize('NFKC').toLowerCase().replace(/[^a-z0-9]+/g,' ').trim();
// Bounded edit distance is computed at search time; misspellings are not stored.
function distance(a,b){
 if(Math.abs(a.length-b.length)>2)return 3;
 let previous=Array.from({length:b.length+1},(_,i)=>i),before;
 for(let i=1;i<=a.length;i++){
  const row=[i];for(let j=1;j<=b.length;j++){
   row[j]=Math.min(row[j-1]+1,previous[j]+1,previous[j-1]+Number(a[i-1]!==b[j-1]));
   if(before&&i>1&&j>1&&a[i-1]===b[j-2]&&a[i-2]===b[j-1])row[j]=Math.min(row[j],before[j-2]+1);
  }before=previous;previous=row;
 }return previous[b.length];
}
function search(products,input){
 const query=normalize(input).slice(0,120);if(!query)return products.map(product=>({product,suggested:false}));
 return products.map(product=>{
  const names=[product.name,product.slug,...product.aliases||[]].map(normalize);
  const direct=names.some(n=>(n===query||n.startsWith(query)||n.includes(' '+query))||query.split(' ').every(word=>n.split(' ').some(part=>part.startsWith(word))));
  const exact=names.includes(query);
  const fuzzy=!direct&&query.length>=4&&names.some(n=>distance(query,n)<=Math.min(2,Math.floor(query.length/4)));
  return {product,suggested:fuzzy,rank:exact?0:direct?1:fuzzy?2:3};
 }).filter(x=>x.rank<3).sort((a,b)=>a.rank-b.rank||a.product.name.localeCompare(b.product.name));
}
window.CVEHARBOR_DIRECTORY_SEARCH={search,normalize};
})();
