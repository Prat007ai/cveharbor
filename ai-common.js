export const $=id=>document.getElementById(id);
export const element=(tag,text,className)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(className)n.className=className;return n;};
export const money=value=>new Intl.NumberFormat('en-US',{style:'currency',currency:'USD',maximumFractionDigits:6}).format(value);
export async function api(path,method='GET',body){
 const r=await fetch('https://api.cveharbor.com/v1'+path,{method,credentials:'include',cache:'no-store',headers:{'Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});
 const data=await r.json();if(!r.ok){const e=Error(data.message||data.error||'The request could not be completed.');e.status=r.status;e.data=data;throw e;}return data;
}
export function metric(label,value,detail){const n=element('article',undefined,'ai-card');n.append(element('p',label),element('strong',value,'ai-value'),element('small',detail));return n;}
export function table(headers,rows){const n=element('table'),head=element('thead'),tr=element('tr'),body=element('tbody');for(const title of headers){const th=element('th',title);th.scope='col';tr.append(th);}head.append(tr);for(const values of rows){const row=element('tr');for(const value of values){const cell=element('td');cell.append(value instanceof Node?value:document.createTextNode(String(value??'—')));row.append(cell);}body.append(row);}n.append(head,body);return n;}
export function status(text){$('status').textContent=text;}
