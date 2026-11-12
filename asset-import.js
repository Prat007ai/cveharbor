(function(root){
'use strict';
const headers=['Asset Name','Asset Type','Technology','Version','Notes'];
const types=new Set(['Server','WEB','Application','Database','Cloud Service','Network Device','Software','Other']);
const norm=x=>String(x||'').trim().toLowerCase();
const key=a=>[a.name,a.asset_type,a.technology,a.version].map(norm).join('\u0000');
function parse(text){
 if(new TextEncoder().encode(text).length>131072)throw Error('CSV file exceeds 128 KB. Use the collector’s numbered files.');
 const rows=[];let row=[],field='',quoted=false,closed=false;
 const input=text.replace(/^\uFEFF/,'');
 for(let i=0;i<input.length;i++){
  const c=input[i];
  if(quoted){if(c==='"'&&input[i+1]==='"'){field+='"';i++;}else if(c==='"'){quoted=false;closed=true;}else field+=c;continue;}
  if(c===','){row.push(field);field='';closed=false;}
  else if(c==='\r'||c==='\n'){if(c==='\r'&&input[i+1]==='\n')i++;row.push(field);if(row.some(v=>v.trim()))rows.push(row);row=[];field='';closed=false;}
  else if(c==='"'){if(field||closed)throw Error('Invalid CSV quoting.');quoted=true;}
  else {if(closed)throw Error('Unexpected text after a quoted CSV value.');field+=c;}
 }
 if(quoted)throw Error('Unclosed quoted CSV value.');
 row.push(field);if(row.some(v=>v.trim()))rows.push(row);
 const networkColumn=rows[0]?.length===6&&norm(rows[0][5])==='server network';
 if((rows[0]?.length!==5&&!networkColumn)||headers.some((h,i)=>norm(rows[0][i])!==norm(h)))throw Error('Headers must be: '+headers.join(', ')+', optionally followed by Server Network.');
 if(rows.length<2||rows.length>201)throw Error('Include 1–200 entries per file.');
 const seen=new Set(),entries=[],warnings=[],networks=new Map();let duplicates=0;
 rows.slice(1).forEach((cells,i)=>{
  if(cells.length!==(networkColumn?6:5))throw Error('Row '+(i+2)+' does not match the header columns.');
  const [name,asset_type,technology,version,notes]=cells.map(v=>v.trim());
  if(!name||name.length>120||!technology||technology.length>120||!types.has(asset_type)||version.length>80||notes.length>500||cells.some(v=>/[\u0000-\u001f\u007f]/.test(v)))throw Error('Invalid or overlong fields on row '+(i+2)+'.');
  if(cells.some(v=>/^[=+@-]/.test(v.trim())))throw Error('Row '+(i+2)+' begins with a spreadsheet formula character. Prefix that value with an apostrophe.');
  const entry={name,asset_type,technology,version,notes};
  if(networkColumn&&cells[5].trim()){
   let snapshot;try{snapshot=JSON.parse(cells[5]);}catch{throw Error('Invalid Server Network JSON on row '+(i+2));}
   if(cells[5].length>14000||snapshot?.version!==1||!Array.isArray(snapshot.adapters)||!snapshot.adapters.length||snapshot.adapters.length>32||!Number.isFinite(Date.parse(snapshot.collected_at)))throw Error('Invalid network snapshot on row '+(i+2));
   let count=0;const ids=new Set();
   for(const a of snapshot.adapters){
    if(!a||typeof a.id!=='string'||!a.id||a.id.length>80||ids.has(a.id)||typeof a.name!=='string'||!a.name||a.name.length>120||typeof a.status!=='string'||!a.status||a.status.length>32||!Array.isArray(a.addresses)||a.addresses.length>64)throw Error('Invalid network adapter on row '+(i+2));
    ids.add(a.id);const ips=new Set();
    for(const p of a.addresses){
     let valid=false;try{valid=typeof p.ip==='string'&&(p.ip.includes(':')?/^[a-f0-9:]+$/i.test(p.ip)&&!!new URL('http://['+p.ip+']/'):/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(p.ip)&&p.ip.split('.').every(n=>Number(n)<=255));}catch{}
     if(!valid||ips.has(p.ip)||!Number.isInteger(p.prefix)||p.prefix<0||p.prefix>(p.ip.includes(':')?128:32)||typeof p.state!=='string'||!p.state||p.state.length>32)throw Error('Invalid network address on row '+(i+2));ips.add(p.ip);count++;
    }
   }
   if(count>128||snapshot.suggested&&!snapshot.adapters.some(a=>a.id===snapshot.suggested.adapter_id&&a.addresses.some(p=>p.ip===snapshot.suggested.ip)))throw Error('Invalid network primary suggestion on row '+(i+2));
   const previous=networks.get(norm(name));if(previous&&JSON.stringify(previous.snapshot)!==JSON.stringify(snapshot))throw Error('Conflicting network snapshots for '+name+'. Use one collection per server in each file.');
   networks.set(norm(name),{name,snapshot});
  }
  if(seen.has(key(entry))){duplicates++;return;}seen.add(key(entry));entries.push(entry);
  if(!version)warnings.push('Row '+(i+2)+': version is unknown; affected-version assessment needs review.');
 });
 return {entries,warnings,duplicates,networks:[...networks.values()]};
}
const el=(tag,value='',cls='')=>{const e=document.createElement(tag);e.textContent=value;if(cls)e.className=cls;return e;};
function anchor(label,href){const a=el('a',label,'ops-download');a.href=href;return a;}
function dashboardURL(scope){return '/customer-dashboard/?'+new URLSearchParams({customer:scope.customer,environment:scope.environment,...(scope.org?{org:scope.org}:{})});}
function mount(host,{scope,readAssets,saveAsset,saveNetwork,afterImport=async()=>{}}){
 if(!document.querySelector('link[href^="/inventory-import.css"]')){const css=document.createElement('link');css.rel='stylesheet';css.href='/inventory-import.css?v=windows-inventory-1';document.head.append(css);}
 const panel=el('section','','inventory-plugin-import inventory-bulk-import');
 panel.append(el('h3','Import server inventory and assess vulnerabilities'),el('p','Collect → upload → review → import → assess. No AI is used. Each installed version is retained separately. Existing identical rows are skipped; older versions are not removed.','ops-note'));
 const download=anchor('Download Windows PowerShell collector','/collectors/Export-CVEHarborInventory.ps1');download.download='Export-CVEHarborInventory.ps1';
 panel.append(download,anchor('Collector instructions','/collectors/README.txt'));
 const template=el('button','Download Excel CSV template','ops-download');template.type='button';
 template.onclick=()=>{const samples=['Production Web Stack,WEB,PHP,8.4.26,Example only','Production Web Stack,WEB,NGINX,1.26.3,Example only','Production Web Stack,WEB,Ubuntu Linux,24.04,Example only','DEMO-WEB01,Server,Windows Server,,Example only - collect exact OS build before import'];const url=URL.createObjectURL(new Blob(['\uFEFF'+[headers.join(','),...samples].join('\r\n')+'\r\n'],{type:'text/csv;charset=utf-8'}));const a=anchor('Download',url);a.download='cveharbor-asset-import.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};panel.append(template);
 const label=el('label','Upload inventory CSV','inventory-plugin-file-label'),file=el('input');file.type='file';file.accept='.csv';label.append(file);
 const preview=el('div','','inventory-bulk-preview'),message=el('p','','ops-note');message.setAttribute('role','status');
 const consent=el('input');consent.type='checkbox';const consentLabel=el('label','I reviewed the inventory and selected customer/environment. ');consentLabel.prepend(consent);
 const submit=el('button','Import and assess vulnerabilities','ops-download');submit.type='button';submit.disabled=true;
 let batch=null,snapshot=null,busy=false,sequence=0;
 const same=()=>JSON.stringify(scope())===JSON.stringify(snapshot);
 function reset(){batch=null;consent.checked=false;submit.disabled=true;preview.replaceChildren();}
 consent.onchange=()=>{submit.disabled=busy||!batch||!consent.checked||!same();};
 file.onchange=async()=>{
  const ticket=++sequence;reset();message.textContent='';const chosen=file.files?.[0];if(!chosen)return;
  snapshot={...scope()};
  try{
   if(!snapshot.customer||!snapshot.environment)throw Error('Select a customer environment before uploading.');
   if(!/\.csv$/i.test(chosen.name)||chosen.size>131072)throw Error('Select a CSV file no larger than 128 KB.');
   const parsed=parse(await chosen.text());if(ticket!==sequence)return;if(!same())throw Error('Customer/environment changed. Upload the file again.');batch=parsed;
   preview.append(el('p',parsed.entries.length+' distinct entries; '+parsed.duplicates+' duplicate rows removed.'));
   for(const network of parsed.networks){const detail=el('details');detail.append(el('summary',network.name+' · '+network.snapshot.adapters.length+' network adapters · review IP addresses'));for(const a of network.snapshot.adapters)detail.append(el('p',a.name+' ('+a.status+'): '+(a.addresses.map(p=>p.ip+'/'+p.prefix).join(', ')||'No IP recorded')));preview.append(detail);}
   const wrap=el('div');wrap.style.overflowX='auto';const table=el('table','','inventory-bulk-table');const head=el('tr');headers.forEach(h=>head.append(el('th',h)));table.append(head);
   for(const a of parsed.entries){const tr=el('tr');[a.name,a.asset_type,a.technology,a.version||'Unknown',a.notes].forEach(v=>tr.append(el('td',v)));table.append(tr);}wrap.append(table);preview.append(wrap);
   for(const warning of parsed.warnings)preview.append(el('p',warning,'ops-note'));
   message.textContent='Review all rows. Product matching and advisory coverage may still need verification.';
  }catch(e){if(ticket===sequence){reset();message.textContent=e.message;}}
 };
 submit.onclick=async()=>{
  if(busy||!batch||!consent.checked)return;
  if(!same()){reset();message.textContent='Customer/environment changed. Upload the file again.';return;}
  busy=true;submit.disabled=true;file.disabled=true;consent.disabled=true;let created=0,skipped=0;const target={...snapshot};
  try{
   const existing=new Set((await readAssets(target)).filter(a=>a.environment_id===target.environment).map(key));
   if(batch.networks.length&&!saveNetwork)throw Error('Network import is not available in this workspace.');
   for(const item of batch.entries){
    if(!same()||!panel.isConnected)throw Error('Import stopped because the selected context changed.');
    if(existing.has(key(item))){skipped++;continue;}
    await saveAsset({...item,environment_id:target.environment},target);existing.add(key(item));created++;
    message.textContent='Imported '+created+'; skipped '+skipped+'.';
   }
   for(const network of batch.networks){
    if(!same()||!panel.isConnected)throw Error('Network import stopped because the selected context changed.');
    await saveNetwork({...network,environment_id:target.environment},target);
   }
   await afterImport(target);reset();
   message.textContent=created+' entries imported; '+skipped+' existing entries skipped. Open the dashboard to run the inventory assessment against the available advisory index.';
   const go=anchor('Assess in Customer Security Dashboard',dashboardURL(target));preview.append(go);
   // Navigation runs the assessment over the persisted inventory, never CSV-only results.
   location.assign(dashboardURL(target));
  }catch(e){message.textContent='Imported '+created+'; skipped '+skipped+'. '+e.message+' Re-upload to review and retry; saved identical rows will be skipped.';batch=null;}
  finally{busy=false;file.disabled=false;consent.disabled=false;submit.disabled=true;}
 };
 panel.append(label,preview,consentLabel,submit,message);host.append(panel);return panel;
}
root.CVEHARBOR_ASSET_IMPORT={parse,key,headers,mount,dashboardURL};
})(typeof window==='undefined'?globalThis:window);
