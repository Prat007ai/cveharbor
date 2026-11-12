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
 if(rows[0]?.length!==5||headers.some((h,i)=>norm(rows[0][i])!==norm(h)))throw Error('Headers must be: '+headers.join(', ')+'.');
 if(rows.length<2||rows.length>201)throw Error('Include 1–200 entries per file.');
 const seen=new Set(),entries=[],warnings=[];let duplicates=0;
 rows.slice(1).forEach((cells,i)=>{
  if(cells.length!==5)throw Error('Row '+(i+2)+' must have five columns.');
  const [name,asset_type,technology,version,notes]=cells.map(v=>v.trim());
  if(!name||name.length>120||!technology||technology.length>120||!types.has(asset_type)||version.length>80||notes.length>500||cells.some(v=>/[\u0000-\u001f\u007f]/.test(v)))throw Error('Invalid or overlong fields on row '+(i+2)+'.');
  if(cells.some(v=>/^[=+@-]/.test(v.trim())))throw Error('Row '+(i+2)+' begins with a spreadsheet formula character. Prefix that value with an apostrophe.');
  const entry={name,asset_type,technology,version,notes};
  if(seen.has(key(entry))){duplicates++;return;}seen.add(key(entry));entries.push(entry);
  if(!version)warnings.push('Row '+(i+2)+': version is unknown; affected-version assessment needs review.');
 });
 return {entries,warnings,duplicates};
}
const el=(tag,value='',cls='')=>{const e=document.createElement(tag);e.textContent=value;if(cls)e.className=cls;return e;};
function anchor(label,href){const a=el('a',label,'ops-download');a.href=href;return a;}
function dashboardURL(scope){return '/customer-dashboard/?'+new URLSearchParams({customer:scope.customer,environment:scope.environment,...(scope.org?{org:scope.org}:{})});}
function mount(host,{scope,readAssets,saveAsset,afterImport=async()=>{}}){
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
   for(const item of batch.entries){
    if(!same()||!panel.isConnected)throw Error('Import stopped because the selected context changed.');
    if(existing.has(key(item))){skipped++;continue;}
    await saveAsset({...item,environment_id:target.environment},target);existing.add(key(item));created++;
    message.textContent='Imported '+created+'; skipped '+skipped+'.';
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
