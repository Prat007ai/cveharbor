(() => {
'use strict';
const $=id=>document.getElementById(id);
if(!$('inventoryWorkspace'))return;
const api='https://api.cveharbor.com/v1/inventory';
let signedIn=false,ready=false,data={customers:[],environments:[],assets:[]};
let pluginSources=new Map(),pluginSourceReady=false;
const make=(tag,className='',value='')=>{
 const el=document.createElement(tag);if(className)el.className=className;el.textContent=String(value);return el;
};
const status=message=>{$('inventoryMessage').textContent=message;};
async function call(path='',method='GET',body){
 const res=await fetch(api+path,{method,credentials:'include',
 headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
 const result=await res.json().catch(()=>({}));
 if(!res.ok)throw Error(result.error||'Inventory service unavailable');
 return result;
}
function option(select,value,label){
 const o=make('option','',label);o.value=value;select.append(o);
}
function selects(){
 const customers=$('inventoryCustomerSelect'),envs=$('inventoryEnvironmentSelect');
 const previousCustomer=customers.value,previousEnv=envs.value;
 customers.replaceChildren();envs.replaceChildren();
 option(customers,'','Choose customer');option(envs,'','Choose environment');
 for(const customer of data.customers)option(customers,customer.id,customer.name);
 for(const environment of data.environments){
  const owner=data.customers.find(x=>x.id===environment.customer_id);
  option(envs,environment.id,(owner?.name||'Customer')+' / '+environment.name);
 }
 if(data.customers.some(x=>x.id===previousCustomer))customers.value=previousCustomer;
 if(data.environments.some(x=>x.id===previousEnv))envs.value=previousEnv;
}
function renderMatches(){
 const panel=$('inventoryMatchResults');if(!panel)return;
 panel.replaceChildren();
 const engine=window.CVEHARBOR_INVENTORY_MATCH;
 const feed=window.CVEHARBOR_DATA||{},catalog=window.CVEHARBOR_CATALOG||{};
 if(!signedIn||!ready){panel.append(make('p','ops-note','Sign in and connect D1 to review customer-specific advisory matches.'));return;}
 if(!engine){panel.append(make('p','ops-note','Matching module unavailable.'));return;}
 const chosen=$('inventoryMatchCustomer').value;
 const environments=new Set(data.environments.filter(e=>!chosen||e.customer_id===chosen).map(e=>e.id));
 const assets=data.assets.filter(a=>environments.has(a.environment_id));
 const advisories=[...(feed.advisories||[]),...(catalog.advisories||[])];
 const matches=engine.evaluate(assets,advisories,150);
 $('inventoryMatchCount').textContent=matches.total+' potential matches';
 if(!matches.total){panel.append(make('p','ops-note','No category matches found in the current limited index. This does not establish that customer assets are secure.'));return;}
 for(const item of matches.items){
  const asset=assets.find(a=>a.id===item.asset_id);
  const environment=data.environments.find(e=>e.id===asset?.environment_id);
  const customer=data.customers.find(c=>c.id===environment?.customer_id);
  const card=make('article','ops-result inventory-match-card');
  const top=make('div','ops-result-top');
  top.append(make('strong','',item.id+' · '+item.severity.toUpperCase()));
  if(item.known_exploited)top.append(make('span','ops-tag','CISA KEV'));
  card.append(top,make('p','',item.title));
  card.append(make('p','', (customer?.name||'Customer')+' / '+(environment?.name||'Environment')+' / '+(asset?.name||'Asset')+
   ' · '+item.technology+' '+(item.version||'Version unknown')));
  card.append(make('p','ops-note',item.evidence));
  const actions=make('div','inventory-actions');
  const assign=make('button','ops-download','Assign for review');assign.type='button';
  assign.addEventListener('click',()=>window.dispatchEvent(new CustomEvent('cveharbor:assign-remediation',{detail:{id:item.id}})));
  actions.append(assign);
  if(item.source_url){
   const a=make('a','ops-download','Original advisory');a.href=item.source_url;
   a.target='_blank';a.rel='noopener noreferrer';actions.append(a);
  }
  card.append(actions);panel.append(card);
 }
 if(matches.limited)panel.append(make('p','ops-note','Showing the first 150 prioritized matches. Narrow to a customer to review additional entries.'));
}
// Check just-saved WordPress plugin entries as soon as their D1 writes finish.
const pluginSlugOverrides={'yoast seo':'wordpress-seo','wp file manager':'wp-file-manager','wps hide login':'wps-hide-login','autoptimize':'autoptimize','wp mail smtp':'wp-mail-smtp','advanced editor tools':'tinymce-advanced','addtoany share buttons':'add-to-any','events manager':'events-manager','wp store locator':'wp-store-locator','wpbakery page builder':'js_composer'};
async function checkSavedPlugin(asset){
 if(!asset?.technology?.startsWith('WordPress Plugin: '))return;
 const name=asset.technology.slice('WordPress Plugin: '.length);
 const slug=pluginSlugOverrides[name.toLowerCase()]||name.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
 const panel=$('inventoryMatchResults');if(!panel)return;
 const row=make('article','ops-result','');
 row.append(make('strong','',name+' · '+(asset.version||'Version unknown')));
 const note=make('p','ops-note','Checking plugin vulnerability advisory source…');row.append(note);panel.prepend(row);
 try{
  const url='https://api.cveharbor.com/v1/plugin-monitor/refresh';
  const response=await fetch(url,{method:'POST',credentials:'include',headers:{Accept:'application/json','Content-Type':'application/json'},body:JSON.stringify({asset_id:asset.id})});
  const payload=await response.json().catch(()=>({}));
  if(!response.ok||payload.status!=='checked'){
   note.textContent='Plugin vulnerability coverage unverified: '+(payload.reason||payload.error||'Source unavailable');return;
  }
  const findings=payload.findings||[];
  note.textContent=findings.length+' potential CVE '+(findings.length===1?'match':'matches')+' from WPVulnerability for installed version '+asset.version+'. Validate affected versions before remediation.';
  for(const finding of findings.slice(0,15)){
   const item=make('p','ops-note',finding.id+' · '+finding.title);
   if(finding.sources?.[0]?.url){
    const link=make('a','ops-link',' · Source');link.href=finding.sources[0].url;link.target='_blank';link.rel='noopener noreferrer';item.append(link);
   }
   row.append(item);
  }
  if(!findings.length)row.append(make('p','ops-note','No matching CVEs returned by this source. This does not establish that the plugin is secure.'));
 }catch(_){note.textContent='Plugin advisory lookup unavailable. Inventory was saved successfully.'}
}
function checkSavedPlugins(assets){
 let index=0;
 async function worker(){while(index<assets.length){const asset=assets[index++];await checkSavedPlugin(asset)}}
 void Promise.all(Array.from({length:Math.min(3,assets.length)},worker));
}
function setupSourceEditor(){
 const host=$('inventoryAssetForm');if(!host)return;
 const box=make('section','inventory-plugin-import inventory-source-editor');
 box.append(make('h3','','Edit WordPress plugin sources'),make('p','ops-note','Choose an existing WordPress plugin, then save its vendor, release and security advisory URLs. Only verified WordPress.org plugin URLs are used for automatic version lookups.'));
 const select=document.createElement('select');select.setAttribute('aria-label','Select existing plugin');select.className='inventory-source-select';
 const pickerLabel=make('div','inventory-source-picker-label');
 const pickerTitle=make('label','','Plugin');pickerLabel.append(pickerTitle);
 const pickerInput=document.createElement('input');pickerInput.type='search';pickerInput.className='inventory-source-search';pickerInput.placeholder='Search and select a plugin';pickerInput.autocomplete='off';pickerInput.setAttribute('aria-label','Search existing WordPress plugins');pickerInput.setAttribute('aria-expanded','false');
 const pickerList=make('div','inventory-source-list');pickerList.setAttribute('role','listbox');pickerList.hidden=true;
 const pickerCount=make('p','ops-note inventory-source-count','');pickerCount.setAttribute('role','status');
 pickerLabel.append(pickerInput,pickerCount,pickerList);box.append(pickerLabel);
 select.hidden=true;box.append(select);
 function closePicker(){
  pickerList.hidden=true;pickerInput.setAttribute('aria-expanded','false');
 }
 function choosePlugin(entry){
  select.value=entry.value;pickerInput.value=entry.textContent;closePicker();select.dispatchEvent(new Event('change'));
 }
 function showPicker(){
  pickerList.replaceChildren();
  const query=pickerInput.value.trim().toLowerCase();
  const allEntries=[...select.options].filter(o=>o.value);
  const entries=allEntries.filter(o=>o.textContent.toLowerCase().includes(query));
  pickerCount.textContent=entries.length+' matching plugins of '+allEntries.length+' in this environment';
  for(const entry of entries){
   const choice=document.createElement('div');
   choice.className='inventory-source-choice';choice.textContent=entry.textContent;
   choice.setAttribute('role','option');choice.setAttribute('tabindex','0');
   choice.setAttribute('aria-selected',String(select.value===entry.value));
   choice.addEventListener('mousedown',e=>e.preventDefault());
   choice.addEventListener('click',()=>choosePlugin(entry));
   choice.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();choosePlugin(entry)}});
   pickerList.append(choice);
  }
  if(!entries.length)pickerList.append(make('p','ops-note','No matching plugins in this environment.'));
  pickerList.hidden=false;pickerInput.setAttribute('aria-expanded','true');
 }
 pickerInput.addEventListener('focus',()=>{pickerInput.select();showPicker()});
 pickerInput.addEventListener('input',showPicker);
 pickerInput.addEventListener('keydown',e=>{
  if(e.key==='Escape'){closePicker();return}
  if(e.key==='ArrowDown'){e.preventDefault();pickerList.querySelector('[role=option]')?.focus();return}
  if(e.key==='Enter'&&!pickerList.hidden){e.preventDefault();const first=pickerList.querySelector('[role=option]');if(first)first.click()}
 });
 document.addEventListener('pointerdown',e=>{if(!pickerLabel.contains(e.target))closePicker()});
  const fieldGrid=make('div','inventory-source-fields');box.append(fieldGrid);
 const fields=['vendor_url','release_url','advisory_url'].map(key=>{
  const label=make('label','ops-note',key.replace('_',' '));
  const input=document.createElement('input');input.type='url';input.placeholder='https://';input.setAttribute('aria-label',key);
  label.append(input);fieldGrid.append(label);return {key,input};
 });
 const info=make('p','ops-note inventory-source-feedback','');info.setAttribute('role','status');
 const actions=make('div','inventory-source-actions');
 const button=make('button','ops-download','Save plugin sources');button.type='button';
 const verify=make('button','ops-download','Validate source mapping');verify.type='button';
 function redraw(){
  const previous=select.value;select.replaceChildren();option(select,'','Select plugin');
  const envId=$('inventoryEnvironmentSelect').value;
  for(const a of data.assets.filter(x=>x.environment_id===envId&&x.technology.startsWith('WordPress Plugin: ')))option(select,a.id,a.technology.slice(18));
  if([...select.options].some(o=>o.value===previous))select.value=previous;
  pickerInput.value=select.selectedOptions[0]?.value?select.selectedOptions[0].textContent:'';
  pickerCount.textContent=([...select.options].filter(o=>o.value).length)+' plugins in this environment';
  pickerList.hidden=true;pickerInput.setAttribute('aria-expanded','false');
  const source=pluginSources.get(select.value)||{};
  for(const {key,input} of fields)input.value=source[key]||'';
  info.textContent=source.verification||'No source verification yet';
 }
 select.addEventListener('change',redraw);
 $('inventoryEnvironmentSelect').addEventListener('change',redraw);
 async function saveSources(){
  if(!pluginSourceReady){info.textContent='Plugin source database migration is required';return false}
  if(!select.value){info.textContent='Select an existing plugin';return false}
  const payload=Object.fromEntries(fields.map(f=>[f.key,f.input.value.trim()]));
  const res=await fetch('https://api.cveharbor.com/v1/plugin-sources/'+select.value,{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const value=await res.json().catch(()=>({}));
  if(!res.ok){info.textContent=value.error||'Could not save source';return false}
  pluginSources.set(select.value,{...payload,verification:value.verification});
  info.textContent='Saved. '+value.verification;return true;
 }
 button.addEventListener('click',()=>void saveSources());
 verify.addEventListener('click',async()=>{
  if(!await saveSources())return;
  verify.disabled=true;info.textContent='Checking the official release source…';
  try{
   const r=await fetch('https://api.cveharbor.com/v1/plugin-sources/'+select.value+'/verify',{method:'POST',credentials:'include'});
   const value=await r.json().catch(()=>({}));
   if(!r.ok)throw Error(value.error||'Verification unavailable');
   info.textContent=value.verification==='Release Verified'?
    'Verified '+value.slug+' · Latest published '+value.latest_version+' · '+value.update_status:
    'Needs Review · '+(value.reason||'Official release could not be verified');
  }catch(e){info.textContent='Could not verify source: '+e.message}
  finally{verify.disabled=false}
 });
 actions.append(button,verify);box.append(actions,info);host.after(box);
 window.addEventListener('cveharbor:inventory-loaded',redraw);redraw();
}
function refreshMatchCustomers(){
 const selector=$('inventoryMatchCustomer'),current=selector.value;
 selector.replaceChildren();option(selector,'','All customers');
 for(const customer of data.customers)option(selector,customer.id,customer.name);
 if(data.customers.some(c=>c.id===current))selector.value=current;
}
$('inventoryMatchCustomer').addEventListener('change',renderMatches);

// Import WordPress plugin name and version pairs into the selected environment.
// Uses the existing authenticated inventory API; no new D1 schema is required.
function setupPluginImport(){
 const form=$('inventoryAssetForm');
 if(!form)return;
 const panel=make('section','inventory-plugin-import');
 panel.append(make('h3','','Import WordPress plugins'),
  make('p','ops-note','Select a customer environment above, then select a local .txt file or paste one plugin per line as Plugin Name | Version | Vendor URL (optional). Each plugin is recorded separately. Existing entries with the same name are updated rather than duplicated.'));
 const area=make('textarea','','');area.placeholder='Gravity Forms | 2.9.5\nYoast SEO | 24.7';
 area.rows=7;area.setAttribute('aria-label','WordPress plugin names and versions');
 const fileLabel=make('label','inventory-plugin-file-label','Select a TXT file from your computer');
 const fileInput=document.createElement('input');
 fileInput.type='file';
 fileInput.accept='.txt,text/plain';
 fileInput.setAttribute('aria-label','Choose a WordPress plugin TXT file');
 const result=make('p','ops-note inventory-plugin-status','');
 result.setAttribute('role','status');
 const readText=file=>new Promise((resolve,reject)=>{
  if(typeof file.text==='function'){file.text().then(resolve,reject);return}
  const reader=new FileReader();
  reader.onload=()=>resolve(String(reader.result||''));
  reader.onerror=()=>reject(Error('File could not be read'));
  reader.readAsText(file);
 });
 fileLabel.append(fileInput);
 fileInput.addEventListener('change',async()=>{
  const file=fileInput.files?.[0];
  if(!file){result.textContent='No file selected. Choose a TXT file.';return}
  if(file.size>65536){result.textContent='File too large. Choose a TXT file smaller than 64 KB.';return}
  // Some Windows downloads hide the extension or report text/plain without it.
  const name=String(file.name||'');
  if(!/\.txt$/i.test(name)&&file.type!=='text/plain'){
   result.textContent='Choose a plain text (.txt) file. Selected: '+name;return;
  }
  try{
   const content=(await readText(file)).replace(/^\uFEFF/,'');
   if(!content.trim()){result.textContent='The selected file is empty.';return}
   area.value=content;
   const count=content.split(/\r?\n/).filter(line=>line.trim()).length;
   result.textContent='Loaded '+name+' ('+count+' lines). Review the list, then click Import plugins.';
  }catch(_){result.textContent='Could not read the selected file. Please select it again.'}
 });
 const button=make('button','ops-download','Import plugins');button.type='button';
 button.addEventListener('click',async()=>{
  const environmentId=$('inventoryEnvironmentSelect').value;
  const assetName=$('inventoryAssetName').value.trim();
  if(!signedIn||!ready){result.textContent='Sign in to manage private inventory.';return}
  if(!environmentId||!assetName){result.textContent='Choose an environment and enter the WordPress site asset name first.';return}
  const lines=area.value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
  if(!lines.length||lines.length>150){result.textContent='Paste between 1 and 150 plugin entries.';return}
  const plugins=[];
  for(const line of lines){
   const parts=line.split('|');
   if((parts.length!==2&&parts.length!==3)||!parts[0].trim()||!parts[1].trim()){
    result.textContent='Use Plugin Name | Version | optional Vendor URL.';return;
   }
   const name=parts[0].trim(),version=parts[1].trim();
   if(name.length>100||version.length>80||!/^\d[\w.+-]*$/.test(version)){
    result.textContent='Check plugin name or version: '+line;return;
   }
   const vendor_url=(parts[2]||'').trim();
   if(vendor_url&&!/^https:\/\/[^\s]+$/i.test(vendor_url)){result.textContent='Vendor URL must start with https:// for '+name;return}
   plugins.push({name,version,vendor_url});
  }
  if(plugins.some(p=>p.vendor_url)&&!pluginSourceReady){
   result.textContent='Plugin source migration is required before importing URLs. No entries were changed.';return;
  }
  if(new Set(plugins.map(p=>p.name.toLowerCase())).size!==plugins.length){
   result.textContent='Duplicate plugin names in paste. Remove duplicates and retry.';return;
  }
  button.disabled=true;
  let saved=0;
  const checkEntries=[];
  try{
   // Refresh before importing to avoid duplicate entries after another session.
   data=await call();
   for(const plugin of plugins){
    const technology='WordPress Plugin: '+plugin.name;
    const matches=data.assets.filter(a=>a.environment_id===environmentId&&
      a.name.toLowerCase()===assetName.toLowerCase()&&a.technology.toLowerCase()===technology.toLowerCase());
    const payload={environment_id:environmentId,name:assetName,asset_type:'Software',
     technology,version:plugin.version,notes:'WordPress plugin inventory'};
    if(matches.length===1){
     if(matches[0].version!==plugin.version)await call('/assets/'+matches[0].id,'PUT',payload);
     checkEntries.push({...payload,id:matches[0].id});
    }else if(matches.length===0){
     const response=await call('/assets','POST',payload);
     checkEntries.push({...payload,id:response.id});
     // Re-read before subsequent requests so retrying never overwrites.
     data=await call();
    }else throw Error('Duplicate existing inventory entries for '+plugin.name+'. Resolve before continuing.');
    const assetId=matches.length===1?matches[0].id:checkEntries[checkEntries.length-1]?.id;
    if(plugin.vendor_url&&assetId){
     const res=await fetch('https://api.cveharbor.com/v1/plugin-sources/'+assetId,{method:'PUT',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({vendor_url:plugin.vendor_url,release_url:pluginSources.get(assetId)?.release_url||'',advisory_url:pluginSources.get(assetId)?.advisory_url||''})});
     if(!res.ok)throw Error('Source URL could not be saved for '+plugin.name+': '+(await res.json()).error);
    }
    saved++;
    result.textContent='Processed '+saved+' of '+plugins.length+' plugins';
   }
   await load();result.textContent=saved+' WordPress plugin entries processed and inventory updated successfully.';
   checkSavedPlugins(checkEntries);
  }catch(error){await load();result.textContent='Imported '+saved+' entries. '+error.message+' Review and retry to continue.'}
  finally{button.disabled=false}
 });
 panel.append(fileLabel,area,button,result);
 form.after(panel);
}
setupPluginImport();
setupSourceEditor();

function setupBulkAssetImport(){
 const form=$('inventoryAssetForm');if(!form)return;
 const panel=make('section','inventory-plugin-import inventory-bulk-import');
 panel.append(make('h3','','Bulk import technology stack'),make('p','ops-note','Select the customer environment above, then upload a CSV file exported from Excel. Review the entries before saving. Existing assets are never overwritten.'));
 const template=make('button','ops-download','Download Excel CSV template');template.type='button';
 template.addEventListener('click',()=>{
  const csv='Asset Name,Asset Type,Technology,Version,Notes\r\nWEB01,WEB,PHP,8.4.26,Production web server\r\nWEB01,WEB,WordPress,6.8.3,\r\nDB01,Database,MySQL,8.0.43,\r\n';
  const blob=new Blob([csv],{type:'text/csv;charset=utf-8'});
  const url=URL.createObjectURL(blob),link=document.createElement('a');
  link.href=url;link.download='cveharbor-asset-import.csv';document.body.append(link);link.click();link.remove();URL.revokeObjectURL(url);
 });
 const label=make('label','inventory-plugin-file-label','Upload Excel CSV file');
 const file=document.createElement('input');file.type='file';file.accept='.csv,text/csv,text/plain';file.setAttribute('aria-label','Choose asset inventory CSV file');label.append(file);
 const preview=make('div','inventory-bulk-preview');preview.hidden=true;
 const result=make('p','ops-note inventory-plugin-status','');result.setAttribute('role','status');
 const importButton=make('button','ops-download','Import reviewed assets');importButton.type='button';importButton.disabled=true;
 let parsed=[],previewEnvironment='';
 function parseCsv(text){
  const rows=[],row=[];let field='',quoted=false;
  const input=text.replace(/^\\uFEFF/,'');
  for(let i=0;i<input.length;i++){
   const c=input[i];
   if(quoted){if(c==='"'&&input[i+1]==='"'){field+='"';i++}else if(c==='"')quoted=false;else field+=c}
   else if(c==='"'){if(field!=='')throw Error('Invalid CSV quotes');quoted=true}
   else if(c===','){row.push(field);field=''}
   else if(c==='\\n'||c==='\\r'){if(c==='\\r'&&input[i+1]==='\\n')i++;row.push(field);field='';if(row.some(x=>x.trim()))rows.push(row.splice(0))}
   else field+=c;
  }
  if(quoted)throw Error('Unclosed quoted field');
  row.push(field);if(row.some(x=>x.trim()))rows.push(row);
  return rows;
 }
 function resetPreview(message){
  parsed=[];importButton.disabled=true;preview.hidden=true;preview.replaceChildren();result.textContent=message||'';
 }
 file.addEventListener('change',async()=>{
  resetPreview('');
  const chosen=file.files?.[0];if(!chosen)return;
  if(chosen.size>131072){resetPreview('CSV file exceeds 128 KB.');return}
  if(!/\\.csv$/i.test(chosen.name)){resetPreview('Export the Excel worksheet as CSV UTF-8 first.');return}
  const envId=$('inventoryEnvironmentSelect').value;
  if(!envId){resetPreview('Select a customer environment before uploading.');return}
  try{
   const rows=parseCsv(await chosen.text());
   const expected=['Asset Name','Asset Type','Technology','Version','Notes'];
   if(!rows.length||expected.some((v,i)=>(rows[0][i]||'').trim().toLowerCase()!==v.toLowerCase())||rows[0].length!==5)throw Error('The CSV headers must be Asset Name, Asset Type, Technology, Version, Notes.');
   if(rows.length<2||rows.length>201)throw Error('Include between 1 and 200 asset entries.');
   const allowed=new Set(['Server','WEB','Application','Database','Cloud Service','Network Device','Software','Other']);
   const unique=new Set();
   parsed=rows.slice(1).map((cells,index)=>{
    if(cells.length!==5)throw Error('Row '+(index+2)+' must have five columns.');
    const [name,asset_type,technology,version,notes]=cells.map(v=>v.trim());
    if(!name||name.length>120||!technology||technology.length>120||!allowed.has(asset_type)||version.length>80||notes.length>500)throw Error('Invalid asset fields on row '+(index+2));
    const key=[name.toLowerCase(),asset_type.toLowerCase(),technology.toLowerCase()].join('|');
    if(unique.has(key))throw Error('Duplicate asset technology on row '+(index+2));
    unique.add(key);return {environment_id:envId,name,asset_type,technology,version,notes};
   });
   previewEnvironment=envId;
   const summary=make('p','ops-note',parsed.length+' entries ready for review. Showing the first 10.');
   const table=make('table','inventory-bulk-table');
   const head=make('tr','');for(const value of expected)head.append(make('th','',value));table.append(head);
   for(const entry of parsed.slice(0,10)){const tr=make('tr','');for(const value of [entry.name,entry.asset_type,entry.technology,entry.version,entry.notes])tr.append(make('td','',value));table.append(tr)}
   preview.append(summary,table);preview.hidden=false;importButton.disabled=false;
   result.textContent='Review the preview and select Import reviewed assets. Existing records with the same asset name, type and technology will be skipped.';
  }catch(e){resetPreview(e.message)}
 });
 $('inventoryEnvironmentSelect').addEventListener('change',()=>{if(parsed.length)resetPreview('Environment changed. Please upload the CSV again.')});
 importButton.addEventListener('click',async()=>{
  if(!signedIn||!ready){result.textContent='Sign in and ensure inventory storage is ready.';return}
  if(!parsed.length||previewEnvironment!==$('inventoryEnvironmentSelect').value){resetPreview('Select the original environment and upload again.');return}
  importButton.disabled=true;
  let created=0,skipped=0;
  try{
   data=await call();
   const existing=new Set(data.assets.filter(a=>a.environment_id===previewEnvironment).map(a=>[a.name.toLowerCase(),a.asset_type.toLowerCase(),a.technology.toLowerCase()].join('|')));
   for(const item of parsed){
    const key=[item.name.toLowerCase(),item.asset_type.toLowerCase(),item.technology.toLowerCase()].join('|');
    if(existing.has(key)){skipped++;continue}
    await call('/assets','POST',item);existing.add(key);created++;
    result.textContent='Importing '+(created+skipped)+' of '+parsed.length;
   }
   await load();resetPreview('Import complete: '+created+' created, '+skipped+' existing entries skipped.');
  }catch(e){await load();resetPreview('Imported '+created+' entries and skipped '+skipped+'. '+e.message+' Review before retrying.')}
  finally{importButton.disabled=!parsed.length}
 });
 panel.append(template,label,preview,importButton,result);
 form.after(panel);
}
setupBulkAssetImport();


function render(){
 selects();
 $('inventoryCustomerCount').textContent=data.customers.length;
 $('inventoryEnvironmentCount').textContent=data.environments.length;
 $('inventoryAssetCount').textContent=data.assets.length;
 const root=$('inventoryRecords');root.replaceChildren();
 for(const customer of data.customers){
  const card=make('article','inventory-customer');
  const header=make('div','ops-result-top');header.append(make('h4','',customer.name));
  const deleteCustomer=make('button','ops-remove','Remove customer');deleteCustomer.type='button';
  deleteCustomer.addEventListener('click',()=>remove('customers',customer.id,customer.name));
  header.append(deleteCustomer);card.append(header);
  const envs=data.environments.filter(x=>x.customer_id===customer.id);
  if(!envs.length)card.append(make('p','ops-note','No environments added yet.'));
  for(const env of envs){
   const group=make('section','inventory-environment');
   const h=make('div','ops-result-top');h.append(make('strong','',env.name+' · '+env.kind));
   const del=make('button','ops-remove','Remove environment');del.type='button';
   del.addEventListener('click',()=>remove('environments',env.id,env.name));h.append(del);group.append(h);
   const assets=data.assets.filter(x=>x.environment_id===env.id);
   if(!assets.length)group.append(make('p','ops-note','No servers, applications or software versions recorded.'));
   // One asset can carry many technologies. Keep legacy D1 rows intact and
   // present entries with the same environment, asset name and type together.
   const groups=new Map();
   for(const asset of assets){
    const key=asset.name.trim().toLowerCase()+'|'+asset.asset_type;
    if(!groups.has(key))groups.set(key,[]);
    groups.get(key).push(asset);
   }
   for(const entries of groups.values()){
    const groupCard=make('div','inventory-asset-group');
    const first=entries[0];
    groupCard.append(make('strong','inventory-asset-group-title',first.name+' · '+first.asset_type));
    groupCard.append(make('p','ops-note',entries.length+' technology '+(entries.length===1?'entry':'entries')));
    for(const asset of entries){
    const row=make('div','inventory-asset ops-result-top');
    const info=make('div','');
    const pluginPrefix='WordPress Plugin: ';
    const plugin=asset.technology.startsWith(pluginPrefix);
    const displayName=plugin?asset.technology.slice(pluginPrefix.length):asset.technology;
    info.append(make('strong','inventory-technology-name',displayName),
      make('p','ops-note inventory-technology-meta',(plugin?'WordPress plugin · ':'')+
        asset.asset_type+' · Version: '+(asset.version||'Not recorded')+
        (asset.notes?' · '+asset.notes:'')));
    const actions=make('div','inventory-actions');
    const edit=make('button','ops-remove','Edit');edit.type='button';
    edit.addEventListener('click',()=>{
      $('inventoryEnvironmentSelect').value=asset.environment_id;
      $('inventoryAssetName').value=asset.name;
      $('inventoryType').value=asset.asset_type;
      $('inventoryTechnology').value=asset.technology;
      $('inventoryVersion').value=asset.version;
      $('inventoryNotes').value=asset.notes;
      $('inventoryAdditionalTechnologies').value='';
      $('inventoryAssetEditId').value=asset.id;
      $('inventoryAssetSave').textContent='Update asset';
      $('inventoryAssetName').focus();
    });
    const removeAsset=make('button','ops-remove','Remove');removeAsset.type='button';
    removeAsset.addEventListener('click',()=>remove('assets',asset.id,asset.name));
    actions.append(edit,removeAsset);row.append(info,actions);groupCard.append(row);
    }
    group.append(groupCard);
   }
   card.append(group);
  }
  root.append(card);
 }
 if(!data.customers.length)root.append(make('p','ops-note','Start by adding a customer, then create an environment and register its installed technologies.'));
 refreshMatchCustomers();renderMatches();window.dispatchEvent(new Event('cveharbor:inventory-loaded'));
}
async function load(){
 data=await call();
 try{const r=await fetch('https://api.cveharbor.com/v1/plugin-sources',{credentials:'include'});const s=await r.json();pluginSourceReady=!!s.ready;pluginSources=new Map((s.sources||[]).map(x=>[x.asset_id,x]));}catch(_){pluginSourceReady=false;pluginSources=new Map()}
 render();
}
async function remove(type,id,name){
 if(!window.confirm('Remove '+name+' and any records it contains?'))return;
 try{await call('/'+type+'/'+id,'DELETE');await load();status(name+' removed from your private inventory.')}
 catch(e){status(e.message)}
}
async function onAccount(event){
 signedIn=!!event.detail?.authenticated;
 document.querySelectorAll('#inventoryWorkspace form input,#inventoryWorkspace form select,#inventoryWorkspace form textarea,#inventoryWorkspace form button')
  .forEach(el=>{el.disabled=!signedIn});
 if(!signedIn){ready=false;data={customers:[],environments:[],assets:[]};render();status('Sign in above to view your private customer inventory.');return;}
 try{
  const flags=await call('/status');ready=!!flags.ready;
  if(!ready){status('Cloudflare D1 inventory migration is required before customer records can be saved.');return;}
  await load();status('Inventory loaded from your private Cloudflare D1 account.');
 }catch(e){status('Unable to load inventory: '+e.message)}
}
window.addEventListener('cveharbor:account-state',event=>{void onAccount(event)});
async function save(form,endpoint,payload){
 if(!signedIn||!ready){status('Sign in and complete the database migration first.');return;}
 const button=form.querySelector('button[type=submit]');button.disabled=true;
 try{await call(endpoint,'POST',payload);form.reset();await load();status('Saved to your account inventory.')}
 catch(e){status('Could not save: '+e.message)}
 finally{button.disabled=false}
}
$('inventoryCustomerForm').addEventListener('submit',event=>{
 event.preventDefault();
 void save(event.currentTarget,'/customers',{name:$('inventoryCustomerName').value.trim()});
});
$('inventoryEnvironmentForm').addEventListener('submit',event=>{
 event.preventDefault();
 void save(event.currentTarget,'/environments',{customer_id:$('inventoryCustomerSelect').value,
 name:$('inventoryEnvironmentName').value.trim(),kind:$('inventoryKind').value});
});
$('inventoryAssetForm').addEventListener('submit',async event=>{
 event.preventDefault();
 if(!signedIn||!ready){status('Sign in and complete database migration first.');return;}
 const form=event.currentTarget,editId=$('inventoryAssetEditId').value;
 const payload={environment_id:$('inventoryEnvironmentSelect').value,
 name:$('inventoryAssetName').value.trim(),asset_type:$('inventoryType').value,
 technology:$('inventoryTechnology').value.trim(),version:$('inventoryVersion').value.trim(),
 notes:$('inventoryNotes').value.trim()};
 const button=$('inventoryAssetSave');button.disabled=true;
 try{
  const extra=$('inventoryAdditionalTechnologies').value.trim();
  const parsed=extra?extra.split(/\r?\n/).map(line=>{
   const chunks=line.split('|');
   if(chunks.length!==2)throw Error('Use Technology | Version for each additional line.');
   const technology=chunks[0].trim(),version=chunks[1].trim();
   if(!technology||technology.length>120||version.length>80)
    throw Error('Each additional technology needs a valid name and optional version.');
   return {technology,version};
  }):[];
  if(editId&&parsed.length)throw Error('Additional technologies can only be added with a new asset entry. Use Add asset for more software on the same server.');
  const all=[payload,...parsed.map(x=>({...payload,technology:x.technology,version:x.version}))];
  const unique=new Set(all.map(x=>x.technology.toLowerCase()));
  if(unique.size!==all.length)throw Error('The same technology cannot appear twice in one submission.');
  let saved=0;
  const checkEntries=[];
  for(const entry of all){
   const response=await call(editId?'/assets/'+editId:'/assets',editId?'PUT':'POST',entry);
   if(entry.technology.startsWith('WordPress Plugin: '))checkEntries.push({...entry,id:editId||response.id});
   saved++;
  }
  form.reset();$('inventoryAssetEditId').value='';button.textContent='Add asset';
  await load();status(editId?'Technology updated in D1.':saved+' technology entries saved for '+payload.name+'.');
  checkSavedPlugins(checkEntries);
 }catch(e){status(e.message)}
 finally{button.disabled=false}
});
$('inventoryAssetCancel').addEventListener('click',()=>{
 $('inventoryAssetForm').reset();$('inventoryAssetEditId').value='';
 $('inventoryAssetSave').textContent='Add asset';
});
render();status('Sign in to manage your private customer environments.');
})();
