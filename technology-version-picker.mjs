let directory, dialog, closeActive;
const element=(tag,value='')=>Object.assign(document.createElement(tag),{textContent:value});
async function api(path,signal) {
  const response=await fetch('/v1/version-picker/'+path,{signal,cache:'no-store'});
  if(!response.ok)throw Error('The source is unavailable. Retry the check.');
  return response.json();
}
export function dismiss(){closeActive?.();}
export async function openPicker(card,context) {
  dismiss();
  dialog=element('dialog');dialog.className='cvie-identity-dialog version-picker';
  dialog.setAttribute('aria-labelledby','versionPickerTitle');
  const panel=dialog, controller=new AbortController();
  let generation=0, scanController, locked=false;
  closeActive=()=>{panel.close();};
  panel.onclose=()=>{controller.abort();scanController?.abort();panel.remove();if(dialog===panel)closeActive=null;};
  const close=element('button','Close');close.type='button';close.onclick=()=>panel.close();
  const header=element('div');header.className='cvie-identity-head';
  const heading=element('h2','Check an installed version');heading.id='versionPickerTitle';header.append(heading,close);
  const topic=element('p',card);const message=element('p','Loading available versions…');message.setAttribute('role','status');
  panel.append(header,topic,message);document.body.append(panel);panel.showModal();
  try {directory??=await api('catalogue',controller.signal);}catch{if(panel.open)message.textContent='The release list could not load. Close and reopen to retry.';return;}
  if(!panel.open)return;
  const ids=directory.cards[card]||Object.keys(directory.products).filter(k=>directory.products[k].name===card);
  if(!ids.length){message.textContent='Use Customize technologies to register this custom product.';return;}
  function field(title,input){
    input.setAttribute('aria-label',title);
    const label=element('label');label.className='version-field';label.append(element('span',title),input);panel.append(label);return label;
  }
  const select=element('select');for(const id of ids)select.add(new Option(directory.products[id].name,id));
  const saved=ids.find(id=>context.saved(directory.products[id].name));
  if(saved)select.value=saved;
  field('Installed product',select);
  const line=element('select');const lineField=field('Release line',line);
  const releases=element('select');field('Release',releases);
  const input=element('input');input.maxLength=48;input.autocomplete='off';const manual=field('Installed version',input);
  const guidance=element('p');guidance.className='cvie-caption';const source=element('a','Release source');source.target='_blank';source.rel='noopener noreferrer';
  const action=element('button','Save and scan last 3 months'),more=element('button','Find more vulnerabilities · last 12 months');
  const retry=element('button','Retry unfinished check');retry.hidden=true;
  const actions=element('div');actions.className='cvie-identity-actions';actions.append(action,more,retry);
  const resultStatus=element('p');resultStatus.setAttribute('role','status');const results=element('section');
  results.className='version-results';results.setAttribute('aria-label','Scan results');
  const pageSize=15;
  let resultPage=0;
  function drawResults(){
    results.replaceChildren();
    if(!state?.records.length)return;
    const start=resultPage*pageSize;
    const list=element('ul');
    for(const row of state.records.slice(start,start+pageSize)){
      const li=element('li'), open=element('button');
      open.type='button';open.className='version-result';
      const id=element('strong',row.id),title=element('span',row.title||row.id);
      title.className='version-result-title';
      const meta=element('small',[row.severity?.toUpperCase(),row.published?.slice(0,10),row.evidence].filter(Boolean).join(' · '));
      open.append(id,title,meta);open.onclick=()=>context.detail(row,directory.products[state.id],state.version);
      li.append(open);list.append(li);
    }
    results.append(element('h3','CVEHarbor advisories'),list);
    if(state.records.length<=pageSize)return;
    const nav=element('nav');nav.setAttribute('aria-label','Scan result pages');
    const prev=element('button','Previous'),next=element('button','Next');
    prev.disabled=resultPage===0;next.disabled=start+pageSize>=state.records.length;
    prev.onclick=()=>{resultPage--;drawResults();};
    next.onclick=()=>{resultPage++;drawResults();};
    nav.append(prev,element('span',(start+1)+'–'+Math.min(start+pageSize,state.records.length)+' of '+state.records.length),next);
    results.append(nav);
  }
  panel.append(guidance,source,actions,resultStatus,results);
  let state;
  function reset(){
    generation++;scanController?.abort();state=null;retry.hidden=true;more.hidden=true;
    resultPage=0;results.replaceChildren();resultStatus.textContent='';input.setCustomValidity('');
  }
  function mode(){
    reset();manual.hidden=releases.value!=='manual';
    const p=directory.products[select.value];
    guidance.textContent=manual.hidden?'Select the release installed in your environment.':'Enter the '+p.name+' version as shown by the vendor. Example: '+p.example+'.';
  }
  function update(){
    const p=directory.products[select.value], feed=directory.releases[select.value];
    line.replaceChildren(new Option('Recent releases','recent'));
    if(feed?.supported?.length)line.add(new Option('Supported release lines','supported'));
    const names=Object.keys(feed?.lines||{}).sort((a,b)=>b.localeCompare(a,undefined,{numeric:true}));
    for(const name of names)line.add(new Option(name,'line:'+name));
    lineField.hidden=!names.length&&!feed?.supported?.length;
    const saved=context.saved(p.name);
    if(saved&&!feed?.versions.some(v=>v.version===saved)){
      const found=names.find(name=>feed.lines[name].some(v=>v.version===saved));
      if(found)line.value='line:'+found;
    }
    populate(saved);
  }
  function populate(existing=''){
    const p=directory.products[select.value], feed=directory.releases[select.value];
    const entries=(line.value==='supported'?feed?.supported:line.value.startsWith('line:')?feed?.lines[line.value.slice(5)]:feed?.versions)||[];
    releases.replaceChildren(new Option('Choose an installed release',''));
    for(const entry of entries)releases.add(new Option([entry.version,entry.support,entry.date].filter(Boolean).join(' · '),entry.version));
    releases.add(new Option('Enter a version manually…','manual'));
    input.value=existing||'';input.placeholder=p.example;
    releases.value=existing&&!entries.some(v=>v.version===existing)?'manual':existing||'';
    source.hidden=!feed;if(feed)source.href=feed.url;
    message.textContent=feed?'Release list checked '+feed.checked.slice(0,10)+(feed.order==='version'?' · ordered by version.':'.'):'Release list unavailable. Enter the installed version manually.';
    if(p.supportNote)message.textContent+=' '+p.supportNote;
    mode();
  }
  async function run(){
    const ticket=generation,s=state;
    scanController=new AbortController();retry.hidden=true;more.hidden=true;
    try{
      while(panel.open&&ticket===generation){
        resultStatus.textContent='Checking '+s.months+' months · '+s.seen.size+' advisories found…';
        const params=new URLSearchParams({product:s.id,version:s.version,months:s.months,day:s.day,quarter:s.q,cursor:s.cursor});
        const page=await api('scan?'+params,scanController.signal);
        if(ticket!==generation||!panel.open)return;
        for(const row of page.rows){
          if(s.seen.has(row.id))continue;s.seen.add(row.id);
          s.records.push(row);
        }
        drawResults();
        const marker=s.q+':'+s.cursor;s.visited.add(marker);
        if(page.next)s.cursor=page.next;
        else if(page.nextQuarter!==null){s.q=page.nextQuarter;s.cursor='';}
        else break;
        if(s.visited.has(s.q+':'+s.cursor))throw Error('The source repeated a page.');
      }
      if(ticket!==generation||!panel.open)return;
      resultStatus.textContent=s.seen.size+' published advisories returned for '+s.version+' in the last '+s.months+' months. Verify vendor coverage and your configuration.';
      more.hidden=s.months===12;
    }catch{if(ticket===generation&&panel.open){resultStatus.textContent='The source check is incomplete. Results already shown are retained.';retry.hidden=false;}}
  }
  action.onclick=async()=>{
    if(locked)return;
    const id=select.value,p=directory.products[id],version=(manual.hidden?releases.value:input.value).trim();
    if(!version||!new RegExp(directory.formats[p.format]).test(version)){
      resultStatus.textContent='Enter a valid '+p.name+' version, for example '+p.example+'.';
      (manual.hidden?releases:input).focus();return;
    }
    reset();locked=true;action.disabled=select.disabled=line.disabled=releases.disabled=input.disabled=true;
    resultStatus.textContent='Saving installed version…';
    try{
      await context.save(p,version);
      if(!panel.open)return;
      state={id,version,months:3,q:0,cursor:'',day:new Date().toISOString().slice(0,10),seen:new Set(),visited:new Set(),records:[]};
      await run();
    }catch(e){if(panel.open)resultStatus.textContent=e.message;}
    finally{locked=false;action.disabled=select.disabled=line.disabled=releases.disabled=input.disabled=false;}
  };
  more.onclick=()=>{if(!state)return;const isPackage=directory.products[state.id].match.startsWith('osv:');
    state.months=12;state.q=isPackage?0:1;state.cursor='';state.visited.clear();void run();};
  retry.onclick=()=>void run();
  line.onchange=()=>populate();select.onchange=update;releases.onchange=mode;input.oninput=reset;update();
}
