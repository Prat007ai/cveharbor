(() => {
  'use strict';
  const report=window.CVEHARBOR_THREATS || {indicators:[],sources:{},count:0};
  const root=document.getElementById('threatRows');
  if(!root)return;
  const count=document.getElementById('threatCount');
  const status=document.getElementById('threatStatus');
  const select=document.getElementById('threatSourceFilter');
  const search=document.getElementById('threatSearch');
  const activity=document.getElementById('threatActivityFilter');
  const items=Array.isArray(report.indicators)?report.indicators:[];
  const sources=Object.entries(report.sources||{});
  const sourceNames={dshield_scanners:'DShield scanning',blocklist_de:'blocklist.de attacks',greensnow:'GreenSnow attacks/scanning',feodo_c2:'Feodo botnet C2',threatfox:'ThreatFox malware IPs',spamhaus_drop:'Spamhaus DROP ranges'};
  const pageSize=30,limits=new Map();
  let openGroup=null;
  const groups=[
    {id:'attack',label:'Attack & scanning sources',description:'DShield, blocklist.de and GreenSnow reports of scanning, server attacks and brute-force activity.'},
    {id:'malware',label:'Malware-associated IPs',description:'Feodo botnet command-and-control and ThreatFox malware reports.'},
    {id:'network',label:'Network ranges',description:'Spamhaus DROP listings for entire networks, rather than individual hosts.'},
    {id:'other',label:'Other reported activity',description:'Reports from other intelligence sources.'}
  ];
  const categoryFor=x=>x.kind==='network'||x.source_id==='spamhaus_drop'?'network':['dshield_scanners','blocklist_de','greensnow'].includes(x.source_id)?'attack':['feodo_c2','threatfox'].includes(x.source_id)?'malware':'other';
  const matchesFilters=x=>{
    const q=search.value.trim().toLowerCase();
    return (activity.value==='all'||categoryFor(x)===activity.value)&&(select.value==='all'||x.source_id===select.value)&&(!q||x.ip.includes(q)||String(x.activity||'').toLowerCase().includes(q));
  };
  window.CVEHARBOR_THREAT_ACTIVITY={categoryFor,matchesFilters};
  if(items.some(x=>categoryFor(x)==='other')){
    const option=document.createElement('option');option.value='other';option.textContent='Other reported activity';activity.append(option);
  }
  const format=time=>time&&!Number.isNaN(new Date(time).getTime())?new Date(time).toLocaleString('en-CA',{timeZone:'America/Toronto'})+' ET':'Not recorded';
  const freshness=()=>{
    const attempt=Date.parse(report.checked_at),age=Date.now()-attempt;
    const stale=!Number.isFinite(attempt)||age>3*60*60*1000||age< -5*60*1000;
    const healthy=sources.filter(([,s])=>s.ok).length;
    const warning=stale?'STALE SNAPSHOT — latest publication is over 3 hours old or its timestamp is invalid. ':healthy<sources.length?'FEED FAILURE — some results may be retained from an earlier successful fetch. ':'';
    status.textContent=warning+'Last collection attempt: '+format(report.checked_at)+'. '+healthy+' of '+sources.length+' sources responded. '+
      'Coverage: configured scanning, botnet C2, malware-IP and network-range feeds; not a complete list of malicious IPs. '+
      (report.last_changed_at?'Displayed indicator list last changed: '+format(report.last_changed_at)+'. ':'List-change time was not recorded in this snapshot. ')+
      (Number.isInteger(report.added_count)?report.added_count+' added / '+report.removed_count+' removed in the latest collection. ':'')+
      'An unchanged count does not establish freshness or completeness.';
    status.dataset.health=stale?'stale':healthy<sources.length?'degraded':'current';
    refreshAttackDownloads();
  };
  freshness();setInterval(freshness,60000);
  const health=document.createElement('div');health.className='threat-source-health';
  for(const [id,s] of sources){
    const p=document.createElement('p');
    const fetched=s.published_count??items.filter(x=>x.source_id===id).length;
    p.textContent=(sourceNames[id]||id)+': '+
      (s.ok?fetched+' available of '+(s.count??fetched)+' source entries'+(s.truncated?' (limited to '+report.per_source_limit+')':''):'Unavailable; '+(s.retained_count||0)+' older reports retained')+
      '. Last successful fetch: '+format(s.last_success||(s.ok?report.checked_at:null))+'.'+
      (s.error?' Error: '+s.error:'');
    health.append(p);
  }
  status.after(health);
  for(const [id,s] of sources){
    const option=document.createElement('option');
    option.value=id;
    option.textContent=(sourceNames[id]||id)+(s.ok?'':' (feed unavailable)');
    select.append(option);
  }
  const make=(tag,value)=>{const el=document.createElement(tag);el.textContent=value;return el;};
  function showThreatDetail(x){
    const dialog=document.getElementById('threatDetailDialog');
    const content=document.getElementById('threatDetailContent');
    if(!dialog||!content)return;
    content.replaceChildren();
    const heading=make('h2',x.ip);
    heading.id='threatDetailTitle';
    content.append(heading);
    const type=make('p',x.activity);
    type.className='threat-detail-type';content.append(type);
    const details=[
      ['Intelligence source',x.source],
      ['Reported activity',x.activity],
      ['Source category',x.kind==='network'?'Network range (CIDR), not an individual host':sourceNames[x.source_id]||'Third party report'],
      ['Source record',x.sbl_id||x.evidence?.map(e=>e.ioc_id).join(', ')||'See original feed'],
      ['Source observation',x.observed_at||'Not supplied by this feed'],
      ['Indicator expiry',x.expires_at?format(x.expires_at):'Current source membership; unrefreshed retained data expires after 72 hours'],
      ['Last successful source fetch',format(report.sources?.[x.source_id]?.last_success||(report.sources?.[x.source_id]?.ok?report.checked_at:null))],
      ['Source reported last seen',x.last_seen||(x.source_id==='threatfox'?null:x.observed_at)||'Not supplied by this feed'],
      ['Confidence / block status','Not independently validated. Manual review recommended']
    ];
    for(const [name,value] of details){
      const item=make('div','');item.className='threat-detail-field';
      const label=make('span',name);const val=make('strong',value);
      item.append(label,val);content.append(item);
    }
    for(const e of x.evidence||[]){const p=make('p','Malware: '+e.malware+' · '+e.threat_type+' · Port '+e.port+' · Provider confidence: '+(e.source_confidence??'not supplied')+' · First seen: '+(e.first_seen||'not supplied')+' · Last seen: '+(e.last_seen||'not supplied'));content.append(p);}
    const caution=make('p','Review your firewall and WAF logs, trusted scanner allowlists, ownership, and impact before blocking. Inclusion in a third party feed does not confirm an attack on your environment.');
    caution.className='threat-detail-warning';content.append(caution);
    // Source reference is shown as text to keep the default action entirely in CVEHarbor.
    const source=make('p','Original feed: '+x.source_url);source.className='threat-detail-source';content.append(source);
    if(typeof dialog.showModal==='function')dialog.showModal();
    else dialog.setAttribute('open','');
  }
  const close=document.getElementById('closeThreatDialog');
  if(close)close.addEventListener('click',()=>document.getElementById('threatDetailDialog').close());
  const dialog=document.getElementById('threatDetailDialog');
  if(dialog)dialog.addEventListener('click',e=>{if(e.target===dialog)dialog.close();});
  function freshTime(value){
    const age=Date.now()-Date.parse(value);
    return Number.isFinite(age)&&age>=-5*60*1000&&age<=3*60*60*1000;
  }
  function attackDownloadReady(){return !!report.attack_export?.available&&freshTime(report.checked_at)&&freshTime(report.attack_export.generated_at)}
  function refreshAttackDownloads(){
    const ready=attackDownloadReady();
    for(const link of root.querySelectorAll('[data-attack-download]')){
      link.setAttribute('aria-disabled',String(!ready));link.tabIndex=ready?0:-1;
    }
    for(const message of root.querySelectorAll('.threat-attack-export-status')){
      const meta=report.attack_export;
      message.textContent=!meta?.available?'No current attack/scanning export is available.':!ready?'Downloads paused: this snapshot is stale. Wait for a fresh collection before using it for firewall updates.':meta.complete?'All configured attack/scanning feeds contributed to this export.':'Some attack/scanning feeds are unavailable and excluded from this export.';
    }
  }
  function makeAttackExport(){
    const meta=report.attack_export;if(!meta)return null;
    const box=make('div','');box.className='threat-attack-export';
    box.append(make('h4','Full current attack/scanning list'));
    box.append(make('p',meta.count.toLocaleString('en-US')+' unique IPs. Downloads include all accepted addresses from the available attack/scanning feeds, beyond the 500-per-feed page preview. Malware reports and network ranges are excluded.'));
    const message=make('p','');message.className='threat-attack-export-status';box.append(message);
    if(meta.available){
      const links=make('div','');links.className='threat-attack-export-links';
      for(const [url,label] of [['/attack-scanning-current.txt','Download IP list'],['/attack-scanning-current.csv','Download CSV with sources']]){
        const link=make('a',label);link.href=url;link.download=url.slice(1);link.dataset.attackDownload='true';link.className='threat-download-link';
        link.addEventListener('click',event=>{if(!attackDownloadReady())event.preventDefault()});links.append(link);
      }
      box.append(links);
    }
    return box;
  }
  function makeRow(x){
    const row=make('article','');row.className='threat-entry';
    const name=make('strong',x.ip);name.className='threat-ip';
    const tag=make('span',x.activity);tag.className='threat-type';
    const meta=make('div',x.source+(x.kind==='network'?' · ENTIRE NETWORK RANGE':'')+(x.stale?' · RETAINED: latest source fetch failed':'')+' · Source-reported activity · '+(x.last_seen?'Provider last seen: '+format(x.last_seen):'Last-seen time not supplied by source'));
    meta.className='threat-meta';
    const link=make('button','View details');link.type='button';link.className='threat-view-details';
    link.setAttribute('aria-label','View threat intelligence details for '+x.ip);
    link.addEventListener('click',()=>showThreatDetail(x));
    const head=make('div','');head.className='threat-entry-head';head.append(name,tag);
    row.append(head,meta,link);return row;
  }
  function fillGroup(body,group,entries,focusIndex){
    body.replaceChildren();
    const limit=limits.get(group.id)||pageSize,visible=entries.slice(0,limit);
    const progress=make('p','Showing '+visible.length+' of '+entries.length+' source reports in this group.');
    progress.className='threat-group-progress';
    const list=make('div','');list.className='threat-list';
    for(const x of visible)list.append(makeRow(x));
    if(group.id==='attack'){const downloads=makeAttackExport();if(downloads)body.append(downloads)}
    body.append(progress,list);
    refreshAttackDownloads();
    if(entries.length>limit){
      const more=make('button','Show more reports');more.type='button';more.className='threat-group-more';
      more.addEventListener('click',()=>{limits.set(group.id,limit+pageSize);fillGroup(body,group,entries,limit)});
      body.append(more);
    }
    if(Number.isInteger(focusIndex))list.querySelectorAll('.threat-view-details')[focusIndex]?.focus();
  }
  function render(){
    root.replaceChildren();
    const matching=items.filter(matchesFilters);
    count.textContent=new Set(matching.filter(x=>x.kind!=='network').map(x=>x.ip)).size+' matching IPs · '+new Set(matching.filter(x=>x.kind==='network').map(x=>x.ip)).size+' network ranges · '+matching.length+' source reports';
    if(!matching.length){
      const p=make('p','No indicators match these filters. Try another activity type, feed or IP address.');
      p.className='threat-empty';root.append(p);
    }
    for(const group of groups){
      const entries=matching.filter(x=>categoryFor(x)===group.id);
      if(!entries.length)continue;
      const details=make('details','');details.className='threat-group';details.dataset.activity=group.id;
      details.setAttribute('name','threat-activity');details.open=openGroup===group.id;
      const summary=make('summary',''),chevron=make('span','›');chevron.className='threat-group-chevron';chevron.setAttribute('aria-hidden','true');
      const label=make('span','');label.className='threat-group-label';
      const description=make('span',group.description);description.className='threat-group-description';
      label.append(make('strong',group.label),description);
      const unique=new Set(entries.map(x=>x.ip)).size;
      const total=make('span',unique+(group.id==='network'?(unique===1?' range':' ranges'):(unique===1?' IP':' IPs')));total.className='threat-group-count';
      summary.append(chevron,label,total);
      const body=make('div','');body.className='threat-group-body';
      details.append(summary,body);root.append(details);
      if(details.open)fillGroup(body,group,entries);
      details.addEventListener('toggle',()=>{
        if(!root.contains(details))return;
        if(details.open){
          openGroup=group.id;
          for(const other of root.querySelectorAll('.threat-group[open]'))if(other!==details){other.open=false;other.querySelector('.threat-group-body').replaceChildren()}
          if(!body.childElementCount)fillGroup(body,group,entries);
        }else{
          if(openGroup===group.id)openGroup=null;
          body.replaceChildren();
        }
      });
    }
    window.dispatchEvent(new CustomEvent('cveharbor:threat-filter-change'));
  }
  function filterChanged(){
    limits.clear();
    const matching=items.filter(matchesFilters);
    if(activity.value!=='all')openGroup=activity.value;
    else if(select.value!=='all')openGroup=categoryFor({source_id:select.value});
    else if(search.value.trim()){
      if(!matching.some(x=>categoryFor(x)===openGroup))openGroup=matching.length?categoryFor(matching[0]):null;
    }else openGroup=null;
    render();
  }
  activity.addEventListener('change',()=>{
    select.value='all';
    for(const option of select.options)option.disabled=option.value!=='all'&&activity.value!=='all'&&categoryFor({source_id:option.value})!==activity.value;
    filterChanged();
  });
  select.addEventListener('change',filterChanged);
  search.addEventListener('input',filterChanged);
  render();
})();
