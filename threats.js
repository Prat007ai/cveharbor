(() => {
  'use strict';
  const report=window.CVEHARBOR_THREATS || {indicators:[],sources:{},count:0};
  const root=document.getElementById('threatRows');
  if(!root)return;
  const count=document.getElementById('threatCount');
  const status=document.getElementById('threatStatus');
  const select=document.getElementById('threatSourceFilter');
  const search=document.getElementById('threatSearch');
  const items=Array.isArray(report.indicators)?report.indicators:[];
  const sources=Object.entries(report.sources||{});
  const format=time=>time&&!Number.isNaN(new Date(time).getTime())?new Date(time).toLocaleString('en-CA',{timeZone:'America/Toronto'})+' ET':'Not recorded';
  const freshness=()=>{
    const attempt=Date.parse(report.checked_at),age=Date.now()-attempt;
    const stale=!Number.isFinite(attempt)||age>3*60*60*1000||age< -5*60*1000;
    const healthy=sources.filter(([,s])=>s.ok).length;
    const warning=stale?'STALE SNAPSHOT — latest publication is over 3 hours old or its timestamp is invalid. ':healthy<sources.length?'FEED FAILURE — some results may be retained from an earlier successful fetch. ':'';
    status.textContent=warning+'Last collection attempt: '+format(report.checked_at)+'. '+healthy+' of '+sources.length+' sources responded. '+
      'Coverage: DShield top scanning sources and Feodo botnet C2 only; not a complete list of malicious IPs. '+
      (report.last_changed_at?'Displayed IP list last changed: '+format(report.last_changed_at)+'. ':'List-change time was not recorded in this snapshot. ')+
      (Number.isInteger(report.added_count)?report.added_count+' added / '+report.removed_count+' removed in the latest collection. ':'')+
      'An unchanged count does not establish freshness or completeness.';
    status.dataset.health=stale?'stale':healthy<sources.length?'degraded':'current';
  };
  freshness();setInterval(freshness,60000);
  const health=document.createElement('div');health.className='threat-source-health';
  for(const [id,s] of sources){
    const p=document.createElement('p');
    const fetched=s.published_count??items.filter(x=>x.source_id===id).length;
    p.textContent=(id==='dshield_scanners'?'DShield top IPs':'Feodo botnet C2')+': '+
      (s.ok?fetched+' displayed of '+(s.count??fetched)+' source entries'+(s.truncated?' (limited to '+report.per_source_limit+')':''):'Unavailable; '+(s.retained_count||0)+' older reports retained')+
      '. Last successful fetch: '+format(s.last_success||(s.ok?report.checked_at:null))+'.'+
      (s.error?' Error: '+s.error:'');
    health.append(p);
  }
  status.after(health);
  for(const [id,s] of sources){
    const option=document.createElement('option');
    option.value=id;
    option.textContent=(id==='dshield_scanners'?'Observed scanning':id==='feodo_c2'?'Botnet C2':id)+(s.ok?'':' (feed unavailable)');
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
      ['Source category',x.source_id==='dshield_scanners'?'Observed scanning or attack source':x.source_id==='feodo_c2'?'Botnet command and control':'Third party report'],
      ['Last successful source fetch',format(report.sources?.[x.source_id]?.last_success||(report.sources?.[x.source_id]?.ok?report.checked_at:null))],
      ['Source reported last seen',x.observed_at || 'Not supplied by this feed'],
      ['Confidence / block status','Not independently validated. Manual review recommended']
    ];
    for(const [name,value] of details){
      const item=make('div','');item.className='threat-detail-field';
      const label=make('span',name);const val=make('strong',value);
      item.append(label,val);content.append(item);
    }
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
  function render(){
    root.replaceChildren();
    const filter=select.value,q=search.value.trim().toLowerCase();
    const matching=items.filter(x=>(filter==='all'||x.source_id===filter)&&(!q||x.ip.includes(q)||x.activity.toLowerCase().includes(q)));
    const visible=matching.slice(0,150);
    count.textContent=new Set(matching.map(x=>x.ip)).size+' matching IPs · '+visible.length+' of '+matching.length+' source reports shown';
    if(!visible.length){
      const p=make('p','No indicators match. A missing or failed feed is not a security clearance.');
      p.className='threat-empty';root.append(p);return;
    }
    for(const x of visible){
      const row=make('article','');row.className='threat-entry';
      const name=make('strong',x.ip);name.className='threat-ip';
      const tag=make('span',x.activity);tag.className='threat-type';
      const meta=make('div',x.source+(x.stale?' · RETAINED: latest source fetch failed':'')+' · Source-reported activity · No verified last-seen timestamp');
      meta.className='threat-meta';
      const link=make('button','View details');
      link.type='button';link.className='threat-view-details';
      link.setAttribute('aria-label','View threat intelligence details for '+x.ip);
      link.addEventListener('click',()=>showThreatDetail(x));
      const head=make('div','');head.className='threat-entry-head';head.append(name,tag);
      row.append(head,meta,link);root.append(row);
    }
  }
  select.addEventListener('change',render);
  search.addEventListener('input',render);
  render();
})();
