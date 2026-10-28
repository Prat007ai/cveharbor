/* Read-only 30-day disclosure trend from the public CVEHarbor snapshot.
   Counts unique published CVE IDs, not discoveries, confirmed attacks, or AI attribution. */
(() => {
  'use strict';
  const root=document.getElementById('disclosureTrend');
  if(!root)return;
  const byId=id=>document.getElementById(id);
  const feed=window.CVEHARBOR_DATA;
  const DAY=86400000;
  const todayUTC=Math.floor(Date.now()/DAY)*DAY;
  // Today's disclosures are incomplete. Compare only 30 finished UTC dates.
  const days=Array.from({length:30},(_,i)=>new Date(todayUTC-(30-i)*DAY).toISOString().slice(0,10));
  const validDate=value=>{
    const date=String(value||'').slice(0,10);
    if(!/^\d{4}-\d{2}-\d{2}$/.test(date))return null;
    const ms=Date.parse(date+'T00:00:00Z');
    return Number.isFinite(ms)&&new Date(ms).toISOString().slice(0,10)===date?date:null;
  };
  const names=date=>new Date(date+'T12:00:00Z').toLocaleDateString('en-CA',{
    timeZone:'UTC',month:'short',day:'numeric'
  });
  const fullDate=date=>new Date(date+'T12:00:00Z').toLocaleDateString('en-CA',{
    timeZone:'UTC',year:'numeric',month:'long',day:'numeric'
  });
  const fmt=value=>Number(value).toLocaleString('en-CA');
  const note=byId('disclosureTrendNote');

  if(!feed||!Array.isArray(feed.advisories)){
    byId('disclosureTrendStatus').textContent='The vulnerability feed is unavailable. No trend can be calculated.';
    return;
  }

  // Several public sources may describe the same CVE. Use only the earliest
  // original publication date provided for each unique ID. Backfills can revise
  // earlier bars, so this is an indexed snapshot rather than immutable history.
  const published=new Map();
  for(const record of feed.advisories){
    const id=String(record?.id||'').toUpperCase();
    if(!/^CVE-\d{4}-\d{4,}$/.test(id)||/rejected|withdrawn/i.test(String(record?.status||'')))continue;
    const date=validDate(record.published);
    if(!date)continue;
    if(!published.has(id)||date<published.get(id))published.set(id,date);
  }
  const totals=new Map(days.map(day=>[day,0]));
  for(const date of published.values())if(totals.has(date))totals.set(date,totals.get(date)+1);
  const counts=days.map(date=>totals.get(date));
  const total=counts.reduce((a,b)=>a+b,0);
  const latest=counts.slice(-7).reduce((a,b)=>a+b,0);
  const previous=counts.slice(-14,-7).reduce((a,b)=>a+b,0);
  const peak=Math.max(1,...counts);
  byId('disclosureTrendTotal').textContent=fmt(total);
  byId('disclosureTrendAverage').textContent=(total/30).toFixed(1);
  const change=byId('disclosureTrendChange');
  if(previous===0){
    change.textContent=latest===0?'No activity':'No baseline';
  }else{
    const percent=Math.round((latest-previous)/previous*100);
    change.textContent=(percent>0?'+':'')+percent+'%';
  }
  byId('disclosureTrendCompare').textContent=fmt(latest)+' in the latest 7 days vs '+fmt(previous)+' in the previous 7 days';
  byId('disclosureTrendDates').textContent=names(days[0])+' to '+names(days[29])+' (UTC)';
  byId('disclosureTrendTop').textContent=fmt(peak);
  byId('disclosureTrendMiddle').textContent=fmt(Math.round(peak/2));
  const row=byId('disclosureTrendBars');
  const detail=byId('disclosureTrendSelected');
  row.replaceChildren();
  let selected=null;
  const showDay=(button,index)=>{
    if(selected)selected.setAttribute('aria-pressed','false');
    selected=button;
    button.setAttribute('aria-pressed','true');
    const count=counts[index];
    detail.textContent=fullDate(days[index])+': '+fmt(count)+' CVE'+(count===1?'':'s')+' published in this index';
  };
  for(let i=0;i<days.length;i++){
    const button=document.createElement('button');
    button.type='button';
    button.className='disclosure-day-button';
    const label=fullDate(days[i])+': '+fmt(counts[i])+' published CVE'+(counts[i]===1?'':'s')+' in the CVEHarbor index';
    button.setAttribute('aria-label',label);
    button.setAttribute('aria-pressed','false');
    button.title=label;
    const bar=document.createElement('span');
    bar.className='disclosure-day-bar'+(counts[i]===0?' is-zero':'');
    bar.style.height=counts[i]===0?'2px':(counts[i]/peak*100).toFixed(2)+'%';
    button.append(bar);
    button.addEventListener('click',()=>showDay(button,i));
    row.append(button);
    if(i===days.length-1)showDay(button,i);
  }
  const xlabels=byId('disclosureTrendTicks');
  xlabels.replaceChildren();
  for(const i of [0,6,12,18,24,29]){
    const label=document.createElement('span');
    label.textContent=names(days[i]);
    xlabels.append(label);
  }
  // The line smooths over the last seven completed days. It is NOT an AI trend.
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('class','disclosure-trend-line');
  svg.setAttribute('viewBox','0 0 300 160');
  svg.setAttribute('preserveAspectRatio','none');
  svg.setAttribute('aria-hidden','true');
  const avgPoints=[];
  for(let i=6;i<30;i++){
    const mean=counts.slice(i-6,i+1).reduce((a,b)=>a+b,0)/7;
    avgPoints.push([5+i*10,160-mean/peak*160]);
  }
  const path=document.createElementNS('http://www.w3.org/2000/svg','path');
  path.setAttribute('d',avgPoints.map(([x,y],i)=>(i?'L':'M')+x.toFixed(1)+' '+y.toFixed(1)).join(' '));
  path.setAttribute('fill','none');
  path.setAttribute('stroke','#ffd08a');
  path.setAttribute('stroke-width','2.4');
  path.setAttribute('stroke-linecap','round');
  path.setAttribute('stroke-linejoin','round');
  path.setAttribute('vector-effect','non-scaling-stroke');
  svg.append(path);
  byId('disclosureTrendPlot').append(svg);
  byId('disclosureTrendStatus').textContent=total
    ? 'Daily bars show original publication dates within our monitored sources.'
    : 'No published CVEs appear in this 30-day window of the current index. This does not mean that no vulnerabilities were published.';
  const stamped=Date.parse(feed.last_successful_update||feed.last_checked_at||'');
  const age=Number.isFinite(stamped) ? Date.now()-stamped : NaN;
  const fresh=Number.isFinite(age)&&age>=0&&age<=8*3600000;
  const stamp=Number.isFinite(stamped)?new Date(stamped).toISOString().slice(0,16).replace('T',' ')+' UTC':'unknown';
  note.textContent='Source: CVEHarbor public advisory snapshot. Last refresh: '+stamp+'. '+
    (fresh?'':'Refresh may be delayed. ')+
    'Limited source coverage. Historical counts may change as providers publish or correct records. This is not a worldwide CVE total.';
})();
