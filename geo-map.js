(() => {
  'use strict';
  const data = window.CVEHARBOR_THREATS || {};
  const indicators = Array.isArray(data.indicators) ? data.indicators : [];
  const el = id => document.getElementById(id);
  const canvas = el('threatWorldMap');
  if (!canvas) return;
  const status = el('geoMapStatus'), ranking = el('geoCountryRanking'), filter = el('geoMapSourceFilter');
  const summary = el('geoMapSummary');
  const valid = x => x && Number.isFinite(x.geo?.latitude) && Number.isFinite(x.geo?.longitude) && typeof x.geo?.country === 'string' && x.geo.country.trim();
  const geoItems = indicators.filter(valid);
  const options = [...new Set(indicators.map(x => x.source_id))];
  for (const source of options) {
    const option = document.createElement('option');
    option.value = source;
    option.textContent = source === 'dshield_scanners' ? 'Observed scanning' : source === 'feodo_c2' ? 'Botnet C2' : source;
    filter.append(option);
  }
  let chosen = '';
  let map = null;
  let markers = null;
  function group() {
    const selected = geoItems.filter(x => (filter.value === 'all' || x.source_id === filter.value)
      && (!chosen || x.geo.country === chosen));
    const countries = new Map();
    for (const x of selected) {
      const country = x.geo.country;
      if (!countries.has(country)) countries.set(country, { name:country, ips:[], latitude:0, longitude:0 });
      const g = countries.get(country);
      if (!g.ips.some(y => y.ip === x.ip)) g.ips.push(x);
    }
    for (const g of countries.values()) {
      g.latitude = g.ips.reduce((sum,x) => sum+x.geo.latitude,0)/g.ips.length;
      g.longitude = g.ips.reduce((sum,x) => sum+x.geo.longitude,0)/g.ips.length;
    }
    return [...countries.values()].sort((a,b)=>b.ips.length-a.ips.length || a.name.localeCompare(b.name));
  }
  function draw() {
    const all = group();
    ranking.replaceChildren();
    const visibleCount = all.reduce((sum,g)=>sum+g.ips.length,0);
    summary.textContent = visibleCount+' geolocated IPs across '+all.length+' countries';
    for (const g of all) {
      const row=document.createElement('button');row.type='button';row.className='geo-ranking-row';
      const name=document.createElement('span');name.textContent=g.name;
      const value=document.createElement('strong');value.textContent=String(g.ips.length);
      row.append(name,value);
      row.addEventListener('click',()=>{chosen=chosen===g.name?'':g.name;draw();});
      ranking.append(row);
      if(chosen===g.name)row.classList.add('selected');
    }
    if (!window.L) {
      status.textContent = geoItems.length ? 'The interactive map library is unavailable. Country totals are shown below.' : 'No IP geolocation is available from the current feed. Rankings will appear after the next successful collection.';
      return;
    }
    if (!map) {
      map=window.L.map(canvas,{worldCopyJump:true,scrollWheelZoom:false,minZoom:2,maxZoom:8}).setView([24,4],2);
      window.L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png',{
        attribution:'&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap contributors</a>',
        maxZoom:8
      }).addTo(map);
      markers=window.L.layerGroup().addTo(map);
    }
    markers.clearLayers();
    for (const g of all) {
      const radius=Math.min(26,8+Math.sqrt(g.ips.length)*5);
      const circle=window.L.circleMarker([g.latitude,g.longitude],{
        radius,weight:2,color:'#63ebda',fillColor:'#f08b5a',fillOpacity:0.7
      }).addTo(markers);
      const list=g.ips.slice(0,16).map(x=>x.ip+' ('+(x.source_id==='feodo_c2'?'Botnet C2':'Scanning')+')').join('\n');
      const popup=document.createElement('div');
      const heading=document.createElement('strong');heading.textContent=g.name+' · '+g.ips.length+' reported IPs';
      const pre=document.createElement('pre');pre.textContent=list+(g.ips.length>16?'\nMore indicators available in the list below.':'');
      pre.style.cssText='font-size:11px;white-space:pre-wrap;max-height:180px;overflow:auto';
      const b=document.createElement('button');b.type='button';b.textContent='Show only this country';
      b.addEventListener('click',()=>{chosen=g.name;draw();map.closePopup();});
      popup.append(heading,pre,b);
      circle.bindPopup(popup);
    }
    status.textContent = geoItems.length ? 'Showing approximate geolocated network addresses. Click a circle or country to drill down. Drag to pan and use + or − to zoom.' :
      'No geolocation is available in the current feed. The map will populate after a successful enrichment run.';
    if (all.length && chosen) map.setView([all[0].latitude,all[0].longitude],4);
    if (!chosen && all.length && markers.getLayers().length) {
      const bounds=window.L.featureGroup(markers.getLayers()).getBounds();
      if(bounds.isValid())map.fitBounds(bounds.pad(.35),{maxZoom:4});
    }
    setTimeout(()=>map.invalidateSize(),50);
  }
  filter.addEventListener('change',()=>{chosen='';draw();});
  const reset=el('geoMapReset');
  if(reset)reset.addEventListener('click',()=>{chosen='';filter.value='all';draw();});
  draw();
})();