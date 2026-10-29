(()=>{'use strict';
const body=document.body;
if(!body||(!body.classList.contains('account-page')&&(!body.dataset.page||body.dataset.page==='home')))return;
body.classList.add('command-center-app');
const groups=[
 {label:'Intelligence',items:[['Overview','/','layout-dashboard'],['Vulnerabilities','/vulnerabilities/','shield-alert'],['Threat IPs','/threats/','radar'],['Malware','/malware/','bug'],['Lifecycle','/lifecycle/','calendar-clock']]},
 {label:'Workspace',items:[['My Workspace','/workspace/','briefcase-business'],['Customers','/customer-dashboard/','building-2'],['Environments','/environments/','server'],['Reports','/customer-reports/','file-chart-column'],['Remediation','/remediation/','list-checks']]},
 {label:'Tools',items:[['Admin Tools','/admin-tools/','settings-2'],['Account','/account/','circle-user-round']]}
];
const symbols={
'layout-dashboard':'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
'shield-alert':'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="M12 8v4m0 4h.01"/>',
'radar':'<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="m12 12 6-6"/>',
'bug':'<path d="M8 2l1.5 2M16 2l-1.5 2M3 9h3m12 0h3M3 15h3m12 0h3M8 20l-2 2m10-2 2 2"/><rect x="6" y="4" width="12" height="16" rx="6"/><path d="M6 12h12"/>',
'calendar-clock':'<rect x="3" y="4" width="18" height="17" rx="2"/><path d="M8 2v4m8-4v4M3 9h18"/><circle cx="12" cy="15" r="3"/><path d="M12 13v2l1 1"/>',
'briefcase-business':'<rect x="2" y="7" width="20" height="14" rx="2"/><path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M2 12h20"/>',
'building-2':'<rect x="4" y="2" width="12" height="20" rx="1"/><path d="M16 10h4v12M8 6h1m3 0h1M8 10h1m3 0h1M8 14h1m3 0h1M10 22v-4"/>',
'server':'<rect x="3" y="3" width="18" height="8" rx="2"/><rect x="3" y="13" width="18" height="8" rx="2"/><path d="M7 7h.01M7 17h.01"/>',
'file-chart-column':'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6Z"/><path d="M14 2v6h6M8 18v-3m4 3v-6m4 6v-8"/>',
'list-checks':'<path d="m3 6 2 2 4-4M12 6h9m-18 7 2 2 4-4m3 2h9M3 20h18"/>',
'settings-2':'<path d="M4 7h16M4 17h16"/><circle cx="9" cy="7" r="3"/><circle cx="16" cy="17" r="3"/>',
'circle-user-round':'<circle cx="12" cy="12" r="10"/><circle cx="12" cy="9" r="3"/><path d="M5 19a8 8 0 0 1 14 0"/>'
};
const svg=name=>'<svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+symbols[name]+'</svg>';
const bar=document.createElement('aside');bar.className='command-sidebar';bar.setAttribute('aria-label','Application navigation');
const logo=document.createElement('a');logo.href='/';logo.className='command-logo';logo.setAttribute('aria-label','CVEHarbor home');logo.textContent='C';bar.append(logo);
const nav=document.createElement('nav');nav.className='command-sidebar-nav';nav.setAttribute('aria-label','Security command center');
const route=location.pathname.replace(/\/index\.html$/,'/').replace(/\/$/,'')||'/';
for(const group of groups){
 const label=document.createElement('span');label.className='command-nav-section';label.textContent=group.label;nav.append(label);
 for(const [name,url,icon] of group.items){
  const link=document.createElement('a');link.href=url;link.className='command-nav-link';link.title=name;link.setAttribute('aria-label',name);
  link.innerHTML=svg(icon)+'<span>'+name+'</span>';
  if((url.replace(/\/$/,'')||'/')===route){link.classList.add('is-current');link.setAttribute('aria-current','page')}
  nav.append(link);
 }
}
bar.append(nav);body.insertBefore(bar,body.firstChild);
})();