const ink='#142f36', muted='#4b676c', mist='#f0f6f3', teal='#075d56';
export const escapeHtml=value=>String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// A small tiled lighthouse survives remote-image blocking in email clients.
const light=['.......m....','......mmm...','bbbbbbyyy...','...bbbmwm...','.......w....','......mwm...','......www...','.....mmwwm..','..mmmmmmmmmm','....bbb.....'];
const colors={'.':'#103942',m:'#53b9aa',w:'#d4f3e7',b:'#28676d',y:'#ffeead'};
const tiles=light.map(line=>'<tr>'+Array.from(line.matchAll(/(.)\1*/g),m=>'<td colspan="'+m[0].length+'" height="4" bgcolor="'+colors[m[1]]+'" style="width:'+m[0].length*5+'px;height:4px;font-size:0;line-height:4px">&nbsp;</td>').join('')+'</tr>').join('');
const artwork='<table width="60" aria-hidden="true" role="presentation" cellspacing="0" cellpadding="0" border="0">'+tiles+'</table>';
const buttonStyle='display:inline-block;background:'+teal+';color:#fff;text-decoration:none;border:0;border-radius:6px;padding:13px 19px;font:600 15px Arial,sans-serif;cursor:pointer';
function frame(label,title,content){
 return '<table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="margin:0 auto;max-width:620px;background:white;color:'+ink+';font:16px/1.55 Arial,sans-serif;border:1px solid #ccdeda;border-radius:12px;overflow:hidden">'+
 '<tr><td bgcolor="#0b303b" style="padding:24px;color:white;border-bottom:4px solid #59d9c2"><table role="presentation" width="100%"><tr><td><b style="font:700 27px Arial">CVE<span style="color:#76e0cf">Harbor</span></b><br><span style="color:#d0e6e0;font:11px Arial;letter-spacing:1px">FIREWALL INTELLIGENCE</span></td><td align="right">'+artwork+'</td></tr></table></td></tr>'+
 '<tr><td style="padding:26px;overflow-wrap:anywhere"><b style="font:700 12px Arial;color:#206c61;letter-spacing:1px">'+label+'</b><h1 style="margin:10px 0 16px;font:700 30px/1.15 Arial;color:'+ink+'">'+title+'</h1>'+content+'</td></tr>'+
 '<tr><td bgcolor="'+mist+'" style="padding:12px 26px;border-top:1px solid #cfddd9;color:'+muted+';font:13px Arial">CVEHarbor &middot; Vulnerability intelligence</td></tr></table>';
}
const cta=(label,url)=>'<a href="'+escapeHtml(url)+'" style="'+buttonStyle+'">'+label+' &rarr;</a>';
const panel=html=>'<div style="background:'+mist+';border-left:3px solid #35aa99;padding:14px 18px;margin:16px 0">'+html+'</div>';
export function firewallPage(title,content,status=200,label='EMAIL SUBSCRIPTION'){
 const style='*{box-sizing:border-box}body{margin:0;padding:clamp(12px,5vw,60px) 10px;background:#edf4f2;color:'+ink+';font:16px/1.55 Arial,sans-serif}button{'+buttonStyle+'}p{margin:0 0 18px}fieldset{border:1px solid #b3cbc4;border-radius:8px;margin:15px 0;padding:10px}fieldset label{display:block;padding:6px}input[type=email]{width:100%;padding:12px;margin:8px 0 14px}a{color:'+teal+'}button:focus-visible,a:focus-visible{outline:3px solid #177db3;outline-offset:3px}';
 return new Response('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+title+' | CVEHarbor</title><style>'+style+'</style><main>'+frame(label,title,content)+'</main></html>',{status,headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Robots-Tag':'noindex','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",'X-Content-Type-Options':'nosniff'}});
}
export function confirmEmail(link){
 return {subject:'Confirm your CVEHarbor firewall updates',text:'Confirm your email to receive daily firewall updates. This link expires in 24 hours. '+link,
 html:frame('EMAIL CONFIRMATION','Confirm your firewall updates','<p>Get a daily list of newly observed IPv4 addresses from the CVEHarbor firewall feeds, ready for your team to review.</p>'+cta('Confirm my email',link)+'<p>This link expires in 24 hours.</p><p style="color:'+muted+'">If you didn’t request these updates, you can ignore this email.</p>')};
}
export function confirmPage(email){
 return firewallPage('Receive daily firewall updates?','<p>Confirm your subscription for <strong>'+escapeHtml(email)+'</strong>. You’ll receive one digest on days when new addresses appear.</p>'+panel('<strong>Daily firewall digest</strong><br>New IPv4 count, a sample and the full dated list.')+'<form method="post"><button>Confirm subscription</button></form>');
}
export function activePage(email,preferences){
 return firewallPage('You’re on the list.','<p>Your daily firewall digest will go to <strong>'+escapeHtml(email)+'</strong>.</p>'+panel('<strong>When to expect your first email</strong><br>Coverage starts with your first full UTC day. If new IPs appear, you’ll receive the digest after that day closes and the feed refreshes.')+'<p>You can unsubscribe using the link in any daily digest. <a href="'+escapeHtml(preferences)+'">Manage email preferences</a></p>',200,'SUBSCRIPTION CONFIRMED');
}
export function preferencesPage(email){
 return firewallPage('Choose which emails to stop','<p>Manage optional emails for <strong>'+escapeHtml(email)+'</strong>.</p><form method="post"><fieldset><legend>Unsubscribe from</legend><label><input type="radio" name="scope" value="digest" checked> Daily firewall digest</label><label><input type="radio" name="scope" value="all"> All optional CVEHarbor email updates</label></fieldset><p>Sign-in codes and messages for investigations assigned to you are separate from these subscriptions.</p><button>Unsubscribe</button></form>',200,'EMAIL PREFERENCES');
}
export function stoppedPage(scope,email){
 const what=scope==='all'?'All optional CVEHarbor email updates':'Daily firewall digests';
 return firewallPage('You’re unsubscribed.','<p>'+what+' have been turned off'+(email?' for <strong>'+escapeHtml(email)+'</strong>':'')+'.</p>',200,'PREFERENCES SAVED');
}
export function dailyEmail(day,ips,file,unsubscribe){
 const sample=ips.slice(0,10), count=ips.length, subject='CVEHarbor firewall updates · '+day+' · '+count+' new IPs';
 const message=count+' IPv4 addresses first appeared in the firewall exports on '+day+' (UTC). Review them against your allowlist before changing a firewall rule.';
 return {subject,text:message+'\n'+sample.join('\n')+'\nFull list: '+file+'\nUnsubscribe or manage email preferences: '+unsubscribe,
 html:frame('DAILY FIREWALL DIGEST','New firewall addresses',panel('<b style="font:700 32px Arial;color:'+teal+'">'+count.toLocaleString('en-US')+'</b> new IPv4 addresses<br>'+day+' · UTC')+'<p>'+message+'</p><strong>Newly observed addresses</strong> &middot; '+sample.length+' of '+count+'<p style="font:15px/1.6 Consolas,monospace">'+sample.map(escapeHtml).join('<br>')+'</p>'+cta('View full IP list',file)+'<hr style="margin-top:24px;border:0;border-top:1px solid #cfddd9"><p style="font-size:13px;color:'+muted+'">You receive this email because you confirmed your subscription.</p><a style="color:'+teal+'" href="'+escapeHtml(unsubscribe)+'">Unsubscribe or manage email preferences</a>')};
}
