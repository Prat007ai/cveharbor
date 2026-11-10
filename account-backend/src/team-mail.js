import {escapeHtml as escape} from './firewall-templates.js';
import {harborLight} from './team-invitation-art.js';

export function invitationMessage({organization, inviter, email, role, customers, link}) {
  const scope = customers === null ? 'All current and future customers' : customers.join(', ');
  const description = {Viewer:'View assets, findings and reports.', Editor:'View and update shared customer records.', Owner:'Manage members and all workspace records.'}[role];
  const subject = 'Your invitation to '+organization+' on CVEHarbor';
  const artwork='cid:harbor-light.png';
  const text_body = [subject,'',inviter+' invited you to join '+organization+'. Sign in with '+email+' to accept.',
    'Role: '+role+' · '+description,'Customer access: '+scope,'','Accept invitation: '+link,
    'This personal invitation expires in seven days. If you did not expect it, you can ignore it.'].join('\n');
  const html_body = '<table role="presentation" width="100%" bgcolor="#edf3f4"><tr><td align="center" style="padding:16px">'+
    '<table role="presentation" width="100%" cellspacing="0" bgcolor="#ffffff" style="max-width:600px;font:15px/1.5 Arial,sans-serif;color:#183642">'+
    '<tr><td bgcolor="#0c273a" style="padding:17px 24px;font-size:23px;color:white"><b>CVE<span style="color:#78dcd0">Harbor</span></b></td></tr>'+
    '<tr><td><img src="'+artwork+'" width="600" alt="" style="display:block;width:100%;height:auto"></td></tr>'+
    '<tr><td style="padding:20px 24px"><small>WORKSPACE INVITATION</small><h1>Join '+escape(organization)+'</h1><p>'+escape(inviter)+' invited you to the team’s CVEHarbor workspace. Sign in with <b>'+escape(email)+'</b> to accept.</p>'+
    '<p style="padding:14px;background:#eef6f5;border-left:3px solid #20877c"><b>'+role+'</b> · '+description+'<br>Customer access: '+escape(scope)+'</p>'+
    '<p><a style="display:inline-block;background:#076b68;color:#ffffff;padding:12px 22px;text-decoration:none;border-radius:6px" href="'+escape(link)+'">Accept invitation →</a></p>'+
    '<small>This personal invitation expires in seven days. If you weren’t expecting it, you can ignore this email.</small></td></tr></table></td></tr></table>';
  return {subject,text_body,html_body};
}

export async function deliverInvitation(env, invitation) {
  if(env.STAGING_MODE==='true'||env.OUTBOUND_EMAIL_DISABLED==='true')throw Error('Outbound invitation delivery is disabled.');
  if(!env.EMAIL_FROM||!env.SMTP2GO_API_KEY)throw Error('Invitation mail is unavailable.');
  const result=await fetch('https://api.smtp2go.com/v3/email/send',{method:'POST',
    headers:{'Content-Type':'application/json','X-Smtp2go-Api-Key':env.SMTP2GO_API_KEY},
    body:JSON.stringify({sender:env.EMAIL_FROM,to:[invitation.email],...invitationMessage(invitation),
      inlines:[{filename:'harbor-light.png',mimetype:'image/png',fileblob:harborLight}]})});
  if(!result.ok)throw Error('Invitation delivery failed.');
  const receipt=await result.json();
  if(receipt.data?.succeeded!==1||receipt.data?.failed!==0)throw Error('Invitation delivery unconfirmed.');
}
