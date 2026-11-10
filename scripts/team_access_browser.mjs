import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import worker from '../account-backend/src/index.js';
import {unifiedFixture} from '../account-backend/tests/helpers/unified-db.mjs';
import {encryptSecret,totp,newSecret} from '../account-backend/src/totp.js';

const require=createRequire(new URL('../staging/package.json',import.meta.url));
const {chromium}=require('playwright-core');
const root=fileURLToPath(new URL('../',import.meta.url)),site=path.join(root,'public');
const fixture=await unifiedFixture(), {env,DB,emails}=fixture;
for(const file of ['account-backend/migrations/0029_finding_assignment_links.sql','deployment/proposals/customer-remediation/schema.sql','account-backend/migrations/0032_recovery_control.sql','deployment/proposals/organization-team-access/schema.sql']){
  DB.sql.exec(fs.readFileSync(path.join(root,file),'utf8'));
}
env.TEAM_ACCESS_ENABLED='true';env.TOTP_ENCRYPTION_KEY='fictional browser test only encryption key';
const existingSecret=newSecret();
DB.sql.prepare('UPDATE user_totp SET encrypted_secret=? WHERE user_id=?').run(await encryptSecret(env,existingSecret,'b'),'b');
globalThis.fetch=fixture.fetcher;
const browser=await chromium.launch({headless:true,...(process.env.TEAM_TEST_CHROME?{executablePath:process.env.TEAM_TEST_CHROME}:{})});
let lane=Promise.resolve();
const mime={'.html':'text/html','.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.json':'application/json','.png':'image/png'};
async function session(cookie){
  const context=await browser.newContext({viewport:{width:1080,height:900}});
  if(cookie)await context.addCookies([{name:'cvh_session',value:cookie,url:'https://api.cveharbor.com/',httpOnly:true,secure:true,sameSite:'Strict'}]);
  await context.route('**/*',async route=>{
    const source=route.request(),url=new URL(source.url());
    if(url.hostname==='api.cveharbor.com'){
      const headers=await source.allHeaders();
      const request=new Request(url,{method:source.method(),headers,...(source.postData()?{body:source.postData()}:{})});
      const pending=lane.then(()=>worker.fetch(request,env));lane=pending.catch(()=>{});
      const res=await pending;
      return route.fulfill({status:res.status,headers:Object.fromEntries(res.headers),body:await res.text()});
    }
    if(url.hostname!=='cveharbor.com')return route.abort();
    const file=path.resolve(site,'.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));
    if(!file.startsWith(site+path.sep)||!fs.existsSync(file))return route.fulfill({status:404,body:'Not found'});
    return route.fulfill({body:fs.readFileSync(file),contentType:mime[path.extname(file)]||'application/octet-stream'});
  });
  const page=await context.newPage();page.setDefaultTimeout(8000);return page;
}
try{
  const owner=await session(fixture.request('/me').headers.get('cookie').slice('cvh_session='.length));
  await owner.goto('https://cveharbor.com/account/');
  await owner.locator('#teamTab').click();
  await owner.getByLabel('Organization name').fill('Fictional Northstar');
  await owner.getByLabel('Customer inventory').selectOption('existing');
  await owner.getByRole('button',{name:'Create organization'}).click();
  for(const [email,newAccount] of [['john@example.test',true],['other@example.test',false]]){
    await owner.getByRole('button',{name:'Invite member'}).click();
    await owner.getByLabel('Email address',{exact:true}).fill(email);
    await owner.getByLabel('Customer North',{exact:true}).check();
    await owner.getByRole('button',{name:'Preview invitation email'}).click();
    await owner.frameLocator('iframe').getByText('Join Fictional Northstar',{exact:true}).waitFor();
    await owner.getByRole('button',{name:'Send invitation'}).click();
    await owner.locator('#teamStatus').getByText('Invitation sent.').waitFor();
    const url=emails.filter(e=>e.subject.includes('invitation')).at(-1).text_body.match(/https:\/\/cveharbor.com\/workspace\/#team-invite=[a-f0-9]{64}/)[0];
    const john=await session();await john.goto(url);
    await john.locator('#accountPageEmail').fill(email);
    await john.locator('#accountPageSend').click();await john.locator('#accountPageCode').waitFor({state:'visible'});
    const code=emails.filter(e=>e.subject==='CVEHarbor sign in code'&&e.to[0]===email).at(-1).text_body.match(/\d{6}/)[0];
    await john.locator('#accountPageCode').fill(code);await john.locator('#accountPageConfirm').click();
    if(newAccount){
      await john.locator('#accountPageRequiredCode').waitFor({state:'visible'});
      const key=(await john.locator('#accountPageRequiredSecret').innerText()).replace(/\s/g,'');
      await john.locator('#accountPageRequiredCode').fill(await totp(key));await john.locator('#accountPageRequiredEnrollForm button[type=submit]').click();
      await john.locator('#accountPageRequiredRecovery button').last().click();
    }else{
      await john.locator('#accountPageTotpCode').fill(await totp(existingSecret));await john.locator('#accountPageTotpVerify button[type=submit]').click();
    }
    await john.getByRole('button',{name:'Join workspace'}).click();
    await john.locator('#teamPanel').getByText('Web Server 01',{exact:true}).first().waitFor();
    assert.equal(await john.locator('#teamPanel').getByText('Customer South',{exact:true}).count(),0);
    assert.equal(await john.locator('#teamPanel').getByRole('button',{name:'Edit asset'}).count(),0);
    await john.locator('#teamPanel').getByRole('heading',{name:'Potential findings'}).waitFor();
    if(newAccount){
      await owner.getByRole('button',{name:'Refresh members'}).click();
      const member=owner.getByRole('row').filter({hasText:email});
      await member.getByText('Active',{exact:true}).waitFor();
      await member.getByRole('button',{name:'Edit'}).click();
      await owner.getByLabel('Organization role').selectOption('Owner');
      await owner.getByLabel('Organization role').selectOption('Editor');
      assert.equal(await owner.getByLabel('Customer access').inputValue(),'selected');
      await owner.getByLabel('Customer North',{exact:true}).uncheck();
      await owner.getByLabel('Customer South',{exact:true}).check();
      await owner.getByRole('button',{name:'Save changes'}).click();
      await owner.locator('#teamStatus').getByText('Access updated.').waitFor();
      await john.locator('#teamPanel').getByRole('button',{name:'Refresh',exact:true}).click();
      await john.locator('#teamPanel').getByText('Web Server 02',{exact:true}).first().waitFor();
      assert.equal(await john.locator('#teamPanel').getByText('Web Server 01',{exact:true}).count(),0);
      await john.locator('#teamPanel').getByRole('button',{name:'Edit asset'}).waitFor();
      owner.once('dialog',dialog=>dialog.accept());
      await member.getByRole('button',{name:'Remove'}).click();
      await member.waitFor({state:'detached'});
      await john.locator('#teamPanel').getByRole('button',{name:'Refresh',exact:true}).click();
      await john.locator('#teamPanel').getByText('Workspace or record unavailable.').waitFor();
      assert.equal(await john.locator('#teamPanel').getByText('Web Server 02',{exact:true}).count(),0);
    }
    await john.context().close();
  }
  await owner.locator('#personalTab').click();assert.equal(await owner.locator('#accountSecurityDashboard section:visible').count(),6);
  console.log('PASS: owner invite and email preview; new-user MFA enrollment and recovery; returning-user MFA; scoped viewer dashboard; six personal security sections.');
}finally{await browser.close();}
