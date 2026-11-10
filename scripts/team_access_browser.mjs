import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath,pathToFileURL} from 'node:url';
const worker=(await import(process.env.TEAM_TEST_WORKER?pathToFileURL(process.env.TEAM_TEST_WORKER).href:'../account-backend/src/index.js')).default;
import {unifiedFixture} from '../account-backend/tests/helpers/unified-db.mjs';
import {encryptSecret,totp,newSecret} from '../account-backend/src/totp.js';

const require=createRequire(new URL('../staging/package.json',import.meta.url));
const {chromium}=require('playwright-core');
const root=fileURLToPath(new URL('../',import.meta.url)),site=process.env.TEAM_TEST_SITE||path.join(root,'public');
const fixture=await unifiedFixture(), {env,DB,emails}=fixture;
for(const file of ['account-backend/migrations/0029_finding_assignment_links.sql','deployment/proposals/customer-remediation/schema.sql','account-backend/migrations/0032_recovery_control.sql','deployment/proposals/organization-team-access/schema.sql']){
  DB.sql.exec(fs.readFileSync(path.join(root,file),'utf8'));
}
DB.sql.prepare('UPDATE sessions SET created_at=unixepoch()-3600 WHERE user_id=?').run('a');
DB.sql.prepare('UPDATE team_last_login SET signed_at=unixepoch()-3600 WHERE user_id=?').run('a');
env.TEAM_ACCESS_ENABLED='true';env.TOTP_ENCRYPTION_KEY='fictional browser test only encryption key';
const existingSecret=newSecret();
DB.sql.prepare('UPDATE user_totp SET encrypted_secret=? WHERE user_id=?').run(await encryptSecret(env,existingSecret,'b'),'b');
globalThis.fetch=fixture.fetcher;
const browser=await chromium.launch({headless:true,...(process.env.TEAM_TEST_CHROME?{executablePath:process.env.TEAM_TEST_CHROME}:{})});
let lane=Promise.resolve();
const mime={'.html':'text/html','.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.json':'application/json','.png':'image/png','.jpg':'image/jpeg'};
const harborDesign=fs.existsSync(path.join(site,'assets/team-harbor/invitation.jpg'));
const accountDesign=fs.existsSync(path.join(site,'account-harbor.css'));
async function verifyArt(page,selector,filename,pseudo=null){
  const node=page.locator(selector);
  await node.waitFor({state:'visible'});
  await node.evaluate(async(el,{filename,pseudo})=>{
    const css=getComputedStyle(el,pseudo).backgroundImage;
    const url=new URL('/assets/team-harbor/'+filename,location.origin).href;
    if(!css.includes(url))throw Error('Missing background '+filename);
    const image=new Image();image.src=url;await image.decode();
    if(!image.naturalWidth)throw Error('Invalid artwork '+filename);
  },{filename,pseudo});
}
async function screenshot(page,name,selector='#teamAccess'){
  const folder=process.env.TEAM_TEST_SCREENSHOTS;
  if(!folder)return;
  fs.mkdirSync(folder,{recursive:true});
  await page.locator(selector).screenshot({path:path.join(folder,name+'.png')});
}
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
  if(accountDesign){
    await owner.setViewportSize({width:1536,height:1024});
    await verifyArt(owner,'.account-mast','account-beacon.jpg');
    for(const tile of ['profile','authenticator','recovery','notifications','session','workspace']){
      await verifyArt(owner,'.'+tile+'-tile','tile-'+tile+'.jpg','::before');
    }
    await screenshot(owner,'account-security','body');
    await owner.setViewportSize({width:390,height:844});
    await owner.locator('#accountSecurityRecoveryStart').click();
    assert.ok(await owner.locator('#accountSecurityRecoveryCode').isVisible());
    assert.ok(await owner.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
    await screenshot(owner,'account-mobile','body');
    await owner.reload();await owner.setViewportSize({width:1536,height:1024});
  }
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
    if(newAccount)await screenshot(owner,'invitation-preview');
    await owner.getByRole('button',{name:'Send invitation'}).click();
    await owner.locator('#teamStatus').getByText('Invitation sent.').waitFor();
    if(accountDesign)await owner.locator('.member-counts').getByText('1 Pending').waitFor();
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
    if(harborDesign){
      await verifyArt(john,'.harbor-invitation','invitation.jpg','::before');
      await john.getByRole('button',{name:'Use another account'}).waitFor();
      if(newAccount){
        await screenshot(john,'invitation-review');
        await john.setViewportSize({width:390,height:844});
        assert.ok(await john.locator('.harbor-invitation').evaluate(el=>el.getBoundingClientRect().right<=innerWidth+1));
        await screenshot(john,'invitation-mobile');
        await john.setViewportSize({width:1080,height:900});
      }
    }
    await john.getByRole('button',{name:'Join workspace'}).click();
    await john.locator('#teamPanel').getByText('Web Server 01',{exact:true}).first().waitFor();
    assert.equal(await john.locator('#teamPanel').getByText('Customer South',{exact:true}).count(),0);
    assert.equal(await john.locator('#teamPanel').getByRole('button',{name:'Edit asset'}).count(),0);
    await john.locator('#teamPanel').getByRole('heading',{name:'Potential findings'}).waitFor();
    if(newAccount){
      if(harborDesign)await verifyArt(john,'.harbor-metrics','network.jpg');
      await screenshot(john,'assigned-workspace');
      await owner.getByRole('button',{name:'Refresh members'}).click();
      const member=owner.getByRole('row').filter({hasText:email});
      await member.getByText('Active',{exact:true}).waitFor();
      if(accountDesign){
        await verifyArt(owner,'.account-new-main','team-beacon.jpg');
        await verifyArt(owner,'#teamAccess','team-coast.jpg',process.env.CVEHARBOR_SITE_RELEASE==='account-responsive'?'::after':null);
        await owner.locator('.member-counts').getByText('2 Active').waitFor();
        await owner.locator('.member-counts').getByText('0 Pending').waitFor();
        await screenshot(owner,'account-team','body');
      }else if(harborDesign){
        await verifyArt(owner,'.team-banner','harbor.jpg');
        await verifyArt(owner,'#teamAccess','shoreline.jpg');
      }
      await screenshot(owner,'team-members');
      await member.getByRole('button',{name:'Edit'}).click();
      await owner.getByLabel('Organization role').selectOption('Owner');
      await owner.getByLabel('Organization role').selectOption('Editor');
      assert.equal(await owner.getByLabel('Customer access').inputValue(),'selected');
      await screenshot(owner,'edit-customer-access');
      await owner.getByLabel('Customer North',{exact:true}).uncheck();
      await owner.getByLabel('Customer South',{exact:true}).check();
      await owner.getByRole('button',{name:'Save changes'}).click();
      await owner.locator('#teamStatus').getByText('Access updated.').waitFor();
      await john.locator('#teamPanel').getByRole('button',{name:'Refresh',exact:true}).click();
      await john.locator('#teamPanel').getByText('Web Server 02',{exact:true}).first().waitFor();
      assert.equal(await john.locator('#teamPanel').getByText('Web Server 01',{exact:true}).count(),0);
      await john.locator('#teamPanel').getByRole('button',{name:'Edit asset'}).waitFor();
      if(harborDesign){
        await john.getByRole('button',{name:'Add asset',exact:true}).waitFor();
        await screenshot(john,'editor-workspace');
        await owner.setViewportSize({width:390,height:844});
        assert.ok(await owner.locator('#teamPanel .team-table-wrap').evaluate(el=>
          el.getBoundingClientRect().right<=innerWidth+1 && el.scrollWidth>=el.clientWidth));
        await owner.setViewportSize({width:1080,height:900});
      }
      if(harborDesign)await member.locator('summary').click();
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
  if(accountDesign){
    await owner.locator('#teamTab').click();
    await verifyArt(owner,'.organization-card','org-panorama.jpg','::before');
    await owner.locator('.organization-card').getByRole('link',{name:'Open workspace'}).waitFor();
    await owner.setViewportSize({width:1536,height:1024});
    await screenshot(owner,'organization-workspaces','body');
    await owner.setViewportSize({width:390,height:844});
    assert.ok(await owner.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
    await owner.getByRole('button',{name:'Manage team'}).click();
    await owner.locator('.member-counts').getByText('2 Members').waitFor();
  }
  console.log('PASS: owner invite and email preview; new-user MFA enrollment and recovery; returning-user MFA; scoped viewer dashboard; six personal security sections.');
}finally{await browser.close();}
