// Render verified bytes read back from production, using a fictional account.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdir,readFile} from 'node:fs/promises';
import path from 'node:path';
const require=createRequire(new URL('../staging/package.json',import.meta.url));
const {chromium}=require('playwright-core');
const origin='https://cveharbor.com', api='https://api.cveharbor.com';
const organization={id:'mock-harbor',name:'Whitecap Canada Inc',role:'Owner'};
const members=[
  {id:'demo-viewer',email:'maya@example.com',role:'Viewer',scope:'selected',customers:['demo'],status:'Active'},
  {id:'demo-owner',email:'alex@example.com',role:'Owner',scope:'all',customers:[],status:'Active',founder:true}
].map(member=>({...member,active:true,signed_at:1794315600,revision:1}));
const reads=new Map([
  ['/v1/me',{authenticated:true,email:'alex@example.com'}],
  ['/v1/auth/totp/status',{enabled:true}],
  ['/v1/team/organizations',{organizations:[organization],can_create:false}],
  ['/v1/team/organizations/mock-harbor/members',{members,customers:[{id:'demo',name:'Northstar Demo'}]}]
]);
const folder=process.env.TEAM_TEST_SCREENSHOTS;
const served=path.resolve(process.env.VERIFIED_SITE);
const responsive=process.env.CVEHARBOR_SITE_RELEASE==='account-responsive';
const types={'.css':'text/css','.js':'text/javascript','.html':'text/html','.jpg':'image/jpeg','.svg':'image/svg+xml'};
await mkdir(folder,{recursive:true});
const browser=await chromium.launch({executablePath:process.env.TEAM_TEST_CHROME});
try{
  const context=await browser.newContext({viewport:{width:1536,height:1024},serviceWorkers:'block'});
  await context.route('**/*',async route=>{
    const req=route.request(),url=new URL(req.url());
    if(req.method()!=='GET')return route.abort();
    if(url.origin===origin){
      const file=path.resolve(served,'.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));
      assert.ok(file.startsWith(served+path.sep));
      try{return await route.fulfill({body:await readFile(file),contentType:types[path.extname(file)]});}
      catch(error){if(error.code!=='ENOENT')throw error;return route.fulfill({status:404,body:'Unpublished asset'});}
    }
    if(url.origin===api && reads.has(url.pathname))return route.fulfill({json:reads.get(url.pathname),
      headers:{'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Credentials':'true'}});
    return route.abort();
  });
  const page=await context.newPage();
  async function art(selector,file,pseudo=null){
    await page.locator(selector).evaluate(async(el,{file,pseudo})=>{
      const url=new URL('/assets/team-harbor/'+file+'.jpg',location.origin).href;
      if(!getComputedStyle(el,pseudo).backgroundImage.includes(url))throw Error('Missing displayed artwork: '+file);
      const img=new Image();img.src=url;await img.decode();
    },{file,pseudo});
  }
  async function capture(name,selector,maxHeight,pseudo=null){
    if(responsive){
      for(const [width,height] of [[320,640],[390,844],[768,1024],[1024,600],[1366,768],[1920,1080],[3440,1440],[1920,550],[390,844]]){
        await page.setViewportSize({width,height});
        const size=await page.locator(selector).evaluate((el,pseudo)=>({
          height:pseudo?parseFloat(getComputedStyle(el,pseudo).height):el.getBoundingClientRect().height,
          pageWidth:document.documentElement.scrollWidth
        }),pseudo);
        assert.ok(size.pageWidth<=width+1,name+' overflows at '+width+'px');
        assert.ok(size.height>0 && size.height<=maxHeight+1,name+' banner is '+size.height+'px at '+width+' × '+height);
        if(name==='03-organization-workspaces'){
          const entry=await page.getByRole('button',{name:'Manage team'}).boundingBox();
          assert.ok(entry.y+entry.height<=height,'Workspace controls below the fold at '+width+' × '+height);
        }
        console.log(name,width+'x'+height,'banner height',Math.round(size.height));
      }
      await page.setViewportSize({width:1536,height:1024});
    }
    await page.screenshot({path:path.join(folder,name+'.png'),fullPage:true});
  }
  assert.equal((await page.goto(origin+'/account/')).status(),200);
  await page.getByText('alex@example.com',{exact:true}).waitFor();
  assert.equal(await page.locator('#accountSecurityDashboard section:visible').count(),6);
  await art('.account-mast','account-beacon');
  for(const tile of ['profile','authenticator','recovery','notifications','session','workspace']){
    await art('.'+tile+'-tile','tile-'+tile,'::before');
  }
  await capture('01-account-security','.account-mast',192);
  await page.locator('#teamTab').click();
  await page.getByRole('heading',{name:organization.name}).waitFor();
  await art('.organization-card','org-panorama','::before');
  await capture('03-organization-workspaces','.organization-card',208,'::before');
  await page.getByRole('button',{name:'Manage team'}).click();
  await page.getByText('2 Active',{exact:true}).waitFor();
  await page.getByRole('row').filter({hasText:'maya@example.com'}).getByText('Northstar Demo').waitFor();
  await art('.account-new-main','team-beacon');await art('#teamAccess','team-coast',responsive?'::after':null);
  await capture('02-team-access','.roster-header',180);
  console.log('Verified all three rendered production views, with fictional account and membership responses.');
}finally{await browser.close();}
