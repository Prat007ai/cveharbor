import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {createHash} from 'node:crypto';
import {createFrontend} from '../frontend.mjs';
import {TARGET} from '../target.mjs';
const file='staging/.build/public/assets/vendor/qrcodejs-1.0.0.min.js',code=fs.readFileSync(file,'utf8');
test('staging MFA page loads identical pinned QR bytes locally before the account script',()=>{
 const html=fs.readFileSync('staging/.build/public/workspace/index.html','utf8');
 assert.ok(html.indexOf('/assets/vendor/qrcodejs-1.0.0.min.js')<html.indexOf('/account-page.js'));
 assert.doesNotMatch(html,/https:\/\/cdnjs\.cloudflare\.com\/ajax\/libs\/qrcodejs/);
 const sri='sha512-'+createHash('sha512').update(code).digest('base64');assert.ok(html.includes(sri));
 assert.match(fs.readFileSync('staging/.build/public/assets/vendor/qrcodejs-1.0.0.min.LICENSE.txt','utf8'),/MIT License/);
 assert.match(fs.readFileSync('workspace/index.html','utf8'),/https:\/\/cdnjs\.cloudflare\.com\/ajax\/libs\/qrcodejs/);
});
test('local QR library paints an enrollment URI without any network request',()=>{
 const paints=[],context={fillRect(){paints.push(this.fillStyle);},strokeRect(){},clearRect(){}};
 const elements=[],document={documentElement:{tagName:'HTML'},createElement:name=>{const e={tagName:name,style:{},getContext:()=>context};Object.defineProperty(e,'src',{set:value=>{assert.ok(value.startsWith('data:'),'QR rendering must stay local');}});elements.push(e);return e;}};
 const browser={document,navigator:{userAgent:'test-browser'},window:{devicePixelRatio:1},CanvasRenderingContext2D:function(){},fetch:()=>assert.fail('No external request')};
 vm.runInNewContext(code,browser);
 const target={appendChild(){}};
 const qr=new browser.QRCode(target,{text:'otpauth://totp/CVEHarbor:synthetic%40example.invalid?secret=JBSWY3DPEHPK3PXP&issuer=CVEHarbor&algorithm=SHA1&digits=6&period=30',width:196,height:196,colorDark:'#071624',colorLight:'#ffffff',correctLevel:browser.QRCode.CorrectLevel.M});
 assert.ok(qr._oQRCode.getModuleCount()>=21);assert.ok(paints.includes('#071624'));assert.ok(paints.includes('#ffffff'));assert.ok(paints.length>400);
 assert.equal(elements.find(e=>e.tagName==='canvas').width,196);
});
test('existing staging CSP permits the local script without adding a CDN origin',async()=>{
 const front=createFrontend(async()=>true);
 const response=await front.fetch(new Request(TARGET.origin+'/assets/vendor/qrcodejs-1.0.0.min.js'),{ASSETS:{fetch:async()=>new Response(code,{headers:{'Content-Type':'text/javascript'}})}});
 assert.equal(response.status,200);const csp=response.headers.get('Content-Security-Policy');assert.match(csp,/script-src 'self' 'unsafe-inline'/);assert.doesNotMatch(csp,/cdnjs|https:/);assert.equal(await response.text(),code);
});
