// Public-key encryption only. The runner never receives a private recovery key.
import fs from 'node:fs';
import {X509Certificate,createHash,verify} from 'node:crypto';
import {spawnSync} from 'node:child_process';
export const hash=x=>createHash('sha256').update(x).digest('hex');
export function requireThat(ok,category){if(!ok)throw Error(category);}
export function certificate(pem,fingerprint,now=Date.now()){
 const cert=new X509Certificate(pem),key=cert.publicKey;
 requireThat(cert.fingerprint256.replaceAll(':','').toLowerCase()===fingerprint,'recipient_fingerprint');
 requireThat(key.asymmetricKeyType==='rsa'&&key.asymmetricKeyDetails.modulusLength>=3072,'recipient_strength');
 requireThat(Date.parse(cert.validFrom)<=now&&Date.parse(cert.validTo)>now,'recipient_validity');return cert;
}
export function encrypt(source,destination,pem,fingerprint,dir){
 certificate(pem,fingerprint);const cert=dir+'/recipient.pem';fs.writeFileSync(cert,pem,{mode:0o600,flag:'wx'});
 try{const r=spawnSync('openssl',['cms','-encrypt','-binary','-aes-256-gcm','-outform','DER','-in',source,'-out',destination,'-recip',cert,'-keyopt','rsa_padding_mode:oaep','-keyopt','rsa_oaep_md:sha256','-keyopt','rsa_mgf1_md:sha256'],{env:{PATH:process.env.PATH,HOME:dir,TMPDIR:dir},stdio:'pipe',timeout:30000});requireThat(r.status===0&&r.signal===null&&fs.statSync(destination).size>0,'encryption_failed');fs.chmodSync(destination,0o600);}finally{fs.rmSync(cert,{force:true});}
}
export function verifyReceipt(receipt,signature,pem,fingerprint,expected,now=Date.now()){
 const cert=certificate(pem,fingerprint,now);
 requireThat(verify('sha256',Buffer.from(receipt),cert.publicKey,Buffer.from(signature,'base64')),'receipt_signature');
 const p=JSON.parse(receipt);requireThat(p&&p.format===1&&p.kind==='offline-recovery-restore'&&p.status==='passed'&&p.checkpoint===29&&p.restore_integrity===true&&p.decrypted===true,'receipt_shape');
 for(const [k,v]of Object.entries(expected))requireThat(p[k]===v,'receipt_binding');
 requireThat(Number.isFinite(Date.parse(p.verified_at))&&now-Date.parse(p.verified_at)>=0&&now-Date.parse(p.verified_at)<=3600000,'receipt_expired');return p;
}
