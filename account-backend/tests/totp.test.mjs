import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {totp,verifyTotp,encryptSecret,decryptSecret,newSecret,newRecoveryCodes,hashRecovery} from '../src/totp.js';
globalThis.crypto ||= webcrypto;
test('TOTP RFC 6238 SHA1 known vector truncated to six digits',async()=>{
 const secret='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
 assert.equal(await totp(secret,59000),'287082');
 assert.equal(await verifyTotp(secret,'287082',59000),1);
 assert.equal(await verifyTotp(secret,'000000',59000),-1);
});
test('TOTP secret encryption binds to user and decrypts',async()=>{
 const env={TOTP_ENCRYPTION_KEY:'test-configuration-secret-never-use-in-production'};
 const secret=newSecret();
 const cipher=await encryptSecret(env,secret,'user-one');
 assert.notEqual(cipher,secret);
 assert.equal(await decryptSecret(env,cipher,'user-one'),secret);
 await assert.rejects(decryptSecret(env,cipher,'user-two'));
});
test('recovery codes have unique stable per-user hashes',async()=>{
 const codes=newRecoveryCodes();
 assert.equal(codes.length,8);
 assert.equal(new Set(codes).size,8);
 assert.ok(codes.every(code=>/^[a-f0-9]{16}$/.test(code)));
 assert.notEqual(await hashRecovery(codes[0],'user-one'),await hashRecovery(codes[0],'user-two'));
});
