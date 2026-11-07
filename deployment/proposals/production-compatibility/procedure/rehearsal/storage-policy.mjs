// Explicit operator evidence, not an OS inspection or proof of owner approval.
import assert from 'node:assert/strict';
export const diskException='pr270-owner-test-data-no-full-disk-encryption-2026-11-06';
export const custodyException='pr270-owner-test-data-online-d-drive-custody-2026-11-06';
export function verifyStorage(p,destination){
 assert.equal(p?.version,1,'Storage evidence required');
 assert.equal(p.destination,destination,'Storage evidence target');
 assert.equal(p.disk_encryption_status,'unverified','Never claim disk encryption verified under this exception');
 assert.equal(p.disk_encryption_owner_exception,diskException);
 assert.equal(p.scope,'pr270-test-data-rehearsal-on-owner-pc');
 for(const k of ['owner_only_acl_verified','sync_exclusion_verified','ordinary_sharing_exclusion_verified','trusted_administrative_access_confirmed','capacity_verified','encrypted_packages_required','temporary_plaintext_inventory_required','key_acl_verified','key_sync_and_sharing_exclusion_verified','passphrase_separate_custody_confirmed','recipient_roundtrip_verified'])assert.equal(p[k],true,`Missing storage prerequisite: ${k}`);
 assert.equal(p.key_custody_owner_exception,custodyException);
 assert.equal(p.key_directory,'D:\\CVEHarbor-Recovery-Keys\\pr270');
 assert.equal(p.key_custody,'passphrase-encrypted-online-same-pc');
 assert.equal(p.offline_key_custody_verified,false);
 assert.equal(p.independent_custody_copy_verified,false);
 assert.match(p.recipient_fingerprint_sha256||'',/^[a-f0-9]{64}$/);
 assert.match(p.private_evidence_sha256||'',/^[a-f0-9]{64}$/);
 return p;
}
