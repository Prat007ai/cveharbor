# Run only in an owner-visible local console. Never redirect input, use transcripts,
# put a passphrase in arguments/environment, or run through a captured agent PTY.
# Creates new encrypted keys only; no overwrite, deletion, export or cloud operation.
$ErrorActionPreference = 'Stop'
# A GUI child may inherit PowerShell 7 module paths while running Windows PS 5.1.
# Resolve only this host's built-in modules for this process; no persistent change.
$env:PSModulePath = Join-Path $PSHOME 'Modules'
$openssl = 'C:\CVEHarbor-Recovery\tools\OpenSSL-4.1.0\bin\openssl.exe'
$keyRoot = 'D:\CVEHarbor-Recovery-Keys\pr270'
$publicRoot = 'C:\CVEHarbor-Recovery\custody'
$evidenceRoot = 'C:\CVEHarbor-Recovery\preparation'
function CheckExit { if ($LASTEXITCODE -ne 0) { throw 'OpenSSL failed; preserve files and reconcile. Do not rerun automatically.' } }
$stage = 'software-and-folder-preflight'
try {
    if ((Get-FileHash $openssl -Algorithm SHA256).Hash.ToLower() -ne '266a8a13497bc8cb545cc57fff6f798544b6a6d646e1baf7ceb2f5ea1cbba022') { throw 'OpenSSL pin mismatch' }
    if ((Get-AuthenticodeSignature $openssl).Status -ne 'Valid') { throw 'OpenSSL signature invalid' }
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($directory in @($keyRoot,$publicRoot,$evidenceRoot)) {
        $item = Get-Item -LiteralPath $directory
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'No linked storage' }
        $acl = Get-Acl -LiteralPath $directory
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -eq 'Allow' -and $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -ne $sid) { throw 'Unexpected ACL principal' }
        }
    }
    $stage = 'new-file-preflight'
    $key = Join-Path $keyRoot 'recipient-key.encrypted.pem'
    $cert = Join-Path $publicRoot 'recipient-cert.pem'
    $receipt = Join-Path $evidenceRoot 'recipient-verification.json'
    $plain = Join-Path $evidenceRoot 'fictional-roundtrip.txt'
    $cipher = Join-Path $evidenceRoot 'fictional-roundtrip.cms'
    $restored = Join-Path $evidenceRoot 'fictional-roundtrip-restored.txt'
    foreach ($file in @($key,$cert,$receipt,$plain,$cipher,$restored)) { if (Test-Path -LiteralPath $file) { throw 'Existing setup evidence; stop for reconciliation' } }
    'Preflight passed; waiting for owner passphrase input.' | Set-Content (Join-Path $evidenceRoot 'owner-console-status.txt')
    Write-Host 'Create a strong UNIQUE recovery-key passphrase. Store it outside both recovery folders, preferably in your password manager.'
    Write-Host 'Enter it only at the OpenSSL prompts below. It will not be displayed or recorded by this script.'
    $stage = 'encrypted-key-generation'
    & $openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -aes-256-cbc -out $key
    CheckExit
    $stage = 'public-certificate-generation'
    & $openssl req -config 'C:\CVEHarbor-Recovery\tools\OpenSSL-4.1.0\config\openssl.cnf' -new -x509 -key $key -sha256 -days 365 -subj '/CN=CVEHarbor PR270 Test Data Recovery/' -addext 'keyUsage=critical,keyEncipherment' -out $cert
    CheckExit
    $stage = 'fictional-roundtrip'
    [System.IO.File]::WriteAllText($plain,'CVEHarbor PR270 fictional encryption roundtrip only.')
    & $openssl cms -encrypt -binary -aes-256-gcm -outform DER -in $plain -out $cipher -recip $cert -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256 -keyopt rsa_mgf1_md:sha256
    CheckExit
    & $openssl cms -decrypt -binary -inform DER -in $cipher -recip $cert -inkey $key -out $restored
    CheckExit
    if ((Get-FileHash $plain).Hash -ne (Get-FileHash $restored).Hash) { throw 'Roundtrip mismatch' }
    $fp = & $openssl x509 -in $cert -noout -fingerprint -sha256
    CheckExit
    if ($fp -notmatch '=([0-9A-Fa-f:]+)$') { throw 'Fingerprint unavailable' }
    $fingerprint = $Matches[1].Replace(':','').ToLower()
    $confirm = Read-Host 'Passphrase saved separately from the PC recovery folders, and D:\CVEHarbor-Recovery-Keys excluded from sync/backup/ordinary sharing with trusted admins only? Type YES'
    if ($confirm -cne 'YES') { throw 'Custody confirmation incomplete; preserve files and stop' }
    @{
        checked_at_utc=[DateTime]::UtcNow.ToString('o'); recipient_fingerprint_sha256=$fingerprint
        key_encrypted=$true; recipient_roundtrip_verified=$true; passphrase_separate_custody_confirmed=$true
        key_sync_and_sharing_exclusion_owner_attested=$true
        key_custody='passphrase-encrypted-online-same-pc'; offline_key_custody_verified=$false
        independent_custody_copy_verified=$false; disk_encryption_status='unverified'
        temporary_plaintext=@($plain,$restored); plaintext_deleted=$false; production_data_used=$false
    } | ConvertTo-Json | Set-Content -LiteralPath $receipt -Encoding UTF8
    Write-Host 'Setup passed. Only the public fingerprint and verification receipt may be reported. No private key or passphrase.'
    Write-Host ('Public certificate fingerprint: '+$fingerprint)
} catch {
    Write-Host 'STOP: setup incomplete. Preserve files; ask Codex to reconcile metadata. No automatic retry or cleanup.' -ForegroundColor Red
    Write-Host ('Failed stage: '+$stage+'; script line: '+$_.InvocationInfo.ScriptLineNumber+'; category: '+$_.CategoryInfo.Category)
    if($stage -eq 'software-and-folder-preflight') { [System.IO.File]::WriteAllText((Join-Path $evidenceRoot 'owner-preflight-error.txt'),$_.Exception.Message) }
}
Read-Host 'Press Enter to close this owner-only console'
