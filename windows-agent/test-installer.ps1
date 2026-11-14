param([Parameter(Mandatory=$true)][string]$Installer,[Parameter(Mandatory=$true)][string]$UpgradeInstaller)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Installer mutation tests run only on an isolated GitHub-hosted Windows runner.'}
if(Get-Service -Name CVEHarborAgent -ErrorAction SilentlyContinue){throw 'Refusing to replace an existing service.'}
$Installer=(Resolve-Path -LiteralPath $Installer).Path;$UpgradeInstaller=(Resolve-Path -LiteralPath $UpgradeInstaller).Path
$log=Join-Path $env:RUNNER_TEMP 'agent-install.log'
function Msi([string]$operation,[string]$file,[int[]]$expected=@(0,3010)){
 $p=Start-Process -FilePath (Join-Path $env:WINDIR 'System32/msiexec.exe') -ArgumentList @($operation,('"'+$file+'"'),'/qn','/norestart','/l*v',('"'+$log+'"')) -WindowStyle Hidden -Wait -PassThru
 if($expected -notcontains $p.ExitCode){Get-Content -LiteralPath $log -Tail 100;throw "Installer exit $($p.ExitCode)"}
}
try{
 Msi '/i' $Installer
 $service=Get-CimInstance Win32_Service -Filter "Name='CVEHarborAgent'"
 if($service.StartName -ne 'NT AUTHORITY\LocalService' -or $service.State -ne 'Running'){throw 'Service must run under LocalService.'}
 if($service.PathName -notmatch '^".*CVEHarbor-Agent.exe"$'){throw 'Service executable path must be quoted.'}
 $root=Join-Path $env:ProgramData 'CVEHarborAgent'
 $acl=Get-Acl -LiteralPath $root
 if(!$acl.AreAccessRulesProtected){throw 'Private state must not inherit broad access.'}
 if($acl.Access | Where-Object {$_.IdentityReference.Value -match 'Everyone|Authenticated Users|BUILTIN\\Users|LOCAL SERVICE'}){throw 'Private state has an overbroad ACL.'}
 Set-Content -LiteralPath (Join-Path $root 'pending.bin') -Value 'Fictional upgrade-retention sentinel'
 Msi '/i' $UpgradeInstaller
 if(!(Test-Path -LiteralPath (Join-Path $root 'pending.bin'))){throw 'Upgrade lost the bounded local queue.'}
 Msi '/i' $Installer @(1603)
 Msi '/x' $UpgradeInstaller
 if(Get-Service -Name CVEHarborAgent -ErrorAction SilentlyContinue){throw 'Service remained after uninstall.'}
 if(Test-Path -LiteralPath (Join-Path $root 'pending.bin')){throw 'Uninstall retained device state.'}
 Write-Output 'Install, least-privilege service, private state, upgrade retention, downgrade rejection and uninstall passed.'
}finally{
 if(Get-Service -Name CVEHarborAgent -ErrorAction SilentlyContinue){Msi '/x' $UpgradeInstaller @(0,1605,3010);Msi '/x' $Installer @(0,1605,3010)}
}
