param([string]$OutputDirectory=(Join-Path $PSScriptRoot 'dist'))
$ErrorActionPreference='Stop'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (!(Test-Path -LiteralPath $compiler)) { throw 'Windows .NET Framework compiler required.' }
$null=New-Item -ItemType Directory -Force -Path $OutputDirectory
& $compiler /nologo /target:library /platform:x64 /optimize+ /warnaserror+ "/out:$OutputDirectory\CVEHarbor.Agent.dll" /reference:System.Net.Http.dll /reference:System.Security.dll /reference:System.Management.dll /reference:System.Web.Extensions.dll /reference:System.Core.dll "$PSScriptRoot\Agent.cs" "$PSScriptRoot\AssemblyInfo.cs" "$PSScriptRoot\..\collector-app\Inventory.cs"
if ($LASTEXITCODE -ne 0) { throw 'Agent compilation failed.' }
foreach ($target in @(@{Name='CVEHarbor-Agent';Source='Service';Gui=$false;Admin=$false},@{Name='CVEHarbor-Agent-Setup';Source='Setup';Gui=$true;Admin=$true},@{Name='CVEHarbor-Agent-Enroll';Source='EnrollConsole';Gui=$false;Admin=$true})) {
 $options=@('/nologo','/platform:x64','/optimize+','/warnaserror+',"/out:$OutputDirectory\$($target.Name).exe",'/reference:System.ServiceProcess.dll','/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll',"/reference:$OutputDirectory\CVEHarbor.Agent.dll")
 if($target.Gui){$options+='/target:winexe'}else{$options+='/target:exe'}
 if($target.Admin){$options+="/win32manifest:$PSScriptRoot\setup.manifest"}
 & $compiler @options "$PSScriptRoot\$($target.Source).cs" "$PSScriptRoot\AssemblyInfo.cs"
 if ($LASTEXITCODE -ne 0) { throw "Failed to compile $($target.Name)" }
 '<configuration><startup><supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.8" /></startup><runtime><loadFromRemoteSources enabled="false" /></runtime></configuration>' | Set-Content -LiteralPath (Join-Path $OutputDirectory ($target.Name+'.exe.config')) -Encoding UTF8
}
Write-Output 'Built Windows Agent binaries. Trusted publisher signing is required before distribution.'
