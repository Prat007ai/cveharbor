param([string]$OutputDirectory=(Join-Path $PSScriptRoot 'dist'))
$ErrorActionPreference='Stop'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (!(Test-Path -LiteralPath $compiler)) { throw 'Windows .NET Framework compiler required.' }
$null=New-Item -ItemType Directory -Force -Path $OutputDirectory
$exe=Join-Path $OutputDirectory 'CVEHarbor-Collector.exe'
& $compiler /nologo /target:winexe /platform:x64 /optimize+ "/out:$exe" "/win32manifest:$PSScriptRoot\app.manifest" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Management.dll /reference:System.Web.Extensions.dll /reference:System.Core.dll "$PSScriptRoot\Inventory.cs" "$PSScriptRoot\App.cs" "$PSScriptRoot\SelfTest.cs"
if ($LASTEXITCODE -ne 0) { throw 'Collector compilation failed.' }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'CVEHarbor-Collector.exe.config') -Destination $OutputDirectory
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.txt') -Destination $OutputDirectory
Get-FileHash -Algorithm SHA256 -LiteralPath $exe | ForEach-Object { $_.Hash.ToLowerInvariant()+'  CVEHarbor-Collector.exe' } | Set-Content -LiteralPath (Join-Path $OutputDirectory 'SHA256SUMS.txt') -Encoding ASCII
Write-Output "Built $exe"
