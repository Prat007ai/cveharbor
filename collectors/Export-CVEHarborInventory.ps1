#Requires -Version 5.1
<#
.SYNOPSIS
Read Windows inventory and export CVEHarbor onboarding CSV files locally.
.DESCRIPTION
No network requests, installs, repairs, execution-policy changes or automatic uploads.
Reads the OS, Programs and Features registry records, .NET Framework and .NET folders.
Use a separate run per server. See README.txt for coverage and import limitations.
#>
[CmdletBinding()]
param(
    [string]$AssetName = $env:COMPUTERNAME,
    [ValidateSet('Web','Database','Application','Active Directory','File','Print','Remote Desktop','Other')]
    [string[]]$ServerRole = @(),
    [string]$OutputDirectory = (Join-Path (Get-Location) ('CVEHarbor-Inventory-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8))),
    [string[]]$DotNetRoot = @(),
    # Offline fixture mode for testing the exporter; never inventories this machine.
    [string]$FixturePath
)
$ErrorActionPreference = 'Stop'
$rows = New-Object 'System.Collections.Generic.List[object]'
$warnings = New-Object 'System.Collections.Generic.List[string]'
$collected = [DateTime]::UtcNow.ToString('o')
$network = $null
if ([string]::IsNullOrWhiteSpace($AssetName) -or $AssetName.Length -gt 120 -or $AssetName -match '[\x00-\x1f\x7f]') { throw 'Provide an asset name of 1 to 120 characters without control characters.' }
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Choose a new output directory. Existing files are never overwritten.' }
function Safe-Cell([string]$Value) {
    $Value = ($Value -replace '[\x00-\x1f\x7f]', ' ').Trim()
    if ($Value -match '^[=+@-]') { return "'" + $Value }
    return $Value
}
function Add-Product([string]$Name, [string]$Version, [string]$Details) {
    $Name = Safe-Cell $Name; $Version = Safe-Cell $Version; $Details = Safe-Cell $Details
    if (!$Name) { return }
    if ($Name.Length -gt 120 -or $Version.Length -gt 80) { $warnings.Add('Skipped an overlong product name or version. Review source inventory manually.'); return }
    if (!$Version) { $warnings.Add('Version unavailable: ' + $Name) }
    if ($ServerRole.Count) { $Details = 'Server role: ' + (($ServerRole | Select-Object -Unique) -join ' / ') + '; ' + $Details }
    if ($Details.Length -gt 500) { $Details = $Details.Substring(0,500) }
    $rows.Add([pscustomobject][ordered]@{'Asset Name'=(Safe-Cell $AssetName); 'Asset Type'='Server'; Technology=$Name; Version=$Version; Notes=$Details})
}
$safeAssetName = Safe-Cell $AssetName
if ($safeAssetName.Length -gt 120) { throw 'Escaped asset name exceeds 120 characters. Choose a shorter asset name.' }
function Add-InstalledProduct($Product, [string]$Source) {
    if (!$Product.DisplayName) { return }
    $name = [string]$Product.DisplayName; $version = [string]$Product.DisplayVersion
    # Only explicit Microsoft installer names are normalized. Other products retain their identity.
    if ($name -match '^Microsoft (?:\.NET|\.NET Core) Runtime - ([0-9.]+)(?: \((x64|x86|arm64)\))?$') { $name='.NET Runtime'; $version=$Matches[1] }
    elseif ($name -match '^Microsoft (?:ASP\.NET Core|\.NET) (?:Windows )?Desktop Runtime - ([0-9.]+)(?: \((x64|x86|arm64)\))?$') { $name='.NET Desktop Runtime'; $version=$Matches[1] }
    elseif ($name -match '^Microsoft ASP\.NET Core ([0-9.]+) - Shared Framework(?: \((x64|x86|arm64)\))?$') { $name='ASP.NET Core Runtime'; $version=$Matches[1] }
    elseif ($name -match '^Microsoft \.NET SDK ([0-9.]+)(?: \((x64|x86|arm64)\))?$') { $name='.NET SDK'; $version=$Matches[1] }
    $details = 'Publisher: ' + $Product.Publisher + '; source: ' + $Source + '; installed: ' + $Product.InstallDate + '; collected UTC: ' + $collected
    Add-Product $name $version $details
}
if ($FixturePath) {
    $fixture = Get-Content -LiteralPath $FixturePath -Raw | ConvertFrom-Json
    $network = $fixture.network
    foreach ($p in $fixture.products) { Add-InstalledProduct $p 'Fictional fixture' }
    foreach ($p in $fixture.technologies) { Add-Product $p.name $p.version 'Fictional fixture' }
} else {
    if ($env:OS -ne 'Windows_NT') { throw 'This collector supports Windows only.' }
    try {
        # Reads local configuration only. No ping, DNS lookup, external IP lookup or port scan.
        $adapters = @(Get-NetAdapter -IncludeHidden)
        $addresses = @(Get-NetIPAddress)
        $interfaces = @(Get-NetIPInterface)
        $routes = @(Get-NetRoute | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') })
        $candidates = @()
        $adapterRows = @($adapters | ForEach-Object {
            $a = $_
            $adapterId = [string]$a.InterfaceGuid
            if (!$adapterId) { $adapterId = 'index-' + $a.ifIndex }
            $ips = @($addresses | Where-Object { $_.InterfaceIndex -eq $a.ifIndex } | ForEach-Object {
                $p = $_
                $ip = ([string]$p.IPAddress -split '%')[0]
                $family = if ($ip.Contains(':')) {'IPv6'} else {'IPv4'}
                if ($a.Status -eq 'Up' -and $p.AddressState -eq 'Preferred' -and !$p.SkipAsSource -and $ip -notmatch '^(127\.|169\.254\.|0\.|fe80:|::1$|::$)') {
                    foreach ($r in @($routes | Where-Object { $_.InterfaceIndex -eq $a.ifIndex -and [string]$_.AddressFamily -eq $family })) {
                        $i = $interfaces | Where-Object { $_.InterfaceIndex -eq $a.ifIndex -and [string]$_.AddressFamily -eq $family } | Select-Object -First 1
                        $script:candidates += [pscustomobject]@{adapter_id=$adapterId;ip=$ip;family=$family;metric=([int]$r.RouteMetric+[int]$i.InterfaceMetric)}
                    }
                }
                [pscustomobject]@{ip=$ip;prefix=[int]$p.PrefixLength;state=[string]$p.AddressState;skip_source=[bool]$p.SkipAsSource}
            })
            [pscustomobject]@{id=$adapterId;name=[string]$a.Name;status=[string]$a.Status;addresses=$ips}
        })
        # A default route is a suggestion, not proof of the customer's management network.
        $preferred = @($candidates | Where-Object {$_.family -eq 'IPv4'})
        if (!$preferred.Count) { $preferred = @($candidates) }
        $suggested = $null
        if ($preferred.Count) {
            $minimum = ($preferred | Measure-Object metric -Minimum).Minimum
            $best = @($preferred | Where-Object {$_.metric -eq $minimum} | Sort-Object adapter_id,ip -Unique)
            if ($best.Count -eq 1) { $suggested = @{adapter_id=$best[0].adapter_id;ip=$best[0].ip} }
        }
        if ($adapterRows.Count) { $network = [ordered]@{version=1;collected_at=$collected;adapters=$adapterRows;suggested=$suggested} }
    } catch { $warnings.Add('Network configuration could not be collected: '+$_.Exception.GetType().Name) }
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $tech = if ($os.Caption -match 'Windows Server') {'Windows Server'} else {'Windows'}
        $build = [string]$os.Version
        if ($null -ne $cv.UBR) { $build += '.' + $cv.UBR }
        Add-Product $tech $build ('Edition: '+$os.Caption+'; display version: '+$cv.DisplayVersion+'; architecture: '+$os.OSArchitecture+'; collected UTC: '+$collected)
    } catch { $warnings.Add('Operating system collection incomplete: ' + $_.Exception.GetType().Name) }
    foreach ($hive in @('LocalMachine','CurrentUser')) {
        foreach ($view in @('Registry64','Registry32')) {
            $base=$null; $uninstall=$null
            try {
                $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$hive,[Microsoft.Win32.RegistryView]::$view)
                $uninstall=$base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
                if ($uninstall) { foreach ($sub in $uninstall.GetSubKeyNames()) {
                    $entry=$null
                    try {
                        $entry=$uninstall.OpenSubKey($sub)
                        if ($entry) {
                            Add-InstalledProduct ([pscustomobject]@{DisplayName=$entry.GetValue('DisplayName');DisplayVersion=$entry.GetValue('DisplayVersion');Publisher=$entry.GetValue('Publisher');InstallDate=$entry.GetValue('InstallDate')}) ($hive+'/'+$view+' Programs and Features records')
                        }
                    } catch { $warnings.Add('An installed-software record could not be read in '+$hive+'/'+$view) }
                    finally { if ($entry) {$entry.Dispose()} }
                }}
            } catch { $warnings.Add('Installed-software registry view unavailable: '+$hive+'/'+$view) }
            finally { if ($uninstall) {$uninstall.Dispose()}; if ($base) {$base.Dispose()} }
        }
    }
    try {
        $ndp='HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP'
        if (Test-Path -LiteralPath $ndp) {
            $fullRelease = (Get-ItemProperty -LiteralPath ($ndp+'\v4\Full') -ErrorAction SilentlyContinue).Release
            foreach ($key in Get-ChildItem -LiteralPath $ndp -Recurse) {
                $p=Get-ItemProperty -LiteralPath $key.PSPath
                if ($p.Release -and $key.PSChildName -eq 'Full') {
                    $release=[int]$p.Release
                    $v = if($release -ge 533320){'4.8.1'}elseif($release -ge 528040){'4.8'}elseif($release -ge 461808){'4.7.2'}elseif($release -ge 461308){'4.7.1'}elseif($release -ge 460798){'4.7'}elseif($release -ge 394802){'4.6.2'}elseif($release -ge 394254){'4.6.1'}elseif($release -ge 393295){'4.6'}elseif($release -ge 379893){'4.5.2'}elseif($release -ge 378675){'4.5.1'}elseif($release -ge 378389){'4.5'}else{''}
                    Add-Product '.NET Framework' $v ('Registry release: '+$release+'; framework family, not a Windows patch-level assessment; collected UTC: '+$collected)
                } elseif ($p.Install -eq 1 -and $p.Version -and !$p.Release) {
                    # 4.5+ replaces v4 in place; Client/locale CLR values are not separate 4.0 installations.
                    if ($fullRelease -and $key.Name -match '\\v4\\') { continue }
                    if ($key.PSChildName -match '^\d+$') { continue }
                    Add-Product '.NET Framework' ([string]$p.Version) ('Framework registry version; collected UTC: '+$collected)
                }
            }
        }
    } catch { $warnings.Add('.NET Framework inventory may be incomplete: '+$_.Exception.GetType().Name) }
    $roots=@($DotNetRoot)
    foreach ($dir in @($env:ProgramW6432,$env:ProgramFiles,${env:ProgramFiles(x86)})) { if ($dir) { $roots += Join-Path $dir 'dotnet' } }
    if ($env:USERPROFILE) { $roots += Join-Path $env:USERPROFILE '.dotnet' }
    if ($env:DOTNET_ROOT) { $roots += $env:DOTNET_ROOT }
    foreach ($rootPath in ($roots | Where-Object {$_} | Select-Object -Unique)) {
        if ($rootPath -match '^\\\\') { $warnings.Add('Network .NET path skipped; only local inventory is collected.'); continue }
        foreach ($component in @(@('shared\Microsoft.NETCore.App','.NET Runtime'),@('shared\Microsoft.AspNetCore.App','ASP.NET Core Runtime'),@('shared\Microsoft.WindowsDesktop.App','.NET Desktop Runtime'),@('sdk','.NET SDK'))) {
            try {
                $folder=Join-Path $rootPath $component[0]
                if (Test-Path -LiteralPath $folder) {
                    foreach ($versionDir in Get-ChildItem -LiteralPath $folder -Directory) {
                        if ($versionDir.Name -match '^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$') {
                            Add-Product $component[1] $versionDir.Name ('Discovered .NET installation directory; verify active usage; collected UTC: '+$collected)
                        }
                    }
                }
            } catch { $warnings.Add('A .NET installation directory could not be read.') }
        }
    }
    try {
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\InetStp') {
            $iis=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp'
            if ($null -ne $iis.MajorVersion) { Add-Product 'IIS' ($iis.MajorVersion.ToString()+'.'+$iis.MinorVersion) 'IIS version; Windows build/patch evidence is also required.' }
        }
    } catch { $warnings.Add('IIS version could not be read.') }
}
# Preserve side-by-side versions. Merge identical entries from multiple registry views.
$unique=@{};foreach($row in $rows){$id=($row.'Asset Name',$row.'Asset Type',$row.Technology,$row.Version -join "`0").ToLowerInvariant();if(!$unique.ContainsKey($id)){$unique[$id]=$row}}
$ordered=@($unique.Values | Sort-Object Technology,Version)
$networkJson = ''
if ($network) {
    $networkJson = $network | ConvertTo-Json -Depth 8 -Compress
    $addressCount = @($network.adapters | ForEach-Object {$_.addresses}).Count
    if ($networkJson.Length -gt 14000 -or @($network.adapters).Count -gt 32 -or $addressCount -gt 128 -or @($network.adapters | Where-Object {@($_.addresses).Count -gt 64}).Count) {
        $warnings.Add('Network inventory exceeds import limits (32 adapters / 128 addresses / 14 KB). Review collection-report.json; network data was not included in the CSV.')
        $networkJson = ''
    }
}
foreach ($row in $ordered) { $row | Add-Member -NotePropertyName 'Server Network' -NotePropertyValue $networkJson }
$null=New-Item -ItemType Directory -Path $OutputDirectory
$utf8=New-Object System.Text.UTF8Encoding($true)
$part=1;$batch=New-Object 'System.Collections.Generic.List[object]';$files=New-Object 'System.Collections.Generic.List[string]'
function Save-Batch {
    if(!$batch.Count){return}
    $name='cveharbor-assets-{0:D3}.csv' -f $script:part
    $csv=(@($batch.ToArray() | ConvertTo-Csv -NoTypeInformation) -join "`r`n")+"`r`n"
    [IO.File]::WriteAllText((Join-Path $OutputDirectory $name),$csv,$utf8)
    $files.Add($name);$script:part++;$batch.Clear()
}
foreach($row in $ordered){
    $trial=@($batch.ToArray())+@($row)
    $size=[Text.Encoding]::UTF8.GetByteCount((@($trial | ConvertTo-Csv -NoTypeInformation) -join "`r`n")+"`r`n")+3
    if($batch.Count -ge 200 -or $size -gt 131072){Save-Batch}
    $batch.Add($row)
}
Save-Batch
$report=[ordered]@{collector_version='1.2';network=$network;server_roles=@($ServerRole);collected_utc=$collected;asset_name=(Safe-Cell $AssetName);entries=$ordered.Count;files=@($files.ToArray());warnings=@($warnings.ToArray());coverage=@('Read-only local inventory; no vulnerability or network scan.','Network data is a point-in-time snapshot. Recollect after address changes. Default-route primary is a suggestion; customer choices are preserved.','Programs and Features records: machine 32/64-bit views and the executing user only. Other user profiles and Microsoft Store packages are not enumerated.','Portable software, containers, application-bundled runtimes and nonstandard paths may be missing.','Directory discovery does not prove that a runtime is actively used.','Windows and .NET Framework patch applicability needs vendor/build evidence.','Import is additive. Removed software and superseded versions must be reviewed manually.');fixture_mode=[bool]$FixturePath}
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'collection-report.json'),($report | ConvertTo-Json -Depth 10),$utf8)
Write-Output ('Saved '+$ordered.Count+' inventory entries in '+$files.Count+' CSV file(s) to '+$OutputDirectory)
Write-Output 'Review collection-report.json, then upload each CSV to the selected CVEHarbor customer environment.'
