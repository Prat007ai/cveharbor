$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot
$scriptPath=Join-Path $root 'collectors/Export-CVEHarborInventory.ps1'
$temp=Join-Path ([IO.Path]::GetTempPath()) ('cveharbor-fictional-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
$fixture=Join-Path $temp 'fixture.json'
$products=@(
 @{DisplayName='Microsoft .NET Runtime - 8.0.1 (x64)';DisplayVersion='8.0.1';Publisher='Microsoft';InstallDate='20260101'},
 @{DisplayName='Microsoft .NET Runtime - 8.0.1 (x86)';DisplayVersion='8.0.1';Publisher='Microsoft'},
 @{DisplayName='Microsoft .NET Runtime - 8.0.2 (x64)';DisplayVersion='8.0.2';Publisher='Microsoft'},
 @{DisplayName='=unsafe spreadsheet value';DisplayVersion='1.2';Publisher='Fictional'},
 @{DisplayName='Unknown Product';DisplayVersion='';Publisher='Fictional'}
)
1..402 | ForEach-Object {$products+=@{DisplayName=('Fictional Software '+$_);DisplayVersion='1.2.3';Publisher=('Example, "Testing" '+('X'*300))}}
@{products=$products;technologies=@(@{name='Windows Server';version='10.0.20348.1'})}|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $fixture -Encoding UTF8
$out=Join-Path $temp 'export'
& $scriptPath -FixturePath $fixture -AssetName 'NORTHSTAR-DEMO01' -OutputDirectory $out
$report=Get-Content (Join-Path $out 'collection-report.json') -Raw|ConvertFrom-Json
if(!$report.fixture_mode -or $report.entries -ne 407){throw 'Unexpected fixture entry count.'}
$all=@()
foreach($name in $report.files){
 $path=Join-Path $out $name;$bytes=[IO.File]::ReadAllBytes($path)
 if($bytes.Length -gt 131072 -or $bytes[0] -ne 239 -or $bytes[1] -ne 187 -or $bytes[2] -ne 191){throw 'Invalid CSV encoding/size.'}
 $rows=@(Import-Csv -LiteralPath $path)
 if($rows.Count -gt 200){throw 'CSV row limit exceeded.'}
 if(($rows[0].PSObject.Properties.Name -join ',') -ne 'Asset Name,Asset Type,Technology,Version,Notes'){throw 'CSV header mismatch.'}
 $all+=$rows
}
if(@($all|Where-Object Technology -eq '.NET Runtime').Count -ne 2){throw 'Side-by-side runtime versions lost or duplicates retained.'}
if(!($all|Where-Object Technology -eq "'=unsafe spreadsheet value")){throw 'Spreadsheet formula protection missing.'}
if(!$report.warnings.Count){throw 'Missing version warning absent.'}
$blocked=$false;try{& $scriptPath -FixturePath $fixture -AssetName 'NORTHSTAR-DEMO01' -OutputDirectory $out}catch{$blocked=$true}
if(!$blocked){throw 'Existing export could be overwritten.'}
Write-Output 'PASS: fictional collector export, exact headers, distinct versions, duplicate handling, formula protection, UTF8, row/byte splitting and overwrite refusal.'
