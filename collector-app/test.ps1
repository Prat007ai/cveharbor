$ErrorActionPreference='Stop'
Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' | ForEach-Object {
    $tokens=$null; $parseErrors=$null
    $null=[System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$parseErrors)
    if ($parseErrors.Count) { throw $parseErrors[0] }
}
$exe=Join-Path $PSScriptRoot 'dist/CVEHarbor-Collector.exe'
$test=Start-Process -FilePath $exe -ArgumentList '--self-test verification' -WindowStyle Hidden -PassThru -Wait
if ($test.ExitCode -ne 0) { Get-Content verification/test-failure.txt; throw 'Collector tests failed' }
Get-Content verification/test-results.txt
