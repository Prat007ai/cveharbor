$ErrorActionPreference='Stop'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$out=Join-Path $PSScriptRoot 'dist'
& $compiler /nologo /target:exe /platform:x64 /warnaserror+ "/out:$out\AgentSelfTest.exe" "/reference:$out\CVEHarbor.Agent.dll" "$PSScriptRoot\SelfTest.cs"
if($LASTEXITCODE -ne 0){throw 'Agent self-test compilation failed'}
& (Join-Path $out 'AgentSelfTest.exe') (Join-Path $out 'fictional-payload.json')
if($LASTEXITCODE -ne 0){throw 'Agent self-test failed'}
& node (Join-Path $PSScriptRoot 'test-contract.mjs')
if($LASTEXITCODE -ne 0){throw 'Agent/backend contract failed'}
