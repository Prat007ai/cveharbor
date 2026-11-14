param([string]$OutputDirectory=(Join-Path $PSScriptRoot 'package'),[switch]$Production,[string]$PublisherThumbprint,[ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version='1.0.0')
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'dist'
$files=@('CVEHarbor-Agent.exe','CVEHarbor-Agent.exe.config','CVEHarbor.Agent.dll','CVEHarbor-Agent-Setup.exe','CVEHarbor-Agent-Setup.exe.config','CVEHarbor-Agent-Enroll.exe','CVEHarbor-Agent-Enroll.exe.config')
foreach($name in $files){if(!(Test-Path -LiteralPath (Join-Path $source $name))){throw "Build missing: $name"}}
if($Production){
 if($PublisherThumbprint -notmatch '^[a-fA-F0-9]{40}$'){throw 'An approved publisher certificate thumbprint is required.'}
 foreach($name in $files | Where-Object {$_ -match '\.(exe|dll)$'}){
  $signature=Get-AuthenticodeSignature -LiteralPath (Join-Path $source $name)
  if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $PublisherThumbprint -or !$signature.TimeStamperCertificate){throw "Trusted publisher signature and timestamp required: $name"}
 }
}
$null=New-Item -ItemType Directory -Force -Path $OutputDirectory
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
$msi=Join-Path $OutputDirectory 'CVEHarbor-Agent.msi'
if(Test-Path -LiteralPath $msi){throw 'Use a fresh output directory to avoid replacing a reviewed installer.'}
$ddf=@('.OPTION EXPLICIT','.Set CabinetNameTemplate=agent.cab',('.Set DiskDirectoryTemplate="'+$OutputDirectory+'"'),('.Set InfFileName="'+(Join-Path $OutputDirectory 'setup.inf')+'"'),('.Set RptFileName="'+(Join-Path $OutputDirectory 'setup.rpt')+'"'),'.Set CompressionType=LZX','.Set Cabinet=on','.Set Compress=on')
for($i=0;$i -lt $files.Count;$i++){$ddf+=('"'+(Join-Path $source $files[$i])+'" F'+$i)}
$ddfPath=Join-Path $OutputDirectory 'agent.ddf';$ddf | Set-Content -LiteralPath $ddfPath -Encoding ASCII
& (Join-Path $env:WINDIR 'System32/makecab.exe') /F $ddfPath | Out-Null
if($LASTEXITCODE -ne 0){throw 'Cabinet creation failed.'}
function Invoke-Com($object,[string]$name,[object[]]$arguments){
 switch($name){
  'OpenDatabase' {return $object.OpenDatabase([string]$arguments[0],[int]$arguments[1])}
  'OpenView' {return $object.OpenView([string]$arguments[0])}
  'CreateRecord' {return $object.CreateRecord([int]$arguments[0])}
  'Execute' {return $object.Execute($arguments[0])}
  'Close' {return $object.Close()}
  'Commit' {return $object.Commit()}
  'Persist' {return $object.Persist()}
  'SetStream' {return $object.SetStream([int]$arguments[0],[string]$arguments[1])}
  default {throw 'Unsupported MSI build operation'}
 }
}
function Set-Com($object,[string]$name,[object[]]$arguments){
 switch($name){
  'IntegerData' {$object.IntegerData([int]$arguments[0])=[int]$arguments[1]}
  'StringData' {$object.StringData([int]$arguments[0])=[string]$arguments[1]}
  'Property' {$object.Property([int]$arguments[0])=$arguments[1]}
  default {throw 'Unsupported MSI property'}
 }
}
$installer=New-Object -ComObject WindowsInstaller.Installer
$db=Invoke-Com $installer 'OpenDatabase' @($msi,3)
function Exec([string]$sql,[object[]]$values=@()){
 try{$view=Invoke-Com $db 'OpenView' @($sql)}catch{throw ('Invalid MSI build SQL: '+$sql)}
 try{
  $record=$null
  if($values.Count){$record=Invoke-Com $installer 'CreateRecord' @($values.Count);for($i=0;$i -lt $values.Count;$i++){if($null -ne $values[$i]){if($values[$i] -is [int]){Set-Com $record 'IntegerData' @(($i+1),$values[$i])}else{Set-Com $record 'StringData' @(($i+1),[string]$values[$i])}}}}
  Invoke-Com $view 'Execute' @($record)
 }finally{Invoke-Com $view 'Close' @()}
}
function Row([string]$table,[string[]]$columns,[object[]]$values){Exec ('INSERT INTO `'+$table+'` ('+(($columns | ForEach-Object {'`'+$_+'`'}) -join ',')+') VALUES ('+((@('?')*$columns.Count) -join ',')+')') $values}
$schemas=@{
 Property='`Property` CHAR(72) NOT NULL, `Value` CHAR(0) NOT NULL LOCALIZABLE PRIMARY KEY `Property`';
 Directory='`Directory` CHAR(72) NOT NULL, `Directory_Parent` CHAR(72), `DefaultDir` CHAR(255) NOT NULL LOCALIZABLE PRIMARY KEY `Directory`';
 Component='`Component` CHAR(72) NOT NULL, `ComponentId` CHAR(38), `Directory_` CHAR(72) NOT NULL, `Attributes` SHORT NOT NULL, `Condition` CHAR(255), `KeyPath` CHAR(72) PRIMARY KEY `Component`';
 File='`File` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL, `FileName` CHAR(255) NOT NULL LOCALIZABLE, `FileSize` LONG NOT NULL, `Version` CHAR(72), `Language` CHAR(20), `Attributes` SHORT, `Sequence` SHORT NOT NULL PRIMARY KEY `File`';
 Feature='`Feature` CHAR(38) NOT NULL, `Feature_Parent` CHAR(38), `Title` CHAR(64) LOCALIZABLE, `Description` CHAR(255) LOCALIZABLE, `Display` SHORT, `Level` SHORT NOT NULL, `Directory_` CHAR(72), `Attributes` SHORT NOT NULL PRIMARY KEY `Feature`';
 FeatureComponents='`Feature_` CHAR(38) NOT NULL, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Feature_`, `Component_`';
 Media='`DiskId` SHORT NOT NULL, `LastSequence` SHORT NOT NULL, `DiskPrompt` CHAR(64) LOCALIZABLE, `Cabinet` CHAR(255), `VolumeLabel` CHAR(32), `Source` CHAR(72) PRIMARY KEY `DiskId`';
 ServiceInstall='`ServiceInstall` CHAR(72) NOT NULL, `Name` CHAR(255) NOT NULL, `DisplayName` CHAR(255) LOCALIZABLE, `ServiceType` LONG NOT NULL, `StartType` LONG NOT NULL, `ErrorControl` LONG NOT NULL, `LoadOrderGroup` CHAR(255), `Dependencies` CHAR(255), `StartName` CHAR(255), `Password` CHAR(255), `Arguments` CHAR(255), `Component_` CHAR(72) NOT NULL, `Description` CHAR(255) LOCALIZABLE PRIMARY KEY `ServiceInstall`';
 ServiceControl='`ServiceControl` CHAR(72) NOT NULL, `Name` CHAR(255) NOT NULL, `Event` SHORT NOT NULL, `Arguments` CHAR(255), `Wait` SHORT, `Component_` CHAR(72) NOT NULL PRIMARY KEY `ServiceControl`';
 MsiServiceConfig='`MsiServiceConfig` CHAR(72) NOT NULL, `Name` CHAR(255) NOT NULL, `Event` SHORT NOT NULL, `ConfigType` SHORT NOT NULL, `Argument` CHAR(255), `Component_` CHAR(72) NOT NULL PRIMARY KEY `MsiServiceConfig`';
 CreateFolder='`Directory_` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Directory_`, `Component_`';
 MsiLockPermissionsEx='`MsiLockPermissionsEx` CHAR(72) NOT NULL, `LockObject` CHAR(72) NOT NULL, `Table` CHAR(32) NOT NULL, `SDDLText` CHAR(0) NOT NULL, `Condition` CHAR(255) PRIMARY KEY `MsiLockPermissionsEx`';
 Shortcut='`Shortcut` CHAR(72) NOT NULL, `Directory_` CHAR(72) NOT NULL, `Name` CHAR(128) NOT NULL LOCALIZABLE, `Component_` CHAR(72) NOT NULL, `Target` CHAR(72) NOT NULL, `Arguments` CHAR(255), `Description` CHAR(255) LOCALIZABLE, `Hotkey` SHORT, `Icon_` CHAR(72), `IconIndex` SHORT, `ShowCmd` SHORT, `WkDir` CHAR(72) PRIMARY KEY `Shortcut`';
 LaunchCondition='`Condition` CHAR(255) NOT NULL, `Description` CHAR(255) NOT NULL LOCALIZABLE PRIMARY KEY `Condition`';
 AppSearch='`Property` CHAR(72) NOT NULL, `Signature_` CHAR(72) NOT NULL PRIMARY KEY `Property`, `Signature_`';
 Signature='`Signature` CHAR(72) NOT NULL, `FileName` CHAR(255) NOT NULL, `MinVersion` CHAR(20), `MaxVersion` CHAR(20), `MinSize` LONG, `MaxSize` LONG, `MinDate` LONG, `MaxDate` LONG, `Languages` CHAR(255) PRIMARY KEY `Signature`';
 RegLocator='`Signature_` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL, `Name` CHAR(255), `Type` SHORT PRIMARY KEY `Signature_`';
 Upgrade='`UpgradeCode` CHAR(38) NOT NULL, `VersionMin` CHAR(20), `VersionMax` CHAR(20), `Language` CHAR(255), `Attributes` LONG NOT NULL, `Remove` CHAR(255), `ActionProperty` CHAR(72) NOT NULL PRIMARY KEY `UpgradeCode`, `VersionMin`, `VersionMax`, `Language`, `Attributes`';
 RemoveFile='`FileKey` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL, `FileName` CHAR(255) LOCALIZABLE, `DirProperty` CHAR(72) NOT NULL, `InstallMode` SHORT NOT NULL PRIMARY KEY `FileKey`';
 InstallExecuteSequence='`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`';
 InstallUISequence='`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`'
 CustomAction='`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255) PRIMARY KEY `Action`'
}
foreach($entry in $schemas.GetEnumerator()){Exec ('CREATE TABLE `'+$entry.Key+'` ('+$entry.Value+')')}
$upgrade='{DC9D4527-7785-47E8-A170-10268D409A01}'
$properties=@{ProductCode=('{'+[guid]::NewGuid().ToString().ToUpperInvariant()+'}');ProductName='CVEHarbor Windows Agent';ProductVersion=$Version;ProductLanguage='1033';Manufacturer='CVEHarbor';UpgradeCode=$upgrade;ALLUSERS='1';INSTALLLEVEL='1';ARPNOMODIFY='1';ARPNOREPAIR='1';ARPCONTACT='prat.mahen@gmail.com';ARPURLINFOABOUT='https://cveharbor.com';SecureCustomProperties='OLDPRODUCTS;NEWERPRODUCT';MSIRESTARTMANAGERCONTROL='Disable'}
foreach($entry in $properties.GetEnumerator()){Row 'Property' @('Property','Value') @($entry.Key,$entry.Value)}
foreach($r in @(@('TARGETDIR',$null,'SourceDir'),@('ProgramFiles64Folder','TARGETDIR','.'),@('INSTALLDIR','ProgramFiles64Folder','CVEHarbor Agent'),@('CommonAppDataFolder','TARGETDIR','.'),@('STATEDIR','CommonAppDataFolder','CVEHarborAgent'),@('ProgramMenuFolder','TARGETDIR','.'),@('MENUDIR','ProgramMenuFolder','CVEHarbor'))){Row 'Directory' @('Directory','Directory_Parent','DefaultDir') $r}
Row 'Feature' @('Feature','Title','Level','Directory_','Attributes') @('Agent','CVEHarbor Windows Agent',1,'INSTALLDIR',0)
for($i=0;$i -lt $files.Count;$i++){
 $component='C'+$i;$file='F'+$i;$path=Join-Path $source $files[$i];$fileVersion=if($files[$i] -match '\.(exe|dll)$'){'1.0.0.0'}else{$null}
 $componentGuid=('{7D8B75A1-A4CE-48B9-94BB-'+($i.ToString('D12'))+'}')
 Row 'Component' @('Component','ComponentId','Directory_','Attributes','KeyPath') @($component,$componentGuid,'INSTALLDIR',256,$file)
 Row 'File' @('File','Component_','FileName','FileSize','Version','Attributes','Sequence') @($file,$component,$files[$i],[int](Get-Item -LiteralPath $path).Length,$fileVersion,512,($i+1))
 Row 'FeatureComponents' @('Feature_','Component_') @('Agent',$component)
}
Row 'Component' @('Component','ComponentId','Directory_','Attributes') @('State','{7D8B75A1-A4CE-48B9-94BB-000000000100}','STATEDIR',256)
Row 'FeatureComponents' @('Feature_','Component_') @('Agent','State')
Row 'CreateFolder' @('Directory_','Component_') @('STATEDIR','State')
# Windows service SID is SHA1(UTF16LE(uppercase service name)), interpreted as five DWORDs.
$sha=[Security.Cryptography.SHA1]::Create();$sidHash=$sha.ComputeHash([Text.Encoding]::Unicode.GetBytes('CVEHARBORAGENT'));$sha.Dispose()
$sid='S-1-5-80-'+((0..4 | ForEach-Object {[BitConverter]::ToUInt32($sidHash,$_ * 4)}) -join '-')
Row 'MsiLockPermissionsEx' @('MsiLockPermissionsEx','LockObject','Table','SDDLText') @('PrivateState','STATEDIR','CreateFolder',('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;'+$sid+')'))
Row 'ServiceInstall' @('ServiceInstall','Name','DisplayName','ServiceType','StartType','ErrorControl','StartName','Component_','Description') @('AgentService','CVEHarborAgent','CVEHarbor Windows Agent',16,2,32769,'NT AUTHORITY\LocalService','C0','Collects local inventory and securely uploads to the enrolled CVEHarbor customer environment.')
Row 'ServiceControl' @('ServiceControl','Name','Event','Wait','Component_') @('AgentControl','CVEHarborAgent',163,1,'C0')
Row 'MsiServiceConfig' @('MsiServiceConfig','Name','Event','ConfigType','Argument','Component_') @('ServiceIdentity','CVEHarborAgent',5,5,'1','C0')
Row 'MsiServiceConfig' @('MsiServiceConfig','Name','Event','ConfigType','Argument','Component_') @('DelayedStart','CVEHarborAgent',5,3,'1','C0')
Row 'MsiServiceConfig' @('MsiServiceConfig','Name','Event','ConfigType','Argument','Component_') @('Privileges','CVEHarborAgent',5,6,'SeChangeNotifyPrivilege','C0')
Row 'Shortcut' @('Shortcut','Directory_','Name','Component_','Target','Description','ShowCmd','WkDir') @('AgentSetup','MENUDIR','CVEHarbor Agent Setup','C3','[#F3]','Connect this server to your CVEHarbor customer environment',1,'INSTALLDIR')
Row 'AppSearch' @('Property','Signature_') @('NETFRAMEWORKRELEASE','Net48')
Row 'RegLocator' @('Signature_','Root','Key','Name','Type') @('Net48',2,'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full','Release',18)
Row 'AppSearch' @('Property','Signature_') @('WINDOWSBUILD','WindowsBuild')
Row 'RegLocator' @('Signature_','Root','Key','Name','Type') @('WindowsBuild',2,'SOFTWARE\Microsoft\Windows NT\CurrentVersion','CurrentBuildNumber',18)
Row 'LaunchCondition' @('Condition','Description') @('Installed OR (VersionNT64 AND WINDOWSBUILD >= "14393" AND NETFRAMEWORKRELEASE >= "#528040")','Windows 10/11 or Windows Server 2016+ x64 with .NET Framework 4.8 is required.')
Row 'Upgrade' @('UpgradeCode','VersionMin','Attributes','ActionProperty') @($upgrade,$Version,258,'NEWERPRODUCT')
Row 'Upgrade' @('UpgradeCode','VersionMax','Attributes','ActionProperty') @($upgrade,$Version,1,'OLDPRODUCTS')
Row 'LaunchCondition' @('Condition','Description') @('NOT NEWERPRODUCT','A newer CVEHarbor Agent is already installed. Downgrades are blocked.')
foreach($name in @('credential.bin','pending.bin','status.txt','*.tmp')){Row 'RemoveFile' @('FileKey','Component_','FileName','DirProperty','InstallMode') @(('State'+[Array]::IndexOf(@('credential.bin','pending.bin','status.txt','*.tmp'),$name)),'State',$name,'AGENTCLEANUPDIR',2)}
Row 'CustomAction' @('Action','Type','Source','Target') @('SetCleanupPath',51,'AGENTCLEANUPDIR','[STATEDIR]')
Row 'InstallExecuteSequence' @('Action','Condition','Sequence') @('SetCleanupPath','REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE',3400)
Row 'RemoveFile' @('FileKey','Component_','DirProperty','InstallMode') @('MenuFolder','C3','MENUDIR',2)
Row 'Media' @('DiskId','LastSequence','Cabinet') @(1,$files.Count,'#agent.cab')
$sequence=@{FindRelatedProducts=25;AppSearch=50;LaunchConditions=100;ValidateProductID=700;CostInitialize=800;FileCost=900;CostFinalize=1000;MigrateFeatureStates=1200;InstallValidate=1400;InstallInitialize=1500;RemoveExistingProducts=1510;ProcessComponents=1600;UnpublishFeatures=1800;StopServices=1900;DeleteServices=2000;RemoveShortcuts=3200;RemoveFiles=3500;RemoveFolders=3600;CreateFolders=3700;InstallFiles=4000;CreateShortcuts=4500;InstallServices=5800;MsiConfigureServices=5850;StartServices=5900;RegisterUser=6000;RegisterProduct=6100;PublishFeatures=6300;PublishProduct=6400;InstallFinalize=6600}
foreach($entry in $sequence.GetEnumerator()){Row 'InstallExecuteSequence' @('Action','Sequence') @($entry.Key,$entry.Value)}
foreach($entry in @{FindRelatedProducts=25;AppSearch=50;LaunchConditions=100;ValidateProductID=700;CostInitialize=800;FileCost=900;CostFinalize=1000;MigrateFeatureStates=1200;ExecuteAction=1300}.GetEnumerator()){Row 'InstallUISequence' @('Action','Sequence') @($entry.Key,$entry.Value)}
$stream=Invoke-Com $installer 'CreateRecord' @(2);Set-Com $stream 'StringData' @(1,'agent.cab');Invoke-Com $stream 'SetStream' @(2,(Join-Path $OutputDirectory 'agent.cab'))
$view=Invoke-Com $db 'OpenView' @('INSERT INTO `_Streams` (`Name`,`Data`) VALUES (?,?)');Invoke-Com $view 'Execute' @($stream);Invoke-Com $view 'Close' @()
$summary=$db.SummaryInformation(20)
foreach($entry in @{1=1252;2='Installation Database';3='CVEHarbor Windows Agent';4='CVEHarbor';7='x64;1033';9=('{'+[guid]::NewGuid().ToString().ToUpperInvariant()+'}');14=500;15=2;19=2}.GetEnumerator()){Set-Com $summary 'Property' @([int]$entry.Key,$entry.Value)}
Invoke-Com $summary 'Persist' @();Invoke-Com $db 'Commit' @()
[Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) | Out-Null
[Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) | Out-Null
Write-Output "Built $msi"
if(!$Production){Write-Output 'UNSIGNED EVALUATION BUILD: testing and demos only. Windows may show unknown-publisher or SmartScreen warnings.'}
