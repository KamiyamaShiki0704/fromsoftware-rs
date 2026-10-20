[CmdletBinding()]
param([switch]$Apply)
$ErrorActionPreference='Stop'
$sdkRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../..'))
$topic=[IO.Path]::GetFullPath((Join-Path $sdkRoot '../../Topics/Gameplay/bug-er-1-17-2-dll-compat'))
$plan=Get-Content -LiteralPath (Join-Path $topic 'candidate-manifest.json') -Raw | ConvertFrom-Json
$modRoot='F:\GoldenAge\_GoldenAge'
$dllRoot=Join-Path $modRoot 'dll'
$game='F:\SteamLibrary\steamapps\common\ELDEN RING\Game\eldenring.exe'
function Assert-Stopped {
    if (Get-Process -Name eldenring -ErrorAction SilentlyContinue) {throw 'Exit eldenring before replacing DLLs'}
}
function Assert-InRoot([string]$Path,[string]$Root) {
    $pathFull=[IO.Path]::GetFullPath($Path)
    $rootFull=[IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not $pathFull.StartsWith($rootFull+'\',[StringComparison]::OrdinalIgnoreCase)) {throw "Out of scope: $pathFull"}
    $cursor=Get-Item -LiteralPath $pathFull
    while ($cursor -and $cursor.FullName.Length -ge $rootFull.Length) {
        if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw "Directory/file link requires separate scope: $($cursor.FullName)"}
        $cursor=if($cursor.PSIsContainer){$cursor.Parent}else{$cursor.Directory}
    }
}
function Hash([string]$Path) {(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
Assert-Stopped
if ((Hash $game) -ne $plan.game_exe_sha256) {throw 'Game executable changed since verification'}
if ($plan.artifacts.Count -ne 11 -or $plan.automatic -ne 'PASS') {throw 'Incomplete candidate plan'}
foreach ($entry in $plan.artifacts) {
    Assert-InRoot $entry.installed_path $dllRoot
    if ((Hash $entry.installed_path) -ne $entry.installed_initial_sha256) {throw "Installed DLL changed: $($entry.installed_path)"}
    if ((Hash $entry.artifact) -ne $entry.sha256) {throw "Candidate changed: $($entry.artifact)"}
}
$plan.artifacts | Select-Object project,installed_path,sha256 | Format-Table -AutoSize
if (-not $Apply) {Write-Host 'PREFLIGHT PASS; no installed files changed';return}

$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$backupRoot=Join-Path $sdkRoot "dist/er-1.17.2-rollback-$stamp"
New-Item -ItemType Directory -Path $backupRoot | Out-Null
$protected=@(Get-ChildItem -LiteralPath $dllRoot -Recurse -File | Where-Object {$_.Extension -in @('.ini','.toml','.json')})
$protected+=@(Get-ChildItem -LiteralPath $modRoot -Filter '*.me3' -File)
foreach ($relative in @('GA/regulation.bin','GA/chr/c0010.behbnd.dcx','GA/action/script/c9997.hks','GA/action/script/d0010.hks','dll/CMI/CMI.dll','dll/CMI/cmi_eldenring_loader.dll','dll/ertransmogrify/ertransmogrify.dll')) {
    $path=Join-Path $modRoot $relative
    if(Test-Path -LiteralPath $path){$protected+=Get-Item -LiteralPath $path}
}
$protectedHashes=@($protected | Sort-Object FullName -Unique | ForEach-Object {@{path=$_.FullName;sha256=(Hash $_.FullName)}})
$files=@()
foreach ($entry in $plan.artifacts) {
    $relative=[IO.Path]::GetRelativePath($modRoot,$entry.installed_path)
    $backup=Join-Path $backupRoot (Join-Path 'before' $relative)
    New-Item -ItemType Directory -Path (Split-Path -Parent $backup) -Force | Out-Null
    Copy-Item -LiteralPath $entry.installed_path -Destination $backup
    if((Hash $backup) -ne $entry.installed_initial_sha256){throw 'Backup readback mismatch'}
    $temp=$entry.installed_path+".staged-1172-$stamp"
    if(Test-Path -LiteralPath $temp){throw "Staging collision: $temp"}
    Copy-Item -LiteralPath $entry.artifact -Destination $temp
    if((Hash $temp) -ne $entry.sha256){throw 'Staged candidate readback mismatch'}
    $files+=@{project=$entry.project;target=$entry.installed_path;candidate=$entry.artifact;backup=$backup;
        old_sha256=$entry.installed_initial_sha256;new_sha256=$entry.sha256;staged=$temp;state='STAGED'}
}
$record=[ordered]@{mod_root=$modRoot;game_exe=$game;game_sha256=$plan.game_exe_sha256;backup_root=$backupRoot;
    status='STAGED';files=$files;protected=$protectedHashes;runtime_human='PENDING';restores_dlls_only=$true}
$manifest=Join-Path $backupRoot 'deployment.json'
function Save-Record {$record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $manifest -Encoding utf8}
Save-Record
Assert-Stopped
foreach($file in $files){if((Hash $file.target) -ne $file.old_sha256){throw 'Installed preimage changed after staging'}}
try {
    foreach($file in $files){
        Assert-Stopped
        Move-Item -LiteralPath $file.staged -Destination $file.target -Force
        $file.state='INSTALLED';Save-Record
        if((Hash $file.target) -ne $file.new_sha256){throw 'Installed readback mismatch'}
    }
    foreach($item in $protectedHashes){if((Hash $item.path) -ne $item.sha256){throw "Protected file changed: $($item.path)"}}
    $record.status='INSTALLED_VERIFIED';Save-Record
} catch {
    $failure=$_
    foreach($file in $files | Where-Object state -EQ 'INSTALLED') {
        if((Hash $file.target) -eq $file.new_sha256){Copy-Item -LiteralPath $file.backup -Destination $file.target -Force;$file.state='ROLLED_BACK'}
        else{$file.state='UNKNOWN_POSTIMAGE_NOT_OVERWRITTEN'}
    }
    $record.status='FAILED_ROLLBACK_ATTEMPTED';Save-Record
    throw $failure
}
Copy-Item -LiteralPath $manifest -Destination (Join-Path $topic 'deployment.json')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Restore-VerifiedDlls.ps1') -Destination $backupRoot
Write-Host "INSTALLED_VERIFIED: 11 DLLs; protected files unchanged; backup=$backupRoot"
