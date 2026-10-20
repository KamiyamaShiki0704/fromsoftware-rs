[CmdletBinding()]
param([string]$Manifest=(Join-Path $PSScriptRoot 'deployment.json'),[switch]$Apply)
$ErrorActionPreference='Stop'
if(Get-Process -Name eldenring -ErrorAction SilentlyContinue){throw 'Exit eldenring before restoring DLLs'}
$record=Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json
if($record.mod_root -ne 'F:\GoldenAge\_GoldenAge'){throw 'Unexpected target root'}
$backupRoot=[IO.Path]::GetFullPath((Split-Path -Parent $Manifest)).TrimEnd('\')
function Assert-NoLinks([string]$Path,[string]$Root) {
    $cursor=Get-Item -LiteralPath $Path
    while($cursor -and $cursor.FullName.Length -ge $Root.Length){
        if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw "Refusing linked restore path: $($cursor.FullName)"}
        $cursor=if($cursor.PSIsContainer){$cursor.Parent}else{$cursor.Directory}
    }
}
foreach($file in $record.files){
    $target=[IO.Path]::GetFullPath($file.target)
    $backup=[IO.Path]::GetFullPath($file.backup)
    if(-not $target.StartsWith('F:\GoldenAge\_GoldenAge\dll\',[StringComparison]::OrdinalIgnoreCase) -or
       -not $backup.StartsWith($backupRoot+'\before\',[StringComparison]::OrdinalIgnoreCase)){throw 'Out-of-scope path'}
    Assert-NoLinks $target 'F:\GoldenAge\_GoldenAge\dll'
    Assert-NoLinks $backup $backupRoot
    if((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $file.new_sha256){throw "Refusing later DLL changes: $target"}
    if((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $file.old_sha256){throw 'Backup hash mismatch'}
}
Write-Host 'RESTORE PREFLIGHT PASS. This restores the previous DLL bytes only; the game update is unchanged.'
if(-not $Apply){return}
foreach($file in $record.files){
    if(Get-Process -Name eldenring -ErrorAction SilentlyContinue){throw 'Game started; stop restoration'}
    Copy-Item -LiteralPath $file.backup -Destination $file.target -Force
    if((Get-FileHash -LiteralPath $file.target -Algorithm SHA256).Hash -ne $file.old_sha256){throw 'Restore readback mismatch'}
}
Write-Host 'RESTORED: exact previous DLLs; configuration and game files unchanged'
