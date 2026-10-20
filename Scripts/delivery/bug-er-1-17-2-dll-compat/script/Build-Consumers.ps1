[CmdletBinding()]
param(
    [string[]]$Projects = @(),
    [string]$GameExe = 'F:/SteamLibrary/steamapps/common/ELDEN RING/Game/eldenring.exe',
    [string]$OldExe = 'F:/GoldenAge/Transplantation/ToER/BB/KnowledgeBase/Topics/MapPort/sys-bb-map-to-er/experiments/technical-chain-20261012-001/nav/runtime/eldenring.exe',
    [switch]$CheckSdk
)
$ErrorActionPreference = 'Stop'
$sdkRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../..'))
$projectRoot = Split-Path -Parent $sdkRoot
$reportRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot '../Topics/Gameplay/bug-er-1-17-2-dll-compat'))
$logRoot = Join-Path $reportRoot 'build-logs'
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
$env:CARGO_TARGET_DIR = Join-Path $sdkRoot 'target/consumers-1172'
$env:ER_GAME_EXE = $GameExe
$env:ER_TEST_EXE = $GameExe
$env:RUSTFLAGS = '-C target-feature=+crt-static'
$kitRoot = (Get-ItemProperty -LiteralPath 'HKLM:/SOFTWARE/Microsoft/Windows Kits/Installed Roots').KitsRoot10
$rc = Get-ChildItem -LiteralPath (Join-Path $kitRoot 'bin') -Directory |
    Sort-Object Name -Descending | ForEach-Object {Join-Path $_.FullName 'x64/rc.exe'} |
    Where-Object {Test-Path -LiteralPath $_} | Select-Object -First 1
if (-not $rc) {throw 'Windows SDK rc.exe is required for the Summon version resource'}
$env:RC = $rc

function Invoke-Cargo([string[]]$Arguments, [string]$LogName) {
    & cargo @Arguments 2>&1 | Tee-Object -FilePath (Join-Path $logRoot $LogName)
    if ($LASTEXITCODE -ne 0) {throw "cargo $($Arguments -join ' ') failed; see $LogName"}
}

if ($CheckSdk) {
    Push-Location $sdkRoot
    try {
        Invoke-Cargo @('fmt','-p','eldenring','-p','debug','--check') 'sdk-fmt.txt'
        Invoke-Cargo @('test','-p','eldenring','--lib','--locked','--offline','--target','x86_64-pc-windows-msvc') 'sdk-tests.txt'
        Invoke-Cargo @('clippy','-p','eldenring','--lib','--locked','--offline','--target','x86_64-pc-windows-msvc','--','-D','warnings') 'sdk-clippy.txt'
    } finally {Pop-Location}
}

$entries = @(
    @{Dir='ERGparamPreloadPatch'; Artifact='gparam_preload_patch.dll'; Features=@(); Package=@()},
    @{Dir='ERSoundBankLoader'; Artifact='er_sound_bank_loader.dll'; Features=@(); Package=@()},
    @{Dir='er-torrent-skin-slots'; Artifact='er_torrent_skin_slots.dll'; Features=@(); Package=@()},
    @{Dir='eldenring-covenant-slot'; Artifact='eldenring_covenant_slot.dll'; Features=@(); Package=@()},
    @{Dir='Summon'; Artifact='summon.dll'; Features=@(); Package=@()},
    @{Dir='er-demon-beast'; Artifact='er_demon_beast.dll'; Features=@('--features','native'); Package=@()},
    @{Dir='nightreign_style_hud'; Artifact='nightreign_style_hud.dll'; Features=@(); Package=@('-p','nightreign-style-hud')},
    @{Dir='weapon-animation-hotreload'; Artifact='CapacityExpansion.dll'; Features=@(); Package=@()},
    @{Dir='ERCharacterScale'; Artifact='ERCharacterScale.dll'; Features=@(); Package=@()}
)
foreach ($entry in $entries) {
    if ($Projects.Count -and $entry.Dir -notin $Projects) {continue}
    Push-Location (Join-Path $projectRoot $entry.Dir)
    try {
        $started = Get-Date
        $common = @('--release','--locked','--offline','--target','x86_64-pc-windows-msvc') + $entry.Package
        Invoke-Cargo (@('fmt')+$entry.Package+@('--check')) "$($entry.Dir)-fmt.txt"
        if ($entry.Dir -eq 'er-demon-beast') {
            Invoke-Cargo (@('test')+$common) "$($entry.Dir)-default-tests.txt"
        }
        $tests = @('test')+$common+$entry.Features
        if ($entry.Dir -eq 'ERCharacterScale') {$tests+=@('--','--test-threads=1')}
        Invoke-Cargo $tests "$($entry.Dir)-tests.txt"
        if ($entry.Dir -eq 'er-torrent-skin-slots') {
            foreach ($exe in @($GameExe,$OldExe)) {
                $env:ER_TEST_EXE=$exe
                $version=if($exe -eq $GameExe){'272'}else{'271'}
                Invoke-Cargo (@('test')+$common+@('profile::tests::installed_executable_and_corruptions','--','--ignored')) "$($entry.Dir)-$version-image.txt"
            }
            $env:ER_TEST_EXE=$GameExe
        }
        $lint = @('clippy')+$common+$entry.Features+@('--lib')
        # Existing HUD drawing/state code has style diagnostics unrelated to the
        # compatibility port. Preserve its interfaces and record normal Clippy;
        # every native guard/test/build remains required.
        if ($entry.Dir -ne 'nightreign_style_hud') {$lint+=@('--','-D','warnings')}
        Invoke-Cargo $lint "$($entry.Dir)-clippy.txt"
        Invoke-Cargo (@('build')+$common+$entry.Features+@('--lib')) "$($entry.Dir)-release.txt"
        $tree = & cargo tree --locked --offline --target x86_64-pc-windows-msvc @($entry.Package) @($entry.Features) 2>&1
        if ($LASTEXITCODE -ne 0 -or ($tree -match '(?i)shikifsrs')) {throw 'Dependency tree failed or contains ShikiFSRS'}
        $tree | Set-Content -LiteralPath (Join-Path $logRoot "$($entry.Dir)-dependency-tree.txt") -Encoding utf8
        $candidate = Join-Path (Get-Location) 'dist/er-1.17.2'
        New-Item -ItemType Directory -Path $candidate -Force | Out-Null
        $artifact = Join-Path $env:CARGO_TARGET_DIR "x86_64-pc-windows-msvc/release/$($entry.Artifact)"
        Copy-Item -LiteralPath $artifact -Destination (Join-Path $candidate $entry.Artifact)
        $pdb = [IO.Path]::ChangeExtension($artifact,'.pdb')
        if (Test-Path -LiteralPath $pdb) {Copy-Item -LiteralPath $pdb -Destination (Join-Path $candidate ([IO.Path]::GetFileName($pdb)))}
        $result = [ordered]@{
            project=$entry.Dir; root=(Get-Location).Path; revision=(& git rev-parse HEAD);
            features=$entry.Features; target='x86_64-pc-windows-msvc'; rustflags=$env:RUSTFLAGS;
            rustc=(& rustc --version); cargo=(& cargo --version); rc=$env:RC;
            artifact=(Join-Path $candidate $entry.Artifact); bytes=(Get-Item -LiteralPath $artifact).Length;
            sha256=(Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash;
            lock_sha256=(Get-FileHash -LiteralPath 'Cargo.lock' -Algorithm SHA256).Hash;
            automatic='PASS'; game_runtime='NOT_RUN'; elapsed_seconds=((Get-Date)-$started).TotalSeconds
        }
        $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $candidate 'build-result.json') -Encoding utf8
        Write-Host "COMPLETE $($entry.Dir): $($result.sha256)"
    } finally {Pop-Location}
}
