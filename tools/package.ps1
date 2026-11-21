param(
    [string]$OutputDirectory,
    [switch]$SkipBuild,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$project = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $project 'dist' }
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
$manifest = Get-Content -LiteralPath (Join-Path $project 'Cargo.toml') -Raw
$version = [regex]::Match($manifest, '(?m)^version\s*=\s*"([^"]+)"').Groups[1].Value
if (-not $version) { throw 'Cargo version not found.' }
$sourceName = "luau-devirt-$version-source"
$binaryName = "luau-devirt-$version-windows-x86_64"
$archives = @((Join-Path $OutputDirectory "$sourceName.zip"), (Join-Path $OutputDirectory "$binaryName.zip"))
foreach ($archive in $archives) {
    if ((Test-Path -LiteralPath $archive) -and -not $Force) { throw "Existing archive preserved: $archive (use -Force to replace)" }
}
Push-Location $project
try {
    if (-not $SkipBuild) {
        & cargo build --release --locked
        if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }
    }
    $binary = Join-Path $project 'target\release\luau-devirt.exe'
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw 'Windows release binary missing.' }
    $hostTriple = (& rustc -vV | Where-Object { $_ -match '^host:' })
    if ($hostTriple -notmatch 'x86_64-pc-windows') { throw 'This binary packaging target is Windows x86-64 only.' }
    $stage = Join-Path $project ("target\release-stage-" + [guid]::NewGuid().ToString('N'))
    $sourceStage = Join-Path $stage $sourceName
    $binaryStage = Join-Path $stage $binaryName
    New-Item -ItemType Directory -Path $sourceStage,$binaryStage | Out-Null
    foreach ($file in @('Cargo.toml','Cargo.lock','README.md','LICENSE','CHANGELOG.md','VM_FORMAT.md','VALIDATION.md','AGENTS.md','.gitignore')) {
        Copy-Item -LiteralPath (Join-Path $project $file) -Destination (Join-Path $sourceStage $file)
    }
    foreach ($folder in @('src','tests','examples','.github')) {
        $path = Join-Path $project $folder
        if (Test-Path -LiteralPath $path) { Copy-Item -LiteralPath $path -Destination (Join-Path $sourceStage $folder) -Recurse }
    }
    New-Item -ItemType Directory -Path (Join-Path $sourceStage 'tools') | Out-Null
    foreach ($file in @('install_luau.ps1','verify.ps1','package.ps1')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination (Join-Path $sourceStage "tools\$file")
    }
    Copy-Item -LiteralPath $binary -Destination (Join-Path $binaryStage 'luau-devirt.exe')
    foreach ($file in @('README.md','LICENSE','CHANGELOG.md','VM_FORMAT.md','VALIDATION.md')) {
        Copy-Item -LiteralPath (Join-Path $project $file) -Destination (Join-Path $binaryStage $file)
    }
    # Include only the reviewed recovery artifacts, never the diagnostics,
    # external uploads, process logs, baseline builds, or local tool paths.
    $recoveryFiles = @(
        'target.original.lua','target.decoded.bin','target.bytecode.txt',
        'target.handlers.md','target.deobfuscated.lua','target.analysis.md',
        'target.validation.md','target.concise.luau','target.line-count-review.md',
        'SHA256SUMS.txt'
    )
    $recovery = Join-Path $project 'decompilation\message'
    if (Test-Path -LiteralPath $recovery -PathType Container) {
        foreach ($stageRoot in @($sourceStage,$binaryStage)) {
            $recoveryStage = Join-Path $stageRoot 'decompilation\message'
            New-Item -ItemType Directory -Path $recoveryStage -Force | Out-Null
            foreach ($file in $recoveryFiles) {
                Copy-Item -LiteralPath (Join-Path $recovery $file) -Destination (Join-Path $recoveryStage $file)
            }
        }
    }
    New-Item -ItemType Directory -Path (Join-Path $binaryStage 'examples') | Out-Null
    Copy-Item -LiteralPath (Join-Path $project 'tests\fixtures\sample.lua') -Destination (Join-Path $binaryStage 'examples\sample.lua')
    Copy-Item -LiteralPath (Join-Path $project 'examples\sample.recovered.luau') -Destination (Join-Path $binaryStage 'examples\sample.recovered.luau')
    Compress-Archive -LiteralPath $sourceStage -DestinationPath $archives[0] -Force:$Force
    Compress-Archive -LiteralPath $binaryStage -DestinationPath $archives[1] -Force:$Force
    $checksums = foreach ($archive in $archives) {
        $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $([IO.Path]::GetFileName($archive))"
    }
    $checksumPath = Join-Path $OutputDirectory "luau-devirt-$version-SHA256SUMS.txt"
    $checksums | Set-Content -LiteralPath $checksumPath -Encoding ASCII
    Write-Output ($archives + $checksumPath)
}
finally { Pop-Location }
