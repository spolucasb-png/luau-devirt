param(
    [string]$OutputDirectory,
    [switch]$SkipBuild,
    [switch]$Preview,
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
if ((Test-Path -LiteralPath (Join-Path $project 'src\sarp_large.rs')) -and -not $Preview) {
    throw 'The large SARP profile is incomplete. Use -Preview for a clearly labeled development archive, not a release.'
}
$archiveVersion = if ($Preview) { "$version-development-preview" } else { $version }
$sourceName = "luau-devirt-$archiveVersion-source"
$binaryName = "luau-devirt-$archiveVersion-windows-x86_64"
$archives = @((Join-Path $OutputDirectory "$sourceName.zip"), (Join-Path $OutputDirectory "$binaryName.zip"))
$checksumPath = Join-Path $OutputDirectory "luau-devirt-$archiveVersion-SHA256SUMS.txt"
foreach ($archive in ($archives + $checksumPath)) {
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
    foreach ($file in @('Cargo.toml','Cargo.lock','README.md','LICENSE','CHANGELOG.md','VM_FORMAT.md','VALIDATION.md','AGENTS.md','.gitignore','.gitattributes')) {
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
    $sarpFiles = @(
        'target.original.lua','target.decoded.bin','target.bytecode.txt',
        'target.handlers.md','target.ir.txt','target.structured-ir.txt',
        'target.deobfuscated.lua','target.analysis.md','target.validation.md',
        'SHA256SUMS.txt','acquisition.json',
        'diagnostics\reference.py','diagnostics\reference-review.md',
        'diagnostics\hash_reference.py'
    )
    $sarpRecovery = Join-Path $project 'decompilation\sarp'
    if (Test-Path -LiteralPath $sarpRecovery -PathType Container) {
        foreach ($stageRoot in @($sourceStage,$binaryStage)) {
            $sarpStage = Join-Path $stageRoot 'decompilation\sarp'
            New-Item -ItemType Directory -Path $sarpStage -Force | Out-Null
            foreach ($file in $sarpFiles) {
                $destination = Join-Path $sarpStage $file
                New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($destination)) -Force | Out-Null
                Copy-Item -LiteralPath (Join-Path $sarpRecovery $file) -Destination $destination
            }
        }
    }
    $protectedFiles = @(
        'target.original.lua','acquisition.json','target.transport.bin','target.vm.bin',
        'target.metadata.txt','target.handlers.parsed.txt','target.partial-bytecode.txt',
        'target.status.txt','target.analysis.md','target.validation.md','SHA256SUMS.txt',
        'permutation-A.bin','permutation-B.bin','permutation-C.bin',
        'diagnostics\probe.py','diagnostics\transport_reference.py',
        'diagnostics\initialization_reference.py','diagnostics\initialization_audit.py',
        'diagnostics\w_evidence.py','diagnostics\prototype_reference.py','diagnostics\hash_reference.py',
        'diagnostics\artifact_check.py','diagnostics\artifact-check.json',
        'diagnostics\independent-review.md','diagnostics\loop-contract-review.md',
        'diagnostics\fingerprint.json','diagnostics\transport-reference.json',
        'diagnostics\initialization-reference.json','diagnostics\w-evidence.json',
        'diagnostics\prototype-reference.json','diagnostics\hash-reference-results.json',
        'diagnostics\reference.transport.bin','diagnostics\reference.permutation-A.bin',
        'diagnostics\reference.permutation-B.bin','diagnostics\reference.permutation-C.bin',
        'diagnostics\wrapper.tokens.txt','diagnostics\wrapper-normalized.txt',
        'diagnostics\initOnce.txt','diagnostics\initB.txt','diagnostics\initC.txt',
        'diagnostics\boot.txt','diagnostics\make.txt','diagnostics\U.txt','diagnostics\MO.txt','diagnostics\MO2.txt'
    )
    $protectedFiles += 1..32 | ForEach-Object { "diagnostics\_h_$_.txt" }
    $protectedFiles += @(2094,2380,2880,301,4043,7559,8415) | ForEach-Object { "diagnostics\_dr_$_.txt" }
    $protectedRecovery = Join-Path $project 'decompilation\protected'
    if ($Preview) {
        # Refuse to distribute evidence that differs from its byte manifest.
        # The path list above remains authoritative; the manifest cannot add
        # arbitrary files to the archive.
        $artifactHashes = @{}
        foreach ($line in Get-Content -LiteralPath (Join-Path $protectedRecovery 'SHA256SUMS.txt')) {
            $record = [regex]::Match($line, '^([a-f0-9]{64})  (.+)$')
            if (-not $record.Success) { throw 'Invalid protected artifact checksum record.' }
            $file = $record.Groups[2].Value.Replace('/','\')
            if ($file -eq 'SHA256SUMS.txt' -or $file -notin $protectedFiles -or $artifactHashes.ContainsKey($file)) {
                throw "Artifact checksum is outside the allowlist or duplicated: $file"
            }
            $actual = (Get-FileHash -LiteralPath (Join-Path $protectedRecovery $file) -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $record.Groups[1].Value) { throw "Protected artifact checksum mismatch: $file" }
            $artifactHashes[$file] = $actual
        }
        if ($artifactHashes.Count -ne ($protectedFiles.Count - 1)) { throw 'Protected artifact checksum manifest is incomplete.' }
        foreach ($stageRoot in @($sourceStage,$binaryStage)) {
            foreach ($file in $protectedFiles) {
                $destination = Join-Path $stageRoot "decompilation\protected\$file"
                New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($destination)) -Force | Out-Null
                Copy-Item -LiteralPath (Join-Path $protectedRecovery $file) -Destination $destination
            }
        }
    }
    New-Item -ItemType Directory -Path (Join-Path $binaryStage 'examples') | Out-Null
    Copy-Item -LiteralPath (Join-Path $project 'tests\fixtures\sample.lua') -Destination (Join-Path $binaryStage 'examples\sample.lua')
    Copy-Item -LiteralPath (Join-Path $project 'examples\sample.recovered.luau') -Destination (Join-Path $binaryStage 'examples\sample.recovered.luau')
    Copy-Item -LiteralPath (Join-Path $project 'tests\fixtures\sarp.pretty.luau') -Destination (Join-Path $binaryStage 'examples\sarp.pretty.luau')
    Compress-Archive -LiteralPath $sourceStage -DestinationPath $archives[0] -Force:$Force
    Compress-Archive -LiteralPath $binaryStage -DestinationPath $archives[1] -Force:$Force
    $checksums = foreach ($archive in $archives) {
        $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $([IO.Path]::GetFileName($archive))"
    }
    $checksums | Set-Content -LiteralPath $checksumPath -Encoding ASCII
    Write-Output ($archives + $checksumPath)
}
finally { Pop-Location }
