param(
    [string]$Sample = (Join-Path $PSScriptRoot '..\tests\fixtures\sample.lua'),
    [switch]$RequireExternalTools
)

$ErrorActionPreference = 'Stop'
$project = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
function Invoke-PrettyChecks {
    param([string]$Fixture, [string]$Name)
    foreach ($variant in @(
        @{ Suffix = 'pretty'; Flags = @('--pretty') },
        @{ Suffix = 'pretty-comments'; Flags = @('--pretty','--comments') },
        @{ Suffix = 'pretty-no-strict'; Flags = @('--pretty','--no-strict') },
        @{ Suffix = 'pretty-comments-no-strict'; Flags = @('--pretty','--comments','--no-strict') }
    )) {
        $prettyOutput = Join-Path $project ("target\verified-$Name-" + $variant.Suffix + '.luau')
        Invoke-Checked $binary (@($Fixture,'-o',$prettyOutput,'--force') + $variant.Flags)
        if ($hasCompiler) { Invoke-Checked $compiler @('--null',$prettyOutput) }
        if ($hasAnalyzer) { Invoke-Checked $analyzer @($prettyOutput) }
    }
}
Push-Location $project
try {
    $samplePath = (Resolve-Path -LiteralPath $Sample).Path
    $before = (Get-FileHash -LiteralPath $samplePath -Algorithm SHA256).Hash
    $compiler = if ($env:LUAU_DEVIRT_COMPILER) { $env:LUAU_DEVIRT_COMPILER } else { Join-Path $project 'tools\luau-0.747\luau-compile.exe' }
    $analyzer = if ($env:LUAU_DEVIRT_ANALYZER) { $env:LUAU_DEVIRT_ANALYZER } else { Join-Path $project 'tools\luau-0.747\luau-analyze.exe' }
    $hasCompiler = Test-Path -LiteralPath $compiler -PathType Leaf
    $hasAnalyzer = Test-Path -LiteralPath $analyzer -PathType Leaf
    if ($RequireExternalTools -and (-not $hasCompiler -or -not $hasAnalyzer)) {
        throw 'Install official tools with tools/install_luau.ps1 or set LUAU_DEVIRT_COMPILER and LUAU_DEVIRT_ANALYZER.'
    }
    $previousSample = $env:LUAU_DEVIRT_SAMPLE
    $env:LUAU_DEVIRT_SAMPLE = $samplePath
    try {
        Invoke-Checked 'cargo' @('fmt', '--check')
        Invoke-Checked 'cargo' @('test', '--locked', '--', '--nocapture')
        Invoke-Checked 'cargo' @('build', '--release', '--locked')
        $binary = Join-Path $project 'target\release\luau-devirt.exe'
        Invoke-Checked $binary @('--version')
        $output = Join-Path $project 'target\verified-output.luau'
        Invoke-Checked $binary @($samplePath, '-o', $output, '--force')
        if ($hasCompiler) { Invoke-Checked $compiler @('--null', $output) }
        if ($hasAnalyzer) { Invoke-Checked $analyzer @($output) }
        Invoke-PrettyChecks $samplePath 'sample'
        foreach ($fixtureName in @('base85-rotor.lua','sarp.lua')) {
            $fixture = Join-Path $project "tests\fixtures\$fixtureName"
            if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) { throw "Bundled profile fixture missing: $fixtureName" }
            $fixtureHash = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash
            $profileOutput = Join-Path $project ("target\verified-" + [IO.Path]::GetFileNameWithoutExtension($fixtureName) + '.luau')
            Invoke-Checked $binary @($fixture,'-o',$profileOutput,'--force')
            Invoke-Checked $binary @($fixture,'--inspect')
            if ($hasCompiler) { Invoke-Checked $compiler @('--null',$profileOutput) }
            if ($hasAnalyzer) { Invoke-Checked $analyzer @($profileOutput) }
            Invoke-PrettyChecks $fixture ([IO.Path]::GetFileNameWithoutExtension($fixtureName))
            if ($fixtureHash -ne (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash) { throw "Protected profile fixture changed: $fixtureName" }
        }
        # The fourth profile is a fail-closed development preview, not a fourth
        # readable-output success. Do not compile/analyze this protected input.
        $protectedFixture = Join-Path $project 'tests\fixtures\protected.luau'
        $protectedHash = (Get-FileHash -LiteralPath $protectedFixture -Algorithm SHA256).Hash
        if ($protectedHash.ToLowerInvariant() -ne '1496f231da48222f5aa52d84829e9ad4ef5481eb237f56c6be1b9645dd7136fe') {
            throw 'Pinned fourth-profile specimen hash mismatch.'
        }
        $protectedRecovery = Join-Path $project 'decompilation\protected'
        $artifactHashes = @{}
        foreach ($line in Get-Content -LiteralPath (Join-Path $protectedRecovery 'SHA256SUMS.txt')) {
            $record = [regex]::Match($line, '^([a-f0-9]{64})  (.+)$')
            if (-not $record.Success) { throw 'Invalid protected artifact checksum record.' }
            $file = $record.Groups[2].Value
            if ([IO.Path]::IsPathRooted($file) -or $file -match '(^|[\\/])\.\.([\\/]|$)|:' -or $artifactHashes.ContainsKey($file)) {
                throw "Unsafe or duplicated protected artifact checksum path: $file"
            }
            $actual = (Get-FileHash -LiteralPath (Join-Path $protectedRecovery $file) -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $record.Groups[1].Value) { throw "Protected artifact checksum mismatch: $file" }
            $artifactHashes[$file] = $actual
        }
        if ($artifactHashes.Count -eq 0) { throw 'Empty protected artifact checksum manifest.' }
        Write-Output "Protected evidence: $($artifactHashes.Count) byte-manifest hashes verified."
        $inspectStdout = Join-Path $project 'target\verified-protected-inspect.stdout.txt'
        $inspectStderr = Join-Path $project 'target\verified-protected-inspect.stderr.txt'
        $inspection = Start-Process -FilePath $binary -ArgumentList @(('"' + $protectedFixture + '"'),'--inspect') -RedirectStandardOutput $inspectStdout -RedirectStandardError $inspectStderr -NoNewWindow -Wait -PassThru
        $inspectionText = Get-Content -LiteralPath $inspectStderr -Raw
        if ($inspection.ExitCode -ne 1 -or $inspectionText -notmatch 'Status: INCOMPLETE' -or $inspectionText -notmatch 'unsupported helper 25 generic iteration') {
            throw 'Fourth-profile incomplete-analysis contract changed; review semantics and verification expectations.'
        }
        if ((Get-Item -LiteralPath $inspectStdout).Length -ne 0) { throw 'Incomplete inspection fabricated stdout output.' }
        if ($protectedHash -ne (Get-FileHash -LiteralPath $protectedFixture -Algorithm SHA256).Hash) { throw 'Fourth-profile specimen changed.' }
        Write-Output 'Fourth profile: expected unsupported generic iteration confirmed; no complete IR/Luau available and no target output static checks performed.'
        $after = (Get-FileHash -LiteralPath $samplePath -Algorithm SHA256).Hash
        if ($before -ne $after) { throw 'Specimen changed during verification.' }
        Write-Output "Verified output: $output"
        Write-Output "Unchanged specimen SHA-256: $after"
    }
    finally { $env:LUAU_DEVIRT_SAMPLE = $previousSample }
}
finally { Pop-Location }
