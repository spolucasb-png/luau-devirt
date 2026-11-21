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
        foreach ($fixtureName in @('base85-rotor.lua','sarp.lua')) {
            $fixture = Join-Path $project "tests\fixtures\$fixtureName"
            if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) { throw "Bundled profile fixture missing: $fixtureName" }
            $fixtureHash = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash
            $profileOutput = Join-Path $project ("target\verified-" + [IO.Path]::GetFileNameWithoutExtension($fixtureName) + '.luau')
            Invoke-Checked $binary @($fixture,'-o',$profileOutput,'--force')
            Invoke-Checked $binary @($fixture,'--inspect')
            if ($hasCompiler) { Invoke-Checked $compiler @('--null',$profileOutput) }
            if ($hasAnalyzer) { Invoke-Checked $analyzer @($profileOutput) }
            if ($fixtureHash -ne (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash) { throw "Protected profile fixture changed: $fixtureName" }
        }
        $after = (Get-FileHash -LiteralPath $samplePath -Algorithm SHA256).Hash
        if ($before -ne $after) { throw 'Specimen changed during verification.' }
        Write-Output "Verified output: $output"
        Write-Output "Unchanged specimen SHA-256: $after"
    }
    finally { $env:LUAU_DEVIRT_SAMPLE = $previousSample }
}
finally { Pop-Location }
