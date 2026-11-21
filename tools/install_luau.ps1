param([string]$Version = '0.747')

$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^\d+\.\d+(?:\.\d+)?$') {
    throw 'Version must be a numeric Luau release tag.'
}
$destination = Join-Path $PSScriptRoot "luau-$Version"
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/luau-lang/luau/releases/tags/$Version"
$asset = $release.assets | Where-Object { $_.name -eq 'luau-windows.zip' }
if (-not $asset) { throw 'Official Windows asset not found.' }
if ($asset.browser_download_url -ne "https://github.com/luau-lang/luau/releases/download/$Version/luau-windows.zip") {
    throw 'Unexpected asset download URL.'
}
$digest = $asset.digest
if (-not $digest -and $Version -eq '0.747') {
    $digest = 'sha256:16bbd26575e9a6a3ecd2bd5fc772a81f3232520b56a40a86f2b47fec576d7cc7'
}
if ($digest -notmatch '^sha256:[a-fA-F0-9]{64}$') {
    throw 'Release asset has no verifiable SHA-256 digest.'
}
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$archive = Join-Path $destination 'luau-windows.zip'
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $archive
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ("sha256:$hash" -ne $digest.ToLowerInvariant()) { throw 'Release asset digest mismatch.' }
Expand-Archive -LiteralPath $archive -DestinationPath $destination -Force
Write-Output "Verified Luau $Version installed at $destination"
Write-Output "SHA-256: $hash"
Write-Output 'Use luau-compile and luau-analyze for static verification; do not run the uploaded wrapper.'
