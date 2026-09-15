$ErrorActionPreference = 'Stop'
$previousOS = $env:GOOS
$previousArch = $env:GOARCH
$previousCGO = $env:CGO_ENABLED
Push-Location (Join-Path $PSScriptRoot '..')
try {
    New-Item -ItemType Directory -Path dist -Force | Out-Null
    $env:CGO_ENABLED = '0'
    foreach ($platform in @('windows', 'linux', 'darwin')) {
        foreach ($architecture in @('amd64', 'arm64')) {
            $env:GOOS = $platform
            $env:GOARCH = $architecture
            $extension = if ($platform -eq 'windows') { '.exe' } else { '' }
            go build -trimpath -ldflags='-s -w' -o "dist/subexposure-$platform-$architecture$extension" ./cmd/subexposure
            if ($LASTEXITCODE -ne 0) { throw "Build failed: $platform/$architecture" }
        }
    }
} finally {
    $env:GOOS = $previousOS
    $env:GOARCH = $previousArch
    $env:CGO_ENABLED = $previousCGO
    Pop-Location
}
