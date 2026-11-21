[CmdletBinding()]
param(
    [string]$Version
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$cargoToml = Join-Path $repo 'Cargo.toml'
if ([string]::IsNullOrWhiteSpace($Version)) {
    $match = Select-String -LiteralPath $cargoToml -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
    if (-not $match) {
        throw "Could not read the package version from $cargoToml"
    }
    $Version = $match.Matches[0].Groups[1].Value
}
if ($Version -notmatch '^\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?$') {
    throw "Invalid distribution version: $Version"
}

$dist = [IO.Path]::GetFullPath((Join-Path $repo 'dist'))
$name = "Windissect-v$Version-windows-x64"
$stage = [IO.Path]::GetFullPath((Join-Path $dist $name))
$zip = [IO.Path]::GetFullPath((Join-Path $dist "$name.zip"))

if (-not $stage.StartsWith($dist + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to stage outside $dist"
}

Push-Location $repo
try {
    & cargo build --release --workspace
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }

    & go build -trimpath -ldflags '-s -w' -o 'target/release/windissect-fleet.exe' './cmd/windissect'
    if ($LASTEXITCODE -ne 0) { throw "fleet build failed ($LASTEXITCODE)" }

    # The TUI ships compiled with Bun, so bare `windissect` works without Node.
    Push-Location 'tui'
    try {
        & npm ci --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed ($LASTEXITCODE)" }
        & bun build-exe.ts bun-windows-x64 '../target/release/windissect-tui.exe'
        if ($LASTEXITCODE -ne 0) { throw "TUI build failed ($LASTEXITCODE)" }
    }
    finally {
        Pop-Location
    }

    $reportedVersion = (& 'target/release/windissect.exe' --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $reportedVersion -notmatch "(^|\s)$([regex]::Escape($Version))$") {
        throw "CLI version mismatch: expected $Version, got '$reportedVersion'"
    }
    & 'target/release/windissect-fleet.exe' --help *> $null
    if ($LASTEXITCODE -ne 0) { throw "fleet smoke test failed ($LASTEXITCODE)" }

    New-Item -ItemType Directory -Path $dist -Force | Out-Null
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
    New-Item -ItemType Directory -Path $stage | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stage 'docs') | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stage 'licenses') | Out-Null

    Copy-Item -LiteralPath 'target/release/windissect-gui.exe' -Destination (Join-Path $stage 'Windissect-GUI.exe')
    Copy-Item -LiteralPath 'target/release/windissect.exe' -Destination (Join-Path $stage 'windissect.exe')
    Copy-Item -LiteralPath 'target/release/windissect-fleet.exe' -Destination (Join-Path $stage 'windissect-fleet.exe')
    Copy-Item -LiteralPath 'target/release/windissect-tui.exe' -Destination (Join-Path $stage 'windissect-tui.exe')
    Copy-Item -LiteralPath 'packaging/README-Windows.txt' -Destination (Join-Path $stage 'README.txt')
    Copy-Item -LiteralPath 'README.md' -Destination (Join-Path $stage 'README.md')
    Copy-Item -LiteralPath 'LICENSE' -Destination (Join-Path $stage 'LICENSE.txt')
    Copy-Item -LiteralPath 'gui/DISCORD.md' -Destination (Join-Path $stage 'docs/discord.md')
    Copy-Item -Path 'docs/*.md' -Destination (Join-Path $stage 'docs')
    Copy-Item -LiteralPath 'gui/assets/LICENSE-LUCIDE' -Destination (Join-Path $stage 'licenses/LUCIDE.txt')

    $hashLines = Get-ChildItem -LiteralPath $stage -File -Recurse |
        Sort-Object FullName |
        ForEach-Object {
            $relative = [IO.Path]::GetRelativePath($stage, $_.FullName).Replace('\', '/')
            $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            "$hash  $relative"
        }
    Set-Content -LiteralPath (Join-Path $stage 'SHA256SUMS.txt') -Value $hashLines -Encoding utf8NoBOM

    if (Test-Path -LiteralPath $zip) {
        Remove-Item -LiteralPath $zip -Force
    }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
    $zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath "$zip.sha256" -Value "$zipHash  $([IO.Path]::GetFileName($zip))" -Encoding ascii

    Write-Host "Distribution: $zip"
    Write-Host "SHA-256:      $zipHash"

    # Installer (Inno Setup 6). Skipped with a warning when ISCC isn't installed:
    #   winget install --id JRSoftware.InnoSetup -e --scope user
    $iscc = @(
        $env:ISCC,
        (Get-Command 'ISCC.exe' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1),
        (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    if (-not $iscc) {
        Write-Warning 'Inno Setup (ISCC.exe) not found; skipping the installer.'
        return
    }
    & $iscc /Q "/DAppVersion=$Version" "/DStage=$stage" "/DOutDir=$dist" 'packaging/windissect.iss'
    if ($LASTEXITCODE -ne 0) { throw "installer build failed ($LASTEXITCODE)" }
    $setup = Join-Path $dist "Windissect-v$Version-setup-x64.exe"
    $setupHash = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath "$setup.sha256" -Value "$setupHash  $([IO.Path]::GetFileName($setup))" -Encoding ascii
    Write-Host "Installer:    $setup"
    Write-Host "SHA-256:      $setupHash"
}
finally {
    Pop-Location
}
