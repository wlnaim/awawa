# Empaquetado portable. PowerShell 5.1, ASCII.
# Compila el workspace en release y arma dist\Awawa-<version>\ con los
# 6 .exe, un README de despliegue y SHA256SUMS.txt. Despues compila el instalador
# con esos 6 .exe embebidos (AWAWA_INSTALLER_PAYLOAD) y lo deja en
# dist\Awawa-Setup-<version>.exe, con su hash en el mismo nombre + .sha256.
#
# Firma Authenticode: solo si se pasa -CertThumbprint. Sin huella NO se firma.
#   -DryRunSign  imprime los comandos de firma y verificacion sin ejecutarlos.
# Con huella se firman los 6 .exe ANTES de embeberlos y despues el Setup.

[CmdletBinding()]
param(
    [string]$CertThumbprint = '',
    [string]$TimestampUrl = 'http://timestamp.digicert.com',
    [switch]$DryRunSign
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$workspace = Join-Path $repoRoot 'rust-workspace'
$exeNames = @(
    'awawa-host.exe', 'awawa-operator.exe', 'awawa-relay.exe',
    'awawa-service.exe', 'awawa-admin.exe', 'awawa-session-agent.exe'
)

if ($DryRunSign -and -not $CertThumbprint) {
    throw '-DryRunSign requiere -CertThumbprint.'
}

# Version del workspace ([workspace.package] version).
$cargoToml = Get-Content -LiteralPath (Join-Path $workspace 'Cargo.toml')
$versionLine = $cargoToml | Where-Object { $_ -match '^version\s*=\s*"([^"]+)"' } | Select-Object -First 1
if (-not $versionLine) { throw 'No se encontro la version en rust-workspace\Cargo.toml.' }
$null = $versionLine -match '^version\s*=\s*"([^"]+)"'
$version = $Matches[1]

# Build release reproducible: las rutas absolutas de la maquina se reemplazan por
# prefijos fijos. CARGO_ENCODED_RUSTFLAGS sustituye a los rustflags de
# .cargo\config.toml, por eso se repiten aqui (mantener sincronizados).
$cargoHome = $env:CARGO_HOME
if (-not $cargoHome) { $cargoHome = Join-Path $env:USERPROFILE '.cargo' }
$flags = @(
    '-C', 'control-flow-guard=checks',
    '-C', 'target-feature=+crt-static',
    '-C', 'link-arg=/Brepro',
    ('--remap-path-prefix=' + $workspace + '=/ws'),
    ('--remap-path-prefix=' + $cargoHome + '=/cargo')
)
$env:CARGO_ENCODED_RUSTFLAGS = ($flags -join [string][char]0x1f)
Remove-Item Env:\RUSTFLAGS -ErrorAction SilentlyContinue

Push-Location $workspace
try {
    Write-Host '==> cargo build --workspace --release --locked' -ForegroundColor Cyan
    cargo build --workspace --release --locked
    if ($LASTEXITCODE -ne 0) { throw 'cargo build fallo.' }
} finally {
    Pop-Location
    Remove-Item Env:\CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
}

# Carpeta portable.
$releaseDir = Join-Path $workspace 'target\release'
$pkgDir = Join-Path $repoRoot ('dist\Awawa-' + $version)
if (Test-Path -LiteralPath $pkgDir) { Remove-Item -LiteralPath $pkgDir -Recurse -Force }
New-Item -ItemType Directory -Path $pkgDir | Out-Null

foreach ($name in $exeNames) {
    $src = Join-Path $releaseDir $name
    if (-not (Test-Path -LiteralPath $src)) { throw ('Falta el binario: ' + $src) }
    Copy-Item -LiteralPath $src -Destination (Join-Path $pkgDir $name)
}

$readme = @"
Awawa $version - paquete portable
===============================================

Contenido
  awawa-relay.exe          Relay ciego (QUIC). Se despliega PRIMERO.
  awawa-service.exe        Servicio de Windows (acceso desatendido).
  awawa-session-agent.exe  Agente de sesion lanzado por el servicio.
  awawa-admin.exe          Administracion del acceso desatendido.
  awawa-host.exe           Receptor (bajo demanda) en el equipo a asistir.
  awawa-operator.exe       Consola del operador.
  SHA256SUMS.txt             Hashes de los .exe (se calculan tras firmar).

Orden de despliegue
  1. Relay primero.
  2. awawa-service, awawa-session-agent y awawa-admin SIEMPRE juntos
     (misma version); mezclar versiones deja el desatendido sin servicio.
  3. Host y operador.

Reversion: un binario anterior rechaza el verificador v2 y deja el desatendido
deshabilitado. Para volver atras, borrar
%ProgramData%\Awawa\unattended.verifier y reconfigurar.
"@
[System.IO.File]::WriteAllText((Join-Path $pkgDir 'README.txt'), ($readme -replace "`r`n", "`n"), [System.Text.Encoding]::ASCII)

# Firma Authenticode (opcional).
if ($CertThumbprint) {
    $signtool = (Get-Command signtool.exe -ErrorAction SilentlyContinue | Select-Object -First 1)
    $signtoolPath = $null
    if ($signtool) {
        $signtoolPath = $signtool.Source
    } else {
        $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
        $found = Get-ChildItem -Path $kits -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
        if ($found) { $signtoolPath = $found.FullName }
    }
    if (-not $signtoolPath) {
        if ($DryRunSign) { $signtoolPath = 'signtool.exe' } else { throw 'No se encontro signtool.exe (Windows SDK).' }
    }
}

function Invoke-Sign {
    param([string]$File)
    $name = Split-Path -Leaf $File
    $signArgs = @('sign', '/sha1', $CertThumbprint, '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256', $File)
    $verifyArgs = @('verify', '/pa', $File)
    if ($DryRunSign) {
        Write-Host ('[dry-run] ' + $signtoolPath + ' ' + ($signArgs -join ' '))
        Write-Host ('[dry-run] ' + $signtoolPath + ' ' + ($verifyArgs -join ' '))
    } else {
        & $signtoolPath @signArgs
        if ($LASTEXITCODE -ne 0) { throw ('signtool sign fallo en ' + $name) }
        & $signtoolPath @verifyArgs
        if ($LASTEXITCODE -ne 0) { throw ('signtool verify fallo en ' + $name) }
    }
}

if ($CertThumbprint) {
    foreach ($name in $exeNames) { Invoke-Sign (Join-Path $pkgDir $name) }
}

# Instalador: el mismo build del workspace con AWAWA_INSTALLER_PAYLOAD apuntando a $pkgDir;
# solo el build.rs de awawa-installer se vuelve a ejecutar (embebe los 6 .exe ya firmados).
$setupName = 'Awawa-Setup-' + $version + '.exe'
$setupPath = Join-Path $repoRoot ('dist\' + $setupName)
foreach ($old in @($setupPath, ($setupPath + '.sha256'))) {
    if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old -Force }
}
$env:CARGO_ENCODED_RUSTFLAGS = ($flags -join [string][char]0x1f)
$env:AWAWA_INSTALLER_PAYLOAD = $pkgDir
Push-Location $workspace
try {
    Write-Host '==> cargo build --workspace --release --locked (instalador con carga)' -ForegroundColor Cyan
    cargo build --workspace --release --locked
    if ($LASTEXITCODE -ne 0) { throw 'cargo build del instalador fallo.' }
} finally {
    Pop-Location
    Remove-Item Env:\CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
    Remove-Item Env:\AWAWA_INSTALLER_PAYLOAD -ErrorAction SilentlyContinue
}
Copy-Item -LiteralPath (Join-Path $releaseDir 'awawa-installer.exe') -Destination $setupPath

if ($CertThumbprint) {
    Invoke-Sign $setupPath
    if ($DryRunSign) { Write-Host 'Firma simulada (dry-run): no se firmo nada.' }
} else {
    Write-Host 'SIN FIRMAR: pendiente certificado'
}

# SHA256SUMS.txt (despues de firmar, porque la firma cambia los hashes).
$lines = foreach ($name in $exeNames) {
    $h = (Get-FileHash -LiteralPath (Join-Path $pkgDir $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    $h + ' *' + $name
}
[System.IO.File]::WriteAllText((Join-Path $pkgDir 'SHA256SUMS.txt'), (($lines -join "`n") + "`n"), [System.Text.Encoding]::ASCII)

# Hash del Setup en su propio archivo, junto a el en dist\.
$setupHash = (Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText(($setupPath + '.sha256'), ($setupHash + ' *' + $setupName + "`n"), [System.Text.Encoding]::ASCII)

Write-Host ''
Write-Host ('Paquete: ' + $pkgDir) -ForegroundColor Green
Get-Content -LiteralPath (Join-Path $pkgDir 'SHA256SUMS.txt')
Write-Host ('Instalador: ' + $setupPath) -ForegroundColor Green
Get-Content -LiteralPath ($setupPath + '.sha256')
