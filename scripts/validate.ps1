# Validacion base del workspace. PowerShell 5.1, ASCII.
# Se detiene en el primer fallo y sale con codigo distinto de 0.

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$workspace = Join-Path $repoRoot 'rust-workspace'

function Stop-Validation {
    param([string]$Step)
    Write-Host ''
    Write-Host ('FALLO en el paso: ' + $Step) -ForegroundColor Red
    exit 1
}

function Invoke-Step {
    param([string]$Name, [scriptblock]$Command)
    Write-Host ''
    Write-Host ('==> ' + $Name) -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) { Stop-Validation $Name }
}

Push-Location $workspace
try {
    Invoke-Step 'cargo build --workspace' { cargo build --workspace }
    Invoke-Step 'cargo test --workspace' { cargo test --workspace }
    Invoke-Step 'cargo clippy --workspace --all-targets -- -D warnings' {
        cargo clippy --workspace --all-targets -- -D warnings
    }
    Invoke-Step 'cargo deny check' { cargo deny check }
    Invoke-Step 'git diff --check HEAD' { git -C $repoRoot diff --check HEAD }

    # Formato SOLO-ARCHIVOS-TOCADOS: .rs modificados frente a HEAD y .rs nuevos sin seguimiento.
    Write-Host ''
    Write-Host '==> rustfmt --edition 2024 --check (solo .rs tocados)' -ForegroundColor Cyan
    $modified = @(git -C $repoRoot diff --name-only --diff-filter=d HEAD -- '*.rs')
    if ($LASTEXITCODE -ne 0) { Stop-Validation 'git diff --name-only (rustfmt)' }
    $untracked = @(git -C $repoRoot ls-files --others --exclude-standard -- '*.rs')
    if ($LASTEXITCODE -ne 0) { Stop-Validation 'git ls-files (rustfmt)' }
    $files = @($modified + $untracked | Where-Object { $_ } | Sort-Object -Unique)
    if ($files.Count -eq 0) {
        Write-Host 'sin .rs tocados'
    }
    else {
        $paths = @($files | ForEach-Object { Join-Path $repoRoot $_ })
        rustfmt --edition 2024 --check @paths
        if ($LASTEXITCODE -ne 0) { Stop-Validation 'rustfmt --edition 2024 --check' }
    }
}
finally {
    Pop-Location
}

Write-Host ''
Write-Host 'VALIDACION OK' -ForegroundColor Green
exit 0
