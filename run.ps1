param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvDir = Join-Path $repoRoot ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"
$requirements = Join-Path $repoRoot "requirements.txt"

if (-not (Test-Path $venvPython)) {
    Write-Host ("Creating venv: {0}" -f $venvDir)
    python -m venv $venvDir
}

if (Test-Path $requirements) {
    Write-Host "Installing dependencies (requirements.txt)..."
    & $venvPython -m pip --disable-pip-version-check --quiet install --progress-bar off -r $requirements | Out-Host
} else {
    Write-Host "Installing dependencies (pyproject.toml)..."
    & $venvPython -m pip --disable-pip-version-check --quiet install --progress-bar off -e $repoRoot | Out-Host
}

& $venvPython -m cursor_mover @Args
exit $LASTEXITCODE

