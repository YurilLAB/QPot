# genuserwin.ps1 — Windows counterpart of genuser.sh. Reads QPOT_REPO and
# QPOT_VERSION from .env so both platforms run the same image, instead of
# the previous hardcoded dtagdevsec/qpotinit:24.04.1.
$ErrorActionPreference = 'Stop'

# Resolve repo root (script directory) so the script works regardless of
# the caller's CWD.
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$envFile = Join-Path $repoRoot '.env'

if (-not (Test-Path $envFile)) {
    Write-Error "Cannot find .env at $envFile. Run from the qpotce repo root."
    exit 1
}

function Get-EnvValue([string]$key) {
    $line = Select-String -Path $envFile -Pattern "^$key=" | Select-Object -First 1
    if (-not $line) { return $null }
    return ($line.Line -split '=', 2)[1].Trim('"').Trim("'")
}

$qpotRepo = Get-EnvValue 'QPOT_REPO'
$qpotVersion = Get-EnvValue 'QPOT_VERSION'

if (-not $qpotRepo -or -not $qpotVersion) {
    Write-Error "QPOT_REPO or QPOT_VERSION missing from $envFile."
    exit 1
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error 'docker is not installed or not on PATH.'
    exit 1
}

$homePath = Join-Path $Env:USERPROFILE 'qpotce'
$nginxpasswdPath = Join-Path $homePath 'data\nginx\conf\nginxpasswd'

# Ensure the bind-mount root and the nginxpasswd file exist before docker
# is invoked, otherwise docker creates them with the wrong ownership.
if (-not (Test-Path $homePath)) {
    New-Item -ItemType Directory -Force -Path $homePath | Out-Null
}
if (-not (Test-Path $nginxpasswdPath)) {
    New-Item -ItemType File -Force -Path $nginxpasswdPath | Out-Null
}

Write-Host "### Repository:   $qpotRepo"
Write-Host "### Version Tag:  $qpotVersion"
Write-Host ''

# UID/GID are intentionally not passed — Docker Desktop on Windows runs
# the engine in a Linux VM where the host UID has no meaning.
docker run --rm `
    -v "${homePath}:/data" `
    --entrypoint bash `
    -it `
    "${qpotRepo}/qpotinit:${qpotVersion}" `
    '/opt/qpot/bin/genuser.sh'
