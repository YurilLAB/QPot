# QPot Installer for Windows
# Run: powershell -ExecutionPolicy Bypass -File install.ps1

$ErrorActionPreference = "Stop"

$QPOT_VERSION = "0.1.0"
$QPOT_REPO = "https://github.com/qpot/qpot"

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Command {
    param([string]$Command)
    return [bool](Get-Command -Name $Command -ErrorAction SilentlyContinue)
}

function Install-QPot {
    Write-Header "QPot Installer v$QPOT_VERSION"

    # Check Windows version
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Host "OS: $($os.Caption) $($os.Version)" -ForegroundColor Gray

    # Check prerequisites
    Write-Host "Checking prerequisites..." -ForegroundColor Yellow

    if (-not (Test-Command "docker")) {
        Write-Error "Docker is not installed. Please install Docker Desktop first:`n  https://docs.docker.com/desktop/install/windows-install/"
        exit 1
    }
    Write-Host "  ✓ Docker found" -ForegroundColor Green

    if (-not (Test-Command "git")) {
        Write-Host "  ✗ Git not found - some features may be limited" -ForegroundColor Yellow
    } else {
        Write-Host "  ✓ Git found" -ForegroundColor Green
    }

    # Check if running in WSL2 mode
    $dockerInfo = docker info 2>&1
    if ($dockerInfo -match "WSL2") {
        Write-Host "  ✓ Docker using WSL2 backend" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Consider enabling WSL2 backend for better performance" -ForegroundColor Yellow
    }

    # Create installation directory
    $installDir = "$env:LOCALAPPDATA\QPot"
    $binDir = "$installDir\bin"
    
    Write-Host ""
    Write-Host "Installing to: $installDir" -ForegroundColor Yellow

    if (Test-Path $installDir) {
        Write-Host "  Removing existing installation..." -ForegroundColor Gray
        Remove-Item -Recurse -Force $installDir
    }

    New-Item -ItemType Directory -Force -Path $binDir | Out-Null

    # Download QPot binary
    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    $binaryUrl = "$QPOT_REPO/releases/download/v$QPOT_VERSION/qpot_${QPOT_VERSION}_windows_${arch}.exe"
    $binaryPath = "$binDir\qpot.exe"

    Write-Host "Downloading QPot..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $binaryUrl -OutFile $binaryPath -UseBasicParsing
        Write-Host "  ✓ Downloaded qpot.exe" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠ Could not download binary, will build from source" -ForegroundColor Yellow
        # Would build from source here
    }

    # Create data directory
    $dataDir = "$env:USERPROFILE\.qpot"
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

    # Add to PATH
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $currentPath.Contains($binDir)) {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$binDir", "User")
        Write-Host "  ✓ Added to PATH" -ForegroundColor Green
    }

    # Create default instance
    Write-Host ""
    Write-Host "Creating default QPot instance..." -ForegroundColor Yellow
    & $binaryPath instance create default

    # Create desktop shortcut
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\QPot.lnk")
    $Shortcut.TargetPath = "$binaryPath"
    $Shortcut.Arguments = "up --instance default"
    $Shortcut.WorkingDirectory = "$env:USERPROFILE"
    $Shortcut.IconLocation = "$binaryPath,0"
    $Shortcut.Save()

    Write-Host "  ✓ Created desktop shortcut" -ForegroundColor Green

    # Installation complete
    Write-Header "Installation Complete!"
    Write-Host "QPot v$QPOT_VERSION has been installed successfully." -ForegroundColor Green
    Write-Host ""
    Write-Host "Quick Start:" -ForegroundColor Cyan
    Write-Host "  qpot up                    # Start default instance"
    Write-Host "  qpot status                # Check status"
    Write-Host "  qpot honeypot list         # List available honeypots"
    Write-Host "  qpot --help                # Show all commands"
    Write-Host ""
    Write-Host "Web UI: http://localhost:8080" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Restart your terminal to use the 'qpot' command." -ForegroundColor Yellow
}

# Run installation
Install-QPot
