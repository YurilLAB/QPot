# QPot Installer for Windows
# Run: powershell -ExecutionPolicy Bypass -File install.ps1
#  or: irm https://raw.githubusercontent.com/YurilLAB/QPot/main/scripts/install.ps1 | iex
#
# Installs the qpot program, then offers to run `qpot setup`, which checks the
# computer, installs Docker Desktop when you agree, and starts your first
# honeypot. Set $env:QPOT_NO_SETUP = "1" to install the program only, or
# $env:QPOT_SETUP_ARGS = "--yes" to run setup with those arguments.
#
# Every failure prints an error code (QP-...) explained in doc/setup-errors.md
# and exits with that code's category status, the same as `qpot setup`.

$ErrorActionPreference = "Stop"

$QPOT_VERSION = "0.1.0"
$QPOT_REPO = "https://github.com/YurilLAB/QPot"

# Exit status per error-code category: the same table as `qpot setup`
# (internal/hostsetup/errors.go); a Go test checks they agree.
$ExitStatus = @{
    'HOST' = 11
    'PERM' = 12
    'NET' = 13
    'BUG' = 70
}

# A coded failure: Stop-Coded records it and stops; the handler at the end
# prints it in plain words and exits with its category's status.
$script:Coded = $null

function Stop-Coded {
    param([string]$Code, [string]$What, [string]$Why, [string]$Fix)
    $script:Coded = @{ Code = $Code; What = $What; Why = $Why; Fix = $Fix }
    throw "$Code $What"
}

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

    if (-not [Environment]::Is64BitOperatingSystem) {
        Stop-Coded "QP-HOST-002" "This processor type (32-bit) is not supported." `
            "QPot and Docker Desktop need 64-bit Windows." `
            "Use a 64-bit Windows computer or a Linux server."
    }

    # Docker is not required here: `qpot setup` offers to install Docker
    # Desktop (with winget) and asks before it does.
    Write-Host "Checking prerequisites..." -ForegroundColor Yellow
    if (-not (Test-Command "docker")) {
        Write-Host "  Docker Desktop is not installed yet. 'qpot setup' will show how it installs it and ask you first." -ForegroundColor Yellow
    } else {
        Write-Host "  Docker found" -ForegroundColor Green
        $null = docker info 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  Docker is installed but not running - 'qpot setup' can start Docker Desktop." -ForegroundColor Yellow
        }
    }

    # Create installation directory
    $installDir = "$env:LOCALAPPDATA\QPot"
    $binDir = "$installDir\bin"

    Write-Host ""
    Write-Host "Installing to: $installDir" -ForegroundColor Yellow

    try {
        if (Test-Path $installDir) {
            Write-Host "  Removing existing installation..." -ForegroundColor Gray
            Remove-Item -Recurse -Force $installDir
        }
        New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    } catch {
        Stop-Coded "QP-PERM-007" "The folder $installDir could not be prepared." `
            "It is not writable, a file in it is in use, or the disk is full. ($($_.Exception.Message))" `
            "Close any running qpot program, check the folder's permissions and free space, then run the installer again."
    }

    # Download QPot binary
    $binaryUrl = "$QPOT_REPO/releases/download/v$QPOT_VERSION/qpot_${QPOT_VERSION}_windows_amd64.exe"
    $binaryPath = "$binDir\qpot.exe"

    Write-Host "Downloading QPot..." -ForegroundColor Yellow
    $downloaded = $false
    try {
        Invoke-WebRequest -Uri $binaryUrl -OutFile $binaryPath -UseBasicParsing -TimeoutSec 300
        Write-Host "  Downloaded qpot.exe" -ForegroundColor Green
        $downloaded = $true
    } catch {
        Write-Host "  No prebuilt binary available, building from source..." -ForegroundColor Yellow
    }

    if (-not $downloaded) {
        if (-not (Test-Command "go")) {
            Stop-Coded "QP-HOST-006" "No ready-made QPot download exists for this computer, and Go is not installed to build it." `
                "Building QPot from source needs Go and git." `
                "Install Go from https://go.dev/dl/ (or download a release from $QPOT_REPO/releases), then run the installer again."
        }
        if (-not (Test-Command "git")) {
            Stop-Coded "QP-HOST-006" "git is needed to build QPot from source, but it is not installed." `
                "No ready-made QPot download exists for this computer, so the installer builds it." `
                "Install Git for Windows (winget install -e --id Git.Git), then run the installer again."
        }
        $srcDir = "$installDir\src"
        Write-Host "  Cloning $QPOT_REPO ..." -ForegroundColor Gray
        & git clone --depth 1 "$QPOT_REPO.git" $srcDir 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Stop-Coded "QP-NET-007" "The QPot source code could not be downloaded." `
                "git could not reach $QPOT_REPO.git (no internet connection, or GitHub is blocked)." `
                "Check the internet connection and run the installer again."
        }
        Write-Host "  Building qpot.exe with Go..." -ForegroundColor Gray
        # Let Go fetch the exact toolchain go.mod pins instead of failing on a
        # 'go.mod requires go >= ...' error with an older (>=1.21) Go.
        if (-not $env:GOTOOLCHAIN) { $env:GOTOOLCHAIN = "auto" }
        Push-Location $srcDir
        & go build -o $binaryPath .\cmd\qpot
        $buildExit = $LASTEXITCODE
        Pop-Location
        if ($buildExit -ne 0) {
            Stop-Coded "QP-HOST-008" "Building QPot from source failed." `
                "The Go build stopped with an error (shown above); an old Go or no internet access for Go's downloads are the usual reasons." `
                "Read the build output above, update Go if it is old, and run the installer again."
        }
        Write-Host "  Built qpot.exe from source" -ForegroundColor Green
    }

    # Verify the binary actually runs before claiming success (catches a
    # wrong-arch download or a corrupt build).
    & $binaryPath --version 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Stop-Coded "QP-HOST-007" "The installed qpot program does not run on this computer." `
            "The download was probably for a different processor type, or it was damaged." `
            "Build it from source: git clone $QPOT_REPO.git; cd QPot; go build -o qpot.exe .\cmd\qpot"
    }

    # Create data directory
    $dataDir = "$env:USERPROFILE\.qpot"
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

    # Add to PATH. The User Path can be unset (null) on a fresh profile, so
    # coalesce to "" before calling .Contains to avoid a null-reference error.
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $currentPath) { $currentPath = "" }
    if (-not $currentPath.Contains($binDir)) {
        $newPath = if ($currentPath -eq "") { $binDir } else { "$currentPath;$binDir" }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Write-Host "  Added to PATH" -ForegroundColor Green
    }

    # Create desktop shortcut
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\QPot.lnk")
    $Shortcut.TargetPath = "$binaryPath"
    $Shortcut.Arguments = "up --instance default"
    $Shortcut.WorkingDirectory = "$env:USERPROFILE"
    $Shortcut.IconLocation = "$binaryPath,0"
    $Shortcut.Save()

    Write-Host "  Created desktop shortcut" -ForegroundColor Green

    # Installation complete
    Write-Header "Installation Complete!"
    Write-Host "QPot v$QPOT_VERSION has been installed successfully." -ForegroundColor Green
    Write-Host ""
    Write-Host "Next: set up your first honeypot with" -ForegroundColor Cyan
    Write-Host "  qpot setup"
    Write-Host "It checks this computer, installs Docker Desktop if needed (it shows the"
    Write-Host "command and asks first), starts QPot and prints the web UI address and how to log in."
    Write-Host ""
    Write-Host "Other commands:" -ForegroundColor Cyan
    Write-Host "  qpot doctor                # Check it end to end at any time"
    Write-Host "  qpot status                # Check status"
    Write-Host "  qpot honeypot list         # List available honeypots"
    Write-Host "  qpot --help                # Show all commands"
    Write-Host ""
    Write-Host "Open a new terminal to use the 'qpot' command by name." -ForegroundColor Yellow
    return $binaryPath
}

# Run installation with a plain-words, coded failure message on any error.
$exitCode = 0
try {
    $qpot = Install-QPot
    if ($env:QPOT_NO_SETUP -ne "1" -and $env:QPOT_SETUP_ARGS) {
        # The same hand-over as install.sh: run setup with these arguments.
        $setupArgs = @($env:QPOT_SETUP_ARGS -split '\s+' | Where-Object { $_ })
        & $qpot setup @setupArgs
        $exitCode = $LASTEXITCODE
    } elseif ($env:QPOT_NO_SETUP -ne "1" -and [Environment]::UserInteractive) {
        $answer = Read-Host "Run 'qpot setup' now? [Y/n]"
        if ($answer -eq "" -or $answer -match '^(y|yes)$') {
            & $qpot setup
            $exitCode = $LASTEXITCODE
        } else {
            Write-Host "OK. Run 'qpot setup' when you are ready."
        }
    }
} catch {
    $c = $script:Coded
    if ($null -eq $c) {
        $c = @{ Code = "QP-BUG-002"; What = "The installer stopped unexpectedly."; Why = $_.Exception.Message;
                Fix = "Run the installer again. If it happens again, report it at $QPOT_REPO/issues" }
    }
    $cat = ($c.Code -split '-')[1]
    Write-Host ""
    Write-Host "ERROR $($c.Code): $($c.What)" -ForegroundColor Red
    Write-Host "  Why:  $($c.Why)"
    Write-Host "  Fix:  $($c.Fix)"
    Write-Host "  More: $QPOT_REPO/blob/main/doc/setup-errors.md"
    $exitCode = $ExitStatus[$cat]
}
# `irm ... | iex` runs this inside the user's own PowerShell session, which
# `exit` would close; only a script run from a file exits with the status.
if ($PSCommandPath) {
    exit $exitCode
}
$global:LASTEXITCODE = $exitCode
