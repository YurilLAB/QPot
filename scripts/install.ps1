# QPot Installer for Windows
# Run: powershell -ExecutionPolicy Bypass -File install.ps1
#  or: irm https://raw.githubusercontent.com/YurilLAB/QPot/main/scripts/install.ps1 | iex
#
# Installs the qpot program, then offers to run `qpot setup`, which checks the
# computer, installs Docker Desktop when you agree, and starts your first
# honeypot. Set $env:QPOT_NO_SETUP = "1" to install the program only, or
# $env:QPOT_SETUP_ARGS = "--yes" to run setup with those arguments.
#
# What it installs is checked before anything is put in place: the release's
# SHA256SUMS list is downloaded and the archive must match its entry there;
# downloads come only from GitHub's release servers (a redirect anywhere else
# stops it); with the GitHub CLI (gh) installed, the archive's build
# provenance is verified too ($env:QPOT_REQUIRE_PROVENANCE = "1" makes that
# mandatory). Without a published release it builds from source, but only
# the commit pinned below, which git checks by its hash.
#
# More settings: $env:QPOT_NO_PATH = "1" does not add QPot to your PATH,
# $env:QPOT_NO_SHORTCUT = "1" makes no desktop shortcut, and
# $env:QPOT_DOWNLOAD_BASE sets the releases' download address (a mirror; it
# must be https://, plain http only to this computer).
#
# Every failure prints an error code (QP-...) explained in doc/setup-errors.md
# and exits with that code's category status, the same as `qpot setup`.

$ErrorActionPreference = "Stop"

$QPOT_VERSION = "0.1.0"
$QPOT_REPO = "https://github.com/YurilLAB/QPot"
$QPOT_GH_REPO = "YurilLAB/QPot"
# The one commit the installer builds when no release is published: a main
# commit that passed CI until the first release, then the tag's commit (see
# "Releases" in README.md). git checks the checkout is exactly this commit;
# a test checks both installers pin the same commit from main's history.
$QPOT_SOURCE_COMMIT_PINNED = "c285a2e1cd5e5b6a9d3675619698b804c3e3c209"

$DownloadBase = if ($env:QPOT_DOWNLOAD_BASE) { $env:QPOT_DOWNLOAD_BASE } else { "$QPOT_REPO/releases/download" }
$SourceRepo = if ($env:QPOT_SOURCE_REPO) { $env:QPOT_SOURCE_REPO } else { "$QPOT_REPO.git" }
$SourceCommit = if ($env:QPOT_SOURCE_COMMIT) { $env:QPOT_SOURCE_COMMIT } else { $QPOT_SOURCE_COMMIT_PINNED }

# Exit status per error-code category: the same table as `qpot setup`
# (internal/hostsetup/errors.go); a Go test checks they agree.
$ExitStatus = @{
    'INPUT' = 10
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

# Invoke-Program runs a program and returns its exit status and output.
# Windows PowerShell 5.1 turns a program's stderr into a terminating error
# when $ErrorActionPreference is Stop, so it is relaxed here only.
function Invoke-Program {
    param([string]$Exe, [string[]]$Arguments)
    $ErrorActionPreference = "Continue"
    $out = & $Exe @Arguments 2>&1 | ForEach-Object { "$_" }
    return @{ Code = $LASTEXITCODE; Output = @($out) }
}

# Get-UrlOrigin returns the URL's origin (scheme://host[:port], lower case),
# or $null for anything but an http(s) URL without a user name.
function Get-UrlOrigin {
    param([string]$Url)
    $m = [regex]::Match($Url, '^([Hh][Tt][Tt][Pp][Ss]?://[\[\]A-Za-z0-9.:-]+)(/|$)')
    if (-not $m.Success) { return $null }
    return $m.Groups[1].Value.ToLowerInvariant()
}

# The origins downloads may come from: the download base, and for GitHub its
# two release-asset servers (github.com answers with a redirect to one).
$script:AllowedOrigins = @()
function Set-DownloadBase {
    $origin = Get-UrlOrigin $DownloadBase
    if ($null -eq $origin) {
        Stop-Coded "QP-INPUT-012" "QPOT_DOWNLOAD_BASE ($DownloadBase) is not a usable web address." `
            "It must be an https:// address such as $QPOT_REPO/releases/download" `
            "Remove QPOT_DOWNLOAD_BASE, or set it to the https:// address of a mirror of QPot's releases."
    }
    $local = $origin -match '^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?$'
    if (-not $origin.StartsWith("https://") -and -not $local) {
        Stop-Coded "QP-INPUT-012" "QPOT_DOWNLOAD_BASE ($DownloadBase) is not an https:// address." `
            "Downloads over plain http can be changed by anyone on the network." `
            "Remove QPOT_DOWNLOAD_BASE, or use the https:// address of the mirror."
    }
    $script:AllowedOrigins = @($origin)
    if ($origin -eq "https://github.com") {
        $script:AllowedOrigins += @("https://objects.githubusercontent.com", "https://release-assets.githubusercontent.com")
    }
}

# Invoke-Fetch downloads Url to Dest, following redirects one at a time and
# only to allowed origins. Status: 0 downloaded, 10 no such file, 11 a
# redirect pointed elsewhere, 12 any other failure (Detail says which).
function Invoke-Fetch {
    param([string]$Url, [string]$Dest)
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(300)
    try {
        for ($hop = 0; $hop -le 5; $hop++) {
            $origin = Get-UrlOrigin $Url
            if ($null -eq $origin -or $script:AllowedOrigins -notcontains $origin) {
                return @{ Status = 11; Detail = "redirected to $(($Url -split '\?')[0])" }
            }
            try {
                $resp = $client.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            } catch {
                return @{ Status = 12; Detail = $_.Exception.GetBaseException().Message }
            }
            try {
                $code = [int]$resp.StatusCode
                if ($code -ge 300 -and $code -lt 400 -and $null -ne $resp.Headers.Location) {
                    $Url = (New-Object System.Uri((New-Object System.Uri($Url)), $resp.Headers.Location)).AbsoluteUri
                    continue
                }
                if ($code -eq 404 -or $code -eq 410) { return @{ Status = 10; Detail = "not found" } }
                if ($code -ne 200) { return @{ Status = 12; Detail = "the server answered HTTP $code" } }
                $want = $resp.Content.Headers.ContentLength
                $out = [System.IO.File]::Create($Dest)
                try {
                    $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult().CopyTo($out)
                } catch {
                    return @{ Status = 12; Detail = "the download stopped early: $($_.Exception.GetBaseException().Message)" }
                } finally {
                    $out.Dispose()
                }
                $got = (Get-Item -LiteralPath $Dest).Length
                if ($null -ne $want -and $got -ne $want) {
                    return @{ Status = 12; Detail = "the download stopped early ($got of $want bytes)" }
                }
                return @{ Status = 0; Detail = "" }
            } finally {
                $resp.Dispose()
            }
        }
        return @{ Status = 12; Detail = "too many redirects" }
    } finally {
        $client.Dispose()
    }
}

# Get-SumsEntry reads a SHA256SUMS list. Status 0 with the checksum for Name,
# 1 when the list breaks the format (then nothing in it is trusted), 2 when
# it has no entry for Name. The rules are those of
# internal/release.ParseSums; a Go test runs both on the same inputs.
function Get-SumsEntry {
    param([string]$Path, [string]$Name)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -gt 65536) { return @{ Status = 1 } }
    foreach ($b in $bytes) {
        # NUL and non-ASCII bytes never appear in a list the release writes.
        if ($b -eq 0 -or $b -gt 127) { return @{ Status = 1 } }
    }
    $text = [System.Text.Encoding]::ASCII.GetString($bytes)
    if ($text.EndsWith("`n")) { $text = $text.Substring(0, $text.Length - 1) }
    if ($text.Length -eq 0) { return @{ Status = 1 } }
    $lines = $text.Split("`n")
    if ($lines.Count -gt 256) { return @{ Status = 1 } }
    $seen = @{}
    $hash = $null
    foreach ($line in $lines) {
        $m = [regex]::Match($line, '^([0-9a-f]{64})(  | \*)([A-Za-z0-9][A-Za-z0-9._+-]{0,127})\z')
        if (-not $m.Success) { return @{ Status = 1 } }
        $n = $m.Groups[3].Value
        if ($n.Contains("..") -or $seen.ContainsKey($n)) { return @{ Status = 1 } }
        $seen[$n] = $true
        if ($n -ceq $Name) { $hash = $m.Groups[1].Value }
    }
    if ($null -eq $hash) { return @{ Status = 2 } }
    return @{ Status = 0; Hash = $hash }
}

function Get-FileSha256 {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $digest = $sha.ComputeHash($stream)
    } finally {
        $stream.Dispose()
        $sha.Dispose()
    }
    return (($digest | ForEach-Object { $_.ToString("x2") }) -join "")
}

# Test-GhAttestation reports whether gh can check the provenance the way
# Save-Release asks: an older gh without these flags cannot pin the workflow
# and the tag, so it counts as not installed.
function Test-GhAttestation {
    if (-not (Test-Command "gh")) { return $false }
    $env:GH_PROMPT_DISABLED = "1"
    $env:GH_NO_UPDATE_NOTIFIER = "1"
    $help = Invoke-Program "gh" @("attestation", "verify", "--help")
    if ($help.Code -ne 0) { return $false }
    $text = $help.Output -join "`n"
    foreach ($flag in @("--bundle", "--signer-workflow", "--source-ref", "--deny-self-hosted-runners")) {
        if (-not $text.Contains($flag)) { return $false }
    }
    return $true
}

function Stop-Redirect {
    param([string]$Detail)
    Stop-Coded "QP-NET-011" "A download was redirected to a server QPot does not publish from." `
        "$Detail. QPot releases come only from $DownloadBase and GitHub's download servers, so the installer stopped. Nothing was installed." `
        "Check for a proxy or a captive portal on this network, then run the installer again from a trusted network."
}

# Save-Release downloads this version's Windows archive, checks it against
# SHA256SUMS (and its provenance when gh is installed) and writes qpot.exe to
# ExePath. It returns $false when no release is published (no SHA256SUMS).
function Save-Release {
    param([string]$TempDir, [string]$ExePath)
    $rel = "$DownloadBase/v$QPOT_VERSION"
    $archive = "qpot_${QPOT_VERSION}_windows_amd64.zip"

    Write-Host "Downloading the checksum list of QPot v$QPOT_VERSION..." -ForegroundColor Yellow
    $sumsPath = Join-Path $TempDir "SHA256SUMS"
    $r = Invoke-Fetch "$rel/SHA256SUMS" $sumsPath
    switch ($r.Status) {
        0 { }
        10 {
            Write-Host "  No published release v$QPOT_VERSION (no SHA256SUMS); building from source" -ForegroundColor Yellow
            return $false
        }
        11 { Stop-Redirect $r.Detail }
        default {
            Stop-Coded "QP-NET-007" "The QPot checksum list could not be downloaded." `
                "$($r.Detail) ($rel/SHA256SUMS)" `
                "Check the internet connection and run the installer again."
        }
    }
    $entry = Get-SumsEntry $sumsPath $archive
    if ($entry.Status -eq 2) {
        Stop-Coded "QP-NET-010" "The release's checksum list has no entry for $archive." `
            "Without an entry the download cannot be checked, so nothing was installed." `
            "Run the installer again later. If it keeps happening, report it at $QPOT_REPO/issues"
    } elseif ($entry.Status -ne 0) {
        Stop-Coded "QP-NET-010" "The release's checksum list (SHA256SUMS) is not valid." `
            "It is not in the format the release writes, so none of it is trusted and nothing was installed." `
            "Run the installer again later. If it keeps happening, report it at $QPOT_REPO/issues"
    }

    Write-Host "Downloading $archive..." -ForegroundColor Yellow
    $zip = Join-Path $TempDir $archive
    $r = Invoke-Fetch "$rel/$archive" $zip
    switch ($r.Status) {
        0 { }
        10 {
            Stop-Coded "QP-NET-007" "The QPot download failed." `
                "The release lists $archive, but the file is missing." `
                "Run the installer again later. If it keeps happening, report it at $QPOT_REPO/issues"
        }
        11 { Stop-Redirect $r.Detail }
        default {
            Stop-Coded "QP-NET-007" "The QPot download failed." "$($r.Detail) ($archive). Nothing was installed." `
                "Check the internet connection and run the installer again."
        }
    }
    $got = Get-FileSha256 $zip
    if ($got -ne $entry.Hash) {
        Stop-Coded "QP-NET-009" "The QPot download does not match its published checksum." `
            "$archive has SHA-256 $got, but SHA256SUMS says $($entry.Hash). It was damaged or changed on the way; nothing was installed." `
            "Run the installer again. If it happens again, do not install from this network; report it at $QPOT_REPO/issues"
    }
    Write-Host "  Checksum matches SHA256SUMS ($got)" -ForegroundColor Green

    if (Test-GhAttestation) {
        $bundleName = "qpot_${QPOT_VERSION}_provenance.sigstore.json"
        $bundle = Join-Path $TempDir $bundleName
        $r = Invoke-Fetch "$rel/$bundleName" $bundle
        if ($r.Status -eq 11) { Stop-Redirect $r.Detail }
        if ($r.Status -ne 0) {
            Stop-Coded "QP-NET-012" "The build provenance of the QPot download could not be verified." `
                "The release's provenance file ($bundleName) could not be downloaded: $($r.Detail). Nothing was installed." `
                "Run the installer again. If it keeps happening, report it at $QPOT_REPO/issues"
        }
        $env:GH_PROMPT_DISABLED = "1"
        $gh = Invoke-Program "gh" @("attestation", "verify", $zip, "--bundle", $bundle, "--repo", $QPOT_GH_REPO,
            "--signer-workflow", "$QPOT_GH_REPO/.github/workflows/release.yml",
            "--source-ref", "refs/tags/v$QPOT_VERSION", "--deny-self-hosted-runners")
        if ($gh.Code -ne 0) {
            $gh.Output | Select-Object -Last 5 | ForEach-Object { Write-Host "  $_" }
            Stop-Coded "QP-NET-012" "The build provenance of the QPot download could not be verified." `
                "The GitHub CLI could not confirm that QPot's release workflow built this file from tag v$QPOT_VERSION. Nothing was installed." `
                "Run the installer again. If it fails again, do not use this download; report it at $QPOT_REPO/issues"
        }
        Write-Host "  Build provenance verified: built by $QPOT_GH_REPO's release workflow from tag v$QPOT_VERSION" -ForegroundColor Green
    } elseif ($env:QPOT_REQUIRE_PROVENANCE -eq "1") {
        Stop-Coded "QP-NET-012" "The build provenance of the QPot download could not be verified." `
            "QPOT_REQUIRE_PROVENANCE=1 is set, but the GitHub CLI (gh) is not installed, or is too old to check the workflow and the tag (its gh attestation verify has no --source-ref). Nothing was installed." `
            "Install or update the GitHub CLI (winget install -e --id GitHub.cli), or remove QPOT_REQUIRE_PROVENANCE, then run the installer again."
    } else {
        Write-Host "  Build provenance not checked (the GitHub CLI 'gh' is not installed, or is too old). To check it yourself:" -ForegroundColor Gray
        Write-Host "    gh attestation verify $archive --repo $QPOT_GH_REPO" -ForegroundColor Gray
    }

    # Take only the program out of the checked archive.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $z = [System.IO.Compression.ZipFile]::OpenRead($zip)
    try {
        $e = $z.GetEntry("qpot.exe")
        if ($null -eq $e) {
            Stop-Coded "QP-HOST-007" "The QPot download could not be unpacked." `
                "$archive matched its checksum but holds no qpot.exe." `
                "Report it at $QPOT_REPO/issues"
        }
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $ExePath, $true)
    } finally {
        $z.Dispose()
    }
    return $true
}

# Build-FromSource builds qpot.exe from the pinned commit only.
function Build-FromSource {
    param([string]$TempDir, [string]$ExePath)
    if ($SourceCommit -cnotmatch '^[0-9a-f]{40}$') {
        Stop-Coded "QP-NET-013" "QPot v$QPOT_VERSION has no published release the installer can check." `
            "There is no SHA256SUMS for v$QPOT_VERSION at $DownloadBase, and this installer has no pinned source commit to build instead." `
            "Install a published release from $QPOT_REPO/releases, or build from a checkout you have reviewed: git clone $QPOT_REPO.git; cd QPot; go build -o qpot.exe .\cmd\qpot"
    }
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
    $fileProto = "never"
    if ($SourceRepo -match '^https://') {
    } elseif ($SourceRepo -match '^(file://|[A-Za-z]:[\\/]|\\\\)') {
        $fileProto = "always"
    } else {
        Stop-Coded "QP-INPUT-012" "QPOT_SOURCE_REPO ($SourceRepo) is not an https:// address." `
            "The source code must come over https." "Remove QPOT_SOURCE_REPO, or set it to an https:// git address."
    }
    $srcDir = Join-Path $TempDir "src"
    Write-Host "  Building QPot from source, commit $SourceCommit..." -ForegroundColor Gray
    # Fetch exactly the pinned commit: git names every object by its hash, so
    # a checkout whose HEAD is that commit has exactly that commit's files.
    $ok = (Invoke-Program "git" @("init", "-q", $srcDir)).Code -eq 0
    if ($ok) {
        $ok = (Invoke-Program "git" @("-C", $srcDir, "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
            "-c", "protocol.file.allow=$fileProto", "-c", "transfer.fsckObjects=true",
            "fetch", "-q", "--depth", "1", $SourceRepo, $SourceCommit)).Code -eq 0
    }
    if ($ok) {
        $ok = (Invoke-Program "git" @("-C", $srcDir, "checkout", "-q", "--detach", "FETCH_HEAD")).Code -eq 0
    }
    if (-not $ok) {
        Stop-Coded "QP-NET-007" "The QPot source code could not be downloaded." `
            "git could not fetch commit $SourceCommit from $SourceRepo (no internet connection, GitHub is blocked, or the commit does not exist there)." `
            "Check the internet connection and run the installer again."
    }
    $head = (& git -C $srcDir rev-parse HEAD).Trim()
    if ($head -ne $SourceCommit) {
        Stop-Coded "QP-NET-014" "The downloaded source code is not the commit the installer expects." `
            "git checked out $head, but the installer pins $SourceCommit. Nothing was built." `
            "Run the installer again. If it happens again, report it at $QPOT_REPO/issues"
    }
    # Dependencies are checked against go.sum (part of the pinned commit): the
    # build may not change go.mod or go.sum, and with GOSUMDB on and the
    # opt-outs cleared nothing unchecked can be fetched.
    $saved = @{}
    $goEnv = @{ GOFLAGS = "-mod=readonly"; GOSUMDB = "sum.golang.org"; GONOSUMDB = $null; GONOSUMCHECK = $null
                GONOVERIFY = $null; GOINSECURE = $null; GOPRIVATE = $null }
    if (-not $env:GOTOOLCHAIN) { $goEnv["GOTOOLCHAIN"] = "auto" }
    foreach ($k in $goEnv.Keys) {
        $saved[$k] = [Environment]::GetEnvironmentVariable($k, "Process")
        [Environment]::SetEnvironmentVariable($k, $goEnv[$k], "Process")
    }
    Push-Location $srcDir
    try {
        & go build -trimpath -o $ExePath .\cmd\qpot
        $buildExit = $LASTEXITCODE
    } finally {
        Pop-Location
        foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], "Process") }
    }
    if ($buildExit -ne 0) {
        Stop-Coded "QP-HOST-008" "Building QPot from source failed." `
            "The Go build stopped with an error (shown above); an old Go or no internet access for Go's downloads are the usual reasons." `
            "Read the build output above, update Go if it is old, and run the installer again."
    }
    Write-Host "  Built qpot.exe from source" -ForegroundColor Green
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
    Set-DownloadBase

    # Docker is not required here: `qpot setup` offers to install Docker
    # Desktop (with winget) and asks before it does.
    Write-Host "Checking prerequisites..." -ForegroundColor Yellow
    if (-not (Test-Command "docker")) {
        Write-Host "  Docker Desktop is not installed yet. 'qpot setup' will show how it installs it and ask you first." -ForegroundColor Yellow
    } else {
        Write-Host "  Docker found" -ForegroundColor Green
        if ((Invoke-Program "docker" @("info")).Code -ne 0) {
            Write-Host "  Docker is installed but not running - 'qpot setup' can start Docker Desktop." -ForegroundColor Yellow
        }
    }

    # Download and check everything in a private temporary folder first:
    # nothing in the installation folder changes unless the checks pass.
    Add-Type -AssemblyName System.Net.Http
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        # Windows PowerShell's .NET Framework may not offer TLS 1.2 by default.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("qpot-install-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    try {
        $newExe = Join-Path $tempDir "qpot.exe"
        Write-Host ""
        if (-not (Save-Release $tempDir $newExe)) {
            Build-FromSource $tempDir $newExe
        }

        # Verify the binary actually runs before installing it (catches a
        # wrong-arch download or a corrupt build).
        if ((Invoke-Program $newExe @("--version")).Code -ne 0) {
            Stop-Coded "QP-HOST-007" "The qpot program does not run on this computer." `
                "The download was probably for a different processor type, or it was damaged." `
                "Build it from source: git clone $QPOT_REPO.git; cd QPot; go build -o qpot.exe .\cmd\qpot"
        }

        $installDir = "$env:LOCALAPPDATA\QPot"
        $binDir = "$installDir\bin"
        $binaryPath = "$binDir\qpot.exe"
        Write-Host ""
        Write-Host "Installing to: $installDir" -ForegroundColor Yellow
        try {
            if (Test-Path $installDir) {
                Write-Host "  Removing existing installation..." -ForegroundColor Gray
                Remove-Item -Recurse -Force $installDir
            }
            New-Item -ItemType Directory -Force -Path $binDir | Out-Null
            Copy-Item -LiteralPath $newExe -Destination $binaryPath
        } catch {
            Stop-Coded "QP-PERM-007" "The folder $installDir could not be prepared." `
                "It is not writable, a file in it is in use, or the disk is full. ($($_.Exception.Message))" `
                "Close any running qpot program, check the folder's permissions and free space, then run the installer again."
        }
    } finally {
        Remove-Item -Recurse -Force -LiteralPath $tempDir -ErrorAction SilentlyContinue
    }

    # Create data directory
    $dataDir = "$env:USERPROFILE\.qpot"
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

    # Add to PATH. The User Path can be unset (null) on a fresh profile, so
    # coalesce to "" before calling .Contains to avoid a null-reference error.
    if ($env:QPOT_NO_PATH -ne "1") {
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if (-not $currentPath) { $currentPath = "" }
        if (-not $currentPath.Contains($binDir)) {
            $newPath = if ($currentPath -eq "") { $binDir } else { "$currentPath;$binDir" }
            [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
            Write-Host "  Added to PATH" -ForegroundColor Green
        }
    }

    # A desktop shortcut is a convenience: a desktop that cannot be found
    # (redirected, or none) only skips it.
    if ($env:QPOT_NO_SHORTCUT -ne "1") {
        try {
            $desktop = [Environment]::GetFolderPath("Desktop")
            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("$desktop\QPot.lnk")
            $Shortcut.TargetPath = "$binaryPath"
            $Shortcut.Arguments = "up --instance default"
            $Shortcut.WorkingDirectory = "$env:USERPROFILE"
            $Shortcut.IconLocation = "$binaryPath,0"
            $Shortcut.Save()
            Write-Host "  Created desktop shortcut" -ForegroundColor Green
        } catch {
            Write-Host "  No desktop shortcut was made ($($_.Exception.Message))" -ForegroundColor Yellow
        }
    }

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
    if ($env:QPOT_NO_PATH -ne "1") {
        Write-Host "Open a new terminal to use the 'qpot' command by name." -ForegroundColor Yellow
    }
    return $binaryPath
}

# $env:QPOT_INSTALL_FUNCTIONS_ONLY = "1" loads the functions without
# installing anything (the tests check the checksum parser this way).
if ($env:QPOT_INSTALL_FUNCTIONS_ONLY -eq "1") {
    return
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
