# Exercise scripts/install.ps1 against a real local release server (the
# qpot-release test-server: good and tampered releases on two loopback
# origins), the way test-install.sh exercises install.sh. Every case runs
# install.ps1 in a new PowerShell of the same kind as this one (PowerShell 7
# or Windows PowerShell 5.1) with LOCALAPPDATA, USERPROFILE and TEMP inside
# a throwaway folder, QPOT_NO_PATH and QPOT_NO_SHORTCUT set, and a PATH
# without the real gh: nothing outside the throwaway folder is changed.
# Every failure must print its QP- code, exit with the category status and
# install nothing; a good install must leave a qpot.exe that runs.
# Needs Go and git.
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("qpot-test-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
$server = $null
$script:checks = 0
$script:failures = 0

function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments, [string]$Dir)
    Push-Location $Dir
    try {
        & $Exe @Arguments
        if ($LASTEXITCODE -ne 0) { throw "$Exe $($Arguments -join ' ') exited $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

try {
    foreach ($tool in @("go", "git")) {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool is required" }
    }
    $goExe = (Get-Command go).Source
    $gitExe = (Get-Command git).Source
    # From a Git Bash, git resolves to Git's mingw64\bin\git.exe, which needs
    # Git's own PATH; a Windows PATH has the Git\cmd launcher that sets it.
    $gitCmd = Join-Path (Split-Path (Split-Path (Split-Path $gitExe))) "cmd\git.exe"
    if ($gitExe -like "*\mingw64\bin\git.exe" -and (Test-Path $gitCmd)) { $gitExe = $gitCmd }
    $ps = (Get-Process -Id $PID).Path

    # The release server, and a real qpot.exe for the archives.
    Invoke-Native $goExe @("build", "-o", "$work\qpot-release.exe", "./cmd/qpot-release") $repo
    Invoke-Native $goExe @("build", "-o", "$work\qpot.exe", "./cmd/qpot") $repo
    $server = Start-Process -FilePath "$work\qpot-release.exe" -PassThru -WindowStyle Hidden -ArgumentList @(
        "test-server", "-version", "0.1.0", "-unix-qpot", "$work\qpot.exe", "-win-qpot", "$work\qpot.exe",
        "-ready", "$work\ready", "-log", "$work\requests.log", "-lifetime", "15m")
    for ($i = 0; $i -lt 600 -and -not (Test-Path "$work\ready"); $i++) { Start-Sleep -Milliseconds 100 }
    if (-not (Test-Path "$work\ready")) { throw "the release server did not start" }
    $ready = Get-Content "$work\ready"
    $originA = ($ready | Where-Object { $_ -like "A=*" }).Substring(2)
    $originB = ($ready | Where-Object { $_ -like "B=*" }).Substring(2)

    # A git repository holding a tiny qpot, for the source build.
    $srcRepo = Join-Path $work "src-repo"
    New-Item -ItemType Directory -Path "$srcRepo\cmd\qpot" | Out-Null
    [IO.File]::WriteAllText("$srcRepo\go.mod", "module example.com/fakeqpot`n`ngo 1.21`n")
    [IO.File]::WriteAllText("$srcRepo\cmd\qpot\main.go", "package main`n`nimport `"fmt`"`n`nfunc main() { fmt.Println(`"qpot 0.1.0 (built from source)`") }`n")
    Invoke-Native $gitExe @("init", "-q") $srcRepo
    Invoke-Native $gitExe @("-c", "user.name=test", "-c", "user.email=test@example.invalid", "add", "-A") $srcRepo
    Invoke-Native $gitExe @("-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "core.autocrlf=false", "commit", "-q", "-m", "fake qpot") $srcRepo
    $srcCommit = (& $gitExe -C $srcRepo rev-parse HEAD).Trim()

    # A controlled PATH: Windows, this PowerShell, and the case's fakes.
    $basePath = @("$env:SystemRoot\System32", "$env:SystemRoot", "$env:SystemRoot\System32\WindowsPowerShell\v1.0", (Split-Path $ps)) -join ";"

    function New-Case {
        $script:checks++
        $c = Join-Path $work "case-$($script:checks)"
        foreach ($d in @("local", "profile", "temp", "tools")) { New-Item -ItemType Directory -Path "$c\$d" | Out-Null }
        Set-Content -LiteralPath "$work\requests.log" -Value $null
        return $c
    }

    $pinned = ([regex]::Match([IO.File]::ReadAllText("$repo\scripts\install.ps1"), '(?m)^\$QPOT_SOURCE_COMMIT_PINNED = "([0-9a-f]{40})"')).Groups[1].Value
    if (-not $pinned) { throw "install.ps1 pins no source commit" }
    # A copy without the pin: an installer that has nothing it can build.
    $noPin = Join-Path $work "install-nopin.ps1"
    [IO.File]::WriteAllText($noPin, ([IO.File]::ReadAllText("$repo\scripts\install.ps1") -replace '(?m)^\$QPOT_SOURCE_COMMIT_PINNED = ".*"', '$QPOT_SOURCE_COMMIT_PINNED = ""'))

    # Run install.ps1 (or -Installer) for a scenario of the release server;
    # returns exit code and output.
    function Invoke-Install {
        param([string]$Case, [string]$Scenario, [hashtable]$Env = @{}, [string]$ExtraPath = "", [string]$Installer = "$repo\scripts\install.ps1")
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $ps
        $psi.Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Installer`""
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.WorkingDirectory = $Case
        $vars = $psi.EnvironmentVariables
        foreach ($k in @($vars.Keys)) {
            if ($k -like "QPOT_*" -or $k -like "GH_*" -or $k -like "GITHUB_*") { $vars.Remove($k) }
        }
        $vars["LOCALAPPDATA"] = "$Case\local"
        $vars["USERPROFILE"] = "$Case\profile"
        $vars["TEMP"] = "$Case\temp"
        $vars["TMP"] = "$Case\temp"
        $vars["PATH"] = "$Case\tools;$basePath" + $ExtraPath
        $vars["QPOT_NO_PATH"] = "1"
        $vars["QPOT_NO_SHORTCUT"] = "1"
        $vars["QPOT_NO_SETUP"] = "1"
        $vars["QPOT_DOWNLOAD_BASE"] = "$originA/$Scenario"
        foreach ($k in $Env.Keys) { $vars[$k] = $Env[$k] }
        $p = [System.Diagnostics.Process]::Start($psi)
        $out = $p.StandardOutput.ReadToEndAsync()
        $err = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit(300000)) { $p.Kill(); throw "install.ps1 did not finish" }
        $text = $out.Result + $err.Result
        [IO.File]::WriteAllText("$Case\output.log", $text)
        return @{ Code = $p.ExitCode; Output = $text }
    }

    function Test-Code {
        param($R, [string]$Code, [int]$Status)
        if ($R.Output -notmatch [regex]::Escape("ERROR ${Code}:")) { return "no $Code in the output" }
        if ($R.Code -ne $Status) { return "exit status $($R.Code), want $Status" }
        if ($Code -ne "QP-BUG-002" -and $R.Output -match "QP-BUG-002") { return "the catch-all error was printed too" }
        return ""
    }

    function Test-NothingInstalled {
        param([string]$Case)
        if (Test-Path "$Case\local\QPot\bin\qpot.exe") { return "qpot.exe was installed" }
        if (@(Get-ChildItem -Force "$Case\temp").Count -ne 0) { return "temp files left" }
        return ""
    }

    function Test-Installed {
        param($R, [string]$Case)
        if ($R.Code -ne 0) { return "exit status $($R.Code)" }
        $exe = "$Case\local\QPot\bin\qpot.exe"
        if (-not (Test-Path $exe)) { return "no qpot.exe" }
        $null = & $exe --version
        if ($LASTEXITCODE -ne 0) { return "qpot.exe --version failed" }
        if (@(Get-ChildItem -Force "$Case\temp").Count -ne 0) { return "temp files left" }
        return ""
    }

    function Test-NoOriginB {
        $log = Get-Content -LiteralPath "$work\requests.log" -ErrorAction SilentlyContinue
        if (@($log | Where-Object { $_ -like "B *" }).Count -ne 0) { return "origin B was contacted" }
        return ""
    }

    # Check NAME { ... }: the block returns "" to pass or why it failed.
    function Check {
        param([string]$Name, [scriptblock]$Body, [object[]]$Extra = @())
        $case = New-Case
        $why = & $Body $case @Extra
        if ([string]::IsNullOrEmpty($why)) {
            Write-Host "PASS: $Name"
        } else {
            Write-Host "FAIL: $Name ($why)"
            if (Test-Path "$case\output.log") { Get-Content "$case\output.log" | ForEach-Object { Write-Host "    $_" } }
            $script:failures++
        }
    }

    function Join-Why { param([string[]]$Why) return (($Why | Where-Object { $_ }) -join "; ") }

    # A fake gh: its help lists the flags a current gh has (all but
    # --source-ref with FAKE_GH_OLD), and it records what it was asked.
    function New-FakeGh {
        param([string]$Case)
        $cmd = "@echo off`r`nif `"%1 %2 %3`"==`"attestation verify --help`" (`r`n" +
            "  echo   -b, --bundle string`r`n  echo       --deny-self-hosted-runners`r`n  echo       --signer-workflow string`r`n" +
            "  if not defined FAKE_GH_OLD echo       --source-ref string`r`n  exit /b 0`r`n)`r`n" +
            "echo %* > `"%QPOT_CASE%\gh-args`"`r`nif defined FAKE_GH_RC (echo X verification failed 1>&2 & exit /b %FAKE_GH_RC%)`r`nexit /b 0`r`n"
        [IO.File]::WriteAllText("$Case\tools\gh.cmd", $cmd)
    }

    # Windows PowerShell 5.1 turns a program's stderr into a terminating
    # error; a Docker that is installed but not running writes there.
    Check "a Docker that is not running does not stop the installer" {
        param($c)
        [IO.File]::WriteAllText("$c\tools\docker.cmd", "@echo off`r`necho error during connect: the docker daemon is not running 1>&2`r`nexit /b 1`r`n")
        $r = Invoke-Install $c "good"
        $why = @((Test-Installed $r $c))
        if ($r.Output -notmatch "Docker is installed but not running") { $why += "no not-running note" }
        Join-Why $why
    }

    Check "a good release installs after its checksum matches" {
        param($c)
        $r = Invoke-Install $c "good"
        $why = @((Test-Installed $r $c), (Test-NoOriginB))
        if ($r.Output -notmatch "Checksum matches SHA256SUMS") { $why += "no checksum message" }
        if ($r.Output -notmatch "Build provenance not checked") { $why += "no provenance note" }
        if (-not (Select-String -Quiet -Path "$work\requests.log" -Pattern "^A /good/v0.1.0/qpot_0.1.0_windows_amd64.zip$")) { $why += "the zip was not downloaded" }
        Join-Why $why
    }
    Check "a redirect within the release origin is followed" {
        param($c)
        $r = Invoke-Install $c "redirect-same"
        Join-Why @((Test-Installed $r $c))
    }
    $failing = @(
        @("tampered-archive", "QP-NET-009", 13, "a tampered archive"),
        @("tampered-sums", "QP-NET-009", 13, "tampered checksums"),
        @("malformed-sums", "QP-NET-010", 13, "a malformed SHA256SUMS"),
        @("big-sums", "QP-NET-010", 13, "a SHA256SUMS over 64 KiB"),
        @("no-entry", "QP-NET-010", 13, "no entry for the archive"),
        @("truncated", "QP-NET-007", 13, "a truncated download"),
        @("short-body", "QP-NET-009", 13, "a download cut short without a length"),
        @("redirect-other", "QP-NET-011", 13, "a redirect to another origin"),
        @("redirect-host", "QP-NET-011", 13, "a redirect to another host name"),
        @("redirect-loop", "QP-NET-007", 13, "a redirect loop")
    )
    foreach ($f in $failing) {
        $scenario, $code, $status, $what = $f
        Check "$what is $code and installs nothing" {
            param($c, $scenario, $code, $status)
            $r = Invoke-Install $c $scenario
            Join-Why @((Test-Code $r $code $status), (Test-NothingInstalled $c), (Test-NoOriginB))
        } @($scenario, $code, $status)
    }
    Check "no release and no pinned commit is QP-NET-013 and installs nothing" {
        param($c)
        $r = Invoke-Install $c "missing-sums" -Installer $noPin
        Join-Why @((Test-Code $r "QP-NET-013" 13), (Test-NothingInstalled $c), (Test-NoOriginB))
    }
    Check "a failed check keeps the existing installation" {
        param($c)
        New-Item -ItemType Directory -Path "$c\local\QPot\bin" | Out-Null
        Copy-Item "$work\qpot.exe" "$c\local\QPot\bin\qpot.exe"
        $before = (Get-FileHash "$c\local\QPot\bin\qpot.exe").Hash
        $r = Invoke-Install $c "tampered-archive"
        $why = @((Test-Code $r "QP-NET-009" 13))
        if (-not (Test-Path "$c\local\QPot\bin\qpot.exe") -or (Get-FileHash "$c\local\QPot\bin\qpot.exe").Hash -ne $before) { $why += "the existing qpot.exe changed" }
        Join-Why $why
    }
    Check "a plain-http download base is QP-INPUT-012 (exit 10)" {
        param($c)
        $r = Invoke-Install $c "good" @{ QPOT_DOWNLOAD_BASE = "http://example.invalid/releases" }
        Join-Why @((Test-Code $r "QP-INPUT-012" 10), (Test-NothingInstalled $c))
    }
    Check "gh verifies the provenance with the pinned workflow and tag" {
        param($c)
        New-FakeGh $c
        $r = Invoke-Install $c "good" @{ QPOT_CASE = $c }
        $why = @((Test-Installed $r $c))
        if ($r.Output -notmatch "Build provenance verified") { $why += "no verified message" }
        $ghArgs = if (Test-Path "$c\gh-args") { Get-Content -Raw "$c\gh-args" } else { "" }
        foreach ($want in @("attestation verify", "--bundle", "qpot_0.1.0_provenance.sigstore.json", "--repo YurilLAB/QPot",
                "--signer-workflow YurilLAB/QPot/.github/workflows/release.yml", "--source-ref refs/tags/v0.1.0", "--deny-self-hosted-runners")) {
            if (-not $ghArgs.Contains($want)) { $why += "gh was not given $want" }
        }
        Join-Why $why
    }
    Check "provenance gh rejects is QP-NET-012 and installs nothing" {
        param($c)
        New-FakeGh $c
        $r = Invoke-Install $c "good" @{ QPOT_CASE = $c; FAKE_GH_RC = "1" }
        Join-Why @((Test-Code $r "QP-NET-012" 13), (Test-NothingInstalled $c))
    }
    Check "a missing provenance file is QP-NET-012 when gh is installed" {
        param($c)
        New-FakeGh $c
        $r = Invoke-Install $c "no-provenance" @{ QPOT_CASE = $c }
        Join-Why @((Test-Code $r "QP-NET-012" 13), (Test-NothingInstalled $c))
    }
    Check "QPOT_REQUIRE_PROVENANCE=1 without gh is QP-NET-012" {
        param($c)
        $r = Invoke-Install $c "good" @{ QPOT_REQUIRE_PROVENANCE = "1" }
        Join-Why @((Test-Code $r "QP-NET-012" 13), (Test-NothingInstalled $c))
    }
    # A gh too old to pin the tag (no --source-ref) is not asked: it would
    # accept a build from any ref of the repository.
    Check "a gh without --source-ref is not used" {
        param($c)
        New-FakeGh $c
        $r = Invoke-Install $c "good" @{ QPOT_CASE = $c; FAKE_GH_OLD = "1" }
        $why = @((Test-Installed $r $c))
        if ($r.Output -notmatch "Build provenance not checked") { $why += "no provenance note" }
        if (Test-Path "$c\gh-args") { $why += "the old gh was asked to verify" }
        Join-Why $why
    }
    Check "QPOT_REQUIRE_PROVENANCE=1 with a too old gh is QP-NET-012" {
        param($c)
        New-FakeGh $c
        $r = Invoke-Install $c "good" @{ QPOT_CASE = $c; FAKE_GH_OLD = "1"; QPOT_REQUIRE_PROVENANCE = "1" }
        $why = @((Test-Code $r "QP-NET-012" 13), (Test-NothingInstalled $c))
        if ($r.Output -notmatch "too old") { $why += "the message does not say gh is too old" }
        Join-Why $why
    }
    $toolPath = ";" + (Split-Path $goExe) + ";" + (Split-Path $gitExe)
    Check "no release: the pinned commit is built from source" {
        param($c)
        $r = Invoke-Install $c "missing-sums" @{ QPOT_SOURCE_REPO = $srcRepo; QPOT_SOURCE_COMMIT = $srcCommit
            GOTOOLCHAIN = "local"; GOPROXY = "off"; GOCACHE = "$work\gocache"; GOPATH = "$work\gopath" } $toolPath
        $why = @((Test-Installed $r $c))
        if ($r.Output -notmatch "Built qpot.exe from source") { $why += "no build message" }
        if (Test-Path "$c\local\QPot\bin\qpot.exe") {
            $v = & "$c\local\QPot\bin\qpot.exe" --version
            if ("$v" -notmatch "built from source") { $why += "not the source build: $v" }
        }
        Join-Why $why
    }
    # Without QPOT_SOURCE_COMMIT the installer builds the commit it pins (the
    # test repository does not have it, so the fetch fails, naming it).
    Check "no release: the installer fetches the commit it pins" {
        param($c)
        $r = Invoke-Install $c "missing-sums" @{ QPOT_SOURCE_REPO = $srcRepo; GOTOOLCHAIN = "local"; GOPROXY = "off" } $toolPath
        $why = @((Test-Code $r "QP-NET-007" 13), (Test-NothingInstalled $c))
        if ($r.Output -notmatch "commit $pinned from") { $why += "the pinned commit was not fetched" }
        Join-Why $why
    }
    Check "a pinned commit that is not there is QP-NET-007" {
        param($c)
        $r = Invoke-Install $c "missing-sums" @{ QPOT_SOURCE_REPO = $srcRepo; QPOT_SOURCE_COMMIT = ("0" * 39 + "1")
            GOTOOLCHAIN = "local"; GOPROXY = "off"; GOCACHE = "$work\gocache"; GOPATH = "$work\gopath" } $toolPath
        Join-Why @((Test-Code $r "QP-NET-007" 13), (Test-NothingInstalled $c))
    }
    # A git that reports another commit than the pinned one (a fetch that did
    # not get what was asked for) stops the build.
    Check "another commit than the pinned one is QP-NET-014" {
        param($c)
        [IO.File]::WriteAllText("$c\tools\git.cmd", "@echo off`r`nif `"%3 %4`"==`"rev-parse HEAD`" (echo 0000000000000000000000000000000000000002& exit /b 0)`r`n`"$gitExe`" %*`r`nexit /b %ERRORLEVEL%`r`n")
        $r = Invoke-Install $c "missing-sums" @{ QPOT_SOURCE_REPO = $srcRepo; QPOT_SOURCE_COMMIT = $srcCommit
            GOTOOLCHAIN = "local"; GOPROXY = "off"; GOCACHE = "$work\gocache"; GOPATH = "$work\gopath" } $toolPath
        $why = @((Test-Code $r "QP-NET-014" 13), (Test-NothingInstalled $c))
        if ($r.Output -notmatch "pins $srcCommit") { $why += "the message does not name the pinned commit" }
        Join-Why $why
    }
    Check "no release and no Go is QP-HOST-006 (exit 11)" {
        param($c)
        $r = Invoke-Install $c "missing-sums" @{ QPOT_SOURCE_COMMIT = $srcCommit }
        Join-Why @((Test-Code $r "QP-HOST-006" 11), (Test-NothingInstalled $c))
    }
} finally {
    if ($null -ne $server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }
    Remove-Item -Recurse -Force -LiteralPath $work -ErrorAction SilentlyContinue
}
Write-Host "$($script:checks - $script:failures)/$($script:checks) install.ps1 checks passed ($($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion))"
if ($script:failures -ne 0) { exit 1 }
