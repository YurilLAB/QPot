# QPot setup error codes

Every problem `qpot setup`, `qpot doctor` and the install scripts report has a
code such as `QP-PKG-001`: `QP`, the category, and a number. A code always
means the same problem, and codes are never reused. The process exits with
the category's exit status, so a script can tell kinds of failure apart.

Look a code up from the terminal:

```bash
qpot doctor --explain QP-PKG-001
```

This page is generated from the list in `internal/hostsetup/errors.go`;
a test fails if the two disagree. Regenerate it with
`QPOT_UPDATE_DOCS=1 go test ./internal/hostsetup -run TestErrorDoc`.

## Exit statuses

| Category | Meaning | Exit status |
|----------|---------|-------------|
| `INPUT` | Settings and answers | 10 |
| `HOST` | This computer and its operating system | 11 |
| `PERM` | Permissions and sudo | 12 |
| `NET` | Network and downloads | 13 |
| `PKG` | Package manager | 14 |
| `DOCKER` | Docker Engine | 15 |
| `COMPOSE` | Docker Compose | 16 |
| `PORT` | Network ports | 17 |
| `RES` | Memory and disk space | 18 |
| `SVC` | Services and systemd | 19 |
| `WEB` | Web UI and control plane | 20 |
| `INST` | QPot instance and containers | 21 |
| `INTEL` | Intelligence recovery and ownership | 22 |
| `CLUSTER` | Cluster trust and enrollment | 23 |
| `INT` | Interrupted | 130 |
| `BUG` | Unexpected problems | 70 |

Exit status 0 means success; 1 is a usage error (an unknown flag).

## Settings and answers (`INPUT`, exit 10)

### QP-INPUT-001

**The instance name is not valid.**

- Why: Instance names become folder and container names, so only letters, digits, '-' and '_' work (1 to 32 characters, starting with a letter or digit).
- Fix: Pick a name such as 'default' or 'sensor1' and pass it with -i, for example: qpot setup -i sensor1

### QP-INPUT-002

**That honeypot profile does not exist.**

- Why: The profile names are minimal, standard, hifi, industrial and refrigeration.
- Fix: Use one of them, for example: qpot setup --profile minimal. Or list honeypots yourself with --honeypots cowrie,endlessh

### QP-INPUT-003

**One of the honeypot names is not known.**

- Why: Honeypot names must match the ones QPot ships; a typo is the usual reason.
- Fix: See the names with: qpot honeypot list. Then pass them with --honeypots, separated by commas.

### QP-INPUT-004

**The port number is not valid.**

- Why: A port must be a whole number from 1 to 65535.
- Fix: Choose a free port such as 8080, for example: qpot setup --port 8080

### QP-INPUT-005

**The web UI address is not valid for this computer.**

- Why: The address must be 127.0.0.1 (this computer only), 0.0.0.0 (all networks) or an IP address this computer actually has.
- Fix: Keep the safe default 127.0.0.1 and reach the web UI through an SSH tunnel, or pass an address this computer has with --bind.

### QP-INPUT-006

**That country code is not known.**

- Why: The attack map needs a two-letter ISO country code such as DE, US or AU.
- Fix: Pass a two-letter code with --country, or leave it out to use the computer's time zone.

### QP-INPUT-007

**That database type is not supported.**

- Why: QPot can store events in ClickHouse or TimescaleDB.
- Fix: Use --database clickhouse (the default) or --database timescaledb.

### QP-INPUT-008

**Setup needs an answer but cannot ask for it.**

- Why: There is no terminal to type into (for example in a script or CI), so setup does not prompt.
- Fix: Pass the setting as a flag (the message names it), or run qpot setup in a terminal to answer the questions.

### QP-INPUT-009

**The input ended before setup finished asking its questions.**

- Why: Standard input was closed (Ctrl-D, or a pipe that ran out of lines).
- Fix: Run qpot setup again in a terminal, or pass --yes with flags to run without questions.

### QP-INPUT-010

**Two options were given that cannot be used together.**

- Why: Some options choose the same thing in different ways.
- Fix: Keep only one of the options the message names and run the command again.

### QP-INPUT-011

**That error code is not known.**

- Why: Codes look like QP-PKG-001; this one is not in QPot's list.
- Fix: Check the code for typos, or read the full list in doc/setup-errors.md.

### QP-INPUT-012

**An option has an unsupported value.**

- Why: A setup answer or honeypot setting is missing, unknown, or outside the values accepted by that command.
- Fix: Read the named rule and the command's help. Use qpot setup --help for setup options or qpot honeypot set --help for honeypot settings, then retry.

### QP-INPUT-013

**Setup was cancelled before it changed anything.**

- Why: You answered no when setup asked to go ahead.
- Fix: Nothing was changed. Run qpot setup again whenever you are ready.

## This computer and its operating system (`HOST`, exit 11)

### QP-HOST-001

**This operating system is not supported.**

- Why: QPot runs on Linux, macOS and Windows.
- Fix: Run QPot on a Linux server or virtual machine (Ubuntu, Debian, Fedora, Rocky or AlmaLinux are easiest).

### QP-HOST-002

**This processor type is not supported.**

- Why: Docker and QPot's honeypot images are published for 64-bit x86 (amd64) and 64-bit ARM (arm64).
- Fix: Use a 64-bit x86 or ARM machine or virtual machine.

### QP-HOST-003

**Setup cannot install Docker on this Linux distribution by itself.**

- Why: Setup knows how to install Docker on Debian, Ubuntu, Fedora, CentOS Stream, Rocky, AlmaLinux, RHEL, openSUSE and Arch, and their close relatives.
- Fix: Install Docker Engine and the Compose plugin by following https://docs.docker.com/engine/install/ , then run qpot setup again.

### QP-HOST-004

**Setup could not tell which Linux distribution this is.**

- Why: The file /etc/os-release is missing or unreadable, so setup cannot pick the right install method.
- Fix: Install Docker Engine and the Compose plugin yourself (https://docs.docker.com/engine/install/), then run qpot setup again.

### QP-HOST-005

**Docker does not publish packages for this version of the distribution.**

- Why: This release is newer or older than the releases Docker supports, and the distribution has no Docker package setup can use instead.
- Fix: Upgrade to a release Docker supports (see https://docs.docker.com/engine/install/), or install Docker by hand, then run qpot setup again.

### QP-HOST-006

**A tool needed to build QPot is missing.**

- Why: No ready-made QPot download exists for this machine, so the installer builds it from source, which needs Go and git.
- Fix: Install Go (https://go.dev/dl/) and git, or download a release from https://github.com/YurilLAB/QPot/releases , then run the installer again.

### QP-HOST-007

**The installed qpot program does not run on this computer.**

- Why: The download was probably for a different processor type, or it was damaged.
- Fix: Build it from source: git clone https://github.com/YurilLAB/QPot.git && cd QPot && go build -o qpot ./cmd/qpot

### QP-HOST-008

**Building QPot from source failed.**

- Why: The Go build stopped with an error; the usual reasons are an old Go version or no internet access for Go's downloads.
- Fix: Read the build output above, update Go if it is old, and run the installer again.

### QP-HOST-009

**The package manager this distribution uses was not found.**

- Why: Setup expected apt-get, dnf, zypper or pacman for this distribution, but the command is missing.
- Fix: Install Docker Engine and the Compose plugin by hand (https://docs.docker.com/engine/install/), then run qpot setup again.

### QP-HOST-010

**No program to check a download's checksum was found.**

- Why: The installer checks the QPot download against the release's SHA256SUMS with sha256sum, shasum or openssl, and none of them is installed.
- Fix: Install coreutils (sha256sum) or openssl, then run the installer again.

### QP-HOST-011

**curl is not installed.**

- Why: The installer downloads QPot and the release's checksum list with curl.
- Fix: Install curl (for example: sudo apt-get install curl), then run the installer again.

## Permissions and sudo (`PERM`, exit 12)

### QP-PERM-001

**Setup needs administrator rights, but sudo is not available.**

- Why: Installing or starting Docker changes the system, which needs root. You are not root and the sudo command is not installed.
- Fix: Run setup as root (for example: su -c 'qpot setup'), or install sudo and give your user access to it, then run qpot setup again.

### QP-PERM-002

**sudo needs your password, but there is no terminal to type it in.**

- Why: Setup is running without a terminal (a script or CI), so sudo cannot ask for the password. (sudo answers the same way when your user may not use sudo at all.)
- Fix: Run qpot setup in a terminal so sudo can ask for your password, or run it as root. If your user may not use sudo, ask an administrator to allow it.

### QP-PERM-003

**sudo refused to run the command.**

- Why: Your user is not allowed to use sudo, or the password was wrong too many times.
- Fix: Ask an administrator to give your user sudo rights (or run setup as root), then run qpot setup again.

### QP-PERM-004

**Your user cannot talk to Docker.**

- Why: Docker only lets root and members of the 'docker' group use it. Being in that group is the same as having root on this computer.
- Fix: Run setup again and allow it to add you to the docker group (or pass --docker-group), or run QPot as root.

### QP-PERM-005

**You were added to the docker group, but this login session does not have it yet.**

- Why: Group changes only apply to new login sessions.
- Fix: Log out and back in (or run: newgrp docker), then run the same qpot setup command again. It continues where it stopped.

### QP-PERM-006

**Setup was not allowed to make the changes it needs.**

- Why: You chose not to let setup run the administrator commands it showed.
- Fix: Run the commands yourself, or run qpot setup again and agree (or pass --install-docker).

### QP-PERM-007

**Setup could not write QPot's files.**

- Why: Your home folder (or the folder QPot uses) is not writable, or the disk is read-only.
- Fix: Check that you can write to ~/.qpot (for example: touch ~/.qpot/test), fix the permissions, and run qpot setup again.

### QP-PERM-008

**Setup could not put a file in a system folder.**

- Why: The folder is read-only, the disk is full, or the command was refused.
- Fix: Check that the system disk is writable and has free space (df -h /), then run qpot setup again.

### QP-PERM-009

**Setup could not add your user to the docker group.**

- Why: The usermod command failed; the details show why (for example, the docker group does not exist yet).
- Fix: Run: sudo groupadd -f docker && sudo usermod -aG docker $USER, log out and back in, and run qpot setup again. Or run QPot as root.

### QP-PERM-010

**Setup could not make a private temporary folder.**

- Why: Files that root installs (Docker's signing key, its package source) are first written to a folder only you can use, so no other user can swap them. That folder could not be made, or it is not private.
- Fix: Check that the temporary folder (TMPDIR, or /tmp) exists, is writable and has free space (df -h /tmp), and that TMPDIR does not point into another user's folder, then run qpot setup again.

## Network and downloads (`NET`, exit 13)

### QP-NET-001

**This computer could not look up a server name.**

- Why: There is no internet connection, or DNS (name lookup) is not working.
- Fix: Check the connection (for example: ping -c1 download.docker.com) and your DNS settings, then run qpot setup again.

### QP-NET-002

**This computer could not connect to a download server.**

- Why: The internet connection is down, a firewall blocks it, or a proxy is needed.
- Fix: Check the connection and any proxy settings (HTTPS_PROXY), then run qpot setup again.

### QP-NET-003

**A secure (HTTPS) connection could not be checked.**

- Why: The computer's clock is wrong, the certificate store is missing, or a proxy is intercepting HTTPS.
- Fix: Check the date and time (date), make sure the ca-certificates package is installed, and run qpot setup again.

### QP-NET-004

**A download server answered with an error.**

- Why: The file may have moved, or the server had a temporary problem.
- Fix: Wait a few minutes and run qpot setup again. If it keeps happening, report it at https://github.com/YurilLAB/QPot/issues

### QP-NET-005

**Docker's signing key did not match the published fingerprint.**

- Why: The key that was downloaded is not Docker's real key. Something between you and Docker may be tampering with downloads, so setup stopped without installing anything.
- Fix: Do not install Docker from this network. Try again from a trusted network, and compare the key with https://docs.docker.com/engine/install/

### QP-NET-006

**The package manager could not download packages.**

- Why: There is no internet connection, DNS does not work, or a package mirror is down.
- Fix: Check the connection, then run qpot setup again. Your distribution's mirror may also be busy: wait a little and retry.

### QP-NET-007

**The QPot download failed.**

- Why: GitHub could not be reached, or the release file is missing.
- Fix: Check the internet connection and run the installer again, or build from source as the message shows.

### QP-NET-008

**The GeoIP country database could not be downloaded.**

- Why: The download site could not be reached. QPot works without it, but events get no country and the attack map draws no lines.
- Fix: Run this later to add it: qpot geoip update

### QP-NET-009

**The QPot download does not match its published checksum.**

- Why: The file's SHA-256 differs from the one in the release's SHA256SUMS: it was damaged, cut short or changed on the way. Nothing was installed.
- Fix: Run the installer again. If it happens again, do not install from this network, and report it at https://github.com/YurilLAB/QPot/issues

### QP-NET-010

**The release's checksum list cannot be used.**

- Why: SHA256SUMS is not in the format the release writes, or it has no entry for this computer's download, so the download cannot be checked. Nothing was installed.
- Fix: Run the installer again later. If it keeps happening, report it at https://github.com/YurilLAB/QPot/issues

### QP-NET-011

**A download was redirected to a server QPot does not publish from.**

- Why: QPot's releases come only from GitHub (github.com and its download servers). Something sent the download elsewhere, so the installer stopped before contacting it. Nothing was installed.
- Fix: Check for a proxy or a captive portal on this network, then run the installer again from a trusted network.

### QP-NET-012

**The build provenance of the QPot download could not be verified.**

- Why: The GitHub CLI could not confirm that QPot's release workflow built the file from the version's tag, or provenance was required (QPOT_REQUIRE_PROVENANCE=1) and gh is not installed or too old to check the tag. Nothing was installed.
- Fix: Run the installer again. If it fails again, do not use the download and report it at https://github.com/YurilLAB/QPot/issues . For the check, install or update the GitHub CLI (https://cli.github.com).

### QP-NET-013

**No QPot release the installer can check was found.**

- Why: The version has no published release (no SHA256SUMS), and the installer has no pinned source commit to build instead.
- Fix: Install a published release from https://github.com/YurilLAB/QPot/releases , or build from a checkout you have reviewed: git clone https://github.com/YurilLAB/QPot.git && cd QPot && go build -o qpot ./cmd/qpot

### QP-NET-014

**The downloaded source code is not the commit the installer expects.**

- Why: git checked out a different commit than the one the installer pins, so nothing was built.
- Fix: Run the installer again. If it happens again, report it at https://github.com/YurilLAB/QPot/issues

### QP-NET-015

**Honeypots see Docker's address instead of the visitor's.**

- Why: Some events have a source address inside the instance's own Docker networks. That address is Docker's port forwarder, and every connection it forwards arrives from it. This happens to connections made from this computer itself, and to every connection on a Docker that forwards ports without its packet-filter rules: Docker Desktop, rootless Docker, or a daemon started with iptables off. QPot marks such events, never names that address as an attacker, and keeps the honeypot's connections apart by their own session IDs, but it cannot say who connected.
- Fix: If the events are your own tests from this computer, nothing is wrong. Otherwise run QPot on a Linux host with the standard Docker Engine (not Docker Desktop, not rootless) and leave Docker's iptables setting on, so that visitors reach the honeypots with their own address. Do not put a reverse proxy or a NAT that rewrites the source in front of the honeypot ports. qpot doctor shows the share of marked events over the last day.

## Package manager (`PKG`, exit 14)

### QP-PKG-001

**Another program is installing software right now.**

- Why: The package manager allows one program at a time. Automatic updates often run for a few minutes after a computer starts.
- Fix: Wait a few minutes for the other program to finish, then run qpot setup again.

### QP-PKG-002

**The package lists could not be updated.**

- Why: One of the configured software sources is broken or unreachable.
- Fix: Run the update command the message shows to see which source fails, fix or remove that source, then run qpot setup again.

### QP-PKG-003

**A software source failed its signature check.**

- Why: The package manager could not confirm a source's signing key, so it refused to trust it.
- Fix: Check the source the message names. For Docker's source, delete /etc/apt/keyrings/docker.asc and run qpot setup again so it is fetched and checked again.

### QP-PKG-004

**Installing the packages failed.**

- Why: The package manager stopped with an error; the details below show its last lines.
- Fix: Read the details, fix what they name (often disk space or a broken package), then run qpot setup again.

### QP-PKG-005

**An earlier software installation was interrupted.**

- Why: The package system is half-way through a previous install and must finish it first.
- Fix: Run: sudo dpkg --configure -a   then run qpot setup again.

### QP-PKG-006

**Packages that conflict with Docker are installed.**

- Why: Docker's own packages replace older Docker, containerd, runc or Podman packages that are already installed.
- Fix: Remove the packages the message names (it shows the command), then run qpot setup again.

### QP-PKG-007

**A package setup needs was not found.**

- Why: The distribution's sources do not offer it, or the package lists are out of date.
- Fix: Update the package lists, check that the distribution's standard sources are enabled, then run qpot setup again.

### QP-PKG-008

**A Docker signing key is already installed, and it is not Docker's real key.**

- Why: The file at Docker's standard key location holds a different key, so setup will not trust that source.
- Fix: Look at the file the message names. If you did not put it there on purpose, delete it and run qpot setup again.

### QP-PKG-009

**The package manager took too long and was stopped.**

- Why: The download was very slow, or the package manager was waiting for something.
- Fix: Run qpot setup again. If it keeps timing out, run the shown command yourself to see where it waits.

## Docker Engine (`DOCKER`, exit 15)

### QP-DOCKER-001

**Docker is not installed.**

- Why: QPot runs its honeypots in Docker containers.
- Fix: Run qpot setup in a terminal and let it install Docker, or pass --install-docker, or install it yourself from https://docs.docker.com/engine/install/

### QP-DOCKER-002

**Docker is installed but not running.**

- Why: The Docker service (or Docker Desktop) is stopped.
- Fix: Start it (Linux: sudo systemctl start docker; macOS and Windows: open Docker Desktop), or let setup start it with --install-docker, then run qpot setup again.

### QP-DOCKER-003

**The Docker service failed to start.**

- Why: Docker's background service stopped with an error; the details show its last log lines.
- Fix: Read the details, or run: sudo journalctl -u docker --no-pager -n 50   Fix what it reports, then run qpot setup again.

### QP-DOCKER-004

**The docker command here is Podman, not Docker.**

- Why: The podman-docker package makes 'docker' run Podman, which QPot does not support.
- Fix: Remove podman-docker and install Docker Engine (setup can do both when you agree), then run qpot setup again.

### QP-DOCKER-005

**Docker is too old for QPot.**

- Why: QPot needs Docker Engine 20.10 or newer.
- Fix: Let setup update it (pass --install-docker), or update Docker with your package manager, then run qpot setup again.

### QP-DOCKER-006

**Docker was installed, but the docker command still cannot be found.**

- Why: The command was installed to a folder that is not on your PATH.
- Fix: Open a new terminal (or run: hash -r) and run qpot setup again.

### QP-DOCKER-007

**Docker Desktop is installed and needs to be started once.**

- Why: Docker Desktop asks you to accept its terms the first time it opens, and only then starts Docker.
- Fix: Open Docker Desktop, accept its terms if you agree, wait until it says the engine is running, then run qpot setup again.

### QP-DOCKER-008

**Setup cannot install Docker Desktop by itself here.**

- Why: On macOS setup uses Homebrew and on Windows it uses winget; neither was found.
- Fix: Install Docker Desktop from https://docs.docker.com/desktop/ , start it once, then run qpot setup again.

### QP-DOCKER-009

**Installing Docker Desktop failed.**

- Why: The installer (Homebrew or winget) stopped with an error.
- Fix: Read the installer's message above, fix what it names, or install Docker Desktop from https://docs.docker.com/desktop/ , then run qpot setup again.

### QP-DOCKER-010

**The sandbox policy is not supported.**

- Why: The configured sandbox mode or fallback policy is unknown, or selects Firejail, which does not isolate QPot's Docker containers.
- Fix: Set security.sandbox_mode to gvisor, kata or an explicitly chosen none. Set security.sandbox_fallback to deny, or explicitly allow docker for reviewed non-executing emulators. Executing and unreviewed honeypots never downgrade a requested stronger runtime.

### QP-DOCKER-011

**The requested container isolation could not be verified.**

- Why: Docker is unreachable, its runtime report is invalid, or the requested gVisor or Kata runtime is not registered with the selected daemon.
- Fix: Restore Docker access and install/register the requested runtime on that Docker host. Inspect docker info and retry. For reviewed non-executing emulators only, security.sandbox_fallback: docker explicitly permits standard containers; executing and unreviewed honeypots require the requested runtime.

### QP-DOCKER-012

**The deployment does not use the required container runtime.**

- Why: An existing container or stored Compose service differs from the current isolation policy, or Docker did not provide a trustworthy runtime identity.
- Fix: Keep the instance stopped, inspect its isolation status and recreate the affected honeypots with the intended sandbox policy. A restart does not change a container's runtime. Stop, logs and inspection remain available.

## Docker Compose (`COMPOSE`, exit 16)

### QP-COMPOSE-001

**The Docker Compose plugin is missing.**

- Why: QPot starts its containers with 'docker compose', which is a separate package.
- Fix: Let setup install it (pass --install-docker), or install the docker-compose-plugin package, then run qpot setup again.

### QP-COMPOSE-002

**Docker Compose is too old for QPot.**

- Why: QPot needs Compose version 2 (the 'docker compose' command). The old 'docker-compose' version 1 does not work.
- Fix: Let setup install the Compose plugin (pass --install-docker), or install docker-compose-plugin yourself, then run qpot setup again.

### QP-COMPOSE-003

**Docker Compose was installed but does not work.**

- Why: The 'docker compose' command still fails after installing it.
- Fix: Run: docker compose version   to see the error, fix it, then run qpot setup again.

## Network ports (`PORT`, exit 17)

### QP-PORT-001

**The web UI port is already in use.**

- Why: Another program, or another QPot instance, is already listening on that port.
- Fix: Pick another port with --port (for example --port 8081), or stop the program that uses it.

### QP-PORT-002

**Ports the honeypots need are already in use.**

- Why: Another program, or another QPot instance, already listens on them.
- Fix: Stop the program that uses them, or change base_port in the instance config (qpot config), then run qpot setup again.

### QP-PORT-003

**No free port for the web UI was found.**

- Why: The chosen port and the 100 ports after it are all taken.
- Fix: Free a port, or choose a different one with --port, then run qpot setup again.

### QP-PORT-004

**Ports below 1024 need root.**

- Why: Linux lets only root listen on ports under 1024.
- Fix: Choose a port of 1024 or above (for example 8080), or run QPot as root.

### QP-PORT-005

**The web UI port clashes with a honeypot port.**

- Why: One of the honeypots is set to use the same port as the web UI.
- Fix: Choose another web UI port with --port, then run qpot setup again.

## Memory and disk space (`RES`, exit 18)

### QP-RES-001

**This computer does not have enough memory for QPot.**

- Why: The database and honeypots need at least 1 GiB of memory; 2 GiB or more is recommended.
- Fix: Use a machine with more memory, or close other programs, then run qpot setup again.

### QP-RES-002

**There is not enough free disk space for QPot's data.**

- Why: QPot keeps its settings, logs and database in your home folder and needs at least 2 GiB free there.
- Fix: Free some disk space (for example delete old files or run: docker system prune), then run qpot setup again.

### QP-RES-003

**There is not enough free disk space for Docker's images.**

- Why: The honeypot and database images need at least 3 GiB in Docker's storage folder.
- Fix: Free some disk space in that folder, then run qpot setup again.

### QP-RES-004

**The disk filled up while installing.**

- Why: The package manager ran out of space part of the way through.
- Fix: Free some disk space (for example: sudo apt-get clean), then run qpot setup again.

### QP-RES-005

**HiFi resource limits could not be enforced.**

- Why: Docker has not confirmed active CPU, memory and PID cgroup controls. Rootless Docker without systemd delegation can accept settings without enforcing them.
- Fix: Use an isolated Docker host with working cgroup controllers, or configure systemd cgroup delegation for rootless Docker. Verify CPU, memory and PID limits on that host before starting HiFi again.

### QP-RES-006

**Docker cannot enforce every container resource limit.**

- Why: The Docker daemon reports that it cannot apply some cgroup limits (memory, swap, PIDs or CPU). Docker accepts such a limit and drops it, so a honeypot can use more than its limit. A kernel booted without the memory controller (Raspberry Pi OS by default), rootless Docker without cgroup delegation or a daemon outside a systemd cgroup cause this.
- Fix: Run Docker on a Linux host with cgroup v2 and systemd (current Debian, Ubuntu, Fedora), or enable the missing controllers: on Raspberry Pi OS add cgroup_enable=memory to /boot/firmware/cmdline.txt and reboot; for rootless Docker configure systemd cgroup delegation. Restart Docker and run qpot doctor again.

### QP-RES-007

**Docker cannot enforce the resource limits these honeypots require.**

- Why: Docker did not confirm CPU, memory, swap and PID limits, so a honeypot that handles attacker input could use the whole computer. Rootless Docker without delegated cgroups and old cgroup v1 hosts without swap accounting are the usual causes.
- Fix: Run QPot on a Docker host with cgroup v2 (docker info shows no limit warnings). On rootless Docker, delegate the cpu, memory and pids controllers to the user. Only cowrie, conpot and refrigeration start without confirmed limits; qpot doctor shows which limits are missing.

### QP-RES-008

**The disk is too full to run the honeypots.**

- Why: The disk that holds this instance's data has less free space than cleanup.min_free_mb (512 MB by default). A honeypot that cannot write its log still accepts connections and records nothing, so QPot keeps the honeypots stopped while the disk is this full.
- Fix: Free space on that disk: run qpot cleanup, delete old files, or move the instance's data to a larger disk. qpot serve starts the honeypots it stopped by itself once cleanup.resume_free_mb (1024 MB by default) is free again; qpot up starts them as soon as cleanup.min_free_mb is free. While the instance runs, qpot doctor shows the free space and the honeypots that were stopped.

## Services and systemd (`SVC`, exit 19)

### QP-SVC-001

**systemd is not running on this system.**

- Why: WSL without systemd and containers have no service manager, so services cannot start at boot.
- Fix: On WSL: put '[boot]' and 'systemd=true' in /etc/wsl.conf, run 'wsl.exe --shutdown' in Windows, reopen the terminal and run qpot setup again. Elsewhere, start Docker yourself (sudo dockerd &) and run setup without --service.

### QP-SVC-002

**Installing the QPot service failed.**

- Why: systemd refused to load or start the service; the details show why.
- Fix: Read the details, or check with: systemctl status <the service name shown>. You can also run setup without --service and start QPot with: qpot up -d

### QP-SVC-003

**Running QPot as a service is only supported on Linux.**

- Why: The --service option uses systemd, which only Linux has.
- Fix: Leave out --service. Start QPot with: qpot up -d

### QP-SVC-004

**The systemctl command was not found.**

- Why: This system does not use systemd, so setup cannot manage services with it.
- Fix: Leave out --service and start QPot with: qpot up -d

## Web UI and control plane (`WEB`, exit 20)

### QP-WEB-001

**The QPot control plane (web UI and API) did not start.**

- Why: It stopped while starting; its log names the reason, often a port already in use.
- Fix: Read the log shown in the details, fix what it names, then run: qpot up -d

### QP-WEB-002

**The web UI is not answering as this QPot instance.**

- Why: Nothing answers on the web UI address, or a different program answers there.
- Fix: Run qpot doctor to re-check. If another program holds the port, change web_ui.port with: qpot config

### QP-WEB-003

**The QPot control plane is not running.**

- Why: The web UI, threat intelligence and HiFi resets only run while the control plane runs.
- Fix: Start it with: qpot up -d

### QP-WEB-004

**The API request body is not valid.**

- Why: The request is not the required JSON object, contains unknown fields, exceeds the size limit, or omits a required field.
- Fix: Send the documented JSON object with Content-Type: application/json. Check the field names, types and body size in doc/api.md, then retry.

### QP-WEB-005

**The web UI and API would be reachable from other computers without a login.**

- Why: web_ui.qpot_id_auth is false, no web_ui username and password are both set, and web_ui.bind_addr is not a loopback address.
- Fix: Turn the login back on (web_ui.qpot_id_auth: true, or set both web_ui.username and web_ui.password), or set web_ui.bind_addr: 127.0.0.1 and reach the UI over an SSH tunnel. Edit the settings with: qpot config

## QPot instance and containers (`INST`, exit 21)

### QP-INST-001

**The QPot instance could not be created.**

- Why: Setup could not write the instance's folders or files.
- Fix: Check the details and the free space and permissions of ~/.qpot, then run qpot setup again.

### QP-INST-002

**The instance settings could not be saved.**

- Why: Writing config.yaml failed, usually because of permissions or a full disk.
- Fix: Check the free space and permissions of ~/.qpot, then run qpot setup again.

### QP-INST-003

**The containers could not be started.**

- Why: Docker Compose stopped with an error (shown above), often a missing image or a port in use.
- Fix: Read the messages above, fix what they name, then run qpot setup again (or qpot up -d).

### QP-INST-004

**Some parts were not healthy in time.**

- Why: A container was still starting or kept failing when the wait ran out.
- Fix: Run qpot doctor in a minute or two to check again, and qpot logs <honeypot> to see why a part fails.

### QP-INST-005

**The database is not ready.**

- Why: The database container is not running (it stopped, or is still starting), or its tables were not created.
- Fix: If qpot doctor shows the database exited or not created, start it with: qpot up -d; if it stays down, run qpot down, then qpot setup. If it is still starting, wait a minute and run qpot doctor. Its log: qpot docker logs database (for another instance add -i <instance> to each command)

### QP-INST-006

**The GeoIP database file is missing.**

- Why: The instance is set to use a country database that is no longer on disk, so the log collector cannot start.
- Fix: Download it again with: qpot geoip update

### QP-INST-007

**The QPot instance is not running.**

- Why: Its containers are stopped.
- Fix: Start it with: qpot up -d

### QP-INST-008

**A part of the instance is not running properly.**

- Why: A container stopped, was never created, or reports itself unhealthy.
- Fix: See why with: qpot logs <the part named above>. Start what stopped with: qpot up -d; if it stays down, run qpot down, then qpot setup (for another instance add -i <instance> to each command).

### QP-INST-009

**Another honeypot change is still running.**

- Why: The control plane is already enabling, disabling, restarting or changing settings for a honeypot.
- Fix: Wait for that change to finish, refresh the honeypot status and retry. Do not start a second change to bypass the active one.

### QP-INST-010

**This honeypot is turned off.**

- Why: The requested restart needs an enabled honeypot, but its saved configuration has it disabled.
- Fix: Choose the honeypot in the web UI and turn it on, or run qpot honeypot enable <name> -i <instance>. Then check its status before restarting it.

### QP-INST-011

**The private SSH runtime store could not be prepared.**

- Why: Its location or ownership record is invalid, migration has not finished, or legacy data cannot be moved safely.
- Fix: Stop the instance and inspect the paths in the details. Keep both the instance directory and its recorded runtime store in backups. Do not delete keys or merge conflicting evidence. A move between filesystems must be completed offline while preserving ownership and permissions; then retry qpot up.

### QP-INST-012

**Collector checkpoint migration could not be completed.**

- Why: Legacy and canonical collector state conflict, a state path is not an ordinary directory, or its atomic rename or directory sync failed.
- Fix: Stop the collector and inspect both collector-state and collector inside the instance directory. Preserve cursor files and any completed canonical migration. Resolve conflicts offline without merging, deleting or reseeding acknowledged state; then retry qpot up.

### QP-INST-013

**The HiFi runtime images do not match this QPot build.**

- Why: An unlinked source build selects the preserved legacy latest images, or an existing broker and its application or backup images do not use the same supported source.
- Fix: Use an official release with its matching source-commit images, or build both docker/ssh-proxy/Dockerfile and docker/ssh-backend/Dockerfile from this checkout, set ssh-proxy image_source=local, then recreate the HiFi deployment with qpot up -d. Stop and remove remain available; offline rendering does not prove runtime compatibility.

### QP-INST-014

**The SSH recycler cannot read broker metadata.**

- Why: The broker session log is unreadable or is not an ordinary stable file, so the host cannot safely process reset requests.
- Fix: Keep the broker log and generation counters. Use matching updated HiFi images and regenerate/recreate the deployment so its verified private runtime store enables host-readable broker metadata. Check the operating account and private store permissions; custom broker deployments must grant the trusted recycler read access. Do not delete, truncate or fake reset records.

### QP-INST-015

**These security settings are not supported for the enabled honeypots.**

- Why: security.network_isolation.allow_private_egress switches the egress guard off, and a honeypot that runs or relays what an attacker sends is enabled. It could then reach your network, the Docker host and cloud metadata addresses.
- Fix: Set security.network_isolation.allow_private_egress: false (qpot config), or turn off every honeypot other than cowrie, conpot and refrigeration (qpot honeypot disable <name>): only those three may run with the egress guard off. qpot doctor names the honeypots concerned.

### QP-INST-016

**Files of this instance still carry the QPot ID.**

- Why: An earlier QPot version wrote the QPot ID (the API credential) into the collector's configuration and into every line of the log backups. This version does not, but the instance has not been restarted with it yet, or its backups could not be rewritten.
- Fix: Restart the instance so its files are regenerated and its backups rewritten: qpot down -i <instance>, then qpot up -d -i <instance>. Then run qpot doctor again. If backups were copied elsewhere before this (a SIEM, off-site storage), treat the old QPot ID as disclosed to whoever can read those copies.

## Intelligence recovery and ownership (`INTEL`, exit 22)

### QP-INTEL-001

**Intelligence recovery could not load a valid checkpoint.**

- Why: The database is unavailable or its saved worker state is invalid. No new events are acknowledged.
- Fix: Restore database access and inspect the checkpoint error. Keep the checkpoint; do not delete recovery state to bypass the failure.

### QP-INTEL-002

**The intelligence checkpoint could not be saved.**

- Why: The write failed or its acknowledgment was lost. The worker retains the exact record for retry.
- Fix: Restore database availability or free storage, then let the worker retry. Do not manually mark pending events classified.

### QP-INTEL-003

**The intelligence batch is waiting for replay.**

- Why: An IOC, TTP session or event-tag write failed or returned an uncertain result.
- Fix: Restore database availability. The saved batch will replay with the same revisions and counts before newer events are processed.

### QP-INTEL-004

**The intelligence worker could not claim ownership.**

- Why: Another worker owns the database lease or local lock, or ownership could not be verified.
- Fix: Keep event collection running. QPot tries again by itself, within a minute at most: once the current owner stops and its database lease expires, or the database answers again, a new worker takes over. If this lasts, find the other owner (another control plane on this database) or repair coordination access. Do not delete lease or revision records or remove a lock file held by a running process.

### QP-INTEL-005

**The intelligence batch could not be prepared safely.**

- Why: The backend lacks recovery support, an event lacks an immutable ID, an IOC baseline read failed, or classifier state could not be encoded.
- Fix: Use a supported initialized backend and preserve immutable source-event IDs. Inspect the preparation error and repair the source or backend before retrying. Source events remain available for later processing.

### QP-INTEL-006

**The backend cannot preserve an intelligence string.**

- Why: An IOC or session contains invalid UTF-8, or a NUL byte unsupported by this backend. The worker pauses rather than rewriting the value or acknowledging its source events.
- Fix: Keep the original events and checkpoints. Resolve the backend's string-storage limitation with verified lossless support before retrying. Do not normalize indicator bytes, delete recovery state or manually mark pending events classified; a restart alone will not fix this data.

### QP-INTEL-007

**The intelligence worker lost its database lease.**

- Why: Lease renewal failed or expired, or a successor fenced this worker. Further processing and shutdown replay must stop.
- Fix: Nothing to do when it clears by itself: the stopped worker is not resumed, and QPot starts a new one within a minute, which takes a new lease and recovers the exact batch from the published checkpoint. This happens after any database outage longer than the 30-second lease. If it keeps returning, check that the database and its Keeper stay reachable and whether another control plane owns the lease. Keep the lease, revision counter and published checkpoint. Do not force an old worker to continue.

### QP-INTEL-008

**The database cannot provide safe intelligence ownership.**

- Why: The required atomic coordination mechanism is unavailable or the backend does not implement fenced worker leases.
- Fix: Enable the supported database coordination mechanism; ClickHouse requires Keeper and strict KeeperMap compare-and-swap. Event collection and the UI can continue while the worker is stopped. Stop and drain all pre-upgrade workers before enabling the new ownership protocol.

## Cluster trust and enrollment (`CLUSTER`, exit 23)

### QP-CLUSTER-001

**Legacy cluster requires upgrade.**

- Why: This cluster uses password-derived or shared CA signing credentials.
- Fix: Stop old control planes, update all QPot nodes, run qpot cluster upgrade once on the chosen enrollment host, then leave and rejoin other nodes with the new ID.

### QP-CLUSTER-002

**Unsupported cluster protocol.**

- Why: The cluster or peer uses an incompatible protocol version.
- Fix: Update every node to a QPot release supporting the cluster protocol; do not downgrade trust checks.

### QP-CLUSTER-003

**Invalid node enrollment request.**

- Why: The certificate request is missing, malformed, oversized, uses an unsupported key, or lacks a valid signature.
- Fix: Update the joining QPot and retry enrollment with its locally generated P-256 key.

### QP-CLUSTER-004

**Node is not the enrollment authority.**

- Why: Ordinary cluster members do not hold the CA signing key.
- Fix: Use the host that initialized or upgraded the cluster as the join seed.

### QP-CLUSTER-005

**Invalid or expired node identity.**

- Why: The node certificate, private key, assigned identity, lifetime, or CA does not match.
- Fix: Re-enroll the node through the enrollment host; never bypass TLS verification.

### QP-CLUSTER-006

**Cluster upgrade is blocked.**

- Why: The cluster is running, locked, not unlocked, already current, or its local configuration cannot be upgraded safely.
- Fix: Stop its control plane, unlock the saved password, check the cluster configuration and inspect any upgrade lock before retrying.

### QP-CLUSTER-007

**Cluster changed during upgrade.**

- Why: The saved cluster state no longer matches the prepared upgrade.
- Fix: Reload the state and coordinate with other processes before retrying. The upgrade did not replace it.

### QP-CLUSTER-008

**Cluster upgrade could not be saved.**

- Why: Backup, staging, or atomic activation failed.
- Fix: Check disk space and permissions. Keep the original cluster state and any completed backup, then retry after correcting the error.

### QP-CLUSTER-009

**Cluster upgrade activated; durability uncertain.**

- Why: The new cluster state was atomically activated, but syncing its directory failed.
- Fix: Do not rerun the upgrade or restore the old CA. Inspect qpot cluster status and the private backup, correct the filesystem issue, and keep the new trust state.

### QP-CLUSTER-010

**Cluster encryption is off.**

- Why: Members prove which node they are with their node certificate in the TLS handshake, so a cluster without TLS cannot tell its members apart.
- Fix: Set "enable_encryption": true in ~/.qpot/cluster/cluster.json on every node, then restart their control planes.

## Interrupted (`INT`, exit 130)

### QP-INT-001

**Setup was stopped before it finished.**

- Why: Ctrl-C was pressed, or the process was asked to stop.
- Fix: Run qpot setup again. It checks what is already done and continues from there.

### QP-INT-002

**A step took too long and was stopped.**

- Why: A command did not finish within its time limit.
- Fix: Run qpot setup again. If the same step times out again, check the network and the details shown.

## Unexpected problems (`BUG`, exit 70)

### QP-BUG-001

**Something unexpected went wrong.**

- Why: Setup hit a problem it does not have a better explanation for.
- Fix: Run qpot setup again. If it happens again, report it with the details at https://github.com/YurilLAB/QPot/issues

### QP-BUG-002

**The installer stopped unexpectedly.**

- Why: A command in the install script failed in a way it does not explain.
- Fix: Read the messages above and run the installer again. If it happens again, report it at https://github.com/YurilLAB/QPot/issues
