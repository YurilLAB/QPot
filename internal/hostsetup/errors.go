// Package hostsetup prepares a host for QPot: it finds out what the machine
// is, works out how Docker Engine and the Compose plugin can be installed or
// started on it, shows the exact commands and runs them once the owner agrees.
//
// Every failure it reports is an *Error carrying a stable code from the
// catalog below (QP-<CATEGORY>-<NUMBER>). A code always means the same
// failure: codes are never renumbered or reused, only added.
package hostsetup

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Category groups error codes. Its exit status is what `qpot setup`,
// `qpot doctor` and the install scripts exit with for a code in it, so a
// script can tell kinds of failure apart.
type Category struct {
	Key  string
	Name string
	Exit int
}

// Categories, in documentation order. Exit statuses are part of the
// interface: never change one.
var categories = []Category{
	{"INPUT", "Settings and answers", 10},
	{"HOST", "This computer and its operating system", 11},
	{"PERM", "Permissions and sudo", 12},
	{"NET", "Network and downloads", 13},
	{"PKG", "Package manager", 14},
	{"DOCKER", "Docker Engine", 15},
	{"COMPOSE", "Docker Compose", 16},
	{"PORT", "Network ports", 17},
	{"RES", "Memory and disk space", 18},
	{"SVC", "Services and systemd", 19},
	{"WEB", "Web UI and control plane", 20},
	{"INST", "QPot instance and containers", 21},
	{"INTEL", "Intelligence recovery and ownership", 22},
	{"CLUSTER", "Cluster trust and enrollment", 23},
	{"INT", "Interrupted", 130},
	{"BUG", "Unexpected problems", 70},
}

// Code is one entry of the error catalog.
type Code struct {
	ID    string // QP-<CAT>-<NNN>
	Title string // what went wrong, one plain sentence
	Cause string // why it usually happens
	Fix   string // what to do next
}

// Category returns the key of the code's category, e.g. "PKG".
func (c Code) Category() string {
	parts := strings.Split(c.ID, "-")
	if len(parts) != 3 {
		return ""
	}
	return parts[1]
}

var codeRe = regexp.MustCompile(`^QP-([A-Z]+)-([0-9]{3})$`)

// catalog lists every code. Append new codes; never edit an ID or reuse one.
var catalog = []Code{
	// Runtime intelligence recovery and cluster trust errors.
	{"QP-INTEL-001",
		"Intelligence recovery could not load a valid checkpoint.",
		"The database is unavailable or its saved worker state is invalid. No new events are acknowledged.",
		"Restore database access and inspect the checkpoint error. Keep the checkpoint; do not delete recovery state to bypass the failure."},
	{"QP-INTEL-002",
		"The intelligence checkpoint could not be saved.",
		"The write failed or its acknowledgment was lost. The worker retains the exact record for retry.",
		"Restore database availability or free storage, then let the worker retry. Do not manually mark pending events classified."},
	{"QP-INTEL-003",
		"The intelligence batch is waiting for replay.",
		"An IOC, TTP session or event-tag write failed or returned an uncertain result.",
		"Restore database availability. The saved batch will replay with the same revisions and counts before newer events are processed."},
	{"QP-INTEL-004",
		"This local intelligence worker could not claim ownership.",
		"Another process for this database owns the local lock, or the lock directory is inaccessible.",
		"Run only one worker for a database. Stop the other local control plane or repair lock-directory access, then restart this control plane. Do not delete a lock file held by a running process. Coordinate ownership separately across hosts and OS accounts."},
	{"QP-INTEL-005",
		"The intelligence batch could not be prepared safely.",
		"The backend lacks recovery support, an IOC baseline read failed, or classifier state could not be encoded.",
		"Use a supported initialized backend, inspect its error and retry. Source events remain available for later processing."},
	{"QP-INTEL-006",
		"The backend cannot preserve an intelligence string.",
		"An IOC or session contains invalid UTF-8, or a NUL byte unsupported by this backend. The worker pauses rather than rewriting the value or acknowledging its source events.",
		"Keep the original events and checkpoints. Resolve the backend's string-storage limitation with verified lossless support before retrying. Do not normalize indicator bytes, delete recovery state or manually mark pending events classified; a restart alone will not fix this data."},
	{"QP-CLUSTER-001",
		"Legacy cluster requires upgrade.",
		"This cluster uses password-derived or shared CA signing credentials.",
		"Stop old control planes, update all QPot nodes, run qpot cluster upgrade once on the chosen enrollment host, then leave and rejoin other nodes with the new ID."},
	{"QP-CLUSTER-002",
		"Unsupported cluster protocol.",
		"The cluster or peer uses an incompatible protocol version.",
		"Update every node to a QPot release supporting the cluster protocol; do not downgrade trust checks."},
	{"QP-CLUSTER-003",
		"Invalid node enrollment request.",
		"The certificate request is missing, malformed, oversized, uses an unsupported key, or lacks a valid signature.",
		"Update the joining QPot and retry enrollment with its locally generated P-256 key."},
	{"QP-CLUSTER-004",
		"Node is not the enrollment authority.",
		"Ordinary cluster members do not hold the CA signing key.",
		"Use the host that initialized or upgraded the cluster as the join seed."},
	{"QP-CLUSTER-005",
		"Invalid or expired node identity.",
		"The node certificate, private key, assigned identity, lifetime, or CA does not match.",
		"Re-enroll the node through the enrollment host; never bypass TLS verification."},
	{"QP-CLUSTER-006",
		"Cluster upgrade is blocked.",
		"The cluster is running, locked, not unlocked, already current, or its local configuration cannot be upgraded safely.",
		"Stop its control plane, unlock the saved password, check the cluster configuration and inspect any upgrade lock before retrying."},
	{"QP-CLUSTER-007",
		"Cluster changed during upgrade.",
		"The saved cluster state no longer matches the prepared upgrade.",
		"Reload the state and coordinate with other processes before retrying. The upgrade did not replace it."},
	{"QP-CLUSTER-008",
		"Cluster upgrade could not be saved.",
		"Backup, staging, or atomic activation failed.",
		"Check disk space and permissions. Keep the original cluster state and any completed backup, then retry after correcting the error."},
	{"QP-CLUSTER-009",
		"Cluster upgrade activated; durability uncertain.",
		"The new cluster state was atomically activated, but syncing its directory failed.",
		"Do not rerun the upgrade or restore the old CA. Inspect qpot cluster status and the private backup, correct the filesystem issue, and keep the new trust state."},

	// INPUT: settings and answers.
	{"QP-INPUT-001", "The instance name is not valid.",
		"Instance names become folder and container names, so only letters, digits, '-' and '_' work (1 to 32 characters, starting with a letter or digit).",
		"Pick a name such as 'default' or 'sensor1' and pass it with -i, for example: qpot setup -i sensor1"},
	{"QP-INPUT-002", "That honeypot profile does not exist.",
		"The profile names are minimal, standard and hifi.",
		"Use one of them, for example: qpot setup --profile minimal. Or list honeypots yourself with --honeypots cowrie,endlessh"},
	{"QP-INPUT-003", "One of the honeypot names is not known.",
		"Honeypot names must match the ones QPot ships; a typo is the usual reason.",
		"See the names with: qpot honeypot list. Then pass them with --honeypots, separated by commas."},
	{"QP-INPUT-004", "The port number is not valid.",
		"A port must be a whole number from 1 to 65535.",
		"Choose a free port such as 8080, for example: qpot setup --port 8080"},
	{"QP-INPUT-005", "The web UI address is not valid for this computer.",
		"The address must be 127.0.0.1 (this computer only), 0.0.0.0 (all networks) or an IP address this computer actually has.",
		"Keep the safe default 127.0.0.1 and reach the web UI through an SSH tunnel, or pass an address this computer has with --bind."},
	{"QP-INPUT-006", "That country code is not known.",
		"The attack map needs a two-letter ISO country code such as DE, US or AU.",
		"Pass a two-letter code with --country, or leave it out to use the computer's time zone."},
	{"QP-INPUT-007", "That database type is not supported.",
		"QPot can store events in ClickHouse or TimescaleDB.",
		"Use --database clickhouse (the default) or --database timescaledb."},
	{"QP-INPUT-008", "Setup needs an answer but cannot ask for it.",
		"There is no terminal to type into (for example in a script or CI), so setup does not prompt.",
		"Pass the setting as a flag (the message names it), or run qpot setup in a terminal to answer the questions."},
	{"QP-INPUT-009", "The input ended before setup finished asking its questions.",
		"Standard input was closed (Ctrl-D, or a pipe that ran out of lines).",
		"Run qpot setup again in a terminal, or pass --yes with flags to run without questions."},
	{"QP-INPUT-010", "Two options were given that cannot be used together.",
		"Some options choose the same thing in different ways.",
		"Keep only one of the options the message names and run the command again."},
	{"QP-INPUT-011", "That error code is not known.",
		"Codes look like QP-PKG-001; this one is not in QPot's list.",
		"Check the code for typos, or read the full list in doc/setup-errors.md."},
	{"QP-INPUT-012", "An option has a value setup does not understand.",
		"Each option accepts only the values listed in its help text.",
		"Run qpot setup --help to see the accepted values, then try again."},
	{"QP-INPUT-013", "Setup was cancelled before it changed anything.",
		"You answered no when setup asked to go ahead.",
		"Nothing was changed. Run qpot setup again whenever you are ready."},

	// HOST: this computer and its operating system.
	{"QP-HOST-001", "This operating system is not supported.",
		"QPot runs on Linux, macOS and Windows.",
		"Run QPot on a Linux server or virtual machine (Ubuntu, Debian, Fedora, Rocky or AlmaLinux are easiest)."},
	{"QP-HOST-002", "This processor type is not supported.",
		"Docker and QPot's honeypot images are published for 64-bit x86 (amd64) and 64-bit ARM (arm64).",
		"Use a 64-bit x86 or ARM machine or virtual machine."},
	{"QP-HOST-003", "Setup cannot install Docker on this Linux distribution by itself.",
		"Setup knows how to install Docker on Debian, Ubuntu, Fedora, CentOS Stream, Rocky, AlmaLinux, RHEL, openSUSE and Arch, and their close relatives.",
		"Install Docker Engine and the Compose plugin by following https://docs.docker.com/engine/install/ , then run qpot setup again."},
	{"QP-HOST-004", "Setup could not tell which Linux distribution this is.",
		"The file /etc/os-release is missing or unreadable, so setup cannot pick the right install method.",
		"Install Docker Engine and the Compose plugin yourself (https://docs.docker.com/engine/install/), then run qpot setup again."},
	{"QP-HOST-005", "Docker does not publish packages for this version of the distribution.",
		"This release is newer or older than the releases Docker supports, and the distribution has no Docker package setup can use instead.",
		"Upgrade to a release Docker supports (see https://docs.docker.com/engine/install/), or install Docker by hand, then run qpot setup again."},
	{"QP-HOST-006", "A tool needed to build QPot is missing.",
		"No ready-made QPot download exists for this machine, so the installer builds it from source, which needs Go and git.",
		"Install Go (https://go.dev/dl/) and git, or download a release from https://github.com/YurilLAB/QPot/releases , then run the installer again."},
	{"QP-HOST-007", "The installed qpot program does not run on this computer.",
		"The download was probably for a different processor type, or it was damaged.",
		"Build it from source: git clone https://github.com/YurilLAB/QPot.git && cd QPot && go build -o qpot ./cmd/qpot"},
	{"QP-HOST-008", "Building QPot from source failed.",
		"The Go build stopped with an error; the usual reasons are an old Go version or no internet access for Go's downloads.",
		"Read the build output above, update Go if it is old, and run the installer again."},
	{"QP-HOST-009", "The package manager this distribution uses was not found.",
		"Setup expected apt-get, dnf, zypper or pacman for this distribution, but the command is missing.",
		"Install Docker Engine and the Compose plugin by hand (https://docs.docker.com/engine/install/), then run qpot setup again."},

	// PERM: permissions and sudo.
	{"QP-PERM-001", "Setup needs administrator rights, but sudo is not available.",
		"Installing or starting Docker changes the system, which needs root. You are not root and the sudo command is not installed.",
		"Run setup as root (for example: su -c 'qpot setup'), or install sudo and give your user access to it, then run qpot setup again."},
	{"QP-PERM-002", "sudo needs your password, but there is no terminal to type it in.",
		"Setup is running without a terminal (a script or CI), so sudo cannot ask for the password. (sudo answers the same way when your user may not use sudo at all.)",
		"Run qpot setup in a terminal so sudo can ask for your password, or run it as root. If your user may not use sudo, ask an administrator to allow it."},
	{"QP-PERM-003", "sudo refused to run the command.",
		"Your user is not allowed to use sudo, or the password was wrong too many times.",
		"Ask an administrator to give your user sudo rights (or run setup as root), then run qpot setup again."},
	{"QP-PERM-004", "Your user cannot talk to Docker.",
		"Docker only lets root and members of the 'docker' group use it. Being in that group is the same as having root on this computer.",
		"Run setup again and allow it to add you to the docker group (or pass --docker-group), or run QPot as root."},
	{"QP-PERM-005", "You were added to the docker group, but this login session does not have it yet.",
		"Group changes only apply to new login sessions.",
		"Log out and back in (or run: newgrp docker), then run the same qpot setup command again. It continues where it stopped."},
	{"QP-PERM-006", "Setup was not allowed to make the changes it needs.",
		"You chose not to let setup run the administrator commands it showed.",
		"Run the commands yourself, or run qpot setup again and agree (or pass --install-docker)."},
	{"QP-PERM-007", "Setup could not write QPot's files.",
		"Your home folder (or the folder QPot uses) is not writable, or the disk is read-only.",
		"Check that you can write to ~/.qpot (for example: touch ~/.qpot/test), fix the permissions, and run qpot setup again."},
	{"QP-PERM-008", "Setup could not put a file in a system folder.",
		"The folder is read-only, the disk is full, or the command was refused.",
		"Check that the system disk is writable and has free space (df -h /), then run qpot setup again."},
	{"QP-PERM-009", "Setup could not add your user to the docker group.",
		"The usermod command failed; the details show why (for example, the docker group does not exist yet).",
		"Run: sudo groupadd -f docker && sudo usermod -aG docker $USER, log out and back in, and run qpot setup again. Or run QPot as root."},
	{"QP-PERM-010", "Setup could not make a private temporary folder.",
		"Files that root installs (Docker's signing key, its package source) are first written to a folder only you can use, so no other user can swap them. That folder could not be made, or it is not private.",
		"Check that the temporary folder (TMPDIR, or /tmp) exists, is writable and has free space (df -h /tmp), and that TMPDIR does not point into another user's folder, then run qpot setup again."},

	// NET: network and downloads.
	{"QP-NET-001", "This computer could not look up a server name.",
		"There is no internet connection, or DNS (name lookup) is not working.",
		"Check the connection (for example: ping -c1 download.docker.com) and your DNS settings, then run qpot setup again."},
	{"QP-NET-002", "This computer could not connect to a download server.",
		"The internet connection is down, a firewall blocks it, or a proxy is needed.",
		"Check the connection and any proxy settings (HTTPS_PROXY), then run qpot setup again."},
	{"QP-NET-003", "A secure (HTTPS) connection could not be checked.",
		"The computer's clock is wrong, the certificate store is missing, or a proxy is intercepting HTTPS.",
		"Check the date and time (date), make sure the ca-certificates package is installed, and run qpot setup again."},
	{"QP-NET-004", "A download server answered with an error.",
		"The file may have moved, or the server had a temporary problem.",
		"Wait a few minutes and run qpot setup again. If it keeps happening, report it at https://github.com/YurilLAB/QPot/issues"},
	{"QP-NET-005", "Docker's signing key did not match the published fingerprint.",
		"The key that was downloaded is not Docker's real key. Something between you and Docker may be tampering with downloads, so setup stopped without installing anything.",
		"Do not install Docker from this network. Try again from a trusted network, and compare the key with https://docs.docker.com/engine/install/"},
	{"QP-NET-006", "The package manager could not download packages.",
		"There is no internet connection, DNS does not work, or a package mirror is down.",
		"Check the connection, then run qpot setup again. Your distribution's mirror may also be busy: wait a little and retry."},
	{"QP-NET-007", "The QPot download failed.",
		"GitHub could not be reached, or the release file is missing.",
		"Check the internet connection and run the installer again, or build from source as the message shows."},
	{"QP-NET-008", "The GeoIP country database could not be downloaded.",
		"The download site could not be reached. QPot works without it, but events get no country and the attack map draws no lines.",
		"Run this later to add it: qpot geoip update"},

	// PKG: package manager.
	{"QP-PKG-001", "Another program is installing software right now.",
		"The package manager allows one program at a time. Automatic updates often run for a few minutes after a computer starts.",
		"Wait a few minutes for the other program to finish, then run qpot setup again."},
	{"QP-PKG-002", "The package lists could not be updated.",
		"One of the configured software sources is broken or unreachable.",
		"Run the update command the message shows to see which source fails, fix or remove that source, then run qpot setup again."},
	{"QP-PKG-003", "A software source failed its signature check.",
		"The package manager could not confirm a source's signing key, so it refused to trust it.",
		"Check the source the message names. For Docker's source, delete /etc/apt/keyrings/docker.asc and run qpot setup again so it is fetched and checked again."},
	{"QP-PKG-004", "Installing the packages failed.",
		"The package manager stopped with an error; the details below show its last lines.",
		"Read the details, fix what they name (often disk space or a broken package), then run qpot setup again."},
	{"QP-PKG-005", "An earlier software installation was interrupted.",
		"The package system is half-way through a previous install and must finish it first.",
		"Run: sudo dpkg --configure -a   then run qpot setup again."},
	{"QP-PKG-006", "Packages that conflict with Docker are installed.",
		"Docker's own packages replace older Docker, containerd, runc or Podman packages that are already installed.",
		"Remove the packages the message names (it shows the command), then run qpot setup again."},
	{"QP-PKG-007", "A package setup needs was not found.",
		"The distribution's sources do not offer it, or the package lists are out of date.",
		"Update the package lists, check that the distribution's standard sources are enabled, then run qpot setup again."},
	{"QP-PKG-008", "A Docker signing key is already installed, and it is not Docker's real key.",
		"The file at Docker's standard key location holds a different key, so setup will not trust that source.",
		"Look at the file the message names. If you did not put it there on purpose, delete it and run qpot setup again."},
	{"QP-PKG-009", "The package manager took too long and was stopped.",
		"The download was very slow, or the package manager was waiting for something.",
		"Run qpot setup again. If it keeps timing out, run the shown command yourself to see where it waits."},

	// DOCKER: Docker Engine.
	{"QP-DOCKER-001", "Docker is not installed.",
		"QPot runs its honeypots in Docker containers.",
		"Run qpot setup in a terminal and let it install Docker, or pass --install-docker, or install it yourself from https://docs.docker.com/engine/install/"},
	{"QP-DOCKER-002", "Docker is installed but not running.",
		"The Docker service (or Docker Desktop) is stopped.",
		"Start it (Linux: sudo systemctl start docker; macOS and Windows: open Docker Desktop), or let setup start it with --install-docker, then run qpot setup again."},
	{"QP-DOCKER-003", "The Docker service failed to start.",
		"Docker's background service stopped with an error; the details show its last log lines.",
		"Read the details, or run: sudo journalctl -u docker --no-pager -n 50   Fix what it reports, then run qpot setup again."},
	{"QP-DOCKER-004", "The docker command here is Podman, not Docker.",
		"The podman-docker package makes 'docker' run Podman, which QPot does not support.",
		"Remove podman-docker and install Docker Engine (setup can do both when you agree), then run qpot setup again."},
	{"QP-DOCKER-005", "Docker is too old for QPot.",
		"QPot needs Docker Engine 20.10 or newer.",
		"Let setup update it (pass --install-docker), or update Docker with your package manager, then run qpot setup again."},
	{"QP-DOCKER-006", "Docker was installed, but the docker command still cannot be found.",
		"The command was installed to a folder that is not on your PATH.",
		"Open a new terminal (or run: hash -r) and run qpot setup again."},
	{"QP-DOCKER-007", "Docker Desktop is installed and needs to be started once.",
		"Docker Desktop asks you to accept its terms the first time it opens, and only then starts Docker.",
		"Open Docker Desktop, accept its terms if you agree, wait until it says the engine is running, then run qpot setup again."},
	{"QP-DOCKER-008", "Setup cannot install Docker Desktop by itself here.",
		"On macOS setup uses Homebrew and on Windows it uses winget; neither was found.",
		"Install Docker Desktop from https://docs.docker.com/desktop/ , start it once, then run qpot setup again."},
	{"QP-DOCKER-009", "Installing Docker Desktop failed.",
		"The installer (Homebrew or winget) stopped with an error.",
		"Read the installer's message above, fix what it names, or install Docker Desktop from https://docs.docker.com/desktop/ , then run qpot setup again."},

	// COMPOSE: Docker Compose.
	{"QP-COMPOSE-001", "The Docker Compose plugin is missing.",
		"QPot starts its containers with 'docker compose', which is a separate package.",
		"Let setup install it (pass --install-docker), or install the docker-compose-plugin package, then run qpot setup again."},
	{"QP-COMPOSE-002", "Docker Compose is too old for QPot.",
		"QPot needs Compose version 2 (the 'docker compose' command). The old 'docker-compose' version 1 does not work.",
		"Let setup install the Compose plugin (pass --install-docker), or install docker-compose-plugin yourself, then run qpot setup again."},
	{"QP-COMPOSE-003", "Docker Compose was installed but does not work.",
		"The 'docker compose' command still fails after installing it.",
		"Run: docker compose version   to see the error, fix it, then run qpot setup again."},

	// PORT: network ports.
	{"QP-PORT-001", "The web UI port is already in use.",
		"Another program, or another QPot instance, is already listening on that port.",
		"Pick another port with --port (for example --port 8081), or stop the program that uses it."},
	{"QP-PORT-002", "Ports the honeypots need are already in use.",
		"Another program, or another QPot instance, already listens on them.",
		"Stop the program that uses them, or change base_port in the instance config (qpot config), then run qpot setup again."},
	{"QP-PORT-003", "No free port for the web UI was found.",
		"The chosen port and the 100 ports after it are all taken.",
		"Free a port, or choose a different one with --port, then run qpot setup again."},
	{"QP-PORT-004", "Ports below 1024 need root.",
		"Linux lets only root listen on ports under 1024.",
		"Choose a port of 1024 or above (for example 8080), or run QPot as root."},
	{"QP-PORT-005", "The web UI port clashes with a honeypot port.",
		"One of the honeypots is set to use the same port as the web UI.",
		"Choose another web UI port with --port, then run qpot setup again."},

	// RES: memory and disk space.
	{"QP-RES-001", "This computer does not have enough memory for QPot.",
		"The database and honeypots need at least 1 GiB of memory; 2 GiB or more is recommended.",
		"Use a machine with more memory, or close other programs, then run qpot setup again."},
	{"QP-RES-002", "There is not enough free disk space for QPot's data.",
		"QPot keeps its settings, logs and database in your home folder and needs at least 2 GiB free there.",
		"Free some disk space (for example delete old files or run: docker system prune), then run qpot setup again."},
	{"QP-RES-003", "There is not enough free disk space for Docker's images.",
		"The honeypot and database images need at least 3 GiB in Docker's storage folder.",
		"Free some disk space in that folder, then run qpot setup again."},
	{"QP-RES-004", "The disk filled up while installing.",
		"The package manager ran out of space part of the way through.",
		"Free some disk space (for example: sudo apt-get clean), then run qpot setup again."},

	// SVC: services and systemd.
	{"QP-SVC-001", "systemd is not running on this system.",
		"WSL without systemd and containers have no service manager, so services cannot start at boot.",
		"On WSL: put '[boot]' and 'systemd=true' in /etc/wsl.conf, run 'wsl.exe --shutdown' in Windows, reopen the terminal and run qpot setup again. Elsewhere, start Docker yourself (sudo dockerd &) and run setup without --service."},
	{"QP-SVC-002", "Installing the QPot service failed.",
		"systemd refused to load or start the service; the details show why.",
		"Read the details, or check with: systemctl status <the service name shown>. You can also run setup without --service and start QPot with: qpot up -d"},
	{"QP-SVC-003", "Running QPot as a service is only supported on Linux.",
		"The --service option uses systemd, which only Linux has.",
		"Leave out --service. Start QPot with: qpot up -d"},
	{"QP-SVC-004", "The systemctl command was not found.",
		"This system does not use systemd, so setup cannot manage services with it.",
		"Leave out --service and start QPot with: qpot up -d"},

	// WEB: web UI and control plane.
	{"QP-WEB-001", "The QPot control plane (web UI and API) did not start.",
		"It stopped while starting; its log names the reason, often a port already in use.",
		"Read the log shown in the details, fix what it names, then run: qpot up -d"},
	{"QP-WEB-002", "The web UI is not answering as this QPot instance.",
		"Nothing answers on the web UI address, or a different program answers there.",
		"Run qpot doctor to re-check. If another program holds the port, change web_ui.port with: qpot config"},
	{"QP-WEB-003", "The QPot control plane is not running.",
		"The web UI, threat intelligence and HiFi resets only run while the control plane runs.",
		"Start it with: qpot up -d"},

	// INST: QPot instance and containers.
	{"QP-INST-001", "The QPot instance could not be created.",
		"Setup could not write the instance's folders or files.",
		"Check the details and the free space and permissions of ~/.qpot, then run qpot setup again."},
	{"QP-INST-002", "The instance settings could not be saved.",
		"Writing config.yaml failed, usually because of permissions or a full disk.",
		"Check the free space and permissions of ~/.qpot, then run qpot setup again."},
	{"QP-INST-003", "The containers could not be started.",
		"Docker Compose stopped with an error (shown above), often a missing image or a port in use.",
		"Read the messages above, fix what they name, then run qpot setup again (or qpot up -d)."},
	{"QP-INST-004", "Some parts were not healthy in time.",
		"A container was still starting or kept failing when the wait ran out.",
		"Run qpot doctor in a minute or two to check again, and qpot logs <honeypot> to see why a part fails."},
	{"QP-INST-005", "The database is not ready.",
		"The database container is not running yet, or its tables were not created.",
		"Wait a minute and run qpot doctor. If it stays broken, see: qpot docker logs database"},
	{"QP-INST-006", "The GeoIP database file is missing.",
		"The instance is set to use a country database that is no longer on disk, so the log collector cannot start.",
		"Download it again with: qpot geoip update"},
	{"QP-INST-007", "The QPot instance is not running.",
		"Its containers are stopped.",
		"Start it with: qpot up -d"},
	{"QP-INST-008", "A part of the instance is not running properly.",
		"A container stopped, was never created, or reports itself unhealthy.",
		"See why with: qpot logs <the part named above>   then restart with: qpot down && qpot up -d"},

	// INT: interrupted.
	{"QP-INT-001", "Setup was stopped before it finished.",
		"Ctrl-C was pressed, or the process was asked to stop.",
		"Run qpot setup again. It checks what is already done and continues from there."},
	{"QP-INT-002", "A step took too long and was stopped.",
		"A command did not finish within its time limit.",
		"Run qpot setup again. If the same step times out again, check the network and the details shown."},

	// BUG: unexpected problems.
	{"QP-BUG-001", "Something unexpected went wrong.",
		"Setup hit a problem it does not have a better explanation for.",
		"Run qpot setup again. If it happens again, report it with the details at https://github.com/YurilLAB/QPot/issues"},
	{"QP-BUG-002", "The installer stopped unexpectedly.",
		"A command in the install script failed in a way it does not explain.",
		"Read the messages above and run the installer again. If it happens again, report it at https://github.com/YurilLAB/QPot/issues"},
}

var byID = func() map[string]Code {
	m := make(map[string]Code, len(catalog))
	for _, c := range catalog {
		m[c.ID] = c
	}
	return m
}()

// Codes returns a copy of the catalog in documentation order.
func Codes() []Code { return append([]Code(nil), catalog...) }

// Categories returns the categories in documentation order.
func Categories() []Category { return append([]Category(nil), categories...) }

// CategoryOf returns the category for a key such as "PKG".
func CategoryOf(key string) (Category, bool) {
	for _, c := range categories {
		if c.Key == key {
			return c, true
		}
	}
	return Category{}, false
}

// normalizeCodeRe accepts what people type: any case, surrounding space,
// spaces or underscores for dashes, and the number without leading zeros.
var normalizeCodeRe = regexp.MustCompile(`^(?:QP)?[-_ ]?([A-Za-z]{1,10})[-_ ]?([0-9]{1,3})$`)

// Lookup finds a code, forgiving case, spacing and a missing "QP-" prefix
// ("qp-pkg-1", "PKG 001" and "QP-PKG-001" all find QP-PKG-001).
func Lookup(s string) (Code, bool) {
	s = strings.TrimSpace(s)
	if len(s) > 32 {
		return Code{}, false
	}
	m := normalizeCodeRe.FindStringSubmatch(strings.ToUpper(s))
	if m == nil {
		return Code{}, false
	}
	n := 0
	for _, d := range m[2] {
		n = n*10 + int(d-'0')
	}
	c, ok := byID[fmt.Sprintf("QP-%s-%03d", m[1], n)]
	return c, ok
}

// ExitStatus is the process exit status for a code: its category's.
func ExitStatus(id string) int {
	c, ok := byID[id]
	if !ok {
		return 70
	}
	cat, _ := CategoryOf(c.Category())
	return cat.Exit
}

// Error is a coded setup failure. Why and Fix, when set, replace the
// catalog's general text with one that names this case; Details keeps the
// raw technical output (command, exit status, stderr).
type Error struct {
	Code    string
	Why     string
	Fix     string
	Details string
	Err     error
}

// E starts a coded error. It panics on a code that is not in the catalog,
// which tests catch: a code is never made up at run time.
func E(code string) *Error {
	if _, ok := byID[code]; !ok {
		panic("hostsetup: unknown error code " + code)
	}
	return &Error{Code: code}
}

// WithWhy sets this case's cause.
func (e *Error) WithWhy(format string, a ...any) *Error {
	e.Why = fmt.Sprintf(format, a...)
	return e
}

// WithFix sets this case's fix.
func (e *Error) WithFix(format string, a ...any) *Error {
	e.Fix = fmt.Sprintf(format, a...)
	return e
}

// WithDetails sets the raw technical detail.
func (e *Error) WithDetails(format string, a ...any) *Error {
	e.Details = fmt.Sprintf(format, a...)
	return e
}

// Wrap records the underlying error and, if no details were set, uses its
// text as the details.
func (e *Error) Wrap(err error) *Error {
	e.Err = err
	if e.Details == "" && err != nil {
		e.Details = err.Error()
	}
	return e
}

func (e *Error) Error() string {
	c := byID[e.Code]
	return e.Code + ": " + c.Title
}

func (e *Error) Unwrap() error { return e.Err }

// Entry returns the catalog entry of the error's code.
func (e *Error) Entry() Code { return byID[e.Code] }

// Cause returns the specific cause, or the catalog's general one.
func (e *Error) Cause() string {
	if e.Why != "" {
		return e.Why
	}
	return byID[e.Code].Cause
}

// Remedy returns the specific fix, or the catalog's general one.
func (e *Error) Remedy() string {
	if e.Fix != "" {
		return e.Fix
	}
	return byID[e.Code].Fix
}

// AsError returns err as a coded error. A context cancellation becomes
// QP-INT-001 and a deadline QP-INT-002; anything else that is not coded
// becomes QP-BUG-001 with the original text as its details, so nothing
// uncoded ever reaches the user.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	switch {
	case errors.Is(err, context.Canceled):
		return E("QP-INT-001").Wrap(err)
	case errors.Is(err, context.DeadlineExceeded):
		return E("QP-INT-002").Wrap(err)
	}
	return E("QP-BUG-001").Wrap(err)
}

// Explain renders a code's catalog entry for `qpot doctor --explain`.
func Explain(s string) (string, error) {
	c, ok := Lookup(s)
	if !ok {
		return "", E("QP-INPUT-011").WithWhy("%q is not one of QPot's error codes.", truncate(s, 40))
	}
	cat, _ := CategoryOf(c.Category())
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n", c.ID, c.Title)
	fmt.Fprintf(&b, "  Category: %s (exit status %d)\n", cat.Name, cat.Exit)
	fmt.Fprintf(&b, "  Why:      %s\n", c.Cause)
	fmt.Fprintf(&b, "  Fix:      %s\n", c.Fix)
	return b.String(), nil
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

// RenderDoc renders doc/setup-errors.md from the catalog, so the document
// and the code can never disagree.
func RenderDoc() string {
	var b strings.Builder
	b.WriteString(`# QPot setup error codes

Every problem ` + "`qpot setup`" + `, ` + "`qpot doctor`" + ` and the install scripts report has a
code such as ` + "`QP-PKG-001`" + `: ` + "`QP`" + `, the category, and a number. A code always
means the same problem, and codes are never reused. The process exits with
the category's exit status, so a script can tell kinds of failure apart.

Look a code up from the terminal:

` + "```bash\nqpot doctor --explain QP-PKG-001\n```" + `

This page is generated from the list in ` + "`internal/hostsetup/errors.go`" + `;
a test fails if the two disagree. Regenerate it with
` + "`QPOT_UPDATE_DOCS=1 go test ./internal/hostsetup -run TestErrorDoc`" + `.

## Exit statuses

| Category | Meaning | Exit status |
|----------|---------|-------------|
`)
	for _, cat := range categories {
		fmt.Fprintf(&b, "| `%s` | %s | %d |\n", cat.Key, cat.Name, cat.Exit)
	}
	b.WriteString("\nExit status 0 means success; 1 is a usage error (an unknown flag).\n")
	for _, cat := range categories {
		fmt.Fprintf(&b, "\n## %s (`%s`, exit %d)\n", cat.Name, cat.Key, cat.Exit)
		var codes []Code
		for _, c := range catalog {
			if c.Category() == cat.Key {
				codes = append(codes, c)
			}
		}
		sort.SliceStable(codes, func(i, j int) bool { return codes[i].ID < codes[j].ID })
		for _, c := range codes {
			fmt.Fprintf(&b, "\n### %s\n\n**%s**\n\n- Why: %s\n- Fix: %s\n", c.ID, c.Title, c.Cause, c.Fix)
		}
	}
	return b.String()
}
