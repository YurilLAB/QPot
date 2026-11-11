package hostsetup

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Platform is what setup knows about the machine it runs on.
type Platform struct {
	GOOS, GOARCH string
	Root         string    // filesystem root; "/" on a real host, a temp dir in tests
	OS           OSRelease // Linux only
	EUID         int
	User         string // the login name (for the docker group)
	Systemd      bool   // systemd is the running init (PID 1)
	WSL          bool   // running inside Windows Subsystem for Linux
	Container    bool   // running inside a container
}

// Path joins p under the platform's root.
func (p Platform) Path(elem ...string) string {
	root := p.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(append([]string{root}, elem...)...)
}

func (p Platform) exists(elem ...string) bool {
	_, err := os.Stat(p.Path(elem...))
	return err == nil
}

// DetectPlatform fills in the facts setup needs and rejects operating
// systems and processors QPot cannot run on.
func DetectPlatform(goos, goarch, root string, euid int, user string) (Platform, *Error) {
	p := Platform{GOOS: goos, GOARCH: goarch, Root: root, EUID: euid, User: user}
	switch goos {
	case "linux", "darwin", "windows":
	default:
		return p, E("QP-HOST-001").WithWhy("This computer runs %s, which QPot does not support.", goos)
	}
	switch goarch {
	case "amd64", "arm64":
	default:
		return p, E("QP-HOST-002").WithWhy("This computer's processor type is %s; QPot's images need amd64 or arm64.", goarch)
	}
	if goos != "linux" {
		return p, nil
	}
	data, err := os.ReadFile(p.Path("etc", "os-release"))
	if err != nil {
		data, err = os.ReadFile(p.Path("usr", "lib", "os-release"))
	}
	if err == nil {
		p.OS = ParseOSRelease(data)
	}
	p.Systemd = p.exists("run", "systemd", "system")
	if v, err := os.ReadFile(p.Path("proc", "version")); err == nil {
		lv := strings.ToLower(string(v))
		p.WSL = strings.Contains(lv, "microsoft") || strings.Contains(lv, "wsl")
	}
	p.Container = p.exists(".dockerenv") || p.exists("run", ".containerenv")
	return p, nil
}

// DockerState is what setup found out about Docker on this machine.
type DockerState struct {
	CLI              bool // a docker command exists
	Podman           bool // ... but it is Podman's emulation
	Client           Version
	DaemonUp         bool // the engine answers (possibly only with "permission denied")
	PermissionDenied bool // the engine runs but this user may not use it
	Server           Version
	RootDir          string // where Docker keeps images
	DaemonDetail     string // what `docker info` said when the engine did not answer
	Compose          bool
	ComposeVersion   Version
	ComposeDetail    string
	ComposeV1        bool // only the old docker-compose v1 exists
	Desktop          bool // Docker Desktop (macOS, Windows)
	// Limits is what the daemon says it can enforce; nil when it did not say.
	Limits *CgroupLimits
}

// CgroupLimits reports which container resource limits the Docker daemon
// applies. A limit it cannot apply is accepted and silently dropped.
type CgroupLimits struct {
	Memory, Swap, Pids, CPU bool
}

// Missing names the limits the daemon cannot apply.
func (l CgroupLimits) Missing() []string {
	var missing []string
	for _, c := range []struct {
		ok   bool
		name string
	}{{l.Memory, "memory"}, {l.Swap, "swap"}, {l.Pids, "PID"}, {l.CPU, "CPU"}} {
		if !c.ok {
			missing = append(missing, c.name)
		}
	}
	return missing
}

// dockerInfoFormat ends with the four limit flags, after the free-text
// operating system name, so older parsers' three fields stay first.
const dockerInfoFormat = "{{.ServerVersion}}|{{.DockerRootDir}}|{{.OperatingSystem}}|{{.MemoryLimit}}|{{.SwapLimit}}|{{.PidsLimit}}|{{.CPUCfsQuota}}"

// parseCgroupLimits reads the four trailing flags; anything but exactly
// true/false in each is "not said".
func parseCgroupLimits(fields []string) *CgroupLimits {
	if len(fields) != 4 {
		return nil
	}
	var flags [4]bool
	for i, f := range fields {
		switch strings.TrimSpace(f) {
		case "true":
			flags[i] = true
		case "false":
		default:
			return nil
		}
	}
	return &CgroupLimits{Memory: flags[0], Swap: flags[1], Pids: flags[2], CPU: flags[3]}
}

// Ready reports whether QPot can use Docker as is.
func (s DockerState) Ready() bool {
	return s.CLI && !s.Podman && s.DaemonUp && !s.PermissionDenied && !s.Server.Less(MinEngine) &&
		s.Compose && !s.ComposeVersion.Less(MinCompose)
}

// EngineMissing reports that the engine must be installed or replaced.
func (s DockerState) EngineMissing() bool { return !s.CLI || s.Podman }

// EngineOld reports an engine older than QPot needs.
func (s DockerState) EngineOld() bool {
	if !s.CLI || s.Podman {
		return false
	}
	if s.DaemonUp && !s.PermissionDenied && s.Server != (Version{}) {
		return s.Server.Less(MinEngine)
	}
	return s.Client != (Version{}) && s.Client.Less(MinEngine)
}

// ComposeMissing reports that the Compose v2 plugin must be installed.
func (s DockerState) ComposeMissing() bool {
	return s.CLI && !s.Podman && (!s.Compose || s.ComposeVersion.Less(MinCompose))
}

// DetectDocker asks the docker command what is installed and running. It
// runs as the current user (never with sudo).
func DetectDocker(ctx context.Context, r Runner, lookPath func(string) (string, error)) DockerState {
	var s DockerState
	if _, err := lookPath("docker"); err != nil {
		if _, err := lookPath("docker-compose"); err == nil {
			s.ComposeV1 = true
		}
		return s
	}
	s.CLI = true
	res := r.Run(ctx, Command{Args: []string{"docker", "--version"}, Timeout: 20 * time.Second})
	out := res.Combined()
	if strings.Contains(strings.ToLower(out), "podman") {
		s.Podman = true
		return s
	}
	if v, err := ParseVersion(out); err == nil {
		s.Client = v
	}
	res = r.Run(ctx, Command{Args: []string{"docker", "info", "--format", dockerInfoFormat}, Timeout: 30 * time.Second})
	info := strings.TrimSpace(string(res.Stdout))
	lower := strings.ToLower(res.Combined())
	switch {
	case res.OK() && strings.Count(info, "|") >= 2:
		parts := strings.Split(info, "|")
		s.DaemonUp = true
		if v, err := ParseVersion(parts[0]); err == nil {
			s.Server = v
		}
		s.RootDir = strings.TrimSpace(parts[1])
		osName := strings.Join(parts[2:], "|")
		if len(parts) >= 7 {
			if limits := parseCgroupLimits(parts[len(parts)-4:]); limits != nil {
				s.Limits = limits
				osName = strings.Join(parts[2:len(parts)-4], "|")
			}
		}
		s.Desktop = strings.Contains(strings.ToLower(osName), "docker desktop")
	case strings.Contains(lower, "permission denied"):
		s.DaemonUp, s.PermissionDenied = true, true
	default:
		s.DaemonDetail = LastLines(res.Combined(), 4)
	}
	res = r.Run(ctx, Command{Args: []string{"docker", "compose", "version", "--short"}, Timeout: 20 * time.Second})
	if res.OK() {
		if v, err := ParseVersion(string(res.Stdout)); err == nil {
			s.Compose, s.ComposeVersion = true, v
		}
	} else {
		s.ComposeDetail = LastLines(res.Combined(), 3)
		if _, err := lookPath("docker-compose"); err == nil {
			s.ComposeV1 = true
		}
	}
	return s
}

// lockGroups are the programs that share one package database lock. comm
// names are cut to 15 characters ("unattended-upgr").
var lockGroups = [][]string{
	{"apt", "apt-get", "aptitude", "dpkg", "unattended-upgr"},
	{"dnf", "dnf5", "yum", "rpm", "dnf-automatic"},
	{"zypper"},
	{"pacman"},
}

// lockGroup returns the programs that hold the same lock as tool (all of
// them for a tool that is not a package manager).
func lockGroup(tool string) map[string]bool {
	base := filepath.Base(tool)
	set := map[string]bool{}
	for _, g := range lockGroups {
		for _, n := range g {
			if n == base {
				for _, m := range g {
					set[m] = true
				}
				return set
			}
		}
	}
	for _, g := range lockGroups {
		for _, n := range g {
			set[n] = true
		}
	}
	return set
}

// PackageManagerHolder looks for a running program that holds the same
// package database lock as tool (apt-get, dnf, zypper, pacman, ...) and
// returns its name and pid, or "" when none runs. Programs in another mount
// namespace (a container or another system's chroot) use another package
// database and are not counted; when that cannot be read, they count.
func PackageManagerHolder(p Platform, tool string) (string, int) {
	if p.GOOS != "linux" {
		return "", 0
	}
	busy := lockGroup(tool)
	ents, err := os.ReadDir(p.Path("proc"))
	if err != nil {
		return "", 0
	}
	self := os.Getpid()
	ourNS, _ := os.Readlink(p.Path("proc", "self", "ns", "mnt"))
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		comm, err := os.ReadFile(p.Path("proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(comm))
		if !busy[name] {
			continue
		}
		if ourNS != "" {
			if ns, err := os.Readlink(p.Path("proc", e.Name(), "ns", "mnt")); err == nil && ns != ourNS {
				continue
			}
		}
		return name, pid
	}
	return "", 0
}

// WaitForPackageManager waits up to wait for other package managers to
// finish, printing what it waits for; it returns QP-PKG-001 if one is still
// running at the end.
func WaitForPackageManager(ctx context.Context, p Platform, tool string, wait time.Duration, say func(string)) *Error {
	deadline := time.Now().Add(wait)
	announced := false
	for {
		name, pid := PackageManagerHolder(p, tool)
		if name == "" {
			return nil
		}
		if !announced {
			say("Another program is installing software (" + name + ", process " + strconv.Itoa(pid) + "). Waiting up to " +
				wait.Round(time.Second).String() + " for it to finish...")
			announced = true
		}
		if time.Now().After(deadline) {
			return E("QP-PKG-001").WithWhy("%s (process %d) is still installing software.", name, pid).
				WithFix("Wait for it to finish (automatic updates can take several minutes after the computer starts), then run qpot setup again.")
		}
		select {
		case <-ctx.Done():
			return E("QP-INT-001").Wrap(ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}
}

// FreeBytes returns the free space for unprivileged users at path or, if it
// does not exist yet, at its nearest existing parent. 0 means unknown.
func FreeBytes(path string) int64 {
	for {
		if _, err := os.Stat(path); err == nil {
			return freeBytes(path)
		}
		parent := filepath.Dir(path)
		if parent == path {
			return 0
		}
		path = parent
	}
}

// DataFreeBytes returns the free space for unprivileged users on the disk
// that holds the folder path or, if it does not exist yet, its nearest
// existing parent. The second result is false when the space could not be
// read; a full disk is 0 and true. Unlike FreeBytes it also measures on
// Windows: an instance's data folder is an ordinary folder there.
func DataFreeBytes(path string) (int64, bool) {
	// A path has at most a few thousand elements; the walk ends at the root.
	for {
		if _, err := os.Stat(path); err == nil {
			return dataFreeBytes(path)
		}
		parent := filepath.Dir(path)
		if parent == path {
			return 0, false
		}
		path = parent
	}
}
