package hostsetup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Step is one numbered step of a plan. The commands are shown to the owner
// before anything runs.
type Step struct {
	Title string
	Info  []string  // extra lines shown under the title
	Cmds  []Command // the commands, run in order
	// Show replaces the shown commands when they are only known while the
	// plan runs (Dynamic).
	Show    []string
	Dynamic func(ctx context.Context) ([]Command, *Error)
	// Prepare does work in setup itself before the commands (download and
	// check a key, write a file to a private temp folder).
	Prepare func(ctx context.Context) *Error
	// Done reports that the step is already done; it is then skipped. This
	// is what makes running setup again after a failure safe.
	Done  func(ctx context.Context) bool
	After func(ctx context.Context) *Error
	Kind  StepKind
}

// Plan is what setup will do to get Docker ready.
type Plan struct {
	Title   string
	Method  string
	Steps   []Step
	Notes   []string
	Root    bool // at least one command needs administrator rights
	Desktop bool // installs or starts Docker Desktop
}

// Need is what Docker is missing.
type Need struct {
	Engine  bool // install the engine (it is missing, or the docker command is Podman)
	Upgrade bool // the engine is older than QPot needs
	Compose bool // install the Compose v2 plugin
	Start   bool // start the engine
}

// Any reports whether anything must be done.
func (n Need) Any() bool { return n.Engine || n.Upgrade || n.Compose || n.Start }

// NeedFor works out what to do from what DetectDocker found.
func NeedFor(s DockerState) Need {
	n := Need{Engine: s.EngineMissing(), Upgrade: s.EngineOld()}
	if !n.Engine && !n.Upgrade {
		n.Compose = s.ComposeMissing()
		n.Start = !s.DaemonUp
	}
	return n
}

// Installer builds and runs plans.
type Installer struct {
	P        Platform
	R        Runner
	F        *Fetcher
	LookPath func(string) (string, error)
	Out      io.Writer
	TempDir  string        // a private (0700) folder for downloaded files
	Source   string        // "auto", "docker" (Docker's repository) or "distro" (the distribution's packages)
	LockWait time.Duration // how long to wait for another package manager
	// DaemonWait is how long to wait for the engine to answer after starting it.
	DaemonWait time.Duration
	// RepoBase is where Docker's repositories live; tests point it at a
	// local server. Empty means https://download.docker.com/linux.
	RepoBase string
	// debKey and rpmKey override the pinned fingerprints in tests (which
	// cannot sign with Docker's key).
	debKey, rpmKey string
}

func (in *Installer) debFingerprint() string {
	return compactFingerprint(firstNonEmpty(in.debKey, DockerDebKeyFingerprint))
}
func (in *Installer) rpmFingerprint() string {
	return compactFingerprint(firstNonEmpty(in.rpmKey, DockerRPMKeyFingerprint))
}

func (in *Installer) say(format string, a ...any) {
	if in.Out != nil {
		fmt.Fprintf(in.Out, format+"\n", a...)
	}
}

// Docker's packages, as Docker's install guides list them.
var dockerRepoPackages = []string{"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"}

// Packages that conflict with Docker's own (Docker's install guides).
var (
	aptConflicts = []string{"docker.io", "docker-doc", "docker-compose", "docker-compose-v2", "docker-buildx", "podman-docker", "containerd", "runc"}
	dnfConflicts = []string{"docker", "docker-client", "docker-client-latest", "docker-common", "docker-latest",
		"docker-latest-logrotate", "docker-logrotate", "docker-selinux", "docker-engine-selinux", "docker-engine", "podman-docker"}
)

// Suites Docker's apt repository publishes (checked 2026-11-07). Only used
// when no certificate bundle is installed yet, so the repository cannot be
// asked; otherwise setup asks the repository itself.
var knownDockerSuites = map[string]map[string]bool{
	"ubuntu":   {"jammy": true, "noble": true, "plucky": true, "questing": true, "resolute": true},
	"debian":   {"bookworm": true, "trixie": true},
	"raspbian": {"bookworm": true, "trixie": true},
}

// Distro says how packages are installed on a Linux distribution.
type Distro struct {
	Manager string // apt, dnf, zypper, pacman
	Family  string // the folder of Docker's repository (ubuntu, debian, raspbian, fedora, centos, rhel), "" if none
	Suite   string // apt codename, or the major release for dnf
	// DistroPackages reports that the distribution's own packages can be
	// used (Docker has no repository for it, or it is the better choice).
	DistroPackages bool
}

var suiteRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,31}$`)

// DistroFor maps os-release to an install method, or reports that setup
// does not know this distribution.
func DistroFor(o OSRelease) (Distro, *Error) {
	id := o.ID()
	codename := strings.ToLower(o["VERSION_CODENAME"])
	major := o.MajorVersion()
	var d Distro
	switch {
	case id == "ubuntu":
		d = Distro{"apt", "ubuntu", firstNonEmpty(strings.ToLower(o["UBUNTU_CODENAME"]), codename), true}
	case id == "debian":
		d = Distro{"apt", "debian", codename, true}
	case id == "raspbian":
		d = Distro{"apt", "raspbian", codename, true}
	case o.IsLike("ubuntu") && o["UBUNTU_CODENAME"] != "":
		d = Distro{"apt", "ubuntu", strings.ToLower(o["UBUNTU_CODENAME"]), true}
	case o.IsLike("debian") && o["DEBIAN_CODENAME"] != "":
		d = Distro{"apt", "debian", strings.ToLower(o["DEBIAN_CODENAME"]), true}
	case o.IsLike("debian") || o.IsLike("ubuntu"):
		// Kali, Parrot and other Debian relatives with their own codenames:
		// Docker's repository has nothing for them; their own packages work.
		d = Distro{"apt", "", codename, true}
	case id == "fedora":
		d = Distro{"dnf", "fedora", major, true}
	case id == "rhel":
		d = Distro{"dnf", "rhel", major, false}
	case id == "centos" || id == "rocky" || id == "almalinux" || o.IsLike("rhel") || o.IsLike("centos"):
		d = Distro{"dnf", "centos", major, false}
	case strings.HasPrefix(id, "opensuse") || id == "sles" || o.IsLike("suse") || o.IsLike("opensuse"):
		d = Distro{"zypper", "", "", true}
	case id == "arch" || o.IsLike("arch"):
		d = Distro{"pacman", "", "", true}
	case id == "":
		return d, E("QP-HOST-004")
	default:
		return d, E("QP-HOST-003").WithWhy("This is %s, and setup does not know how to install Docker on it.", o.Pretty())
	}
	if d.Family != "" && !suiteRe.MatchString(d.Suite) {
		if d.Manager == "apt" {
			// No usable codename: only the distribution's packages remain.
			d.Family = ""
		} else {
			return d, E("QP-HOST-004").WithWhy("The release number in /etc/os-release (%q) is not usable.", truncate(o["VERSION_ID"], 20))
		}
	}
	return d, nil
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

func repoArch(goarch string) (deb, rpm string) {
	if goarch == "arm64" {
		return "arm64", "aarch64"
	}
	return "amd64", "x86_64"
}

// Plan works out how to provide what need asks for on this machine.
func (in *Installer) Plan(ctx context.Context, need Need) (*Plan, *Error) {
	if !need.Any() {
		return &Plan{Title: "Docker is ready"}, nil
	}
	switch in.P.GOOS {
	case "darwin":
		return in.planMac(need)
	case "windows":
		return in.planWindows(need)
	}
	if !need.Engine && !need.Upgrade && !need.Compose {
		return in.planStart(), nil
	}
	if in.P.OS.ID() == "" {
		return nil, E("QP-HOST-004")
	}
	d, err := DistroFor(in.P.OS)
	if err != nil {
		return nil, err
	}
	mgr := map[string]string{"apt": "apt-get", "dnf": "dnf", "zypper": "zypper", "pacman": "pacman"}[d.Manager]
	if _, lerr := in.LookPath(mgr); lerr != nil {
		return nil, E("QP-HOST-009").WithWhy("This looks like %s, which installs software with %s, but %s was not found.", in.P.OS.Pretty(), mgr, mgr)
	}
	if d.Manager == "zypper" || d.Manager == "pacman" {
		if in.Source == "docker" {
			return nil, E("QP-HOST-005").WithWhy("Docker publishes no repository for %s; its own packages are used instead.", in.P.OS.Pretty()).
				WithFix("Run setup with --docker-source auto (the default) to use the distribution's Docker packages.")
		}
		return in.planNative(d, need), nil
	}
	useRepo, err := in.chooseRepo(ctx, d, need)
	if err != nil {
		return nil, err
	}
	switch {
	case d.Manager == "apt" && useRepo:
		return in.planAptRepo(ctx, d, need)
	case d.Manager == "apt":
		return in.planAptDistro(d, need), nil
	case useRepo:
		return in.planDnfRepo(ctx, d, need)
	}
	return in.planDnfDistro(d, need), nil
}

// chooseRepo decides between Docker's repository and the distribution's
// packages, asking Docker's repository whether it has this release.
func (in *Installer) chooseRepo(ctx context.Context, d Distro, need Need) (bool, *Error) {
	if in.Source == "distro" {
		if !d.DistroPackages {
			return false, E("QP-HOST-005").WithWhy("%s has no Docker packages of its own; only Docker's repository provides them.", in.P.OS.Pretty()).
				WithFix("Run setup with --docker-source auto or docker to use Docker's repository.")
		}
		return false, nil
	}
	if !need.Engine && !need.Upgrade && need.Compose {
		// Only Compose is missing: take it from where the engine came from.
		if !in.packageInstalled(ctx, d.Manager, "docker-ce") {
			if d.DistroPackages && in.Source != "docker" {
				return false, nil
			}
		}
	}
	if d.Family == "" {
		if in.Source == "docker" {
			return false, E("QP-HOST-005").WithWhy("Docker's repository has no packages for %s.", in.P.OS.Pretty()).
				WithFix("Run setup with --docker-source auto to use the distribution's own Docker packages.")
		}
		return false, nil
	}
	ok, err := in.repoHasRelease(ctx, d)
	if err != nil {
		return false, err
	}
	if ok {
		return true, nil
	}
	if in.Source == "docker" || !d.DistroPackages {
		return false, E("QP-HOST-005").WithWhy("Docker's repository has no packages for %s (release %q).", in.P.OS.Pretty(), d.Suite)
	}
	return false, nil
}

func (in *Installer) repoBase(d Distro) string {
	return firstNonEmpty(in.RepoBase, "https://download.docker.com/linux") + "/" + d.Family
}

func (in *Installer) repoHasRelease(ctx context.Context, d Distro) (bool, *Error) {
	_, rpm := repoArch(in.P.GOARCH)
	var probe string
	if d.Manager == "apt" {
		probe = in.repoBase(d) + "/dists/" + d.Suite + "/Release"
	} else {
		probe = in.repoBase(d) + "/" + d.Suite + "/" + rpm + "/stable/repodata/repomd.xml"
	}
	if !in.F.HasCABundle() {
		// No certificates yet: setup installs them first. Check that the
		// network works at all, and decide from the releases known to exist.
		if err := Reachable(ctx, "download.docker.com"); err != nil {
			return false, err
		}
		if d.Manager == "apt" {
			return knownDockerSuites[d.Family][d.Suite], nil
		}
		return true, nil
	}
	return in.F.Exists(ctx, probe)
}

// packageInstalled asks dpkg or rpm whether a package is installed.
func (in *Installer) packageInstalled(ctx context.Context, manager, pkg string) bool {
	var c Command
	switch manager {
	case "apt":
		c = Command{Args: []string{"dpkg-query", "-W", "-f=${db:Status-Abbrev}", pkg}, Timeout: 30 * time.Second}
		res := in.R.Run(ctx, c)
		return res.OK() && strings.HasPrefix(string(res.Stdout), "ii")
	case "dnf":
		c = Command{Args: []string{"rpm", "-q", "--quiet", pkg}, Timeout: 30 * time.Second}
		return in.R.Run(ctx, c).OK()
	}
	return false
}

func (in *Installer) installedOf(ctx context.Context, manager string, pkgs []string) []string {
	var out []string
	for _, p := range pkgs {
		if in.packageInstalled(ctx, manager, p) {
			out = append(out, p)
		}
	}
	return out
}

// tempFile is a file setup prepares in its private folder and then copies
// into place with `install`.
func (in *Installer) tempPath(name string) string { return filepath.Join(in.TempDir, name) }

func writePrivate(path string, data []byte) *Error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return E("QP-PERM-007").WithWhy("Setup could not write its temporary file %s.", path).Wrap(err)
	}
	return nil
}

func aptEnv() []string { return []string{"DEBIAN_FRONTEND=noninteractive", "LC_ALL=C"} }

func (in *Installer) lockWaitSeconds() string {
	w := in.LockWait
	if w <= 0 {
		w = 2 * time.Minute
	}
	return strconv.Itoa(int(w / time.Second))
}

func (in *Installer) aptCmd(args ...string) Command {
	full := append([]string{"apt-get"}, args[0])
	full = append(full, "-o", "DPkg::Lock::Timeout="+in.lockWaitSeconds())
	full = append(full, args[1:]...)
	return Command{Args: full, Env: aptEnv(), Root: true, Timeout: 20 * time.Minute}
}

func (in *Installer) aptInstall(pkgs ...string) Command {
	args := append([]string{"install", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}, pkgs...)
	return in.aptCmd(args...)
}

func (in *Installer) planAptRepo(ctx context.Context, d Distro, need Need) (*Plan, *Error) {
	debArch, _ := repoArch(in.P.GOARCH)
	if res := in.R.Run(ctx, Command{Args: []string{"dpkg", "--print-architecture"}, Timeout: 30 * time.Second}); res.OK() {
		if a := strings.TrimSpace(string(res.Stdout)); a == "amd64" || a == "arm64" {
			debArch = a
		}
	}
	keyPath := in.P.Path("etc", "apt", "keyrings", "docker.asc")
	keyDir := filepath.Dir(keyPath)
	srcPath := in.P.Path("etc", "apt", "sources.list.d", "docker.sources")
	keyURL := in.repoBase(d) + "/gpg"
	keyOK, kerr := existingKeyOK(keyPath, in.debFingerprint())
	if kerr != nil {
		return nil, kerr
	}
	sources := fmt.Sprintf("# Added by qpot setup: Docker's official package repository.\nTypes: deb\nURIs: %s\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: %s\n",
		in.repoBase(d), d.Suite, debArch, "/etc/apt/keyrings/docker.asc")
	other := otherDockerSource(in.P, srcPath)

	p := &Plan{Title: "Install Docker Engine and the Compose plugin", Root: true,
		Method: fmt.Sprintf("Docker's official repository for %s, signed with Docker's key", prettyWithSuite(in.P.OS.Pretty(), d.Suite))}
	pkgs := dockerRepoPackages
	switch {
	case need.Engine:
	case need.Upgrade:
		p.Title = "Update Docker Engine and the Compose plugin"
		p.Notes = append(p.Notes, "Updating Docker restarts it: containers that are running now are restarted.")
	default:
		p.Title, pkgs = "Install the Docker Compose plugin", []string{"docker-compose-plugin"}
	}
	if !in.F.HasCABundle() {
		p.Steps = append(p.Steps, Step{Title: "Install the certificate bundle used to check secure downloads", Kind: KindInstall,
			Cmds: []Command{in.aptCmd("update"), in.aptInstall("ca-certificates")}})
	}
	if need.Engine || need.Upgrade && !in.packageInstalled(ctx, "apt", "docker-ce") {
		if conflicts := in.installedOf(ctx, "apt", aptConflicts); len(conflicts) > 0 {
			p.Steps = append(p.Steps, Step{Title: "Remove packages that conflict with Docker's own: " + strings.Join(conflicts, ", "),
				Kind: KindRemove, Cmds: []Command{in.aptCmd(append([]string{"remove", "-y"}, conflicts...)...)}})
		}
	}
	p.Steps = append(p.Steps,
		Step{Title: "Create the folder for package signing keys", Kind: KindFile,
			Cmds: []Command{{Args: []string{"install", "-m", "0755", "-d", keyDir}, Root: true}},
			Done: func(context.Context) bool { return isDir(keyDir) }},
		in.keyStep(keyURL, in.debFingerprint(), keyPath, keyOK, nil),
	)
	srcStep := Step{Title: "Add Docker's package source (" + srcPath + ")", Kind: KindFile,
		Info: indentLines(sources),
		Prepare: func(context.Context) *Error {
			return writePrivate(in.tempPath("docker.sources"), []byte(sources))
		},
		Cmds: []Command{{Args: []string{"install", "-m", "0644", in.tempPath("docker.sources"), srcPath}, Root: true}},
		Done: func(context.Context) bool {
			if other != "" {
				return true
			}
			cur, err := os.ReadFile(srcPath) // #nosec G304 -- fixed system path
			return err == nil && bytes.Equal(cur, []byte(sources))
		}}
	if other != "" {
		srcStep.Info = []string{"Docker's repository is already set up in " + other + "; setup uses it as it is."}
	}
	p.Steps = append(p.Steps, srcStep,
		Step{Title: "Update the package lists", Kind: KindUpdate, Cmds: []Command{in.aptCmd("update")}},
		Step{Title: p.Title, Kind: KindInstall, Cmds: []Command{in.aptInstall(pkgs...)}},
	)
	p.Steps = append(p.Steps, in.startStep())
	return p, nil
}

func (in *Installer) planAptDistro(d Distro, need Need) *Plan {
	p := &Plan{Title: "Install Docker Engine and the Compose plugin", Root: true,
		Method: fmt.Sprintf("%s's own Docker packages (Docker's repository has none for this release)", in.P.OS.Pretty())}
	if d.Family == "" {
		p.Method = fmt.Sprintf("%s's own Docker packages", in.P.OS.Pretty())
	}
	p.Steps = append(p.Steps, Step{Title: "Update the package lists", Kind: KindUpdate, Cmds: []Command{in.aptCmd("update")}})
	if need.Engine || need.Upgrade {
		if need.Upgrade {
			p.Title = "Update Docker Engine and install the Compose plugin"
			p.Notes = append(p.Notes, "Updating Docker restarts it: containers that are running now are restarted.")
		}
		p.Steps = append(p.Steps, Step{Title: "Install Docker Engine", Kind: KindInstall, Cmds: []Command{in.aptInstall("docker.io")}})
	} else {
		p.Title = "Install the Docker Compose plugin"
	}
	p.Steps = append(p.Steps, Step{Title: "Install the Docker Compose plugin", Kind: KindInstall,
		Show: []string{ShellJoin(in.R.Argv(in.aptInstall("docker-compose-v2"))) + "   (or docker-compose, whichever this release offers)"},
		Dynamic: func(ctx context.Context) ([]Command, *Error) {
			res := in.R.Run(ctx, Command{Args: []string{"apt-cache", "policy", "docker-compose-v2", "docker-compose-plugin", "docker-compose"},
				Env: []string{"LC_ALL=C"}, Timeout: time.Minute})
			pkg := PickComposePackage(ParseAptPolicy(string(res.Stdout)))
			if pkg == "" {
				return nil, E("QP-PKG-007").WithWhy("%s offers no Docker Compose version 2 package.", in.P.OS.Pretty()).
					WithFix("Install Docker from Docker's repository instead (run setup with --docker-source docker on a release Docker supports), or install the Compose plugin by hand: https://docs.docker.com/compose/install/linux/").
					WithDetails("apt-cache policy:\n%s", LastLines(string(res.Stdout), 12))
			}
			return []Command{in.aptInstall(pkg)}, nil
		}})
	p.Steps = append(p.Steps, in.startStep())
	return p
}

// ParseAptPolicy reads `apt-cache policy` output into package -> candidate
// version ("" when there is none).
func ParseAptPolicy(out string) map[string]string {
	if len(out) > 1<<20 {
		out = out[:1<<20]
	}
	res := map[string]string{}
	cur := ""
	for _, line := range strings.Split(out, "\n") {
		if line != "" && line[0] != ' ' && line[0] != '\t' && strings.HasSuffix(strings.TrimSpace(line), ":") {
			cur = strings.TrimSuffix(strings.TrimSpace(line), ":")
			if strings.ContainsAny(cur, " \t") || cur == "" {
				cur = ""
				continue
			}
			res[cur] = ""
			continue
		}
		if cur == "" {
			continue
		}
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Candidate:"); ok {
			v = strings.TrimSpace(v)
			if v == "(none)" {
				v = ""
			}
			res[cur] = v
		}
	}
	return res
}

// PickComposePackage chooses the distribution package that provides
// `docker compose` version 2, or "".
func PickComposePackage(cands map[string]string) string {
	for _, p := range []string{"docker-compose-v2", "docker-compose-plugin"} {
		if cands[p] != "" {
			return p
		}
	}
	// "docker-compose" is version 1 on older releases; take it only at 2+.
	if c := cands["docker-compose"]; c != "" {
		if v, err := ParseVersion(stripEpoch(c)); err == nil && v.Major >= 2 {
			return "docker-compose"
		}
	}
	return ""
}

func stripEpoch(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		return v[i+1:]
	}
	return v
}

func (in *Installer) dnfCmd(args ...string) Command {
	return Command{Args: append([]string{"dnf", "-y"}, args...), Env: []string{"LC_ALL=C"}, Root: true, Timeout: 20 * time.Minute}
}

func (in *Installer) planDnfRepo(ctx context.Context, d Distro, need Need) (*Plan, *Error) {
	keyPath := in.P.Path("etc", "pki", "rpm-gpg", "docker-ce.gpg")
	repoPath := in.P.Path("etc", "yum.repos.d", "docker-ce.repo")
	keyOK, kerr := existingKeyOK(keyPath, in.rpmFingerprint())
	if kerr != nil {
		return nil, kerr
	}
	repo := fmt.Sprintf("# Added by qpot setup: Docker's official package repository.\n[docker-ce-stable]\nname=Docker CE Stable - $basearch\nbaseurl=%s/%s/$basearch/stable\nenabled=1\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/docker-ce.gpg\n",
		in.repoBase(d), d.Suite)
	other := otherDockerRepo(in.P)
	p := &Plan{Title: "Install Docker Engine and the Compose plugin", Root: true,
		Method: fmt.Sprintf("Docker's official repository for %s, signed with Docker's key", in.P.OS.Pretty())}
	pkgs := dockerRepoPackages
	switch {
	case need.Engine:
	case need.Upgrade:
		p.Title = "Update Docker Engine and the Compose plugin"
		p.Notes = append(p.Notes, "Updating Docker restarts it: containers that are running now are restarted.")
	default:
		p.Title, pkgs = "Install the Docker Compose plugin", []string{"docker-compose-plugin"}
	}
	if need.Engine || need.Upgrade && !in.packageInstalled(ctx, "dnf", "docker-ce") {
		if conflicts := in.installedOf(ctx, "dnf", dnfConflicts); len(conflicts) > 0 {
			p.Steps = append(p.Steps, Step{Title: "Remove packages that conflict with Docker's own: " + strings.Join(conflicts, ", "),
				Kind: KindRemove, Cmds: []Command{in.dnfCmd(append([]string{"remove"}, conflicts...)...)}})
		}
	}
	keyDir := filepath.Dir(keyPath)
	p.Steps = append(p.Steps,
		Step{Title: "Create the folder for package signing keys", Kind: KindFile,
			Cmds: []Command{{Args: []string{"install", "-m", "0755", "-d", keyDir}, Root: true}},
			Done: func(context.Context) bool { return isDir(keyDir) }},
		in.keyStep(in.repoBase(d)+"/gpg", in.rpmFingerprint(), keyPath, keyOK,
			[]Command{{Args: []string{"rpm", "--import", keyPath}, Root: true, Timeout: time.Minute}}),
	)
	repoStep := Step{Title: "Add Docker's package source (" + repoPath + ")", Kind: KindFile,
		Info: indentLines(repo),
		Prepare: func(context.Context) *Error {
			return writePrivate(in.tempPath("docker-ce.repo"), []byte(repo))
		},
		Cmds: []Command{{Args: []string{"install", "-m", "0644", in.tempPath("docker-ce.repo"), repoPath}, Root: true}},
		Done: func(context.Context) bool { return other != "" }}
	if other != "" {
		repoStep.Info = []string{"Docker's repository is already set up in " + other + "; setup uses it as it is."}
	}
	p.Steps = append(p.Steps, repoStep,
		Step{Title: p.Title, Kind: KindInstall, Cmds: []Command{in.dnfCmd(append([]string{"install"}, pkgs...)...)}},
		in.startStep())
	return p, nil
}

func (in *Installer) planDnfDistro(d Distro, need Need) *Plan {
	p := &Plan{Title: "Install Docker Engine and the Compose plugin", Root: true,
		Method: fmt.Sprintf("%s's own Docker packages (Docker's repository has none for this release)", in.P.OS.Pretty())}
	pkgs := []string{"moby-engine", "docker-compose"}
	if !need.Engine && !need.Upgrade {
		p.Title, pkgs = "Install the Docker Compose plugin", []string{"docker-compose"}
	}
	p.Steps = append(p.Steps, Step{Title: p.Title, Kind: KindInstall, Cmds: []Command{in.dnfCmd(append([]string{"install"}, pkgs...)...)}},
		in.startStep())
	return p
}

func (in *Installer) planNative(d Distro, need Need) *Plan {
	p := &Plan{Title: "Install Docker Engine and the Compose plugin", Root: true,
		Method: fmt.Sprintf("%s's own Docker packages", in.P.OS.Pretty())}
	pkgs := []string{"docker", "docker-compose"}
	if !need.Engine && !need.Upgrade {
		p.Title, pkgs = "Install the Docker Compose plugin", []string{"docker-compose"}
	}
	var c Command
	if d.Manager == "zypper" {
		c = Command{Args: append([]string{"zypper", "--non-interactive", "install"}, pkgs...), Env: []string{"LC_ALL=C"}, Root: true, Timeout: 20 * time.Minute}
	} else {
		c = Command{Args: append([]string{"pacman", "-Syu", "--needed", "--noconfirm"}, pkgs...), Env: []string{"LC_ALL=C"}, Root: true, Timeout: 30 * time.Minute}
		p.Notes = append(p.Notes, "Arch only supports full upgrades, so this also updates the rest of the system's packages.")
	}
	p.Steps = append(p.Steps, Step{Title: p.Title, Kind: KindInstall, Cmds: []Command{c}}, in.startStep())
	return p
}

func (in *Installer) planStart() *Plan {
	p := &Plan{Title: "Start Docker", Root: true, Method: "the installed Docker Engine"}
	p.Steps = []Step{in.startStep()}
	return p
}

// startStep starts the engine (and enables it at boot under systemd) and
// waits for it to answer.
func (in *Installer) startStep() Step {
	initScript := in.P.Path("etc", "init.d", "docker")
	st := Step{Title: "Start Docker now and every time the computer starts", Kind: KindService,
		Cmds:  []Command{{Args: []string{"systemctl", "enable", "--now", "docker"}, Root: true, Timeout: 3 * time.Minute}},
		After: in.waitDaemonStep}
	if !in.P.Systemd {
		st.Title = "Start Docker (this system does not run systemd, so Docker will not start by itself after a reboot)"
		st.Cmds = nil
		st.Show = []string{ShellJoin(in.R.Argv(Command{Args: []string{initScript, "start"}, Root: true}))}
		if !isFile(initScript) {
			st.Info = []string{"Docker's packages include this start script on Debian and Ubuntu; where they do not, setup stops here and says how to start Docker yourself."}
		}
		st.Dynamic = func(ctx context.Context) ([]Command, *Error) {
			if _, err := os.Stat(initScript); err != nil {
				return nil, E("QP-SVC-001").WithWhy("Docker is installed, but systemd is not running here and Docker has no start script, so setup cannot start it.")
			}
			return []Command{{Args: []string{initScript, "start"}, Root: true, Timeout: 2 * time.Minute}}, nil
		}
	}
	return st
}

// prettyWithSuite adds the release code name to a system's name unless the
// name already has it ("Debian GNU/Linux 12 (bookworm)").
func prettyWithSuite(pretty, suite string) string {
	if suite == "" || strings.Contains(strings.ToLower(pretty), strings.ToLower(suite)) {
		return pretty
	}
	return pretty + " (" + suite + ")"
}

func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

func (in *Installer) waitDaemonStep(ctx context.Context) *Error {
	wait := in.DaemonWait
	if wait <= 0 {
		wait = 60 * time.Second
	}
	if _, ok := in.WaitDaemon(ctx, wait); ok {
		return nil
	}
	if ctx.Err() != nil {
		return E("QP-INT-001").Wrap(ctx.Err())
	}
	e := E("QP-DOCKER-003").WithWhy("Docker was started, but it did not answer within %s.", wait.Round(time.Second))
	if in.P.Systemd {
		res := in.R.Run(ctx, Command{Args: []string{"systemctl", "status", "docker", "--no-pager", "--lines=15"}, Timeout: 30 * time.Second})
		e.WithDetails("%s", LastLines(res.Combined(), 20))
	} else {
		// Docker's start script logs here when systemd is not running.
		if tail := fileTail(in.P.Path("var", "log", "docker.log"), 64<<10, 15); tail != "" {
			e.WithDetails("last lines of /var/log/docker.log:\n%s", tail)
		}
		if in.P.WSL {
			e.WithFix("Read the details for Docker's own reason. On WSL without systemd, Docker is more reliable with systemd on: put '[boot]' and 'systemd=true' in /etc/wsl.conf, run 'wsl.exe --shutdown' in Windows, reopen the terminal and run qpot setup again.")
		}
	}
	return e
}

// fileTail returns the last n lines of the last max bytes of a file, or ""
// when it cannot be read.
func fileTail(path string, max int64, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	if fi.Size() > max {
		if _, err := f.Seek(fi.Size()-max, io.SeekStart); err != nil {
			return ""
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return ""
	}
	return LastLines(string(data), n)
}

// WaitDaemon polls until the engine answers (even if only with "permission
// denied") or wait passes.
func (in *Installer) WaitDaemon(ctx context.Context, wait time.Duration) (DockerState, bool) {
	deadline := time.Now().Add(wait)
	for {
		s := DetectDocker(ctx, in.R, in.LookPath)
		if s.DaemonUp {
			return s, true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return s, false
		}
		select {
		case <-ctx.Done():
			return s, false
		case <-time.After(2 * time.Second):
		}
	}
}

// keyStep downloads a signing key, checks its fingerprint, and installs it.
func (in *Installer) keyStep(url, fpr, dest string, done bool, extra []Command) Step {
	tmp := in.tempPath(filepath.Base(dest))
	return Step{Title: "Download Docker's signing key and check it is Docker's", Kind: KindFile,
		Info: []string{"from " + url, "it must have the fingerprint " + FormatFingerprint(fpr) + " (as published by Docker)"},
		Prepare: func(ctx context.Context) *Error {
			data, err := in.F.Get(ctx, url, maxKeySize)
			if err != nil {
				return err
			}
			got, kerr := KeyFingerprint(data)
			if kerr != nil {
				return E("QP-NET-005").WithWhy("The file downloaded from %s is not a single valid signing key.", url).Wrap(kerr)
			}
			if got != fpr {
				return E("QP-NET-005").WithDetails("expected %s\ngot      %s", FormatFingerprint(fpr), FormatFingerprint(got))
			}
			return writePrivate(tmp, data)
		},
		Cmds: append([]Command{{Args: []string{"install", "-m", "0644", tmp, dest}, Root: true}}, extra...),
		Done: func(context.Context) bool { return done }}
}

// existingKeyOK reports whether a key file is already in place with the
// right fingerprint. A file there with another key stops setup: something
// else put it there, and trusting or replacing it silently is wrong.
func existingKeyOK(path, fpr string) (bool, *Error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed system path
	if err != nil {
		return false, nil
	}
	got, kerr := KeyFingerprint(data)
	if kerr == nil && got == fpr {
		return true, nil
	}
	return false, E("QP-PKG-008").WithWhy("%s already exists and is not Docker's signing key.", path).
		WithFix("Check where %s came from. If you did not put it there on purpose, delete it (sudo rm %s) and run qpot setup again.", path, path)
}

// otherDockerSource returns an apt source file other than ours that already
// points at Docker's repository, or "".
func otherDockerSource(p Platform, ours string) string {
	files := []string{p.Path("etc", "apt", "sources.list")}
	if ents, err := os.ReadDir(p.Path("etc", "apt", "sources.list.d")); err == nil {
		for _, e := range ents {
			if n := e.Name(); strings.HasSuffix(n, ".list") || strings.HasSuffix(n, ".sources") {
				files = append(files, p.Path("etc", "apt", "sources.list.d", n))
			}
		}
	}
	for _, f := range files {
		if f == ours {
			continue
		}
		if data, err := os.ReadFile(f); err == nil && activeMention(data, "download.docker.com") { // #nosec G304 -- apt source files
			return f
		}
	}
	return ""
}

// otherDockerRepo returns a yum/dnf repo file that already points at
// Docker's repository, or "".
func otherDockerRepo(p Platform) string {
	ents, err := os.ReadDir(p.Path("etc", "yum.repos.d"))
	if err != nil {
		return ""
	}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".repo") {
			continue
		}
		f := p.Path("etc", "yum.repos.d", e.Name())
		if data, err := os.ReadFile(f); err == nil && activeMention(data, "download.docker.com") { // #nosec G304 -- repo files
			return f
		}
	}
	return ""
}

// activeMention reports whether a line that is not a comment contains s.
func activeMention(data []byte, s string) bool {
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && l[0] != '#' && strings.Contains(l, s) {
			return true
		}
	}
	return false
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func indentLines(s string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		out = append(out, "  "+l)
	}
	return out
}
