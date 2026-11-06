package hostsetup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const debianOSRelease = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION_CODENAME=bookworm
ID=debian
`

const rockyOSRelease = `NAME="Rocky Linux"
VERSION_ID="9.4"
ID="rocky"
ID_LIKE="rhel centos fedora"
PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"
`

const fedoraOSRelease = `NAME="Fedora Linux"
VERSION_ID=46
ID=fedora
PRETTY_NAME="Fedora Linux 46"
`

func TestPrettyWithSuite(t *testing.T) {
	for _, c := range []struct{ pretty, suite, want string }{
		{"Ubuntu 24.04 LTS", "noble", "Ubuntu 24.04 LTS (noble)"},
		{"Debian GNU/Linux 12 (bookworm)", "bookworm", "Debian GNU/Linux 12 (bookworm)"},
		{"Debian GNU/Linux 12 (Bookworm)", "bookworm", "Debian GNU/Linux 12 (Bookworm)"},
		{"Rocky Linux 9.8", "", "Rocky Linux 9.8"},
	} {
		if got := prettyWithSuite(c.pretty, c.suite); got != c.want {
			t.Errorf("prettyWithSuite(%q, %q) = %q, want %q", c.pretty, c.suite, got, c.want)
		}
	}
}

func TestDistroFor(t *testing.T) {
	cases := []struct {
		osr                    string
		mgr, family, suite     string
		distroPkgs, wantErrHas bool
		errCode                string
	}{
		{ubuntuOSRelease, "apt", "ubuntu", "noble", true, false, ""},
		{debianOSRelease, "apt", "debian", "bookworm", true, false, ""},
		{"ID=raspbian\nVERSION_CODENAME=bookworm\n", "apt", "raspbian", "bookworm", true, false, ""},
		{"ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_CODENAME=wilma\nUBUNTU_CODENAME=noble\n", "apt", "ubuntu", "noble", true, false, ""},
		{"ID=linuxmint\nID_LIKE=debian\nVERSION_CODENAME=faye\nDEBIAN_CODENAME=bookworm\n", "apt", "debian", "bookworm", true, false, ""},
		{"ID=kali\nID_LIKE=debian\nVERSION_CODENAME=kali-rolling\n", "apt", "", "kali-rolling", true, false, ""},
		{"ID=parrot\nID_LIKE=debian\nVERSION_CODENAME=echo\n", "apt", "", "echo", true, false, ""},
		{fedoraOSRelease, "dnf", "fedora", "46", true, false, ""},
		{rockyOSRelease, "dnf", "centos", "9", false, false, ""},
		{"ID=almalinux\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=9.5\n", "dnf", "centos", "9", false, false, ""},
		{"ID=\"centos\"\nVERSION_ID=\"10\"\n", "dnf", "centos", "10", false, false, ""},
		{"ID=\"rhel\"\nVERSION_ID=\"9.4\"\n", "dnf", "rhel", "9", false, false, ""},
		{"ID=\"opensuse-leap\"\nID_LIKE=\"suse opensuse\"\nVERSION_ID=15.6\n", "zypper", "", "", true, false, ""},
		{"ID=\"opensuse-tumbleweed\"\n", "zypper", "", "", true, false, ""},
		{"ID=arch\n", "pacman", "", "", true, false, ""},
		{"ID=manjaro\nID_LIKE=arch\n", "pacman", "", "", true, false, ""},
		{"ID=alpine\nVERSION_ID=3.20.0\n", "", "", "", false, true, "QP-HOST-003"},
		{"ID=nixos\n", "", "", "", false, true, "QP-HOST-003"},
		{"", "", "", "", false, true, "QP-HOST-004"},
		{"ID=rocky\nVERSION_ID=\"$(x)\"\n", "", "", "", false, true, "QP-HOST-004"},
	}
	for _, c := range cases {
		d, err := DistroFor(ParseOSRelease([]byte(c.osr)))
		if c.wantErrHas {
			if err == nil || err.Code != c.errCode {
				t.Errorf("%q: err = %v, want %s", c.osr, err, c.errCode)
			}
			continue
		}
		if err != nil || d.Manager != c.mgr || d.Family != c.family || d.Suite != c.suite || d.DistroPackages != c.distroPkgs {
			t.Errorf("%q: got %+v, %v", c.osr, d, err)
		}
	}
}

func TestDetectDocker(t *testing.T) {
	h := newFakeHost(t, ubuntuOSRelease)
	in := h.installer(nil, ubuntuOSRelease, 1000)
	st := detect(h, in)
	if st.CLI || !NeedFor(st).Engine {
		t.Fatalf("no docker: %+v", st)
	}
	h.set("docker-installed", true)
	st = detect(h, in)
	if !st.CLI || st.DaemonUp || st.Compose || st.Client != (Version{27, 3, 1}) {
		t.Fatalf("installed, stopped: %+v", st)
	}
	if n := NeedFor(st); !n.Compose || !n.Start || n.Engine {
		t.Fatalf("need = %+v", n)
	}
	h.set("docker-running", true)
	h.set("compose", true)
	st = detect(h, in)
	if !st.Ready() || st.Server != (Version{27, 3, 1}) || st.RootDir != "/var/lib/docker" || NeedFor(st).Any() {
		t.Fatalf("ready: %+v", st)
	}
	h.set("docker-denied", true)
	st = detect(h, in)
	if !st.DaemonUp || !st.PermissionDenied || st.Ready() || NeedFor(st).Any() {
		t.Fatalf("denied: %+v need %+v", st, NeedFor(st))
	}
	h.set("docker-denied", false)
	h.set("podman", true)
	if st = detect(h, in); !st.Podman || !NeedFor(st).Engine {
		t.Fatalf("podman: %+v", st)
	}
	h.set("podman", false)
	t.Setenv("FAKE_DOCKER_VERSION", "19.03.15")
	if st = detect(h, in); !st.EngineOld() || !NeedFor(st).Upgrade {
		t.Fatalf("old: %+v", st)
	}
	t.Setenv("FAKE_DOCKER_VERSION", "27.3.1")
	t.Setenv("FAKE_COMPOSE_VERSION", "1.29.2")
	if st = detect(h, in); !st.ComposeMissing() || !NeedFor(st).Compose {
		t.Fatalf("old compose: %+v", st)
	}
}

// The full apt path: Docker's repository with the key checked, sources
// written, packages installed, Docker started; then a second run has
// nothing left to do.
func TestAptRepoPlanRunsAndIsIdempotent(t *testing.T) {
	h := newFakeHost(t, ubuntuOSRelease)
	rs := newRepoServer(t)
	rs.have["/ubuntu/dists/noble/Release"] = true
	in := h.installer(rs, ubuntuOSRelease, 1000)
	ctx := context.Background()

	plan, err := in.Plan(ctx, NeedFor(detect(h, in)))
	if err != nil {
		t.Fatal(err)
	}
	var desc bytes.Buffer
	in.Describe(&desc, plan)
	for _, want := range []string{
		"Docker's official repository for Ubuntu 24.04.1 LTS (noble)",
		"sudo -n install -m 0755 -d " + h.root + "/etc/apt/keyrings",
		"it must have the fingerprint " + FormatFingerprint(rs.fpr),
		"Suites: noble", "Architectures: amd64", "Signed-By: /etc/apt/keyrings/docker.asc",
		"sudo -n env DEBIAN_FRONTEND=noninteractive LC_ALL=C apt-get update -o DPkg::Lock::Timeout=1",
		"apt-get install -o DPkg::Lock::Timeout=1 -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin",
		"sudo -n systemctl enable --now docker",
	} {
		if !strings.Contains(desc.String(), want) {
			t.Errorf("plan lacks %q:\n%s", want, desc.String())
		}
	}
	if !plan.Root {
		t.Error("plan must say it needs root")
	}

	// First attempt: the package manager is locked during the install.
	h.set("apt-locked", true)
	err = in.Execute(ctx, plan)
	if err == nil || err.Code != "QP-PKG-001" || !strings.Contains(err.Details, "unattended-upgr") {
		t.Fatalf("locked install: %v (%s)", err, errDetails(err))
	}
	key, _ := os.ReadFile(filepath.Join(h.root, "etc/apt/keyrings/docker.asc"))
	if _, canonical, err := CanonicalKey(rs.key); err != nil || !bytes.Equal(key, canonical) {
		t.Fatalf("key not installed (in canonical form) before the failing step: %v\n%s", err, key)
	}

	// Run again (a new plan, as a new setup run makes): the key and source
	// steps are already done and are not repeated.
	h.set("apt-locked", false)
	plan, err = in.Plan(ctx, NeedFor(detect(h, in)))
	if err != nil {
		t.Fatal(err)
	}
	desc.Reset()
	in.Describe(&desc, plan)
	if strings.Count(desc.String(), "(already done; skipped)") != 3 {
		t.Errorf("second plan should skip 3 done steps:\n%s", desc.String())
	}
	if err := in.Execute(ctx, plan); err != nil {
		t.Fatalf("second run: %v (%s)", err, errDetails(err))
	}
	if got := h.countCalls("sudo -n install -m 0644"); got != 2 {
		t.Errorf("key and source files were installed %d times, want 2 (once each)", got)
	}
	src, _ := os.ReadFile(filepath.Join(h.root, "etc/apt/sources.list.d/docker.sources"))
	if !strings.Contains(string(src), "URIs: "+rs.srv.URL+"/ubuntu") {
		t.Errorf("sources = %s", src)
	}
	st := detect(h, in)
	if NeedFor(st).Any() || !st.Ready() {
		t.Fatalf("docker not ready after the plan: %+v", st)
	}
	// Third run: nothing at all to do.
	if p, err := in.Plan(ctx, NeedFor(st)); err != nil || len(p.Steps) != 0 {
		t.Fatalf("third plan = %+v, %v", p, err)
	}
}

// The key file setup installs holds exactly the packets it checked: bytes
// around the armor are refused, and a key it accepts is installed in a
// canonical armor, never as the bytes the server sent.
func TestKeyStepInstallsOnlyTheCheckedKey(t *testing.T) {
	ctx := context.Background()
	keyPath := func(h *fakeHost) string { return filepath.Join(h.root, "etc/apt/keyrings/docker.asc") }

	h := newFakeHost(t, ubuntuOSRelease)
	rs := newRepoServer(t)
	rs.have["/ubuntu/dists/noble/Release"] = true
	other := append(newPacket(6, testKeyBody(t, 4)), newPacket(13, []byte("someone else"))...)
	rs.key = append(append(append([]byte{}, other...), '\n'), rs.key...)
	in := h.installer(rs, ubuntuOSRelease, 1000)
	plan, err := in.Plan(ctx, NeedFor(detect(h, in)))
	if err != nil {
		t.Fatal(err)
	}
	if e := in.Execute(ctx, plan); e == nil || e.Code != "QP-NET-005" {
		t.Fatalf("a key file with another key before the armor: %v", e)
	}
	if _, err := os.Stat(keyPath(h)); err == nil {
		t.Fatal("a key file with extra bytes was installed")
	}

	// A valid key sent with CRLF line ends and an armor header.
	h = newFakeHost(t, ubuntuOSRelease)
	rs = newRepoServer(t)
	rs.have["/ubuntu/dists/noble/Release"] = true
	rs.key = bytes.ReplaceAll(rs.key, []byte("\n"), []byte("\r\n"))
	in = h.installer(rs, ubuntuOSRelease, 1000)
	if plan, err = in.Plan(ctx, NeedFor(detect(h, in))); err != nil {
		t.Fatal(err)
	}
	if e := in.Execute(ctx, plan); e != nil {
		t.Fatalf("valid key: %v (%s)", e, errDetails(e))
	}
	got, _ := os.ReadFile(keyPath(h))
	if bytes.Equal(got, rs.key) || bytes.Contains(got, []byte("\r")) || bytes.Contains(got, []byte("Comment:")) ||
		!bytes.HasPrefix(got, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n")) {
		t.Fatalf("installed key is not the canonical armor:\n%q", got)
	}
	if fpr, err := KeyFingerprint(got); err != nil || fpr != rs.fpr {
		t.Fatalf("installed key: %s %v", fpr, err)
	}
}

// Files a root step installs are written by setup into a folder only this
// user can use, and never through a name that already exists.
func TestInstallerNeedsPrivateTempDir(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost(t, ubuntuOSRelease)
	rs := newRepoServer(t)
	rs.have["/ubuntu/dists/noble/Release"] = true
	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	// Group access alone is enough to swap a file before root installs it.
	group := filepath.Join(t.TempDir(), "group")
	if err := os.Mkdir(group, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(group, 0o770); err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	// A relative name is refused even when that folder exists and is private.
	cwd := t.TempDir()
	t.Chdir(cwd)
	if err := os.Mkdir(filepath.Join(cwd, "qpot-tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	for name, dir := range map[string]string{"empty": "", "relative": "qpot-tmp", "world-readable": open,
		"group-writable": group, "symlink": link} {
		in := h.installer(rs, ubuntuOSRelease, 1000)
		in.TempDir = dir
		plan, err := in.Plan(ctx, NeedFor(detect(h, in)))
		if err == nil || err.Code != "QP-PERM-010" {
			var desc bytes.Buffer
			if plan != nil {
				in.Describe(&desc, plan)
			}
			t.Errorf("%s temp folder %q: plan made (%v):\n%s", name, dir, err, desc.String())
		}
	}

	// Something already at a temp file's name is never written through.
	in := h.installer(rs, ubuntuOSRelease, 1000)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(in.TempDir, "docker.asc")); err != nil {
		t.Fatal(err)
	}
	plan, err := in.Plan(ctx, NeedFor(detect(h, in)))
	if err != nil {
		t.Fatal(err)
	}
	if e := in.Execute(ctx, plan); e != nil {
		t.Fatalf("execute: %v (%s)", e, errDetails(e))
	}
	if v, _ := os.ReadFile(victim); string(v) != "keep me" {
		t.Fatalf("setup wrote through a planted link: %q", v)
	}
	if fpr, err := KeyFingerprint(mustRead(t, filepath.Join(h.root, "etc/apt/keyrings/docker.asc"))); err != nil || fpr != rs.fpr {
		t.Fatalf("installed key: %s %v", fpr, err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func errDetails(e *Error) string {
	if e == nil {
		return ""
	}
	return e.Details
}

func TestAptRepoPlanRefusesWrongKeys(t *testing.T) {
	h := newFakeHost(t, ubuntuOSRelease)
	rs := newRepoServer(t)
	rs.have["/ubuntu/dists/noble/Release"] = true
	in := h.installer(rs, ubuntuOSRelease, 1000)
	ctx := context.Background()

	// The server sends a key with another fingerprint: stop, install nothing.
	in.debKey = DockerDebKeyFingerprint
	plan, err := in.Plan(ctx, NeedFor(detect(h, in)))
	if err != nil {
		t.Fatal(err)
	}
	err = in.Execute(ctx, plan)
	if err == nil || err.Code != "QP-NET-005" {
		t.Fatalf("mismatched key: %v", err)
	}
	if h.countCalls("apt-get") != 0 || h.countCalls("sudo -n install -m 0644") != 0 {
		t.Fatalf("something was installed after a key mismatch: %v", h.calls())
	}

	// A different key already sits where Docker's belongs.
	h.write("etc/apt/keyrings/docker.asc", string(armor(newPacket(6, testKeyBody(t, 4)), true)))
	in.debKey = rs.fpr
	if _, err := in.Plan(ctx, NeedFor(detect(h, in))); err == nil || err.Code != "QP-PKG-008" {
		t.Fatalf("foreign key file: %v", err)
	}
}

func TestAptUsesExistingDockerSourceAndRemovesConflicts(t *testing.T) {
	h := newFakeHost(t, ubuntuOSRelease)
	rs := newRepoServer(t)
	rs.have["/ubuntu/dists/noble/Release"] = true
	h.write("etc/apt/sources.list.d/docker.list", "deb [signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable\n")
	h.set("pkg-containerd", true)
	h.set("pkg-runc", true)
	in := h.installer(rs, ubuntuOSRelease, 1000)
	plan, err := in.Plan(context.Background(), NeedFor(detect(h, in)))
	if err != nil {
		t.Fatal(err)
	}
	var desc bytes.Buffer
	in.Describe(&desc, plan)
	if !strings.Contains(desc.String(), "already set up in "+h.root+"/etc/apt/sources.list.d/docker.list") {
		t.Errorf("existing source not reused:\n%s", desc.String())
	}
	if !strings.Contains(desc.String(), "Remove packages that conflict with Docker's own: containerd, runc") ||
		!strings.Contains(desc.String(), "apt-get remove -o DPkg::Lock::Timeout=1 -y containerd runc") {
		t.Errorf("conflicts not removed:\n%s", desc.String())
	}
	if err := in.Execute(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.root, "etc/apt/sources.list.d/docker.sources")); err == nil {
		t.Error("a second Docker source was added next to the existing one")
	}
}

// Without Docker's repository for the release (probe 404) the
// distribution's own packages are used.
func TestAptDistroFallback(t *testing.T) {
	osr := "ID=debian\nVERSION_CODENAME=forky\nPRETTY_NAME=\"Debian forky\"\n"
	h := newFakeHost(t, osr)
	rs := newRepoServer(t)
	in := h.installer(rs, osr, 1000)
	plan, err := in.Plan(context.Background(), NeedFor(detect(h, in)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.Method, "own Docker packages") {
		t.Fatalf("method = %q", plan.Method)
	}
	if err := in.Execute(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if h.countCalls("apt-get install -o DPkg::Lock::Timeout=1 -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold docker.io") != 1 ||
		h.countCalls("apt-get install -o DPkg::Lock::Timeout=1 -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold docker-compose-v2") != 1 {
		t.Fatalf("calls: %v", h.calls())
	}
	in.Source = "docker"
	if _, err := in.Plan(context.Background(), Need{Engine: true}); err == nil || err.Code != "QP-HOST-005" {
		t.Fatalf("--docker-source docker without a repository: %v", err)
	}
}

func TestDnfRepoPlan(t *testing.T) {
	h := newFakeHost(t, rockyOSRelease)
	rs := newRepoServer(t)
	rs.have["/centos/9/x86_64/stable/repodata/repomd.xml"] = true
	h.set("pkg-podman-docker", true)
	in := h.installer(rs, rockyOSRelease, 0)
	plan, err := in.Plan(context.Background(), NeedFor(detect(h, in)))
	if err != nil {
		t.Fatal(err)
	}
	var desc bytes.Buffer
	in.Describe(&desc, plan)
	for _, want := range []string{
		"env LC_ALL=C dnf -y remove podman-docker",
		"install -m 0644 " + in.TempDir + "/docker-ce.gpg " + h.root + "/etc/pki/rpm-gpg/docker-ce.gpg",
		"rpm --import " + h.root + "/etc/pki/rpm-gpg/docker-ce.gpg",
		"baseurl=" + rs.srv.URL + "/centos/9/$basearch/stable", "gpgcheck=1", "gpgkey=file:///etc/pki/rpm-gpg/docker-ce.gpg",
		"dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin",
		"systemctl enable --now docker",
	} {
		if !strings.Contains(desc.String(), want) {
			t.Errorf("plan lacks %q:\n%s", want, desc.String())
		}
	}
	if strings.Contains(desc.String(), "sudo") {
		t.Error("root must not use sudo")
	}
	if err := in.Execute(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if !detect(h, in).Ready() {
		t.Fatal("not ready")
	}
}

func TestFedoraWithoutDockerRepoUsesFedoraPackages(t *testing.T) {
	h := newFakeHost(t, fedoraOSRelease)
	rs := newRepoServer(t)
	in := h.installer(rs, fedoraOSRelease, 0)
	plan, err := in.Plan(context.Background(), NeedFor(detect(h, in)))
	if err != nil {
		t.Fatal(err)
	}
	var desc bytes.Buffer
	in.Describe(&desc, plan)
	if !strings.Contains(desc.String(), "dnf -y install moby-engine docker-compose") {
		t.Fatalf("plan:\n%s", desc.String())
	}
	// RHEL-family releases have no own Docker packages: a release Docker
	// does not publish is a clear stop.
	h2 := newFakeHost(t, "ID=rocky\nVERSION_ID=11\n")
	in2 := h2.installer(rs, "ID=rocky\nVERSION_ID=11\n", 0)
	if _, err := in2.Plan(context.Background(), Need{Engine: true}); err == nil || err.Code != "QP-HOST-005" {
		t.Fatalf("rocky 11: %v", err)
	}
}

func TestNativePlans(t *testing.T) {
	for _, c := range []struct{ osr, want string }{
		{"ID=\"opensuse-leap\"\nPRETTY_NAME=\"openSUSE Leap 15.6\"\n", "zypper --non-interactive install docker docker-compose"},
		{"ID=arch\nPRETTY_NAME=\"Arch Linux\"\n", "pacman -Syu --needed --noconfirm docker docker-compose"},
	} {
		h := newFakeHost(t, c.osr)
		in := h.installer(nil, c.osr, 1000)
		plan, err := in.Plan(context.Background(), Need{Engine: true})
		if err != nil {
			t.Fatal(err)
		}
		var desc bytes.Buffer
		in.Describe(&desc, plan)
		if !strings.Contains(desc.String(), "sudo -n env LC_ALL=C "+c.want) {
			t.Errorf("%s:\n%s", c.osr, desc.String())
		}
		if err := in.Execute(context.Background(), plan); err != nil {
			t.Fatal(err)
		}
		in.Source = "docker"
		if _, err := in.Plan(context.Background(), Need{Engine: true}); err == nil || err.Code != "QP-HOST-005" {
			t.Errorf("--docker-source docker on %s: %v", c.osr, err)
		}
	}
}

func TestComposeOnlyAndUpgradePlans(t *testing.T) {
	h := newFakeHost(t, ubuntuOSRelease)
	rs := newRepoServer(t)
	rs.have["/ubuntu/dists/noble/Release"] = true
	in := h.installer(rs, ubuntuOSRelease, 1000)
	h.set("docker-installed", true)
	h.set("docker-running", true)
	h.set("pkg-docker-ce", true)
	plan, err := in.Plan(context.Background(), NeedFor(detect(h, in)))
	if err != nil {
		t.Fatal(err)
	}
	var desc bytes.Buffer
	in.Describe(&desc, plan)
	if plan.Title != "Install the Docker Compose plugin" || !strings.Contains(desc.String(), "--force-confold docker-compose-plugin\n") ||
		strings.Contains(desc.String(), "docker-ce-cli") {
		t.Fatalf("compose-only plan:\n%s", desc.String())
	}
	// An old engine from the distribution is replaced, its package removed.
	h.set("pkg-docker-ce", false)
	h.set("pkg-docker.io", true)
	t.Setenv("FAKE_DOCKER_VERSION", "19.03.13")
	h.set("compose", true)
	plan, err = in.Plan(context.Background(), NeedFor(detect(h, in)))
	if err != nil {
		t.Fatal(err)
	}
	desc.Reset()
	in.Describe(&desc, plan)
	if !strings.Contains(desc.String(), "apt-get remove -o DPkg::Lock::Timeout=1 -y docker.io") || !strings.Contains(desc.String(), "restarts it") {
		t.Fatalf("upgrade plan:\n%s", desc.String())
	}
}

func TestStartStep(t *testing.T) {
	h := newFakeHost(t, ubuntuOSRelease)
	in := h.installer(nil, ubuntuOSRelease, 0)
	h.set("docker-installed", true)
	h.set("compose", true)
	plan, err := in.Plan(context.Background(), NeedFor(detect(h, in)))
	if err != nil || plan.Title != "Start Docker" {
		t.Fatalf("%+v %v", plan, err)
	}
	h.set("docker-broken", true)
	if err := in.Execute(context.Background(), plan); err == nil || err.Code != "QP-DOCKER-003" {
		t.Fatalf("broken service: %v", err)
	}
	h.set("docker-broken", false)
	if err := in.Execute(context.Background(), plan); err != nil {
		t.Fatalf("start: %v", err)
	}

	// No systemd: Docker's init script, or a clear stop without one.
	h.set("docker-running", false)
	in.P.Systemd = false
	plan, _ = in.Plan(context.Background(), NeedFor(detect(h, in)))
	if err := in.Execute(context.Background(), plan); err == nil || err.Code != "QP-SVC-001" {
		t.Fatalf("no systemd, no init script: %v", err)
	}
	h.write("etc/init.d/docker", "#!/bin/sh\ntouch '"+h.state+"/docker-running'\n")
	if err := os.Chmod(filepath.Join(h.root, "etc/init.d/docker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := in.Execute(context.Background(), plan); err != nil {
		t.Fatalf("init script: %v", err)
	}
	// Started but never answering.
	h.set("docker-running", false)
	h.write("etc/init.d/docker", "#!/bin/sh\nexit 0\n")
	in.DaemonWait = 500 * time.Millisecond
	if err := in.Execute(context.Background(), plan); err == nil || err.Code != "QP-DOCKER-003" {
		t.Fatalf("silent daemon: %v", err)
	}
	// Docker's own reason, from the start script's log, is in the details.
	h.write("var/log/docker.log", strings.Repeat("level=info msg=noise\n", 5000)+"level=fatal msg=\"the real reason\"\n")
	err = in.Execute(context.Background(), plan)
	if err == nil || err.Code != "QP-DOCKER-003" || !strings.Contains(err.Details, "the real reason") ||
		strings.Count(err.Details, "\n") > 16 {
		t.Fatalf("daemon log tail: %+v", err)
	}
}

func TestPackageManagerLockWait(t *testing.T) {
	h := newFakeHost(t, ubuntuOSRelease)
	in := h.installer(nil, ubuntuOSRelease, 0)
	h.write("proc/4242/comm", "unattended-upgr\n")
	h.write("proc/77/comm", "bash\n")
	if name, pid := PackageManagerHolder(in.P, "apt-get"); name != "unattended-upgr" || pid != 4242 {
		t.Fatalf("holder = %s %d", name, pid)
	}
	// dnf does not hold apt's lock, and apt-get does not hold dnf's.
	if name, _ := PackageManagerHolder(in.P, "dnf"); name != "" {
		t.Fatalf("an apt program counted as holding dnf's lock: %s", name)
	}
	h.write("proc/5151/comm", "dnf\n")
	if name, pid := PackageManagerHolder(in.P, "/usr/bin/dnf"); name != "dnf" || pid != 5151 {
		t.Fatalf("dnf holder = %s %d", name, pid)
	}
	_ = os.RemoveAll(filepath.Join(h.root, "proc/5151"))
	// A package manager in another mount namespace (a container) has its own
	// database; one whose namespace cannot be read still counts.
	if err := os.MkdirAll(filepath.Join(h.root, "proc/self/ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("mnt:[4026531841]", filepath.Join(h.root, "proc/self/ns/mnt")); err != nil {
		t.Fatal(err)
	}
	h.write("proc/4242/ns/.keep", "")
	if err := os.Symlink("mnt:[4026532999]", filepath.Join(h.root, "proc/4242/ns/mnt")); err != nil {
		t.Fatal(err)
	}
	if name, _ := PackageManagerHolder(in.P, "apt-get"); name != "" {
		t.Fatalf("a package manager in another mount namespace counted: %s", name)
	}
	_ = os.Remove(filepath.Join(h.root, "proc/4242/ns/mnt"))
	if name, pid := PackageManagerHolder(in.P, "apt-get"); name != "unattended-upgr" || pid != 4242 {
		t.Fatalf("holder with an unreadable namespace = %s %d", name, pid)
	}
	var said []string
	start := time.Now()
	err := WaitForPackageManager(context.Background(), in.P, "apt-get", 300*time.Millisecond, func(s string) { said = append(said, s) })
	if err == nil || err.Code != "QP-PKG-001" || !strings.Contains(err.Cause(), "process 4242") || len(said) != 1 {
		t.Fatalf("err = %v, said %v", err, said)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("waited far too long")
	}
	// It ends as soon as the other program finishes.
	go func() { time.Sleep(200 * time.Millisecond); _ = os.RemoveAll(filepath.Join(h.root, "proc/4242")) }()
	if err := WaitForPackageManager(context.Background(), in.P, "apt-get", 10*time.Second, func(string) {}); err != nil {
		t.Fatalf("after the holder left: %v", err)
	}
	// Ctrl-C while waiting.
	h.write("proc/4242/comm", "dpkg\n")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := WaitForPackageManager(ctx, in.P, "apt-get", time.Minute, func(string) {}); err == nil || err.Code != "QP-INT-001" {
		t.Fatalf("cancelled wait: %v", err)
	}
}

// While another program installs software, Execute waits for it before
// each package command and stops with QP-PKG-001 without running apt-get.
func TestExecuteWaitsForPackageManager(t *testing.T) {
	h := newFakeHost(t, ubuntuOSRelease)
	rs := newRepoServer(t)
	rs.have["/ubuntu/dists/noble/Release"] = true
	in := h.installer(rs, ubuntuOSRelease, 0)
	plan, err := in.Plan(context.Background(), NeedFor(detect(h, in)))
	if err != nil {
		t.Fatal(err)
	}
	h.write("proc/4242/comm", "apt-get\n")
	in.LockWait = 300 * time.Millisecond
	e := in.Execute(context.Background(), plan)
	if e == nil || e.Code != "QP-PKG-001" || !strings.Contains(e.Cause(), "apt-get (process 4242)") {
		t.Fatalf("Execute with apt-get running: %v", e)
	}
	if n := h.countCalls("apt-get"); n != 0 {
		t.Fatalf("apt-get ran %d times while another apt-get held the lock", n)
	}
}

// Ctrl-C during a package install interrupts the package manager (so it can
// stop cleanly), not just kills it, and reports QP-INT-001.
func TestExecuteInterrupted(t *testing.T) {
	h := newFakeHost(t, ubuntuOSRelease)
	rs := newRepoServer(t)
	rs.have["/ubuntu/dists/noble/Release"] = true
	in := h.installer(rs, ubuntuOSRelease, 1000)
	plan, err := in.Plan(context.Background(), NeedFor(detect(h, in)))
	if err != nil {
		t.Fatal(err)
	}
	h.set("apt-slow", true)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for !strings.Contains(strings.Join(h.calls(), "\n"), "apt-get install") {
			time.Sleep(20 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	e := in.Execute(ctx, plan)
	if e == nil || e.Code != "QP-INT-001" {
		t.Fatalf("interrupted install: %v", e)
	}
	if time.Since(start) > 15*time.Second {
		t.Fatal("the interrupted command was not stopped promptly")
	}
	deadline := time.Now().Add(3 * time.Second)
	for !h.has("got-interrupt") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !h.has("got-interrupt") {
		t.Error("the package manager never got the interrupt")
	}
}

func TestEnsureRoot(t *testing.T) {
	h := newFakeHost(t, ubuntuOSRelease)
	in := h.installer(nil, ubuntuOSRelease, 1000)
	ctx := context.Background()
	if err := in.EnsureRoot(ctx, false); err != nil {
		t.Fatalf("passwordless sudo: %v", err)
	}
	h.set("sudo-password", true)
	if err := in.EnsureRoot(ctx, false); err == nil || err.Code != "QP-PERM-002" {
		t.Fatalf("sudo needs a password: %v", err)
	}
	h.set("sudo-password", false)
	h.set("sudo-refused", true)
	if err := in.EnsureRoot(ctx, false); err == nil || err.Code != "QP-PERM-003" {
		t.Fatalf("not in sudoers: %v", err)
	}
	h.set("missing-sudo", true)
	if err := in.EnsureRoot(ctx, false); err == nil || err.Code != "QP-PERM-001" {
		t.Fatalf("no sudo: %v", err)
	}
	in.P.EUID = 0
	if err := in.EnsureRoot(ctx, false); err != nil {
		t.Fatalf("root: %v", err)
	}
}

func TestGroupPlan(t *testing.T) {
	h := newFakeHost(t, ubuntuOSRelease)
	in := h.installer(nil, ubuntuOSRelease, 1000)
	p, err := in.GroupPlan()
	if err != nil {
		t.Fatal(err)
	}
	var desc bytes.Buffer
	in.Describe(&desc, p)
	if !strings.Contains(desc.String(), "sudo -n usermod -aG docker alice") {
		t.Fatal(desc.String())
	}
	for _, bad := range []string{"", "a b", "x;rm -rf /", "-oops", strings.Repeat("a", 40)} {
		in.P.User = bad
		if _, err := in.GroupPlan(); err == nil || err.Code != "QP-PERM-004" {
			t.Errorf("user %q accepted", bad)
		}
	}
}

func TestDesktopPlans(t *testing.T) {
	h := newFakeHost(t, "")
	h.script("brew", "exit 0")
	h.script("winget", "exit 0")
	for _, goos := range []string{"darwin", "windows"} {
		in := h.installer(nil, "", 1000)
		in.P.GOOS = goos
		p, err := in.Plan(context.Background(), Need{Engine: true})
		if err != nil {
			t.Fatal(err)
		}
		var desc bytes.Buffer
		in.Describe(&desc, p)
		want := map[string]string{"darwin": "brew install --cask docker-desktop", "windows": "winget install -e --id Docker.DockerDesktop"}[goos]
		if !strings.Contains(desc.String(), want) || !strings.Contains(desc.String(), "setup does not accept it for you") ||
			strings.Contains(desc.String(), "--accept") || p.Root {
			t.Errorf("%s:\n%s", goos, desc.String())
		}
	}
	h.set("missing-brew", true)
	h.set("missing-winget", true)
	for _, goos := range []string{"darwin", "windows"} {
		in := h.installer(nil, "", 1000)
		in.P.GOOS = goos
		if _, err := in.Plan(context.Background(), Need{Engine: true}); err == nil || err.Code != "QP-DOCKER-008" {
			t.Errorf("%s without an installer: %v", goos, err)
		}
	}
}

func TestRunnerTimeoutAndArgv(t *testing.T) {
	h := newFakeHost(t, ubuntuOSRelease)
	h.script("slow", "sleep 30")
	r := h.runner(1000)
	res := r.Run(context.Background(), Command{Args: []string{"slow"}, Timeout: 200 * time.Millisecond})
	if !res.TimedOut || res.OK() {
		t.Fatalf("timeout: %+v", res)
	}
	e := ClassifyFailure(KindInstall, "slow", res)
	if e.Code != "QP-PKG-009" {
		t.Fatalf("timed-out install = %s", e.Code)
	}
	if got := ShellJoin(r.Argv(Command{Args: []string{"apt-get", "install", "it's"}, Env: []string{"A=b c"}, Root: true})); got != `sudo -n env 'A=b c' apt-get install 'it'\''s'` {
		t.Fatalf("argv = %s", got)
	}
	res = r.Run(context.Background(), Command{Args: []string{"definitely-not-a-program-" + strconv.Itoa(os.Getpid())}})
	if res.OK() || res.Exit != -1 {
		t.Fatalf("missing program: %+v", res)
	}
	if e := ClassifyFailure(KindInstall, "definitely-not-a-program", res); e.Code != "QP-HOST-009" {
		t.Fatalf("missing program = %s", e.Code)
	}
}
