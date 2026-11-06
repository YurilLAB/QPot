package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/hostsetup"
)

// fakeDocker answers setup's docker, package manager and sudo commands from
// a few switches, and records every command line, so the setup flow can be
// tested on any machine without touching it.
type fakeDocker struct {
	mu        sync.Mutex
	installed bool
	running   bool
	denied    bool
	compose   bool
	calls     []string
	euid      int
}

func (f *fakeDocker) Argv(c hostsetup.Command) []string {
	r := &hostsetup.ExecRunner{EUID: f.euid, NoTTY: true}
	return r.Argv(c)
}

func (f *fakeDocker) Run(ctx context.Context, c hostsetup.Command) hostsetup.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := hostsetup.ShellJoin(f.Argv(c))
	f.calls = append(f.calls, line)
	ok := func(out string) hostsetup.Result { return hostsetup.Result{Stdout: []byte(out)} }
	fail := func(msg string) hostsetup.Result { return hostsetup.Result{Exit: 1, Stderr: []byte(msg)} }
	a := c.Args
	switch {
	case len(a) >= 2 && a[0] == "docker" && a[1] == "--version":
		return ok("Docker version 27.3.1, build ce12230\n")
	case len(a) >= 2 && a[0] == "docker" && a[1] == "info":
		switch {
		case !f.running:
			return fail("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?")
		case f.denied:
			return fail("permission denied while trying to connect to the Docker daemon socket")
		case strings.Contains(strings.Join(a, " "), "Runtimes"):
			return ok(`{"io.containerd.runc.v2":{},"runc":{}}`)
		case strings.Contains(strings.Join(a, " "), "ServerVersion"):
			return ok("27.3.1|/var/lib/docker|Ubuntu 24.04 LTS\n")
		}
		return ok("/var/lib/docker\n")
	case len(a) >= 2 && a[0] == "docker" && a[1] == "compose":
		if !f.compose {
			return fail("docker: 'compose' is not a docker command.")
		}
		return ok("2.29.7\n")
	case a[0] == "sudo":
		return ok("")
	case a[0] == "usermod":
		return ok("")
	}
	return ok("")
}

func (f *fakeDocker) lookPath(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch name {
	case "docker":
		if !f.installed {
			return "", exec.ErrNotFound
		}
	case "docker-compose", "systemctl":
		return "", exec.ErrNotFound
	}
	return "/usr/bin/" + name, nil
}

func (f *fakeDocker) called(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// testEnv builds a setup environment around a fake Docker and a temporary
// home; nothing on the machine is changed.
func testEnv(t *testing.T, d *fakeDocker, stdin string, tty bool) (*setupEnv, *bytes.Buffer, *bool) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=ubuntu\nVERSION_CODENAME=noble\nUBUNTU_CODENAME=noble\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	started := false
	out := &bytes.Buffer{}
	// A stand-in for Docker's repository: it publishes Ubuntu noble but has
	// no signing key, so nothing can ever be installed from it.
	repo := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ubuntu/dists/noble/Release" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(repo.Close)
	env := &setupEnv{
		stdin: strings.NewReader(stdin), stdout: out, stdinTTY: tty, stdoutTTY: tty,
		goos: "linux", goarch: "amd64", root: root, euid: d.euid, user: "alice",
		runner: d, lookPath: d.lookPath,
		fetcher:   &hostsetup.Fetcher{Client: repo.Client(), GOOS: "linux"},
		repoBase:  repo.URL,
		addrs:     func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.0.2.7")} },
		memBytes:  func() int64 { return 8 << 30 },
		freeBytes: func(string) int64 { return 100 << 30 },
		tempDir:   privateTemp(t),
		start: func(ctx context.Context, cfg *config.Config, service bool) (string, error) {
			started = true
			return "", nil
		},
		health: func(ctx context.Context, cfg *config.Config, service bool, timeout time.Duration) []check {
			return []check{{Name: "database", Level: "ok", Detail: "running"}}
		},
		geoip:      func(ctx context.Context, cfg *config.Config) error { return errors.New("offline") },
		runtimes:   func(context.Context) string { return "standard Docker containers" },
		daemonWait: time.Second,
	}
	return env, out, &started
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

func ready() *fakeDocker {
	return &fakeDocker{installed: true, running: true, compose: true, euid: 1000}
}

func codeOf(err error) string {
	if err == nil {
		return ""
	}
	return hostsetup.AsError(err).Code
}

// Without a terminal nothing is asked: flags and defaults make the
// instance, Docker is checked, the instance is started and the summary
// printed. The QPot ID is not printed when the output is not a terminal.
func TestSetupNonInteractiveHappyPath(t *testing.T) {
	d := ready()
	env, out, started := testEnv(t, d, "", false)
	port := freePort(t)
	o := setupOptions{instance: "flow1", instanceSet: true, honeypots: "cowrie,dionaea", honeypotsSet: true,
		port: port, portSet: true, outbound: "block", outboundSet: true, timeout: time.Second}
	if err := runSetup(context.Background(), env, o); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	cfg, err := config.Load("flow1")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sortedCopy(cfg.GetEnabledHoneypots()), ","); got != "cowrie,dionaea" {
		t.Errorf("honeypots = %s", got)
	}
	if cfg.WebUI.Port != port || cfg.WebUI.BindAddr != "127.0.0.1" || !cfg.Security.NetworkIsolation.BlockOutbound {
		t.Errorf("web %+v, outbound block %v", cfg.WebUI, cfg.Security.NetworkIsolation.BlockOutbound)
	}
	if !*started {
		t.Error("not started")
	}
	text := out.String()
	for _, want := range []string{"Running without questions", "Docker:  running, engine 27.3.1",
		fmt.Sprintf("http://127.0.0.1:%d/", port), fmt.Sprintf("ssh -N -L %d:127.0.0.1:%d alice@", port, port),
		"QP-NET-008", "Show it with: qpot id -i flow1", "dionaea"} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, cfg.QPotID) {
		t.Error("the QPot ID was printed although the output is not a terminal")
	}
	if _, err := os.Stat(setupStatePath()); !os.IsNotExist(err) {
		t.Error("saved answers left behind after the instance was created")
	}

	// Run again: the instance exists, nothing is asked or created twice.
	out.Reset()
	*started = false
	if err := runSetup(context.Background(), env, o); err != nil {
		t.Fatalf("second run: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), `Instance "flow1" already exists; its settings are kept.`) ||
		!strings.Contains(out.String(), "only apply to a new instance") {
		t.Errorf("second run output:\n%s", out)
	}
}

func TestSetupDockerMissingNonInteractive(t *testing.T) {
	d := &fakeDocker{euid: 1000}
	env, out, _ := testEnv(t, d, "", false)
	err := runSetup(context.Background(), env, setupOptions{instance: "flow2", instanceSet: true, timeout: time.Second})
	if codeOf(err) != "QP-DOCKER-001" || !strings.Contains(hostsetup.AsError(err).Remedy(), "--install-docker") {
		t.Fatalf("err = %v (%s)\n%s", err, hostsetup.AsError(err).Remedy(), out)
	}
	// The plan with its exact commands was shown, and nothing ran.
	if !strings.Contains(out.String(), "apt-get install -o DPkg::Lock::Timeout=120 -y") || d.called("sudo") {
		t.Errorf("plan not shown, or something ran:\n%s\n%v", out, d.calls)
	}
	if hostsetup.ExitStatus(codeOf(err)) != 15 {
		t.Error("Docker errors exit with 15")
	}
	// Answers were saved so a later run can offer them.
	if a, ok := loadSetupState(); !ok || a.Instance != "flow2" {
		t.Errorf("answers not saved: %+v %v", a, ok)
	}
}

// With consent the plan runs; a signing key that cannot be downloaded stops
// it with a network code before any package is installed.
func TestSetupInstallStopsOnNetworkError(t *testing.T) {
	d := &fakeDocker{euid: 1000}
	env, out, _ := testEnv(t, d, "", false)
	err := runSetup(context.Background(), env, setupOptions{instance: "flow3", instanceSet: true, installDocker: true, timeout: time.Second})
	if codeOf(err) != "QP-NET-004" {
		t.Fatalf("err = %v\n%s", err, out)
	}
	if !d.called("sudo -n true") {
		t.Errorf("sudo was not checked before the plan ran: %v", d.calls)
	}
	if d.called("sudo -n env DEBIAN_FRONTEND=noninteractive LC_ALL=C apt-get") {
		t.Errorf("packages were touched after the failed download: %v", d.calls)
	}
}

func TestSetupDryRunChangesNothing(t *testing.T) {
	d := &fakeDocker{euid: 1000}
	env, out, started := testEnv(t, d, "", true)
	if err := runSetup(context.Background(), env, setupOptions{dryRun: true, timeout: time.Second}); err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	if *started || d.called("sudo") || !strings.Contains(out.String(), "Dry run: nothing was changed") {
		t.Errorf("dry run did something:\n%s\n%v", out, d.calls)
	}
	if _, err := os.Stat(config.Default("default").ConfigPath); err == nil {
		t.Error("dry run created an instance")
	}
	if _, ok := loadSetupState(); ok {
		t.Error("dry run saved answers")
	}
}

// The guided flow: bad answers are asked again, the plan is shown and
// agreed, and the summary shows the QPot ID on the owner's terminal.
func TestSetupInteractive(t *testing.T) {
	d := ready()
	port := freePort(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port
	answers := strings.Join([]string{
		"bad name!",   // instance name: invalid
		"flow4",       // instance name
		"n",           // recommended settings? no
		"9",           // honeypots: not a choice
		"custom",      // honeypots: custom
		"cowrie,nope", // unknown honeypot
		"cowrie",      // honeypots
		"8.8.8.8",     // web UI address: not this computer
		"0.0.0.0",     // all networks
		"n",           // ... not after the warning
		"127.0.0.1",   // web UI address
		"70000",       // port: invalid
		fmt.Sprint(busyPort),
		fmt.Sprint(port),
		"timescaledb",
		"2",  // outbound: block
		"XX", // country: invalid
		"NL",
		"n", // geoip
		"",  // go ahead (default yes)
	}, "\n") + "\n"
	env, out, started := testEnv(t, d, answers, true)
	if err := runSetup(context.Background(), env, setupOptions{timeout: time.Second}); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	text := out.String()
	for _, want := range []string{`"bad name!" is not a valid instance name`, `"9" is not one of the choices`,
		`"nope" is not a honeypot QPot knows`, "8.8.8.8 is not an address of this computer",
		"reachable from the network over plain HTTP", `"70000" is not a port number`,
		fmt.Sprintf("Port %d is already in use", busyPort), `"XX" is not a two-letter country code`} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	cfg, err := config.Load("flow4")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.GetEnabledHoneypots(), ","); got != "cowrie" || cfg.WebUI.Port != port || cfg.Database.Type != "timescaledb" ||
		!cfg.Security.NetworkIsolation.BlockOutbound || cfg.AttackMap.Country != "NL" {
		t.Errorf("cfg: %s %d %s %v %s", got, cfg.WebUI.Port, cfg.Database.Type, cfg.Security.NetworkIsolation.BlockOutbound, cfg.AttackMap.Country)
	}
	if !*started || !strings.Contains(text, "Log in with your QPot ID: "+cfg.QPotID) {
		t.Errorf("not started or no ID on the terminal:\n%s", text)
	}
	if strings.Contains(text, "Downloading the free DB-IP") {
		t.Error("GeoIP was downloaded although the answer was no")
	}
	// Setup's own text never needs escaping: an escape in the transcript
	// means a newline or control character went through termSafe.
	if strings.Contains(text, `\x`) {
		t.Errorf("escaped characters in setup's own text:\n%s", text)
	}
}

func TestSetupInteractiveStops(t *testing.T) {
	for name, c := range map[string]struct {
		stdin, code string
	}{
		"end of input": {"flow5\n", "QP-INPUT-009"},
		"cancel":       {"flow6\n\nn\n", "QP-INPUT-013"},
	} {
		t.Run(name, func(t *testing.T) {
			env, out, started := testEnv(t, ready(), c.stdin, true)
			err := runSetup(context.Background(), env, setupOptions{timeout: time.Second})
			if codeOf(err) != c.code || *started {
				t.Fatalf("err = %v\n%s", err, out)
			}
		})
	}
	// Ctrl-C while a question waits.
	pr, pw := io.Pipe()
	defer pw.Close()
	env, _, _ := testEnv(t, ready(), "", true)
	env.stdin = pr
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	if err := runSetup(ctx, env, setupOptions{timeout: time.Second}); codeOf(err) != "QP-INT-001" {
		t.Fatalf("Ctrl-C: %v", err)
	}
	if hostsetup.ExitStatus("QP-INT-001") != 130 {
		t.Fatal("Ctrl-C exits with 130")
	}
}

// After a failed run the saved answers are offered, and taken with Enter.
func TestSetupOffersSavedAnswers(t *testing.T) {
	d := &fakeDocker{euid: 1000}
	env, out, _ := testEnv(t, d, "", false)
	port := freePort(t)
	_ = runSetup(context.Background(), env, setupOptions{instance: "flow7", instanceSet: true, port: port, portSet: true,
		honeypots: "cowrie", honeypotsSet: true, timeout: time.Second})
	d.installed, d.running, d.compose = true, true, true
	env.stdin, env.stdinTTY, env.stdoutTTY = strings.NewReader("\n\n"), true, true
	out.Reset()
	if err := runSetup(context.Background(), env, setupOptions{timeout: time.Second}); err != nil {
		t.Fatalf("re-run: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "Last time setup stopped before it finished") {
		t.Errorf("answers not offered:\n%s", out)
	}
	cfg, err := config.Load("flow7")
	if err != nil || cfg.WebUI.Port != port || strings.Join(cfg.GetEnabledHoneypots(), ",") != "cowrie" {
		t.Fatalf("saved answers not used: %+v %v", cfg.WebUI, err)
	}
}

func TestSetupDockerGroup(t *testing.T) {
	d := ready()
	d.denied = true
	env, out, _ := testEnv(t, d, "", false)
	err := runSetup(context.Background(), env, setupOptions{instance: "flow8", instanceSet: true, timeout: time.Second})
	if codeOf(err) != "QP-PERM-004" || !strings.Contains(hostsetup.AsError(err).Remedy(), "--docker-group") || d.called("sudo -n usermod") {
		t.Fatalf("without --docker-group: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "same as") || !strings.Contains(out.String(), "full root access") {
		t.Errorf("root-equivalence not explained:\n%s", out)
	}
	err = runSetup(context.Background(), env, setupOptions{instance: "flow8", instanceSet: true, dockerGroup: true, timeout: time.Second})
	if codeOf(err) != "QP-PERM-005" || !d.called("sudo -n usermod -aG docker alice") {
		t.Fatalf("with --docker-group: %v %v", err, d.calls)
	}
	// In a terminal the question defaults to no.
	// (recommended settings: yes; go ahead: yes; join the group: Enter)
	env.stdin, env.stdinTTY = strings.NewReader("y\ny\n\n"), true
	err = runSetup(context.Background(), env, setupOptions{instance: "flow8", instanceSet: true, timeout: time.Second})
	if codeOf(err) != "QP-PERM-004" {
		t.Fatalf("Enter at the group question: %v", err)
	}
}

func TestSetupChecks(t *testing.T) {
	env, _, _ := testEnv(t, ready(), "", false)
	env.memBytes = func() int64 { return 512 << 20 }
	if err := runSetup(context.Background(), env, setupOptions{instance: "flow9", instanceSet: true, timeout: time.Second}); codeOf(err) != "QP-RES-001" {
		t.Fatalf("low memory: %v", err)
	}
	env.memBytes = func() int64 { return 4 << 30 }
	env.freeBytes = func(p string) int64 {
		if strings.Contains(p, "docker") {
			return 1 << 30
		}
		return 50 << 30
	}
	if err := runSetup(context.Background(), env, setupOptions{instance: "flow9", instanceSet: true, timeout: time.Second}); codeOf(err) != "QP-RES-003" {
		t.Fatalf("little space for images: %v", err)
	}
	env.freeBytes = func(string) int64 { return 50 << 30 }
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	bp := busy.Addr().(*net.TCPAddr).Port
	if err := runSetup(context.Background(), env, setupOptions{instance: "flow10", instanceSet: true, port: bp, portSet: true, timeout: time.Second}); codeOf(err) != "QP-PORT-001" {
		t.Fatalf("chosen port taken: %v", err)
	}
	for _, o := range []setupOptions{
		{profile: "standard", profileSet: true, honeypots: "cowrie", honeypotsSet: true},
		{instance: "../x", instanceSet: true},
		{port: 0, portSet: true},
		{dockerSource: "ppa"},
		{bind: "example.com", bindSet: true},
	} {
		o.timeout = time.Second
		if err := runSetup(context.Background(), env, o); err == nil || !strings.HasPrefix(codeOf(err), "QP-INPUT-") {
			t.Errorf("%+v: %v", o, err)
		}
	}
	env.goos = "freebsd"
	if err := runSetup(context.Background(), env, setupOptions{timeout: time.Second}); codeOf(err) != "QP-HOST-001" {
		t.Fatalf("freebsd: %v", err)
	}
	env.goos = "linux"
	if err := runSetup(context.Background(), env, setupOptions{instance: "flow11", instanceSet: true, service: true, serviceSet: true, timeout: time.Second}); codeOf(err) != "QP-SVC-004" {
		t.Fatalf("--service without systemctl: %v", err)
	}
	// Docker Desktop's installers ask the person to accept agreements:
	// without a terminal, --install-docker cannot stand in for that.
	d := &fakeDocker{euid: 501}
	env2, out, _ := testEnv(t, d, "", false)
	env2.goos = "darwin"
	err = runSetup(context.Background(), env2, setupOptions{instance: "flow13", instanceSet: true, installDocker: true, timeout: time.Second})
	if codeOf(err) != "QP-INPUT-008" || !strings.Contains(out.String(), "brew install --cask docker-desktop") || d.called("brew") {
		t.Fatalf("macOS without a terminal: %v\n%s", err, out)
	}
}

func TestSetupHealthFailureIsCoded(t *testing.T) {
	env, out, _ := testEnv(t, ready(), "", false)
	env.health = func(context.Context, *config.Config, bool, time.Duration) []check {
		return []check{{Name: "web UI", Level: "fail", Detail: "no answer", Code: "QP-WEB-002"}}
	}
	err := runSetup(context.Background(), env, setupOptions{instance: "flow12", instanceSet: true, port: freePort(t), portSet: true, timeout: time.Second})
	if codeOf(err) != "QP-WEB-002" || !strings.Contains(out.String(), "some checks failed") || !strings.Contains(out.String(), "(QP-WEB-002)") {
		t.Fatalf("err %v\n%s", err, out)
	}
	env.start = func(context.Context, *config.Config, bool) (string, error) {
		return "", hostsetup.E("QP-INST-003").WithDetails("compose said no")
	}
	if err := runSetup(context.Background(), env, setupOptions{instance: "flow12", instanceSet: true, timeout: time.Second}); codeOf(err) != "QP-INST-003" {
		t.Fatalf("start failure: %v", err)
	}
}

func TestPrintSetupErrorIsPlainAndSafe(t *testing.T) {
	var b bytes.Buffer
	e := hostsetup.E("QP-PKG-001").WithWhy("held by \x1b]52;c;ZXZpbA==\x07 dpkg").WithDetails("line1\n\x1b[2Jline2")
	status := printSetupError(&b, e)
	out := b.String()
	if status != 14 || !strings.Contains(out, "ERROR QP-PKG-001: Another program is installing software right now.") ||
		!strings.Contains(out, "  Why:  held by") || !strings.Contains(out, "  Fix:  Wait a few minutes") ||
		!strings.Contains(out, "    line1\n    \\x1b[2Jline2") || !strings.Contains(out, "qpot doctor --explain QP-PKG-001") {
		t.Fatalf("status %d:\n%s", status, out)
	}
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Fatal("control characters printed")
	}
	b.Reset()
	if printSetupError(&b, errors.New("raw")) != 70 || !strings.Contains(b.String(), "QP-BUG-001") {
		t.Fatalf("uncoded error: %s", b.String())
	}
	var code int
	exitProcess = func(c int) { code = c }
	defer func() { exitProcess = os.Exit }()
	b.Reset()
	if finishCoded(&b, hostsetup.E("QP-PORT-001")) == nil || code != 17 {
		t.Fatalf("finishCoded exit %d", code)
	}
	if finishCoded(&b, nil) != nil {
		t.Fatal("nil error")
	}
}

func TestDoctorExplain(t *testing.T) {
	var code int
	exitProcess = func(c int) { code = c }
	defer func() { exitProcess = os.Exit }()
	cmd := newDoctorCommand()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"--explain", "qp-svc-1"})
	if err := cmd.Execute(); err != nil || code != 0 {
		t.Fatalf("explain: %v %d", err, code)
	}
	if !strings.Contains(out.String(), "QP-SVC-001: systemd is not running") || !strings.Contains(out.String(), "\n  Fix:") {
		t.Fatalf("explain output:\n%q", out.String())
	}
	cmd = newDoctorCommand()
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"--explain", "QP-NOPE-7"})
	_ = cmd.Execute()
	if code != 10 || !strings.Contains(errOut.String(), "QP-INPUT-011") {
		t.Fatalf("unknown code: %d\n%s", code, errOut.String())
	}
}

// privateTemp makes a temporary folder as setup does (os.MkdirTemp: mode
// 0700); t.TempDir's own folder is 0755.
func privateTemp(t testing.TB) string {
	t.Helper()
	d, err := os.MkdirTemp(t.TempDir(), "qpot-setup-")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

type stubCmd struct{}

func (stubCmd) InOrStdin() io.Reader   { return strings.NewReader("") }
func (stubCmd) OutOrStdout() io.Writer { return io.Discard }

// Setup stops when it cannot make a private temporary folder: root installs
// files from there, and a file anywhere else could be swapped first.
func TestNewSetupEnvNeedsPrivateTempDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	setTmp := func(dir string) {
		for _, v := range []string{"TMPDIR", "TMP", "TEMP"} {
			t.Setenv(v, dir)
		}
	}

	setTmp(filepath.Join(t.TempDir(), "missing"))
	env, cleanup, err := newSetupEnv(stubCmd{}, false)
	if err == nil || err.Code != "QP-PERM-010" || env != nil || cleanup != nil {
		t.Fatalf("missing temporary folder: env=%v err=%v", env, err)
	}

	setTmp(t.TempDir())
	env, cleanup, err = newSetupEnv(stubCmd{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(env.tempDir) || hostsetup.CheckPrivateDir(env.tempDir) != nil {
		t.Fatalf("temporary folder %q is not private", env.tempDir)
	}
	dir := env.tempDir
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("temporary folder left behind: %v", err)
	}

	if runtime.GOOS != "windows" {
		// A temporary folder inside one other users can rename things in.
		shared := filepath.Join(t.TempDir(), "shared")
		if err := os.Mkdir(shared, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(shared, 0o777); err != nil {
			t.Fatal(err)
		}
		setTmp(shared)
		env, _, err = newSetupEnv(stubCmd{}, false)
		if err == nil || err.Code != "QP-PERM-010" || !strings.Contains(err.Cause(), "not sticky") {
			t.Fatalf("temporary folder in a shared folder: env=%v err=%v", env, err)
		}
		if ents, _ := os.ReadDir(shared); len(ents) != 0 {
			t.Fatalf("refused temporary folder left behind: %v", ents)
		}
	}
}
