package hostsetup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeHost is a pretend Linux machine for tests: an os-release under a temp
// root, and fake docker, apt-get, dpkg, dnf, rpm, systemctl and sudo
// programs on a private PATH. The fakes log every call and keep their state
// as marker files, so a test can see exactly what setup ran and in what
// order. (Same idea as scripts/test-makefile.sh.)
type fakeHost struct {
	t     *testing.T
	root  string
	bin   string
	state string
	log   string
}

func newFakeHost(t *testing.T, osRelease string) *fakeHost {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake programs are POSIX shell scripts")
	}
	for _, tool := range []string{"sh", "install", "env", "sleep", "touch", "cat"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	d := t.TempDir()
	h := &fakeHost{t: t, root: filepath.Join(d, "root"), bin: filepath.Join(d, "bin"), state: filepath.Join(d, "state"), log: filepath.Join(d, "calls.log")}
	for _, dir := range []string{h.root + "/etc/apt/sources.list.d", h.root + "/etc/yum.repos.d", h.root + "/etc/pki/rpm-gpg", h.bin, h.state} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.write("etc/os-release", osRelease)
	h.writeFakes()
	return h
}

func (h *fakeHost) write(rel, content string) {
	h.t.Helper()
	p := filepath.Join(h.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

// set creates (or with on=false removes) a state marker.
func (h *fakeHost) set(name string, on bool) {
	h.t.Helper()
	p := filepath.Join(h.state, name)
	if on {
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			h.t.Fatal(err)
		}
	} else {
		_ = os.Remove(p)
	}
}

func (h *fakeHost) has(name string) bool {
	_, err := os.Stat(filepath.Join(h.state, name))
	return err == nil
}

func (h *fakeHost) script(name, body string) {
	h.t.Helper()
	text := "#!/bin/sh\nS='" + h.state + "'\nprintf '%s\\n' \"" + name + " $*\" >> '" + h.log + "'\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(h.bin, name), []byte(text), 0o755); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) writeFakes() {
	h.script("sudo", `[ "$1" = "-n" ] && shift
[ -f "$S/sudo-password" ] && { echo "sudo: a password is required" >&2; exit 1; }
[ -f "$S/sudo-refused" ] && { echo "alice is not in the sudoers file.  This incident will be reported." >&2; exit 1; }
exec "$@"`)
	h.script("dpkg", `[ "$1" = "--print-architecture" ] && { echo amd64; exit 0; }; exit 0`)
	h.script("dpkg-query", `for last; do :; done
[ -f "$S/pkg-$last" ] && { printf 'ii '; exit 0; }
echo "dpkg-query: no packages found matching $last" >&2; exit 1`)
	h.script("apt-get", `case " $* " in
*" update "*)
  [ -f "$S/offline" ] && { echo "Err:1 https://download.docker.com/linux/ubuntu noble InRelease" ; echo "  Temporary failure resolving 'download.docker.com'"; echo "E: Failed to fetch https://download.docker.com/linux/ubuntu/dists/noble/InRelease" >&2; exit 100; }
  exit 0 ;;
*" install "*)
  [ -f "$S/apt-locked" ] && { echo "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 4242 (unattended-upgr)" >&2; exit 100; }
  [ -f "$S/apt-slow" ] && { trap 'touch "$S/got-interrupt"; exit 130' INT; sleep 30 & wait $!; }
  case " $* " in *" docker-ce "*|*" docker.io "*) touch "$S/docker-installed" "$S/compose";; esac
  case " $* " in *" docker-compose-plugin "*|*" docker-compose-v2 "*) touch "$S/compose";; esac
  exit 0 ;;
*" remove "*) exit 0 ;;
esac
exit 0`)
	h.script("apt-cache", `echo "docker-compose-v2:"; echo "  Installed: (none)"; echo "  Candidate: 2.24.6"; echo "docker-compose:"; echo "  Candidate: 1.29.2-1"`)
	h.script("rpm", `case "$1" in
-q) for last; do :; done; [ -f "$S/pkg-$last" ]; exit $? ;;
--import) exit 0 ;;
esac
exit 0`)
	h.script("dnf", `case " $* " in
*" install "*) touch "$S/docker-installed" "$S/compose"; exit 0 ;;
esac
exit 0`)
	h.script("zypper", `touch "$S/docker-installed" "$S/compose"; exit 0`)
	h.script("pacman", `touch "$S/docker-installed" "$S/compose"; exit 0`)
	h.script("usermod", `exit 0`)
	h.script("systemctl", `case " $* " in
*" enable "*) [ -f "$S/docker-broken" ] && { echo "Job for docker.service failed because the control process exited with error code." >&2; exit 1; }
  touch "$S/docker-running"; exit 0 ;;
*" status "*) echo "docker.service - Docker Application Container Engine"; echo "   Active: failed (Result: exit-code)"; exit 3 ;;
esac
exit 0`)
	h.script("docker", `case "$1" in
--version) echo "Docker version ${FAKE_DOCKER_VERSION:-27.3.1}, build ce12230"; [ -f "$S/podman" ] && echo "podman version 4.9.4"; exit 0 ;;
info)
  [ -f "$S/docker-running" ] || { echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?" >&2; exit 1; }
  [ -f "$S/docker-denied" ] && { echo "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock" >&2; exit 1; }
  echo "${FAKE_DOCKER_VERSION:-27.3.1}|/var/lib/docker|Ubuntu 24.04 LTS"; exit 0 ;;
compose)
  [ -f "$S/compose" ] || { echo "docker: 'compose' is not a docker command." >&2; exit 1; }
  echo "${FAKE_COMPOSE_VERSION:-2.29.7}"; exit 0 ;;
esac
exit 0`)
}

func (h *fakeHost) calls() []string {
	data, _ := os.ReadFile(h.log)
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (h *fakeHost) countCalls(prefix string) int {
	n := 0
	for _, c := range h.calls() {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// lookPath finds the fakes; docker only once it is "installed".
func (h *fakeHost) lookPath(name string) (string, error) {
	if (name == "docker" && !h.has("docker-installed")) || h.has("missing-"+name) {
		return "", exec.ErrNotFound
	}
	if name == "docker-compose" && !h.has("compose-v1") {
		return "", exec.ErrNotFound
	}
	p := filepath.Join(h.bin, name)
	if _, err := os.Stat(p); err != nil {
		return exec.LookPath(name)
	}
	return p, nil
}

func (h *fakeHost) runner(euid int) *ExecRunner {
	return &ExecRunner{EUID: euid, Sudo: filepath.Join(h.bin, "sudo"), NoTTY: true,
		PathEnv: h.bin + string(os.PathListSeparator) + os.Getenv("PATH"), Grace: 2 * time.Second}
}

// repoServer serves a test signing key and Docker-like repository paths.
type repoServer struct {
	srv  *httptest.Server
	key  []byte
	fpr  string
	have map[string]bool // paths answered 200
}

func newRepoServer(t *testing.T) *repoServer {
	body := testKeyBody(t, 4)
	rs := &repoServer{key: armor(append(newPacket(6, body), newPacket(13, []byte("test <t@example.invalid>"))...), true),
		fpr: fingerprintOf(body), have: map[string]bool{}}
	rs.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/gpg"):
			_, _ = w.Write(rs.key)
		case rs.have[r.URL.Path]:
			_, _ = w.Write([]byte("ok"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(rs.srv.Close)
	return rs
}

func (h *fakeHost) installer(rs *repoServer, osRelease string, euid int) *Installer {
	in := &Installer{
		P: Platform{GOOS: "linux", GOARCH: "amd64", Root: h.root, OS: ParseOSRelease([]byte(osRelease)),
			EUID: euid, User: "alice", Systemd: true},
		R: h.runner(euid), LookPath: h.lookPath, TempDir: h.t.TempDir(), Source: "auto",
		LockWait: time.Second, DaemonWait: 3 * time.Second,
	}
	if rs != nil {
		in.F = &Fetcher{Client: rs.srv.Client(), GOOS: "linux"}
		in.RepoBase = rs.srv.URL
		in.debKey, in.rpmKey = rs.fpr, rs.fpr
	}
	return in
}

func detect(h *fakeHost, in *Installer) DockerState {
	return DetectDocker(context.Background(), in.R, h.lookPath)
}
