package hostsetup

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real messages from apt, dpkg, dnf, zypper, pacman and sudo, and the code
// each must map to.
func TestClassifyFailure(t *testing.T) {
	cases := []struct {
		kind StepKind
		out  string
		code string
	}{
		{KindInstall, "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1234 (unattended-upgr)\nE: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?", "QP-PKG-001"},
		{KindInstall, "Waiting for process with pid 812 to finish.", "QP-PKG-001"},
		{KindInstall, "System management is locked by the application with pid 4242 (zypper).", "QP-PKG-001"},
		{KindInstall, "error: failed to init transaction (unable to lock database)\nerror: could not lock database: File exists\n  if you're sure a package manager is not already\n  running, you can remove /var/lib/pacman/db.lck", "QP-PKG-001"},
		{KindInstall, "E: dpkg was interrupted, you must manually run 'sudo dpkg --configure -a' to correct the problem.", "QP-PKG-005"},
		{KindInstall, "dpkg: error processing archive ...: cannot copy extracted data for './usr/bin/dockerd' to '/usr/bin/dockerd.dpkg-new': failed to write (No space left on device)", "QP-RES-004"},
		{KindInstall, "E: You don't have enough free space in /var/cache/apt/archives/.", "QP-RES-004"},
		{KindUpdate, "W: GPG error: https://download.docker.com/linux/ubuntu noble InRelease: The following signatures couldn't be verified because the public key is not available: NO_PUBKEY 7EA0A9C3F273FCD8\nE: The repository 'https://download.docker.com/linux/ubuntu noble InRelease' is not signed.", "QP-PKG-003"},
		{KindInstall, "Public key for docker-ce-27.3.1-1.el9.x86_64.rpm is not installed. Failing package is: docker-ce", "QP-PKG-003"},
		{KindUpdate, "Err:1 http://archive.ubuntu.com/ubuntu noble InRelease\n  Temporary failure resolving 'archive.ubuntu.com'", "QP-NET-006"},
		{KindUpdate, "E: Failed to fetch https://download.docker.com/linux/ubuntu/dists/noble/InRelease  Could not connect to download.docker.com:443 (1.2.3.4), connection timed out", "QP-NET-006"},
		{KindInstall, "Errors during downloading metadata for repository 'docker-ce-stable':\n  - Curl error (6): Couldn't resolve host name", "QP-NET-006"},
		{KindUpdate, "E: Release file for http://deb.debian.org/debian/dists/bookworm-updates/InRelease is not valid yet (invalid for another 2d 3h).", "QP-PKG-002"},
		{KindInstall, "The following packages have unmet dependencies:\n containerd.io : Conflicts: containerd\nE: Unable to correct problems, you have held broken packages.", "QP-PKG-006"},
		{KindInstall, "Error:\n Problem: problem with installed package podman-docker\n  - package podman-docker conflicts with docker provided by docker-ce", "QP-PKG-006"},
		{KindInstall, "E: Unable to locate package docker-compose-plugin", "QP-PKG-007"},
		{KindInstall, "Package docker-ce is not available, but is referred to by another package.\nE: Package 'docker-ce' has no installation candidate", "QP-PKG-007"},
		{KindInstall, "No match for argument: docker-ce\nError: Unable to find a match: docker-ce", "QP-PKG-007"},
		{KindInstall, "error: target not found: docker-compose", "QP-PKG-007"},
		{KindInstall, "sudo: a password is required", "QP-PERM-002"},
		{KindInstall, "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper", "QP-PERM-002"},
		{KindInstall, "alice is not in the sudoers file.  This incident will be reported.", "QP-PERM-003"},
		{KindInstall, "E: something new and strange", "QP-PKG-004"},
		{KindUpdate, "E: something new and strange", "QP-PKG-002"},
		{KindRemove, "E: something new", "QP-PKG-004"},
		{KindService, "Job for docker.service failed because the control process exited with error code.", "QP-DOCKER-003"},
		{KindDesktop, "Error: It seems there is already an App at '/Applications/Docker.app'.", "QP-DOCKER-009"},
		{KindGroup, "usermod: group 'docker' does not exist", "QP-PERM-009"},
		{KindFile, "install: cannot create regular file '/etc/apt/keyrings/docker.asc': Read-only file system", "QP-PERM-008"},
		{KindOther, "weird", "QP-BUG-001"},
	}
	for _, c := range cases {
		e := ClassifyFailure(c.kind, "apt-get install -y docker-ce", Result{Exit: 100, Stderr: []byte(c.out)})
		if e.Code != c.code {
			t.Errorf("%q -> %s, want %s", firstLineOf(c.out), e.Code, c.code)
		}
		if !strings.Contains(e.Details, "command: apt-get install -y docker-ce") || !strings.Contains(e.Details, "exit status: 100") {
			t.Errorf("details lack the command: %q", e.Details)
		}
	}
	if e := ClassifyFailure(KindInstall, "x", Result{Exit: -1, Canceled: true}); e.Code != "QP-INT-001" {
		t.Errorf("cancelled = %s", e.Code)
	}
	if e := ClassifyFailure(KindService, "x", Result{Exit: -1, TimedOut: true}); e.Code != "QP-INT-002" {
		t.Errorf("timed-out service = %s", e.Code)
	}
}

func firstLineOf(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

func FuzzClassifyFailure(f *testing.F) {
	f.Add(0, "E: Could not get lock /var/lib/dpkg/lock", 100, false, false)
	f.Add(1, "Temporary failure resolving 'x'", 100, false, true)
	f.Add(4, "", -1, true, false)
	f.Fuzz(func(t *testing.T, kind int, out string, exit int, canceled, timedOut bool) {
		e := ClassifyFailure(StepKind(kind%8), "cmd", Result{Exit: exit, Stderr: []byte(out), Canceled: canceled, TimedOut: timedOut})
		if e == nil {
			t.Fatal("nil error")
		}
		if _, ok := byID[e.Code]; !ok {
			t.Fatalf("unknown code %q", e.Code)
		}
		if strings.TrimSpace(e.Cause()) == "" || strings.TrimSpace(e.Remedy()) == "" {
			t.Fatalf("%s has no cause or fix", e.Code)
		}
	})
}

// HTTPS downloads use the certificate bundle under the platform root, and
// every network failure gets its own code.
func TestFetcher(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("hello"))
		case "/big":
			_, _ = w.Write(make([]byte, 2048))
		case "/forbidden":
			w.WriteHeader(http.StatusForbidden)
		case "/boom":
			w.WriteHeader(http.StatusBadGateway)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	root := t.TempDir()
	f := &Fetcher{Root: root, GOOS: "linux", Timeout: 10 * time.Second}
	ctx := context.Background()
	t.Setenv("SSL_CERT_FILE", "")
	if f.HasCABundle() {
		t.Fatal("an empty root has no certificate bundle")
	}
	if _, err := f.Get(ctx, srv.URL+"/ok", 100); err == nil || err.Code != "QP-NET-003" {
		t.Fatalf("no bundle: %v", err)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	bundle := filepath.Join(root, "etc/pki/tls/certs/ca-bundle.crt")
	if err := os.MkdirAll(filepath.Dir(bundle), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, pemCert, 0o644); err != nil {
		t.Fatal(err)
	}
	if !f.HasCABundle() {
		t.Fatal("bundle not found")
	}
	if b, err := f.Get(ctx, srv.URL+"/ok", 100); err != nil || string(b) != "hello" {
		t.Fatalf("Get = %q, %v", b, err)
	}
	if _, err := f.Get(ctx, srv.URL+"/big", 100); err == nil || err.Code != "QP-NET-004" {
		t.Fatalf("oversized: %v", err)
	}
	if ok, err := f.Exists(ctx, srv.URL+"/missing"); ok || err != nil {
		t.Fatalf("404 = %v, %v", ok, err)
	}
	if ok, err := f.Exists(ctx, srv.URL+"/forbidden"); ok || err != nil {
		t.Fatalf("403 = %v, %v", ok, err)
	}
	if _, err := f.Exists(ctx, srv.URL+"/boom"); err == nil || err.Code != "QP-NET-004" {
		t.Fatalf("502: %v", err)
	}
	// A server whose certificate the bundle does not hold.
	other := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	other.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}
	other.StartTLS()
	defer other.Close()
	if _, err := f.Get(ctx, other.URL+"/", 10); err == nil || err.Code != "QP-NET-003" {
		t.Fatalf("untrusted certificate: %v", err)
	}
	// Nothing listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "https://" + ln.Addr().String() + "/"
	ln.Close()
	if _, err := f.Get(ctx, dead, 10); err == nil || err.Code != "QP-NET-002" {
		t.Fatalf("connection refused: %v", err)
	}
	// Ctrl-C during a download.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.Get(cctx, srv.URL+"/ok", 10); err == nil || err.Code != "QP-INT-001" {
		t.Fatalf("cancelled: %v", err)
	}
}

// selfSigned makes a certificate for 127.0.0.1 at run time (no key material
// is kept in the source).
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "other"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestClassifyNetError(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		err  error
		code string
	}{
		{&net.DNSError{Err: "no such host", Name: "download.docker.com", IsNotFound: true}, "QP-NET-001"},
		{x509.UnknownAuthorityError{}, "QP-NET-003"},
		{&tls.CertificateVerificationError{Err: errors.New("expired")}, "QP-NET-003"},
		{&net.OpError{Op: "dial", Err: errors.New("connection refused")}, "QP-NET-002"},
		{errors.New("something"), "QP-NET-002"},
	}
	for _, c := range cases {
		if e := ClassifyNetError(ctx, "https://download.docker.com/x", c.err); e.Code != c.code {
			t.Errorf("%T -> %s, want %s", c.err, e.Code, c.code)
		}
	}
	e := ClassifyNetError(ctx, "https://download.docker.com/x", &net.DNSError{Name: "download.docker.com", IsNotFound: true})
	if !strings.Contains(e.Cause(), "download.docker.com") || !strings.Contains(e.Remedy(), "ping -c1 download.docker.com") {
		t.Errorf("DNS message: %q / %q", e.Cause(), e.Remedy())
	}
}
