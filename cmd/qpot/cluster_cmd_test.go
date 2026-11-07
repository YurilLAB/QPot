package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/cluster"
	"github.com/qpot/qpot/internal/hostsetup"
)

// clusterHome points HOME at a temp dir and returns the cluster data dir.
func clusterHome(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	t.Setenv(cluster.ClusterPasswordEnv, "")
	dir, err := cluster.DefaultDataPath()
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestClusterApprovalWorksWithSpecificBindAddr: `qpot cluster init
// --bind-addr 192.168.1.10` (the documented example) bound the cluster API to
// that address only, but `qpot cluster requests/approve/deny` always dialled
// 127.0.0.1, and the host-only check accepted nothing but loopback peers. With
// approval on (the default) no node could ever be admitted.
func TestClusterApprovalWorksWithSpecificBindAddr(t *testing.T) {
	ip := getLocalIP()
	if ip == "127.0.0.1" {
		t.Skip("no non-loopback IPv4 address")
	}
	dir := clusterHome(t)
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Skip("cannot listen on " + ip)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	const pw = "correct-horse-battery"
	host := cluster.NewManager(dir)
	cfg := cluster.DefaultClusterConfig()
	cfg.BindAddr, cfg.AdvertiseAddr, cfg.BindPort = ip, ip, port
	if _, err := host.InitCluster("prod", pw, cfg); err != nil {
		t.Fatal(err)
	}
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}
	defer host.Stop()

	out, code, err := clusterAPIRequest(http.MethodGet, "/pending", pw, nil)
	if err != nil || code != http.StatusOK {
		t.Fatalf("cluster requests on a cluster bound to %s: code %d, err %v, body %s", ip, code, err, out)
	}
}

// TestClusterHostCommandsUseStoredPassword: `qpot cluster requests`, `approve`
// and `deny` demanded --password on the command line, where any local user
// sees it in the process list (and it lands in shell history), although the
// host already keeps the password in its 0600 cluster.secret.
func TestClusterHostCommandsUseStoredPassword(t *testing.T) {
	dir := clusterHome(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	host := cluster.NewManager(dir)
	cfg := cluster.DefaultClusterConfig()
	cfg.BindAddr, cfg.BindPort = "127.0.0.1", port
	if _, err := host.InitCluster("prod", "correct-horse-battery", cfg); err != nil {
		t.Fatal(err)
	}
	if err := host.SaveSecret(); err != nil {
		t.Fatal(err)
	}
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}
	defer host.Stop()

	cmd := newClusterRequestsCommand()
	cmd.SetOut(io.Discard)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cluster requests without --password on the host: %v", err)
	}
	deny := newClusterDenyCommand()
	deny.SetArgs([]string{"req_unknown"})
	if err := deny.Execute(); err == nil || strings.Contains(err.Error(), "--password") {
		t.Fatalf("cluster deny without --password: %v (want the API's not-found error)", err)
	}
}

// TestClusterInitAdvertisesReachableAddress: with the default --bind-addr
// 0.0.0.0 the host advertised itself as 0.0.0.0. Members learn that address
// from the join response and gossip to it, which reaches the member itself
// (Linux) or nothing (Windows), and the printed join command said
// --seed 0.0.0.0:7946.
func TestClusterInitAdvertisesReachableAddress(t *testing.T) {
	for _, bind := range []string{"", "0.0.0.0", "::"} {
		dir := clusterHome(t)
		cmd := newClusterInitCommand()
		cmd.SetOut(io.Discard)
		args := []string{"--name", "prod", "--password", "correct-horse-battery"}
		if bind != "" {
			args = append(args, "--bind-addr", bind)
		}
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("init (bind %q): %v", bind, err)
		}
		c, err := cluster.NewManager(dir).LoadCluster()
		if err != nil || c == nil {
			t.Fatalf("load: %v", err)
		}
		addr := c.LocalNode.Address
		if ip := net.ParseIP(addr); addr == "" || (ip != nil && ip.IsUnspecified()) {
			t.Errorf("bind %q: host advertises %q, which no member can reach", bind, addr)
		}
		if c.Config.AdvertiseAddr != addr {
			t.Errorf("bind %q: advertise_addr %q differs from the local node address %q", bind, c.Config.AdvertiseAddr, addr)
		}
		_ = os.RemoveAll(filepath.Dir(dir))
	}
}

// TestClusterJoinSendsNoQPotID: `qpot cluster join` read the instance's QPot
// ID (its web API credential) and sent it in the join request, before any
// approval, for the host to store and gossip to every member.
func TestClusterJoinSendsNoQPotID(t *testing.T) {
	clusterHome(t)
	_, id, err := loadInstance("default")
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	seed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer seed.Close()
	cmd := newClusterCommand()
	cmd.SetArgs([]string{"join", "--id", "qc_test", "--password", "correct-horse-battery",
		"--seed", seed.URL, "--node-addr", "127.0.0.1"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil {
		t.Fatal("the join was accepted by a seed that refused it")
	}
	if len(got) == 0 {
		t.Fatal("no join request reached the seed")
	}
	if strings.Contains(string(got), id.ID) || strings.Contains(string(got), "qpot_id") {
		t.Fatalf("the join request carries the instance's QPot ID: %s", got)
	}
}

// testCA makes a CA and a certificate it signed for 127.0.0.1, and returns
// the CA as PEM and the server certificate.
func testCA(t *testing.T) ([]byte, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "operator CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "seed"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

// TestClusterJoinTrustFlags: a seed serving an operator certificate is
// refused unless the join is told to accept one: --ca-file checks it against
// that bundle, --operator-cert alone against the system roots.
func TestClusterJoinTrustFlags(t *testing.T) {
	caPEM, cert := testCA(t)
	otherPEM, _ := testCA(t)
	var reached atomic.Int32
	seed := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		http.Error(w, "denied", http.StatusForbidden)
	}))
	seed.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	seed.StartTLS()
	defer seed.Close()
	dir := t.TempDir()
	caFile, otherFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "other.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherFile, otherPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	join := func(extra ...string) (bool, error) {
		t.Helper()
		clusterHome(t)
		before := reached.Load()
		cmd := newClusterCommand()
		cmd.SetArgs(append([]string{"join", "--id", "qc_test", "--password", "correct-horse-battery",
			"--seed", strings.TrimPrefix(seed.URL, "https://"), "--node-addr", "127.0.0.1"}, extra...))
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		err := cmd.Execute()
		return reached.Load() > before, err
	}
	if got, _ := join(); got {
		t.Error("a seed with an operator certificate was trusted without --operator-cert or --ca-file")
	}
	if got, _ := join("--operator-cert"); got {
		t.Error("--operator-cert trusted a CA the system roots do not hold")
	}
	if got, _ := join("--ca-file", otherFile); got {
		t.Error("--ca-file trusted a certificate from another CA")
	}
	if got, _ := join("--ca-file", caFile); !got {
		t.Error("--ca-file did not trust the seed's certificate from that CA")
	}
	if got, err := join("--ca-file", filepath.Join(dir, "missing.pem")); err == nil || got || !strings.Contains(err.Error(), "--ca-file") {
		t.Errorf("a missing --ca-file: err %v, seed reached %v", err, got)
	}
}

func TestClusterUpgradeCommandPreservesInstanceAndRequiresConfirmation(t *testing.T) {
	dir := clusterHome(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := cluster.DefaultClusterConfig()
	cfg.BindAddr, cfg.BindPort = "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	mgr := cluster.NewManager(dir)
	c, err := mgr.InitCluster("existing", "password123", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.SaveSecret(); err != nil {
		t.Fatal(err)
	}
	c.Version, c.NodeKey, c.NodeCertificate = 0, "", ""
	c.LocalNode.InstanceName = "keep-instance"
	original, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cluster.json")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	abort := newClusterUpgradeCommand()
	abort.SetOut(&output)
	abort.SetErr(io.Discard)
	abort.SetIn(strings.NewReader("n\n"))
	if err := abort.Execute(); err != nil {
		t.Fatal(err)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, original) {
		t.Fatal("declined upgrade modified saved instance")
	}
	upgrade := newClusterUpgradeCommand()
	upgrade.SetOut(&output)
	upgrade.SetErr(io.Discard)
	upgrade.SetArgs([]string{"--yes"})
	if err := upgrade.Execute(); err != nil {
		t.Fatal(err)
	}
	got, err := cluster.NewManager(dir).LoadCluster()
	if err != nil || got.Version != cluster.ProtocolVersion || got.ID == c.ID || got.LocalNode.InstanceName != "keep-instance" {
		t.Fatalf("upgrade did not preserve instance and rotate version/trust: %v", err)
	}
	for _, text := range []string{"new cluster id", "backup", "were not changed", "rejoin"} {
		if !strings.Contains(strings.ToLower(output.String()), text) {
			t.Errorf("upgrade output lacks %q", text)
		}
	}
	if strings.Contains(output.String(), c.CAKey) || strings.Contains(output.String(), got.NodeKey) || strings.Contains(output.String(), "password123") {
		t.Fatal("upgrade output exposed private credentials")
	}
}

func TestClusterUpgradeCommandErrorsAreCoded(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "password"} {
		t.Run(mode, func(t *testing.T) {
			dir := clusterHome(t)
			if mode == "corrupt" {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "cluster.json"), []byte("invalid JSON private marker"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "password" {
				if _, err := cluster.NewManager(dir).InitCluster("test", "password123", nil); err != nil {
					t.Fatal(err)
				}
			}
			cmd := newClusterUpgradeCommand()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"--yes", "--password", "wrong-password"})
			err := cmd.Execute()
			var coded *hostsetup.Error
			if !errors.As(err, &coded) || coded.Code != "QP-CLUSTER-006" || commandExitStatus(err) != 23 {
				t.Fatalf("upgrade error not coded: %v", err)
			}
			if strings.Contains(err.Error(), "private marker") || strings.Contains(err.Error(), "wrong-password") || !strings.Contains(err.Error(), "Fix:") {
				t.Fatalf("upgrade error leaked data or lacks guidance: %v", err)
			}
		})
	}
}

func TestClusterErrorExitStatusPreservesOtherCommands(t *testing.T) {
	if commandExitStatus(errors.New("ordinary command failure")) != 1 || commandExitStatus(hostsetup.E("QP-INPUT-001")) != 1 {
		t.Fatal("unrelated command exit behavior changed")
	}
}

func TestClusterStatusDistinguishesLegacyFutureAndDamagedIdentity(t *testing.T) {
	for _, mode := range []string{"legacy", "future", "missing-key", "missing-certificate", "missing-member-key", "current"} {
		t.Run(mode, func(t *testing.T) {
			dir := clusterHome(t)
			c, err := cluster.NewManager(dir).InitCluster("status-test", "password123", nil)
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			switch mode {
			case "legacy":
				c.Version = 0
				want = "'qpot cluster upgrade'"
			case "future":
				c.Version = cluster.ProtocolVersion + 1
				want = "Update QPot to support this protocol"
			case "missing-key":
				c.NodeKey = ""
				want = "re-enroll"
			case "missing-certificate":
				c.NodeCertificate = ""
				want = "re-enroll"
			case "missing-member-key":
				c.MemberKey = ""
				want = "re-enroll"
			}
			data, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "cluster.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			out := captureStdout(t, func() {
				if err := newClusterStatusCommand().Execute(); err != nil {
					t.Fatal(err)
				}
			})
			if want != "" && !strings.Contains(out, want) {
				t.Fatalf("missing actionable guidance %q: %s", want, out)
			}
			if mode != "legacy" && strings.Contains(out, "'qpot cluster upgrade'") {
				t.Fatal("non-legacy cluster incorrectly advised to perform legacy upgrade")
			}
			if mode == "current" && strings.Contains(out, "[!]") {
				t.Fatalf("valid current identity incorrectly warned: %s", out)
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(data, after) {
				t.Fatal("status changed the saved cluster")
			}
		})
	}
}

func TestClusterUpgradeEnvironmentPasswordAndRepeatedInvocation(t *testing.T) {
	dir := clusterHome(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := cluster.DefaultClusterConfig()
	cfg.BindAddr, cfg.BindPort = "127.0.0.1", listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	c, err := cluster.NewManager(dir).InitCluster("env-password", "password123", cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Version, c.NodeCertificate, c.NodeKey = 0, "", ""
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cluster.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(cluster.ClusterPasswordEnv, "password123")
	cmd := newClusterUpgradeCommand()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("environment-only password upgrade: %v", err)
	}
	upgraded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd = newClusterUpgradeCommand()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--yes"})
	err = cmd.Execute()
	var coded *hostsetup.Error
	if !errors.As(err, &coded) || coded.Code != "QP-CLUSTER-006" || commandExitStatus(err) != 23 {
		t.Fatalf("repeated upgrade must fail with a supported code: %v", err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(upgraded, after) {
		t.Fatal("repeated upgrade rotated or damaged current trust")
	}
}

// testNodeCSR makes the certificate request a joining node sends.
func testNodeCSR(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
