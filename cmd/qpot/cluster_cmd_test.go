package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
