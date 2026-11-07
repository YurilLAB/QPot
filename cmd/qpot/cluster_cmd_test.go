package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/cluster"
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
