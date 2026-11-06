package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
