package ypanel

import (
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/cluster"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/instance"
)

// The CLI writes cluster.json to cluster.DefaultDataPath(); the agent must read
// it from there, not from the instance's own data directory.
func TestAgentFindsCLICluster(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir, err := cluster.DefaultDataPath()
	if err != nil {
		t.Fatal(err)
	}
	ccfg := cluster.DefaultClusterConfig()
	ccfg.EnableEncryption = false
	if _, err := cluster.NewManager(dir).InitCluster("east-coast", "password123", ccfg); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		InstanceName: "test",
		DataPath:     t.TempDir(), // the instance dir holds no cluster.json
		Ypanel: config.YpanelConfig{
			Enabled:     true,
			Base:        "https://example.test",
			InstanceID:  "qp_000000000000000000000001",
			EnrollToken: "yp_" + strings.Repeat("a", 48),
		},
	}
	mgr, err := instance.NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, mgr, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, name := a.clusterIdentity(); name != "east-coast" {
		t.Fatalf("clusterIdentity name = %q, want east-coast", name)
	}
}
