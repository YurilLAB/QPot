package instance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

func TestPublishedHostPort(t *testing.T) {
	cases := map[string]int{
		"8080:80": 8080, "127.0.0.1:19000:9000": 19000, "53:53/udp": 53,
		"[::1]:2222:22": 2222, "9000": 0, "abc:80": 0,
	}
	for in, want := range cases {
		if got := publishedHostPort(in); got != want {
			t.Errorf("publishedHostPort(%q) = %d, want %d", in, got, want)
		}
	}
}

// Two instances whose per-instance hashes collide (prod/cowrie and x/endlessh
// both hash to 172.26.31.0/24) must still get disjoint subnets and host ports
// once the second one is generated next to the first.
func TestSiblingInstancesDoNotCollide(t *testing.T) {
	root := t.TempDir()
	render := func(name string, reservePorts map[int]bool, reserveSubnets map[string]bool) (string, *ComposeGenerator) {
		cfg := config.Default(name)
		cfg.QPotID = "qp_" + name + "0000000000000000000000"
		cfg.DataPath = filepath.Join(root, name)
		for _, hp := range []string{"cowrie", "endlessh"} {
			h := cfg.Honeypots[hp]
			h.Enabled = true
			cfg.Honeypots[hp] = h
		}
		sb, err := security.NewSandbox(&cfg.Security)
		if err != nil {
			t.Fatal(err)
		}
		g := &ComposeGenerator{Config: cfg, Sandbox: sb, ReservedPorts: reservePorts, ReservedSubnets: reserveSubnets}
		out, err := g.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(cfg.DataPath, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cfg.DataPath, "docker-compose.yml"), []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		return out, g
	}
	_, prod := render("prod", nil, nil)
	if prod.buildSubnetMap()["cowrie"] != "172.26.31.0/24" {
		t.Skip("hash layout changed; the colliding pair no longer collides")
	}

	ports, subnets := siblingReservations(filepath.Join(root, "x"))
	if !subnets["172.26.31.0/24"] {
		t.Fatalf("prod's subnet was not read back as reserved: %v", subnets)
	}
	_, x := render("x", ports, subnets)
	for hp, s := range x.buildSubnetMap() {
		if subnets[s] {
			t.Errorf("x/%s reuses subnet %s already used by prod", hp, s)
		}
	}
	for key, p := range x.buildHostPortMap() {
		if ports[p] {
			t.Errorf("x/%s reuses host port %d already used by prod", key, p)
		}
	}
	// prod regenerated next to x keeps its own allocation (stable).
	p2, s2 := siblingReservations(filepath.Join(root, "prod"))
	again := &ComposeGenerator{Config: prod.Config, ReservedPorts: p2, ReservedSubnets: s2}
	if again.buildSubnetMap()["cowrie"] != "172.26.31.0/24" {
		t.Error("prod's allocation changed after x was added")
	}
}
