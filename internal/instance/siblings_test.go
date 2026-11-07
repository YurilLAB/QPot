package instance

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
	"gopkg.in/yaml.v3"
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

func TestParseNetworkInspect(t *testing.T) {
	data := []byte(`[
	 {"Name":"bridge","Labels":{},"IPAM":{"Config":[{"Subnet":"172.17.0.0/16"}]}},
	 {"Name":"other_net","Labels":{"com.docker.compose.project":"other"},"IPAM":{"Config":[{"Subnet":"172.22.0.0/16"},{"Subnet":"fd00::/64"}]}},
	 {"Name":"mine_qpot_internal","Labels":{"com.docker.compose.project":"mine"},"IPAM":{"Config":[{"Subnet":"172.23.0.0/16"}]}},
	 {"Name":"host","Labels":{},"IPAM":{"Config":[]}}]`)
	got := parseNetworkInspect(data, "mine")
	var s []string
	for _, n := range got {
		s = append(s, n.String())
	}
	if strings.Join(s, ",") != "172.17.0.0/16,172.22.0.0/16,fd00::/64" {
		t.Fatalf("got %v", s)
	}
}

// Every QPot network gets an explicit /24, none overlaps a network already on
// the host (even a /16 that contains it), and all are distinct.
func TestSubnetsAvoidHostNetworks(t *testing.T) {
	cfg := config.Default("subnet-host")
	cfg.QPotID = "qp_subnethost00000000000001"
	for _, hp := range []string{"cowrie", "endlessh", "dionaea", "heralding", "conpot", "adbhoney", "ssh-proxy"} {
		h := cfg.Honeypots[hp]
		h.Enabled = true
		cfg.Honeypots[hp] = h
	}
	var reserved []*net.IPNet
	for _, c := range []string{"172.17.0.0/16", "172.18.0.0/16", "172.20.0.0/16", "172.22.0.0/16", "172.25.0.0/16", "172.31.0.0/16"} {
		_, n, _ := net.ParseCIDR(c)
		reserved = append(reserved, n)
	}
	g := &ComposeGenerator{Config: cfg, ReservedNets: reserved}
	m := g.buildSubnetMap()
	for _, want := range []string{"qpot_internal", "qpot_dbhost", "ssh-proxy_backend", "cowrie"} {
		if m[want] == "" {
			t.Errorf("no subnet allocated for %s", want)
		}
	}
	seen := map[string]string{}
	for name, sub := range m {
		_, cand, err := net.ParseCIDR(sub)
		if err != nil {
			t.Fatalf("%s: bad subnet %q", name, sub)
		}
		for _, r := range reserved {
			if r.Contains(cand.IP) {
				t.Errorf("%s got %s inside host network %s", name, sub, r)
			}
		}
		if other, dup := seen[sub]; dup {
			t.Errorf("%s and %s share %s", name, other, sub)
		}
		seen[sub] = name
	}
	sb, _ := security.NewSandbox(&cfg.Security)
	g.Sandbox = sb
	out, err := g.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"qpot_internal", "qpot_dbhost", "ssh-proxy_backend", "cowrie"} {
		if !strings.Contains(out, "- subnet: "+m[name]) {
			t.Errorf("compose does not render the subnet for %s", name)
		}
	}
}

// databasePublished returns the host port the compose file at path publishes
// the database service on (0 if none).
func databasePublished(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			Ports []string `yaml:"ports"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, p := range doc.Services["database"].Ports {
		if hp := publishedHostPort(p); hp > 0 {
			return hp
		}
	}
	return 0
}

// TestDatabasePortClearsSiblings: the database's host port was the instance's
// hash alone, so an instance whose name hashed like a sibling's, or whose
// default fell on a port a sibling's honeypot publishes, rendered a compose
// file that the second `qpot up` could not bind. It is now moved off ports
// other instances publish, kept once in use, and the host-side client dials
// the port the compose file actually publishes.
func TestDatabasePortClearsSiblings(t *testing.T) {
	root := t.TempDir()
	newCfg := func(name, dbType string, honeypots ...string) *config.Config {
		cfg := config.Default(name)
		cfg.DataPath = filepath.Join(root, name)
		cfg.Database.Type = dbType
		if dbType == "timescaledb" {
			cfg.Database.Port = 5432
		}
		enableOnly(cfg, honeypots...)
		return cfg
	}
	generate := func(cfg *config.Config) int {
		t.Helper()
		if err := os.MkdirAll(cfg.DataPath, 0o750); err != nil {
			t.Fatal(err)
		}
		m, err := NewManager(cfg)
		if err != nil {
			t.Skip(err)
		}
		if err := m.generateDockerCompose(); err != nil {
			t.Fatal(err)
		}
		got := databasePublished(t, cfg.GetDockerComposePath())
		if c := cfg.DatabaseClient().Port; c != got {
			t.Errorf("%s: the client dials %d, the compose file publishes the database on %d", cfg.InstanceName, c, got)
		}
		return got
	}
	// findName returns an instance name whose default database port is want.
	findName := func(prefix, dbType string, want map[int]bool) *config.Config {
		for i := 0; i < 20000; i++ {
			cfg := newCfg(fmt.Sprintf("%s-%d", prefix, i), dbType, "cowrie")
			if want[cfg.DatabaseClient().Port] {
				return cfg
			}
		}
		t.Fatalf("no %s name found", prefix)
		return nil
	}

	for _, dbType := range []string{"clickhouse", "timescaledb"} {
		// A sibling with every honeypot on: its ports cover the database range.
		all := newCfg("all-"+dbType, dbType)
		for name := range all.Honeypots {
			all.EnableHoneypot(name)
		}
		allDB := generate(all)
		siblingPorts, _ := siblingReservations(filepath.Join(root, "next-"+dbType))
		hpOnDBRange := map[int]bool{}
		for p := range siblingPorts {
			if p != allDB {
				hpOnDBRange[p] = true
			}
		}

		sameHash := findName("hash-"+dbType, dbType, map[int]bool{allDB: true})
		onHoneypot := findName("onhp-"+dbType, dbType, hpOnDBRange)
		for _, cfg := range []*config.Config{sameHash, onHoneypot} {
			def := cfg.DatabaseClient().Port
			published := generate(cfg)
			if siblingPorts[published] {
				t.Errorf("%s: database published on %d, which %s already publishes (default %d)",
					cfg.InstanceName, published, all.InstanceName, def)
			}
			// Regenerated, it keeps that port.
			if again := generate(cfg); again != published {
				t.Errorf("%s: regenerating moved the database from %d to %d", cfg.InstanceName, published, again)
			}
			if err := os.RemoveAll(cfg.DataPath); err != nil {
				t.Fatal(err)
			}
		}
		// The first instance keeps its port with the others next to it.
		if again := generate(all); again != allDB {
			t.Errorf("%s: regenerating moved the database from %d to %d", all.InstanceName, allDB, again)
		}

		// An instance rendered before this fix shares the sibling's port, and
		// its cowrie sits on the next one: the database moves off the
		// sibling's port, and cowrie off the database's new one.
		cport := 9000
		if dbType == "timescaledb" {
			cport = 5432
		}
		stale := findName("stale-"+dbType, dbType, map[int]bool{allDB: true})
		if err := os.MkdirAll(stale.DataPath, 0o750); err != nil {
			t.Fatal(err)
		}
		before := fmt.Sprintf(`services:
  database:
    ports:
      - "127.0.0.1:%d:%d"
  cowrie:
    ports:
      - "%d:22"
`, allDB, cport, allDB+1)
		if err := os.WriteFile(stale.GetDockerComposePath(), []byte(before), 0o600); err != nil {
			t.Fatal(err)
		}
		if stale.DatabaseClient().Port != allDB {
			t.Fatalf("%s: the client does not dial the port the compose file in use publishes", stale.InstanceName)
		}
		moved := generate(stale)
		if moved == allDB {
			t.Errorf("%s: database kept %d, which %s publishes", stale.InstanceName, moved, all.InstanceName)
		}
		if cowrie := ownHostPorts(stale.GetDockerComposePath())[portKey("cowrie", 22)]; cowrie == moved {
			t.Errorf("%s: cowrie and the database both publish %d", stale.InstanceName, moved)
		}
		if err := os.RemoveAll(stale.DataPath); err != nil {
			t.Fatal(err)
		}

		// The sibling goes away: an instance that moved keeps its port, which
		// its running database still holds when only a honeypot is started.
		keeper := findName("keep-"+dbType, dbType, map[int]bool{allDB: true})
		kept := generate(keeper)
		if err := os.RemoveAll(all.DataPath); err != nil {
			t.Fatal(err)
		}
		if again := generate(keeper); again != kept {
			t.Errorf("%s: with %s gone, regenerating moved the database from %d to %d", keeper.InstanceName, all.InstanceName, kept, again)
		}
		if err := os.RemoveAll(keeper.DataPath); err != nil {
			t.Fatal(err)
		}
	}
}
