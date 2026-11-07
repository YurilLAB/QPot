package instance

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// TestTannerKeepsItsHostPort: tanner's host port is allocated as tanner's but
// published by its snare companion, so reading the compose file in use back
// recorded it as snare's and KeepPorts never found it: enabling another
// honeypot could move snare off the port it holds and give that port to the
// new honeypot, whose `compose up -d <name>` (snare keeps running on it) then
// failed to bind it. The port is now read back as tanner's, by the service's
// qpot.honeypot label.
func TestTannerKeepsItsHostPort(t *testing.T) {
	// An instance where enabling every honeypot, with nothing kept, takes
	// tanner's port for another honeypot: the case keeping has to cover.
	var cfg *config.Config
	var want map[string]int
	for i := 0; i < 20000 && cfg == nil; i++ {
		c := config.Default(fmt.Sprintf("own-ports-%d", i))
		enableOnly(c, "cowrie", "tanner")
		first := (&ComposeGenerator{Config: c}).buildHostPortMap()
		for name := range c.Honeypots {
			c.EnableHoneypot(name)
		}
		if (&ComposeGenerator{Config: c}).buildHostPortMap()[portKey("tanner", 80)] != first[portKey("tanner", 80)] {
			enableOnly(c, "cowrie", "tanner")
			cfg, want = c, first
		}
	}
	if cfg == nil {
		t.Fatal("no instance name moves tanner when every honeypot is enabled")
	}
	cfg.DataPath = t.TempDir()
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Skip(err)
	}
	compose, err := (&ComposeGenerator{Config: cfg, Sandbox: sb}).Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.DataPath, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(compose), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ownHostPorts(path)
	for key, port := range want {
		if got[key] != port {
			t.Errorf("%q read back as %d, the generator gave it %d", key, got[key], port)
		}
	}

	// Enabling every other honeypot leaves tanner where it is.
	for name := range cfg.Honeypots {
		cfg.EnableHoneypot(name)
	}
	after := (&ComposeGenerator{Config: cfg, KeepPorts: got}).buildHostPortMap()
	if after[portKey("tanner", 80)] != want[portKey("tanner", 80)] {
		t.Fatalf("instance %s: enabling more honeypots moved tanner from %d to %d",
			cfg.InstanceName, want[portKey("tanner", 80)], after[portKey("tanner", 80)])
	}
}
