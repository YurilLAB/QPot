package instance

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// TestConpotTemplateChangeKeepsOtherPorts: host ports are hashed and a
// collision probes upward in honeypot order, so Conpot's new ports after a
// template change could take a slot another honeypot had, moving it. `qpot
// honeypot set conpot template=...` recreates only Conpot, so the moved one
// kept its old port while the compose file said otherwise, and Conpot could
// not bind a port it still held. Every pair now keeps the port the compose file
// in use gives it.
func TestConpotTemplateChangeKeepsOtherPorts(t *testing.T) {
	templates := ConpotTemplateIDs()
	moved, cases := 0, 0
	for inst := 0; inst < 60; inst++ {
		cfg := config.Default("ports-" + strconv.Itoa(inst))
		cfg.DataPath = t.TempDir()
		for name, hp := range cfg.Honeypots {
			hp.Enabled = true
			cfg.Honeypots[name] = hp
		}
		setTemplate := func(id string) {
			hp := cfg.Honeypots["conpot"]
			hp.CustomConfig = map[string]string{"template": id}
			cfg.Honeypots["conpot"] = hp
		}
		for _, from := range templates {
			setTemplate(from)
			before := (&ComposeGenerator{Config: cfg}).buildHostPortMap()
			for _, to := range templates {
				if to == from {
					continue
				}
				setTemplate(to)
				fresh := (&ComposeGenerator{Config: cfg}).buildHostPortMap()
				after := (&ComposeGenerator{Config: cfg, KeepPorts: before}).buildHostPortMap()
				cases++
				if otherMoved(before, fresh) {
					moved++
				}
				if key, ok := firstOtherMoved(before, after); ok {
					t.Fatalf("instance %d, conpot %s -> %s: %q moved from %d to %d", inst, from, to,
						strings.ReplaceAll(key, "\x00", ":"), before[key], after[key])
				}
				seen := map[int]string{}
				for key, port := range after {
					if other, dup := seen[port]; dup {
						t.Fatalf("instance %d, %s -> %s: host port %d given to %q and %q", inst, from, to, port, key, other)
					}
					seen[port] = key
				}
			}
		}
	}
	if moved == 0 {
		t.Fatalf("no case in %d moved another honeypot without KeepPorts: the test does not exercise the bug", cases)
	}
	t.Logf("%d of %d template changes moved another honeypot's port without KeepPorts", moved, cases)
}

// otherMoved reports whether a pair of a honeypot other than conpot has a
// different port in after than in before.
func otherMoved(before, after map[string]int) bool {
	_, ok := firstOtherMoved(before, after)
	return ok
}

func firstOtherMoved(before, after map[string]int) (string, bool) {
	for key, port := range before {
		if strings.HasPrefix(key, "conpot\x00") {
			continue
		}
		if after[key] != port {
			return key, true
		}
	}
	return "", false
}

// TestOwnHostPortsReadsTheComposeFile: the ports the generator keeps are those
// of the instance's rendered compose file, keyed like buildHostPortMap's.
func TestOwnHostPortsReadsTheComposeFile(t *testing.T) {
	cfg := config.Default("own-ports")
	cfg.DataPath = t.TempDir()
	enableOnly(cfg, "cowrie", "dionaea", "conpot")
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Skip("no sandbox:", err)
	}
	g := &ComposeGenerator{Config: cfg, Sandbox: sb}
	want := g.buildHostPortMap()
	compose, err := g.Generate()
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
			t.Errorf("%q: compose file has %d, generator assigned %d", strings.ReplaceAll(key, "\x00", ":"), got[key], port)
		}
	}
	if ownHostPorts(filepath.Join(cfg.DataPath, "missing.yml")) != nil {
		t.Error("a missing compose file gave ports")
	}
}

// TestManagerKeepsPortsAcrossConpotTemplateChange drives the real path: the
// manager renders the compose file, the template changes, and the next render
// reads the ports back from the file it wrote.
func TestManagerKeepsPortsAcrossConpotTemplateChange(t *testing.T) {
	templates := ConpotTemplateIDs()
	for inst := 0; inst < 60; inst++ {
		cfg := config.Default("ports-" + strconv.Itoa(inst))
		cfg.DataPath = t.TempDir()
		for name, hp := range cfg.Honeypots {
			hp.Enabled = true
			cfg.Honeypots[name] = hp
		}
		setTemplate := func(id string) {
			hp := cfg.Honeypots["conpot"]
			hp.CustomConfig = map[string]string{"template": id}
			cfg.Honeypots["conpot"] = hp
		}
		for _, from := range templates {
			for _, to := range templates {
				setTemplate(from)
				before := (&ComposeGenerator{Config: cfg}).buildHostPortMap()
				setTemplate(to)
				if !otherMoved(before, (&ComposeGenerator{Config: cfg}).buildHostPortMap()) {
					continue
				}
				// A change that moved another honeypot before: render it for real.
				m, err := NewManager(cfg)
				if err != nil {
					t.Fatal(err)
				}
				setTemplate(from)
				if err := m.generateDockerCompose(); err != nil {
					t.Fatal(err)
				}
				rendered := ownHostPorts(cfg.GetDockerComposePath())
				setTemplate(to)
				if err := m.generateDockerCompose(); err != nil {
					t.Fatal(err)
				}
				if key, ok := firstOtherMoved(rendered, ownHostPorts(cfg.GetDockerComposePath())); ok {
					t.Fatalf("instance %d, conpot %s -> %s: %q moved in the compose file", inst, from, to,
						strings.ReplaceAll(key, "\x00", ":"))
				}
				return
			}
		}
	}
	t.Fatal("no template change moved another honeypot: nothing exercised")
}
