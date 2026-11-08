package instance

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

func TestParseComposePS_JSONL(t *testing.T) {
	// docker compose v2 emits one JSON object per line.
	out := []byte(`{"Name":"default_cowrie","Service":"cowrie","State":"running","Health":"healthy"}
{"Name":"default_ftp","Service":"ftp","State":"exited","Health":""}`)
	m := parseComposePS(out)
	if len(m) != 2 {
		t.Fatalf("got %d entries, want 2", len(m))
	}
	if m["cowrie"].State != "running" {
		t.Errorf("cowrie state = %q, want running", m["cowrie"].State)
	}
	if m["ftp"].State != "exited" {
		t.Errorf("ftp state = %q, want exited", m["ftp"].State)
	}
}

func TestParseComposePS_Array(t *testing.T) {
	out := []byte(`[{"Service":"cowrie","State":"running"},{"Service":"dionaea","State":"running"}]`)
	m := parseComposePS(out)
	if len(m) != 2 || m["dionaea"].State != "running" {
		t.Fatalf("unexpected parse: %+v", m)
	}
}

func TestParseComposePS_Empty(t *testing.T) {
	if m := parseComposePS([]byte("   ")); len(m) != 0 {
		t.Errorf("empty output should yield no entries, got %+v", m)
	}
}

// TestParseComposePS_NoSubstringFalsePositive ensures that a service name that
// is a substring of another container's name does not get matched. Previously
// Status used strings.Contains over the whole blob, so "ftp" would falsely
// match the "tftp"/"default_ftps" container text.
func TestParseComposePS_NoSubstringFalsePositive(t *testing.T) {
	// Only "tftp" is actually running; bare "ftp" is not a service here.
	out := []byte(`{"Name":"default_tftp","Service":"tftp","State":"running"}`)
	m := parseComposePS(out)
	if _, ok := m["ftp"]; ok {
		t.Error("ftp should not be present — only tftp is a real service")
	}
	if e, ok := m["tftp"]; !ok || e.State != "running" {
		t.Error("tftp should be present and running")
	}
}

// While the instance is down (no compose project, Docker stopped) the status
// still lists every configured honeypot: the dashboard counts the enabled ones
// from it and said "0 running of 0 enabled" with ten honeypots on.
func TestStatusListsHoneypotsWhileStopped(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default("status-stopped")
	cfg.DataPath = dir
	cfg.ConfigPath = filepath.Join(dir, "config.yaml")
	hp := cfg.Honeypots["conpot"]
	hp.Enabled = true
	cfg.Honeypots["conpot"] = hp
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Overall != "stopped" {
		t.Fatalf("overall %q with no compose project", st.Overall)
	}
	if len(st.Honeypots) != len(cfg.Honeypots) {
		t.Fatalf("listed %d honeypots, configured %d", len(st.Honeypots), len(cfg.Honeypots))
	}
	enabled := 0
	for _, h := range st.Honeypots {
		want := "disabled"
		if cfg.Honeypots[h.Name].Enabled {
			want = "stopped"
			enabled++
		}
		if h.Status != want || h.Running {
			t.Errorf("%s: status %q running %v, want %q and not running", h.Name, h.Status, h.Running, want)
		}
	}
	if enabled < 2 {
		t.Errorf("only %d enabled honeypots listed", enabled)
	}
}
