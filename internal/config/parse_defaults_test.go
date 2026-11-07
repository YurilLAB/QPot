package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseKeepsWebUIAuthAndLoopbackWhenOmitted: yaml.Unmarshal leaves an
// omitted field at its zero value, so a config file without
// web_ui.qpot_id_auth and web_ui.bind_addr (written by hand, or trimmed to the
// settings that matter) served the whole API without any credential - the
// basic-auth fallback is off with no password - on every interface. Omitted,
// they now keep their secure defaults; set explicitly, they are honoured.
func TestParseKeepsWebUIAuthAndLoopbackWhenOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge", "config.yaml")
	cases := []struct {
		name     string
		yaml     string
		wantAuth bool
		wantBind string
	}{
		{"web_ui without auth or bind", "web_ui:\n  enabled: true\n  port: 8080\n", true, "127.0.0.1"},
		{"no web_ui section", "database:\n  type: clickhouse\n", true, "127.0.0.1"},
		{"explicit choices", "web_ui:\n  enabled: true\n  qpot_id_auth: false\n  bind_addr: 0.0.0.0\n", false, "0.0.0.0"},
		{"explicit auth on, bind omitted", "web_ui:\n  qpot_id_auth: true\n", true, "127.0.0.1"},
		{"empty bind", "web_ui:\n  bind_addr: \"\"\n", true, "127.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tc.yaml), path)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if cfg.WebUI.QPotIDAuth != tc.wantAuth {
				t.Errorf("qpot_id_auth = %v, want %v", cfg.WebUI.QPotIDAuth, tc.wantAuth)
			}
			if cfg.WebUI.BindAddr != tc.wantBind {
				t.Errorf("bind_addr = %q, want %q", cfg.WebUI.BindAddr, tc.wantBind)
			}
		})
	}
}

// TestParseRoundTripsDefaultWebUI: a config Save wrote reads back unchanged.
func TestParseRoundTripsDefaultWebUI(t *testing.T) {
	dir := t.TempDir()
	cfg := Default("rt")
	cfg.DataPath = dir
	cfg.ConfigPath = filepath.Join(dir, "config.yaml")
	cfg.WebUI.QPotIDAuth = false
	cfg.WebUI.BindAddr = "192.0.2.10"
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(data, cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.WebUI != cfg.WebUI {
		t.Fatalf("web_ui read back as %+v, saved %+v", got.WebUI, cfg.WebUI)
	}
}
