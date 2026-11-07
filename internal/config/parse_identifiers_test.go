package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseRefusesHostileIdentifiers: values written into docker-compose.yml,
// paths and the dashboard as they are must be plain identifiers.
func TestParseRefusesHostileIdentifiers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge", "config.yaml")
	refused := map[string]string{
		"database type with a newline": "database:\n  type: \"none\\n  pwn:\\n    image: alpine\"\n",
		"unknown database type":        "database:\n  type: mysql\n",
		"instance name with a newline": "instance_name: \"edge\\n  pwn:\"\n",
		"instance name with a slash":   "instance_name: ../etc\n",
		"honeypot name with markup":    "honeypots:\n  \"<img src=x onerror=alert(1)>\":\n    enabled: true\n",
		"honeypot name with a dot dot": "honeypots:\n  \"../..\":\n    enabled: true\n",
		"honeypot name dot dot":        "honeypots:\n  \"..\":\n    enabled: true\n",
		"honeypot name upper case":     "honeypots:\n  Cowrie:\n    enabled: true\n",
		"risk level with markup":       "honeypots:\n  cowrie:\n    risk_level: \"<img src=x onerror=alert(1)>\"\n",
		"data path with a newline":     "data_path: \"/srv/qpot\\n  pwn:\"\n",
		"geoip path with a newline":    "collector:\n  geoip_db_path: \"/geoip/x.mmdb\\\"\\n\"\n",
	}
	for name, doc := range refused {
		t.Run(name, func(t *testing.T) {
			if cfg, err := Parse([]byte(doc), path); err == nil {
				t.Fatalf("accepted: database %q, instance %q, honeypots %v, data path %q",
					cfg.Database.Type, cfg.InstanceName, cfg.Honeypots, cfg.DataPath)
			}
		})
	}
}

// TestParseAcceptsEveryShippedConfig: the default config, with every honeypot
// QPot knows enabled in turn, the database types and the risk levels in any
// case, still read back - the checks cannot refuse a config QPot wrote.
func TestParseAcceptsEveryShippedConfig(t *testing.T) {
	for _, dbType := range []string{"clickhouse", "timescaledb", "elasticsearch", ""} {
		dir := filepath.Join(t.TempDir(), "edge-1_b")
		cfg := Default("edge-1_b")
		cfg.DataPath, cfg.ConfigPath = dir, filepath.Join(dir, "config.yaml")
		cfg.Database.Type = dbType
		cfg.Collector.GeoIPDBPath = "/geoip/dbip-city-lite.mmdb"
		for name := range cfg.Honeypots {
			cfg.EnableHoneypot(name)
		}
		if err := Save(cfg); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(cfg.ConfigPath)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(data, cfg.ConfigPath)
		if err != nil {
			t.Fatalf("database %q: the default config with every honeypot is refused: %v", dbType, err)
		}
		if len(got.Honeypots) != len(cfg.Honeypots) {
			t.Fatalf("%d honeypots read back, %d saved", len(got.Honeypots), len(cfg.Honeypots))
		}
		for name, hp := range cfg.Honeypots {
			if got.Honeypots[name].RiskLevel != hp.RiskLevel {
				t.Errorf("%s risk %q read back as %q", name, hp.RiskLevel, got.Honeypots[name].RiskLevel)
			}
		}
	}

	doc := "honeypots:\n  cowrie:\n    risk_level: \" High \"\n  ssh-proxy:\n    risk_level: CRITICAL\n  go-pot: {}\n"
	got, err := Parse([]byte(doc), filepath.Join(t.TempDir(), "edge", "config.yaml"))
	if err != nil {
		t.Fatalf("risk levels in another case are refused: %v", err)
	}
	for name, want := range map[string]string{"cowrie": "high", "ssh-proxy": "critical", "go-pot": ""} {
		if r := got.Honeypots[name].RiskLevel; r != want {
			t.Errorf("%s risk_level = %q, want %q", name, r, want)
		}
	}
}
