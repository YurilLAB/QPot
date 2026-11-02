package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

func TestGeoIPCheck(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{InstanceName: "t", DataPath: dir}
	if c := geoIPCheck(cfg); c.Name != "" {
		t.Errorf("no database configured: want no check, got %+v", c)
	}
	cfg.Collector.GeoIPDBPath = "/data/geoip/db.mmdb"
	if c := geoIPCheck(cfg); c.Level != "fail" {
		t.Errorf("missing file: %+v", c)
	}
	if err := os.MkdirAll(filepath.Join(dir, "geoip"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geoip", "db.mmdb"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if c := geoIPCheck(cfg); c.Level != "ok" {
		t.Errorf("present file: %+v", c)
	}
}

func TestSetMapCountry(t *testing.T) {
	cfg := &config.Config{}
	if err := setMapCountry(cfg, ""); err != nil || cfg.AttackMap.Country != "" {
		t.Errorf("empty keeps the setting: %v %q", err, cfg.AttackMap.Country)
	}
	if err := setMapCountry(cfg, " nl "); err != nil || cfg.AttackMap.Country != "NL" {
		t.Errorf("nl: %v %q", err, cfg.AttackMap.Country)
	}
	for _, bad := range []string{"ZZ", "NLD", "D E", "../"} {
		if err := setMapCountry(cfg, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if cfg.AttackMap.Country != "NL" {
		t.Errorf("a rejected code changed the setting: %q", cfg.AttackMap.Country)
	}
}
