package main

import (
	"testing"

	"github.com/qpot/qpot/internal/config"
)

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
