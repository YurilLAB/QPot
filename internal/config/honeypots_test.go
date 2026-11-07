package config

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestSetHoneypotCustomConfig(t *testing.T) {
	cfg := Default("hp-set")
	custom := map[string]string{"persona": "rhel-9"}
	if !cfg.SetHoneypotCustomConfig("cowrie", custom) {
		t.Fatal("cowrie not set")
	}
	custom["persona"] = "changed later"
	if hp, _ := cfg.GetHoneypotConfig("cowrie"); hp.CustomConfig["persona"] != "rhel-9" {
		t.Fatalf("the caller's map is shared: %v", hp.CustomConfig)
	}
	if cfg.SetHoneypotCustomConfig("nosuch", custom) {
		t.Fatal("an unknown honeypot was set")
	}
	if _, ok := cfg.GetHoneypotConfig("nosuch"); ok {
		t.Fatal("an unknown honeypot was added")
	}
}

func TestReplaceHoneypotsAndClone(t *testing.T) {
	dir := t.TempDir()
	cfg := Default("hp-clone")
	cfg.DataPath = dir
	cfg.ConfigPath = filepath.Join(dir, "config.yaml")
	cfg.QPotID = "qp_cloneclonecloneclonecl"
	cfg.SetHoneypotCustomConfig("cowrie", map[string]string{"bait": "off"})

	cp, err := cfg.Clone()
	if err != nil {
		t.Fatal(err)
	}
	if cp == cfg || cp.QPotID != cfg.QPotID || cp.DataPath != dir {
		t.Fatalf("clone: %+v", cp)
	}
	cp.SetHoneypotCustomConfig("cowrie", map[string]string{"bait": "on"})
	cp.EnableHoneypot("conpot")
	if hp, _ := cfg.GetHoneypotConfig("cowrie"); hp.CustomConfig["bait"] != "off" {
		t.Fatal("a change to the clone reached the original")
	}

	cfg.ReplaceHoneypots(cp.SnapshotHoneypots())
	if hp, _ := cfg.GetHoneypotConfig("conpot"); !hp.Enabled {
		t.Fatal("ReplaceHoneypots did not take the other config's honeypots")
	}
	cp.SetHoneypotCustomConfig("cowrie", map[string]string{"bait": "maybe"})
	if hp, _ := cfg.GetHoneypotConfig("cowrie"); hp.CustomConfig["bait"] != "on" {
		t.Fatalf("ReplaceHoneypots shares maps with the other config: %v", hp.CustomConfig)
	}
}

// The setters hold the honeypot lock (run with -race).
func TestHoneypotSettersConcurrent(t *testing.T) {
	cfg := Default("hp-race")
	other := Default("hp-race2")
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); cfg.SetHoneypotCustomConfig("cowrie", map[string]string{"bait": "off"}) }()
		go func() { defer wg.Done(); cfg.ReplaceHoneypots(other.SnapshotHoneypots()) }()
		go func() { defer wg.Done(); _, _ = cfg.Clone() }()
	}
	wg.Wait()
}
