package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzConfigLoad feeds arbitrary YAML into the on-disk config and asserts Load
// never panics and always returns a usable config: malformed YAML must error
// (not crash), and a parsed config must have its intelligence tunables clamped
// to safe values (a zero worker interval would later panic time.NewTicker).
func FuzzConfigLoad(f *testing.F) {
	f.Add("intelligence:\n  enabled: true\n")
	f.Add("instance_name: x\nintelligence:\n  enabled: true\n  worker_interval: 0\n")
	f.Add(": : : not yaml")
	f.Add("database:\n  port: 999999999999999999999\n")
	f.Add("honeypots:\n  cowrie:\n    enabled: true\n    port: -1\n")
	f.Add("")

	home := f.TempDir()
	os.Setenv("HOME", home)
	os.Setenv("USERPROFILE", home) // os.UserHomeDir on Windows
	dir := filepath.Join(home, ".qpot", "instances", "fuzzinst")
	os.MkdirAll(dir, 0o755)
	cfgPath := filepath.Join(dir, "config.yaml")

	f.Fuzz(func(t *testing.T, yamlBody string) {
		if err := os.WriteFile(cfgPath, []byte(yamlBody), 0o644); err != nil {
			t.Skip()
		}
		// Bypass the in-memory cache so each input is re-read from disk.
		configMu.Lock()
		delete(configs, "fuzzinst")
		configMu.Unlock()

		cfg, err := Load("fuzzinst") // must not panic
		// Parse (qpot serve's re-read of the file) reads it as Load does,
		// without touching Load's cache
		configMu.RLock()
		cached := configs["fuzzinst"]
		configMu.RUnlock()
		parsed, perr := Parse([]byte(yamlBody), cfgPath)
		configMu.RLock()
		after := configs["fuzzinst"]
		configMu.RUnlock()
		if after != cached {
			t.Error("Parse changed Load's cache")
		}
		if (err == nil) != (perr == nil) {
			t.Fatalf("Load error %v, Parse error %v", err, perr)
		}
		if err != nil {
			return // malformed YAML correctly rejected
		}
		if parsed.DataPath != cfg.DataPath || parsed.ConfigPath != cfg.ConfigPath ||
			parsed.InstanceName != cfg.InstanceName || parsed.Intelligence != cfg.Intelligence ||
			parsed.Security.ResourceLimits != cfg.Security.ResourceLimits ||
			parsed.Security.SandboxMode != cfg.Security.SandboxMode {
			t.Errorf("Parse and Load differ: %+v / %+v", parsed, cfg)
		}
		// A successfully-loaded config must have safe intelligence tunables.
		if cfg.Intelligence.WorkerInterval <= 0 {
			t.Errorf("WorkerInterval not clamped: %v", cfg.Intelligence.WorkerInterval)
		}
		if cfg.Intelligence.WorkerBatchSize <= 0 {
			t.Errorf("WorkerBatchSize not clamped: %d", cfg.Intelligence.WorkerBatchSize)
		}
	})
}
