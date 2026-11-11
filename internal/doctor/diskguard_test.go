package doctor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/diskguard"
	"github.com/qpot/qpot/internal/hostsetup"
	"github.com/qpot/qpot/internal/instance"
)

const doctorMB = int64(1) << 20

func guardCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default("doctor-guard")
	cfg.DataPath = t.TempDir()
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	return cfg
}

func freeOf(mb int64, known bool, asked *string) func(string) (int64, bool) {
	return func(path string) (int64, bool) {
		if asked != nil {
			*asked = path
		}
		return mb * doctorMB, known
	}
}

func holdStopped(t *testing.T, cfg *config.Config, names ...string) {
	t.Helper()
	var st diskguard.State
	for _, n := range names {
		st.Add(n, time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC))
	}
	if err := diskguard.SaveState(diskguard.Path(cfg.DataPath), st); err != nil {
		t.Fatal(err)
	}
}

// TestDiskGuardCheck: the doctor's line says how much is free against the
// floor, which honeypots the guard keeps stopped, and carries QP-RES-008
// whenever it is not "ok".
func TestDiskGuardCheck(t *testing.T) {
	t.Run("room", func(t *testing.T) {
		cfg := guardCfg(t)
		var asked string
		c := DiskGuardCheck(cfg, freeOf(40000, true, &asked))
		if c.Name != "disk guard" || c.Level != "ok" || c.Code != "" ||
			!strings.Contains(c.Detail, "40000 MB free") || !strings.Contains(c.Detail, "below 512 MB") {
			t.Fatalf("%+v", c)
		}
		if want := filepath.Join(cfg.DataPath, "honeypots"); asked != want {
			t.Errorf("free space read of %s, want %s", asked, want)
		}
	})
	t.Run("below the floor", func(t *testing.T) {
		cfg := guardCfg(t)
		c := DiskGuardCheck(cfg, freeOf(100, true, nil))
		if c.Level != "fail" || c.Code != "QP-RES-008" || !strings.Contains(c.Detail, "100 MB free") || !strings.Contains(c.Detail, "512 MB floor") {
			t.Fatalf("%+v", c)
		}
		if strings.Contains(c.Detail, "stopped by the guard") {
			t.Errorf("names stopped honeypots without a state file: %q", c.Detail)
		}
		holdStopped(t, cfg, "dionaea", "cowrie")
		c = DiskGuardCheck(cfg, freeOf(0, true, nil))
		if c.Level != "fail" || c.Code != "QP-RES-008" || !strings.Contains(c.Detail, "0 MB free") || !strings.Contains(c.Detail, "stopped by the guard: cowrie, dionaea") {
			t.Fatalf("%+v", c)
		}
		// The failure a run of checks ends with is the guard's own code.
		if e := Failure([]Check{c}); e == nil || e.Code != "QP-RES-008" || hostsetup.ExitStatus(e.Code) != 18 {
			t.Fatalf("Failure: %+v", e)
		}
	})
	t.Run("waiting for the resume mark", func(t *testing.T) {
		cfg := guardCfg(t)
		holdStopped(t, cfg, "cowrie")
		c := DiskGuardCheck(cfg, freeOf(700, true, nil))
		if c.Level != "warn" || c.Code != "QP-RES-008" || !strings.Contains(c.Detail, "cowrie stay stopped until 1024 MB are free") {
			t.Fatalf("%+v", c)
		}
		// Above the resume mark with the state file still there (qpot serve
		// has not looked yet, or does not run): still a warning.
		c = DiskGuardCheck(cfg, freeOf(9000, true, nil))
		if c.Level != "warn" || c.Code != "QP-RES-008" || !strings.Contains(c.Detail, "still stopped by the guard: cowrie") || strings.Contains(c.Detail, "until") {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("own marks", func(t *testing.T) {
		cfg := guardCfg(t)
		floor := int64(4096)
		cfg.Cleanup.MinFreeMB, cfg.Cleanup.ResumeFreeMB = &floor, 0
		c := DiskGuardCheck(cfg, freeOf(4000, true, nil))
		if c.Level != "fail" || !strings.Contains(c.Detail, "4096 MB floor") {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("off", func(t *testing.T) {
		cfg := guardCfg(t)
		zero := int64(0)
		cfg.Cleanup.MinFreeMB = &zero
		called := false
		c := DiskGuardCheck(cfg, func(string) (int64, bool) { called = true; return 0, true })
		if c.Level != "ok" || c.Code != "" || !strings.Contains(c.Detail, "off") {
			t.Fatalf("%+v", c)
		}
		if called {
			t.Error("a guard that is off read the disk")
		}
		holdStopped(t, cfg, "cowrie")
		c = DiskGuardCheck(cfg, freeOf(0, true, nil))
		if c.Level != "warn" || c.Code != "QP-RES-008" || !strings.Contains(c.Detail, "still stopped by it: cowrie") {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		cfg := guardCfg(t)
		c := DiskGuardCheck(cfg, freeOf(0, false, nil))
		if c.Level != "warn" || c.Code != "QP-RES-008" || !strings.Contains(c.Detail, "cannot be read") {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("damaged state file", func(t *testing.T) {
		cfg := guardCfg(t)
		if err := os.WriteFile(diskguard.Path(cfg.DataPath), []byte(`{"version":1,"stopped":[{"name":"--volumes"`), 0o600); err != nil {
			t.Fatal(err)
		}
		c := DiskGuardCheck(cfg, freeOf(40000, true, nil))
		if c.Level != "warn" || c.Code != "QP-RES-008" || !strings.Contains(c.Detail, "damaged") || strings.Contains(c.Detail, "volumes") {
			t.Fatalf("%+v", c)
		}
	})
	// Every level it can report has a code the catalog knows.
	if _, ok := hostsetup.Lookup("QP-RES-008"); !ok {
		t.Fatal("QP-RES-008 is not in the catalog")
	}
}

// guardStates answers ServiceStates for the health checks.
type guardStates map[string]instance.ServiceState

func (g guardStates) ServiceStates(context.Context) (map[string]instance.ServiceState, error) {
	return g, nil
}

// TestHealthChecksNameTheDiskGuard: a honeypot the guard stopped is reported
// as stopped by the guard with QP-RES-008, not as an unexplained "exited";
// one the operator stopped keeps its own line.
func TestHealthChecksNameTheDiskGuard(t *testing.T) {
	orig := dataFreeBytes
	defer func() { dataFreeBytes = orig }()
	dataFreeBytes = freeOf(100, true, nil)

	cfg := guardCfg(t)
	cfg.Honeypots = map[string]config.HoneypotConfig{"cowrie": {Enabled: true}, "dionaea": {Enabled: true}, "endlessh": {Enabled: true}}
	cfg.WebUI.Enabled = false
	holdStopped(t, cfg, "cowrie", "endlessh")
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // keeps the database check offline and short
	checks := HealthChecks(ctx, cfg, guardStates{
		"database": {State: "running"}, "collector": {State: "running"},
		"cowrie":   {State: "exited"},  // stopped by the guard
		"dionaea":  {State: "exited"},  // stopped by the operator
		"endlessh": {State: "running"}, // listed, and running again
	}, nil)
	by := map[string]Check{}
	for i, c := range checks {
		by[c.Name] = c
		if c.Name == "disk guard" && i > 1 {
			t.Errorf("the disk guard line is number %d; it explains the lines below it and comes first", i+1)
		}
	}
	if c := by["disk guard"]; c.Level != "fail" || c.Code != "QP-RES-008" || !strings.Contains(c.Detail, "cowrie, endlessh") {
		t.Fatalf("disk guard: %+v", c)
	}
	if c := by["honeypot cowrie"]; c.Level != "fail" || c.Code != "QP-RES-008" || !strings.Contains(c.Detail, "stopped by the disk guard") {
		t.Fatalf("cowrie: %+v", c)
	}
	if c := by["honeypot dionaea"]; c.Level != "fail" || c.Code != "QP-INST-008" || c.Detail != "exited" {
		t.Fatalf("dionaea: %+v", c)
	}
	if c := by["honeypot endlessh"]; c.Code == "QP-RES-008" {
		t.Fatalf("endlessh runs and is blamed on the guard: %+v", c)
	}
	if e := Failure(checks); e == nil || e.Code != "QP-RES-008" {
		t.Fatalf("the report's failure is %+v, want QP-RES-008 first", e)
	}

	// With room and nothing held, the line is ok and no honeypot is blamed.
	dataFreeBytes = freeOf(40000, true, nil)
	if err := diskguard.SaveState(diskguard.Path(cfg.DataPath), diskguard.State{}); err != nil {
		t.Fatal(err)
	}
	for _, c := range HealthChecks(ctx, cfg, guardStates{"database": {State: "running"}, "collector": {State: "running"},
		"cowrie": {State: "exited"}, "dionaea": {State: "running"}, "endlessh": {State: "running"}}, nil) {
		if c.Name == "disk guard" && c.Level != "ok" {
			t.Fatalf("disk guard with room: %+v", c)
		}
		if c.Name == "honeypot cowrie" && c.Code != "QP-INST-008" {
			t.Fatalf("cowrie without the guard: %+v", c)
		}
	}
}
