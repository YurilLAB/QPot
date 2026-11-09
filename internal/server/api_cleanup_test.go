package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/cleanup"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/vectorstate"
)

func cleanupTestServer(t *testing.T) *apiTestServer {
	t.Helper()
	a := newAPITestServer(t, "cleanup-api", nil)
	a.s.api.cleanup.collector = func(context.Context) bool { return true }
	return a
}

// oldCapture writes a cowrie download last changed 40 days ago.
func oldCapture(t *testing.T, a *apiTestServer) string {
	t.Helper()
	p := filepath.Join(a.cfg.DataPath, "honeypots", "cowrie", "dl", "old-sample")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("MZ sample"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-40 * 24 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	return p
}

func getCleanup(t *testing.T, a *apiTestServer) cleanupView {
	t.Helper()
	rec := a.do(http.MethodGet, "/api/cleanup", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/cleanup: %d %s", rec.Code, rec.Body.String())
	}
	var v cleanupView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCleanupSettingsAreSavedAndShown(t *testing.T) {
	a := cleanupTestServer(t)
	v := getCleanup(t, a)
	if !v.Settings.Enabled || v.Settings.MaxAgeDays != 30 || v.Settings.MaxLogMB != 256 || v.Settings.MaxBackupMB != 2048 || v.HoneypotLimitGB != 10 {
		t.Fatalf("defaults: %+v", v)
	}

	rec := a.do(http.MethodPut, "/api/cleanup", `{"enabled":false,"max_age_days":7,"max_backup_mb":512}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	// Saved to the file, and read back from it.
	saved, err := config.Parse(a.configFile(t), a.cfg.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if c := saved.Cleanup; c.On() || c.MaxAgeDays != 7 || c.MaxBackupMB != 512 || c.MaxLogMB != 256 {
		t.Fatalf("config file: %+v", c)
	}
	if v := getCleanup(t, a); v.Settings.Enabled || v.Settings.MaxAgeDays != 7 || v.Settings.MaxBackupMB != 512 || v.NextRun != nil {
		t.Fatalf("after PUT: %+v", v)
	}

	// Negative controls: refused values change nothing.
	before := string(a.configFile(t))
	for _, body := range []string{`{}`, `{"max_age_days":0}`, `{"max_age_days":4000}`, `{"max_log_mb":-1}`,
		`{"max_backup_mb":99999999999}`, `{"max_age_days":"7"}`, `{"nosuch":1}`} {
		rec := a.do(http.MethodPut, "/api/cleanup", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("PUT %s: %d, want 400", body, rec.Code)
		}
	}
	if string(a.configFile(t)) != before {
		t.Error("a refused change was saved")
	}
}

func TestCleanupRunNowAndDryRun(t *testing.T) {
	a := cleanupTestServer(t)
	sample := oldCapture(t, a)

	rec := a.do(http.MethodPost, "/api/cleanup/run?dry_run=1", `{}`)
	var rep cleanup.Report
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rep) != nil || !rep.DryRun || rep.Removed != 1 {
		t.Fatalf("dry run: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(sample); err != nil {
		t.Fatal("the dry run removed the sample")
	}
	if getCleanup(t, a).Last != nil {
		t.Error("a dry run was kept as the last run")
	}

	rec = a.do(http.MethodPost, "/api/cleanup/run", `{}`)
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rep) != nil || rep.DryRun || rep.Removed != 1 || !rep.Collector {
		t.Fatalf("run: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(sample); err == nil {
		t.Fatal("the run kept the sample")
	}
	if last := getCleanup(t, a).Last; last == nil || last.Removed != 1 {
		t.Errorf("last run %+v", last)
	}
	if rec := a.do(http.MethodPost, "/api/cleanup/run?dry_run=maybe", `{}`); rec.Code != http.StatusBadRequest {
		t.Errorf("dry_run=maybe: %d", rec.Code)
	}
	if rec := a.do(http.MethodGet, "/api/cleanup/run", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/cleanup/run: %d", rec.Code)
	}
}

// With cleanup off, the scheduled run does nothing; a manual one still runs.
func TestScheduledCleanupHonoursOff(t *testing.T) {
	a := cleanupTestServer(t)
	sample := oldCapture(t, a)
	if rec := a.do(http.MethodPut, "/api/cleanup", `{"enabled":false}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	rep, err := a.s.runCleanup(context.Background(), false, false)
	if err != nil || rep != nil {
		t.Fatalf("scheduled run while off: %v %v", rep, err)
	}
	if _, err := os.Stat(sample); err != nil {
		t.Fatal("the scheduled run removed a file while off")
	}
	// Control: on again, the scheduled run removes it.
	if rec := a.do(http.MethodPut, "/api/cleanup", `{"enabled":true}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	rep, err = a.s.runCleanup(context.Background(), false, false)
	if err != nil || rep == nil || rep.Removed != 1 {
		t.Fatalf("scheduled run while on: %+v %v", rep, err)
	}
}

// writeCheckpoint records, as the collector does, that it has delivered the
// cowrie log whose first line is "{}" up to pos. 2294659357232844156 is the
// collector's fingerprint of that line (CRC-64/ECMA-182 of "{}\n").
func writeCheckpoint(t *testing.T, a *apiTestServer, pos int64) {
	t.Helper()
	dir := filepath.Join(a.cfg.DataPath, vectorstate.Dir, vectorstate.HoneypotSource("cowrie"))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	doc := fmt.Sprintf(`{"version":"1","checkpoints":[{"fingerprint":{"first_lines_checksum":2294659357232844156},"position":%d,"modified":"2026-11-09T00:00:00Z"}]}`, pos)
	if err := os.WriteFile(filepath.Join(dir, "checkpoints.json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The collector's state decides whether logs are emptied: it must run, and
// have delivered the whole log.
func TestCleanupEmptiesLogsOnlyWithTheCollectorUp(t *testing.T) {
	a := cleanupTestServer(t)
	log := filepath.Join(a.cfg.DataPath, "honeypots", "cowrie", "logs", "cowrie.json")
	if err := os.MkdirAll(filepath.Dir(log), 0o755); err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat("{}\n", 500<<10)
	if err := os.WriteFile(log, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if rec := a.do(http.MethodPut, "/api/cleanup", `{"max_log_mb":1}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	writeCheckpoint(t, a, int64(len(content)))
	a.s.api.cleanup.collector = func(context.Context) bool { return false }
	if rep, _ := a.s.runCleanup(context.Background(), true, false); rep.Emptied != 0 || len(rep.Notes) == 0 {
		t.Fatalf("collector down: %+v", rep)
	}
	a.s.api.cleanup.collector = func(context.Context) bool { return true }
	writeCheckpoint(t, a, int64(len(content))-3)
	if rep, _ := a.s.runCleanup(context.Background(), true, false); rep.Emptied != 0 || len(rep.Notes) == 0 {
		t.Fatalf("collector up, last line not delivered: %+v", rep)
	}
	writeCheckpoint(t, a, int64(len(content)))
	if rep, _ := a.s.runCleanup(context.Background(), true, false); rep.Emptied != 1 {
		t.Fatalf("collector up: %+v", rep)
	}
	if fi, _ := os.Stat(log); fi.Size() != 0 {
		t.Errorf("log still %d bytes", fi.Size())
	}
}
