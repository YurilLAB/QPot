package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
)

// restoreStore stands in for the database behind `qpot db restore`.
type restoreStore struct {
	rows map[string]bool
}

func (s *restoreStore) Close() error                               { return nil }
func (s *restoreStore) CountEvents(context.Context) (int64, error) { return int64(len(s.rows)), nil }
func (s *restoreStore) RestoreEvents(_ context.Context, events []*database.Event, dryRun bool) (int, error) {
	n := 0
	seen := map[string]bool{}
	for _, e := range events {
		if s.rows[e.ID] || seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		n++
		if !dryRun {
			s.rows[e.ID] = true
		}
	}
	return n, nil
}

func TestDBRestoreCommand(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cfg := config.Default("restore-cmd")
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	day := filepath.Join(cfg.DataPath, "backup", "logs", "2026", "11", "10")
	if err := os.MkdirAll(day, 0o755); err != nil {
		t.Fatal(err)
	}
	lines := []string{
		`{"timestamp":"2026-11-10 12:00:00.000","honeypot":"cowrie","source_ip":"203.0.113.9","command":"id","event_id":"0a0a0a0a-0000-8000-8000-000000000001"}`,
		`{"timestamp":"2026-11-10 12:00:01.000","honeypot":"cowrie","source_ip":"203.0.113.9","command":"uname","event_id":"0a0a0a0a-0000-8000-8000-000000000002"}`,
		`{damaged`,
	}
	if err := os.WriteFile(filepath.Join(day, "cowrie.log"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	store := &restoreStore{rows: map[string]bool{}}
	real := openRestoreTarget
	openRestoreTarget = func(context.Context, *config.Config) (restoreTarget, error) { return store, nil }
	t.Cleanup(func() { openRestoreTarget = real })
	run := func(args ...string) (string, error) {
		t.Helper()
		root := &cobra.Command{Use: "qpot", SilenceUsage: true, SilenceErrors: true, PersistentPreRunE: checkInstanceFlag}
		root.AddCommand(newDBCommand())
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs(append([]string{"db", "restore", "-i", "restore-cmd"}, args...))
		err := root.Execute()
		return out.String(), err
	}

	out, err := run("--dry-run")
	if err != nil || !strings.Contains(out, "Would store 2 events from 1 files (3 lines; 0 already in the database; 1 unreadable)") || len(store.rows) != 0 {
		t.Fatalf("dry run: %v, stored %d\n%s", err, len(store.rows), out)
	}
	out, err = run()
	if err != nil || !strings.Contains(out, "Stored 2 events") || !strings.Contains(out, "2026/11/10 to 2026/11/10") || len(store.rows) != 2 {
		t.Fatalf("restore: %v, stored %d\n%s", err, len(store.rows), out)
	}
	// A database that holds events is not restored into by accident.
	out, err = run()
	if err == nil || !strings.Contains(err.Error(), "already holds 2 events") || !strings.Contains(err.Error(), "--merge") {
		t.Fatalf("restore into a database with events: %v\n%s", err, out)
	}
	out, err = run("--merge", "--json")
	if err != nil {
		t.Fatalf("merge: %v\n%s", err, out)
	}
	var rep database.RestoreReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep.Stored != 0 || rep.AlreadyStored != 2 || rep.Unreadable != 1 {
		t.Fatalf("merge report %+v (%v)\n%s", rep, err, out)
	}
	if _, err := run("--from", filepath.Join(home, "nowhere"), "--merge"); err == nil || !strings.Contains(err.Error(), "no log backups") {
		t.Fatalf("a missing backup folder: %v", err)
	}
}
