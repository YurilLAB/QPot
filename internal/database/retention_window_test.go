package database

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// recordingRetentionDB records the export window and delete cutoff.
type recordingRetentionDB struct {
	stubRetentionDB
	exportErr              error
	exportStart, exportEnd time.Time
	cleanupCalled          bool
	cleanupCutoff          time.Time
}

func (r *recordingRetentionDB) ExportData(ctx context.Context, s, e time.Time, w io.Writer) error {
	r.exportStart, r.exportEnd = s, e
	return r.exportErr
}

func (r *recordingRetentionDB) RetentionCleanup(ctx context.Context, t time.Time) error {
	r.cleanupCalled, r.cleanupCutoff = true, t
	return nil
}

func archivingPolicy(t *testing.T) *RetentionPolicy {
	p := DefaultRetentionPolicy()
	p.ArchiveConfig = &ArchiveConfig{Type: "filesystem", Filesystem: &FilesystemConfig{Path: t.TempDir()}}
	return p
}

// Everything that gets deleted must first have been archived.
func TestRetentionArchivesWhatItDeletes(t *testing.T) {
	db := &recordingRetentionDB{}
	rm := NewRetentionManager(db, t.TempDir())
	p := archivingPolicy(t)
	if err := rm.RegisterPolicy(p); err != nil {
		t.Fatal(err)
	}
	if _, err := rm.ExecutePolicy(context.Background(), p.ID); err != nil {
		t.Fatal(err)
	}
	if !db.cleanupCalled {
		t.Fatal("expired data was not deleted")
	}
	if db.exportEnd.Before(db.cleanupCutoff.Add(-time.Second)) {
		t.Fatalf("archive ends at %v but deletion removes everything before %v: the gap is lost",
			db.exportEnd, db.cleanupCutoff)
	}
}

func TestRetentionSkipsDeleteWhenArchiveFails(t *testing.T) {
	db := &recordingRetentionDB{exportErr: errors.New("disk full")}
	rm := NewRetentionManager(db, t.TempDir())
	p := archivingPolicy(t)
	if err := rm.RegisterPolicy(p); err != nil {
		t.Fatal(err)
	}
	res, err := rm.ExecutePolicy(context.Background(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if db.cleanupCalled {
		t.Fatal("data was deleted even though archiving it failed")
	}
	if len(res.Errors) == 0 {
		t.Fatal("archive failure not reported")
	}
}

// A policy scoped to some honeypots must not delete every honeypot's data.
func TestRetentionRefusesHoneypotScopedPolicy(t *testing.T) {
	db := &recordingRetentionDB{}
	rm := NewRetentionManager(db, t.TempDir())
	p := DefaultRetentionPolicy()
	p.Honeypots = []string{"cowrie"}
	if err := rm.RegisterPolicy(p); err != nil {
		t.Fatal(err)
	}
	if _, err := rm.ExecutePolicy(context.Background(), p.ID); err == nil {
		t.Fatal("honeypot-scoped policy executed")
	}
	if db.cleanupCalled {
		t.Fatal("honeypot-scoped policy deleted all honeypots' data")
	}
}
