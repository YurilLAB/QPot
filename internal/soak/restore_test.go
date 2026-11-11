//go:build unix

package soak

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/instance"
)

// The restore rehearsal: on an instance that holds events (one a soak left in
// place with QPOT_SOAK_KEEP=1), the database is taken away, an empty one is
// started, and `qpot db restore` fills it from the collector's log backups.
// Afterwards the database must hold the same events as before, each once,
// and the worker must have rebuilt the same indicators. Two differences are
// allowed and counted. A backup line that was being written when the disk
// filled is unreadable, and its event is missing unless the collector read
// the log line again later. And an event's time is the moment the collector
// read its line: when a line was read more than once, the restore keeps the
// first reading in the backups, and the database may have kept another (a
// reading that reached the backup just before the collector was killed never
// reached the database).
//
// QPOT_SOAK=1 QPOT_SOAK_RESTORE=1 QPOT_SOAK_INSTANCE=<the kept instance>.

// storedEvent is what must be the same before and after for one event: a
// hash over every column the collector fills, and its time.
type storedEvent struct {
	content uint64
	millis  int64
}

// eventsSnapshot is every event the collector stored, by its ID.
type eventsSnapshot struct {
	Rows   uint64
	Events map[string]storedEvent
}

func (h *harness) snapshot(ctx context.Context) (eventsSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	snap := eventsSnapshot{Events: map[string]storedEvent{}}
	// Canary trips are written by the control plane, not the collector, and
	// are not in the log backups.
	rows, err := h.db.Query(ctx, `SELECT toString(event_id), toUnixTimestamp64Milli(timestamp),
		sipHash64(honeypot, source_ip, toString(source_port), toString(dest_port), protocol, event_type, username,
			password, command, payload, country, city, asn, arraySort(mapKeys(metadata)),
			arrayMap(k -> metadata[k], arraySort(mapKeys(metadata))))
		FROM events WHERE honeypot != 'canary'`)
	if err != nil {
		return snap, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var e storedEvent
		if err := rows.Scan(&id, &e.millis, &e.content); err != nil {
			return snap, err
		}
		snap.Rows++
		snap.Events[id] = e
	}
	return snap, rows.Err()
}

// eventsDiff is how a snapshot differs from an earlier one.
type eventsDiff struct {
	Missing, Extra, Changed, Retimed int
	// MaxShift is the largest difference in time among the retimed events.
	MaxShift time.Duration
	Examples []string
}

func (d eventsDiff) none() bool { return d.Missing+d.Extra+d.Changed+d.Retimed == 0 }

func (s eventsSnapshot) diff(before eventsSnapshot) eventsDiff {
	var d eventsDiff
	note := func(what, id string) {
		if len(d.Examples) < 8 {
			d.Examples = append(d.Examples, what+" "+id)
		}
	}
	for id, was := range before.Events {
		now, ok := s.Events[id]
		switch {
		case !ok:
			d.Missing++
			note("missing", id)
		case now.content != was.content:
			d.Changed++
			note("changed", id)
		case now.millis != was.millis:
			d.Retimed++
			shift := time.Duration(now.millis-was.millis) * time.Millisecond
			if shift < 0 {
				shift = -shift
			}
			d.MaxShift = max(d.MaxShift, shift)
			note("other time", id)
		}
	}
	for id := range s.Events {
		if _, ok := before.Events[id]; !ok {
			d.Extra++
			note("extra", id)
		}
	}
	return d
}

// indicatorTotals returns the number of indicator rows and the sum of their
// sighting counts.
func (h *harness) indicatorTotals(ctx context.Context) (rows, sightings uint64, err error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	err = h.db.QueryRow(ctx, `SELECT count(), toUInt64(sum(count)) FROM intelligence_iocs FINAL`).Scan(&rows, &sightings)
	return rows, sightings, err
}

// classified waits until no event is left unclassified, for at most limit.
func (h *harness) classified(ctx context.Context, limit time.Duration) (time.Duration, bool) {
	start := time.Now()
	for time.Since(start) < limit {
		var n uint64
		qctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := h.db.QueryRow(qctx, `SELECT count() FROM events WHERE classified = 0 AND honeypot != 'canary'`).Scan(&n)
		cancel()
		if err == nil && n == 0 {
			return time.Since(start), true
		}
		select {
		case <-ctx.Done():
			return time.Since(start), false
		case <-time.After(5 * time.Second):
		}
	}
	return time.Since(start), false
}

func TestRestoreRehearsal(t *testing.T) {
	opt := loadOptions(t)
	if os.Getenv("QPOT_SOAK_RESTORE") != "1" {
		t.Skip("set QPOT_SOAK_RESTORE=1 (with QPOT_SOAK=1) and name an instance a soak left in place; see doc/reliability.md")
	}
	h := &harness{t: t, opt: opt, tag: "restore", childEnv: os.Environ()}
	ctx := t.Context()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	h.dir = filepath.Join(home, ".qpot", "instances", opt.instance)
	cfgPath := filepath.Join(h.dir, "config.yaml")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("the instance to rehearse on: %v", err)
	}
	if h.cfg, err = config.Parse(raw, cfgPath); err != nil {
		t.Fatal(err)
	}
	id, err := os.ReadFile(filepath.Join(h.dir, "qpot.id"))
	if err != nil {
		t.Fatal(err)
	}
	h.qid = strings.TrimSpace(string(id))
	h.cfg.QPotID = h.qid
	up := func() {
		t.Helper()
		if out, err := h.qpot(ctx, 15*time.Minute, "up", "-d", "-i", opt.instance); err != nil {
			t.Fatalf("qpot up: %v\n%s", err, tail(out, 12))
		}
	}
	restore := func(args ...string) database.RestoreReport {
		t.Helper()
		out, err := h.qpot(ctx, 30*time.Minute, append([]string{"db", "restore", "-i", opt.instance, "--json"}, args...)...)
		var rep database.RestoreReport
		// The report is the first JSON object; log lines may surround it.
		start := strings.Index(out, "{")
		if err != nil || start < 0 || json.NewDecoder(strings.NewReader(out[start:])).Decode(&rep) != nil {
			t.Fatalf("qpot db restore %v: %v\n%s", args, err, tail(out, 12))
		}
		return rep
	}
	wait := func(what string, limit time.Duration, ok func() bool) {
		t.Helper()
		for start := time.Now(); !ok(); time.Sleep(3 * time.Second) {
			if time.Since(start) > limit {
				t.Fatalf("%s: not within %s", what, limit)
			}
		}
	}

	up()
	if err := h.connectDB(ctx); err != nil {
		t.Fatal(err)
	}
	if d, ok := h.classified(ctx, 20*time.Minute); !ok {
		t.Fatalf("the worker has not classified everything after %s: nothing to compare with", d.Round(time.Second))
	}
	before, err := h.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	iocRows, iocSightings, err := h.indicatorTotals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.Rows == 0 {
		t.Fatal("the instance holds no events: run a soak on it first")
	}
	if before.Rows != uint64(len(before.Events)) {
		t.Fatalf("before the rehearsal %d rows hold %d different events: the database is not clean to start with", before.Rows, len(before.Events))
	}
	h.logf("before: %d events, %d indicators seen %d times", before.Rows, iocRows, iocSightings)

	// The backups must hold everything the database holds: a dry run finds
	// nothing missing and as many lines as there are events.
	dry := restore("--dry-run", "--merge")
	h.logf("dry run on the full database: %d lines in %d files, %d missing, %d unreadable", dry.Lines, dry.Files, dry.Stored, dry.Unreadable)
	if dry.Stored != 0 {
		t.Errorf("the log backups hold %d events the database does not", dry.Stored)
	}

	// Take the database away.
	if out, err := h.qpot(ctx, 10*time.Minute, "down", "-i", opt.instance); err != nil {
		t.Fatalf("qpot down: %v\n%s", err, tail(out, 8))
	}
	if out, err := docker(ctx, 2*time.Minute, "run", "--rm", "--network", "none", "--user", "0:0", "--entrypoint", "/bin/sh",
		"-v", h.dir+":/i", instance.CollectorImage, "-c", "rm -rf /i/db.damaged && mv /i/db /i/db.damaged"); err != nil {
		t.Fatalf("move the database away: %v %s", err, out)
	}
	if !opt.keep {
		t.Cleanup(func() {
			_, _ = docker(context.Background(), 5*time.Minute, "run", "--rm", "--network", "none", "--user", "0:0", "--entrypoint", "/bin/sh",
				"-v", h.dir+":/i", instance.CollectorImage, "-c", "rm -rf /i/db.damaged")
		})
	}
	lost := time.Now()
	up()
	h.db.Close()
	if err := h.connectDB(ctx); err != nil {
		t.Fatal(err)
	}
	var empty eventsSnapshot
	wait("the new database answers", 5*time.Minute, func() bool {
		empty, err = h.snapshot(ctx)
		return err == nil
	})
	if empty.Rows != 0 {
		t.Fatalf("the new database already holds %d events before the restore", empty.Rows)
	}

	started := time.Now()
	rep := restore()
	took := time.Since(started)
	h.logf("restore: %d events stored from %d files in %s (%d already there, %d unreadable lines)", rep.Stored, rep.Files, took.Round(time.Second), rep.AlreadyStored, rep.Unreadable)

	after, err := h.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	diff := after.diff(before)
	if after.Rows != uint64(len(after.Events)) {
		t.Errorf("after the restore %d rows hold %d different events", after.Rows, len(after.Events))
	}
	// Each unreadable backup line can cost one event. Nothing else may be
	// missing, and no event may differ in anything but its reading time.
	if diff.Extra != 0 || diff.Changed != 0 || int64(diff.Missing) > rep.Unreadable {
		t.Errorf("events after the restore differ from before: %d missing, %d with another reading's time, %d changed, %d extra, with %d unreadable backup lines: %v",
			diff.Missing, diff.Retimed, diff.Changed, diff.Extra, rep.Unreadable, diff.Examples)
	} else if !diff.none() {
		h.logf("%d unreadable backup lines; %d events missing; %d events restored with another reading's time (largest difference %s)",
			rep.Unreadable, diff.Missing, diff.Retimed, diff.MaxShift.Round(time.Second))
	}
	// Again: nothing more to store, nothing stored twice.
	if again := restore("--merge"); again.Stored != 0 {
		t.Errorf("a second restore stored %d more events", again.Stored)
	}
	if twice, err := h.snapshot(ctx); err != nil || !twice.diff(after).none() || twice.Rows != after.Rows {
		t.Errorf("a second restore changed the events: %+v (%v)", twice.diff(after), err)
	}

	// The worker classifies the restored events and rebuilds the indicators.
	d, ok := h.classified(ctx, 30*time.Minute)
	if !ok {
		t.Fatalf("restored events are not all classified after %s", d.Round(time.Second))
	}
	time.Sleep(10 * time.Second)
	rows, sightings, err := h.indicatorTotals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h.logf("after: %d events, %d indicators seen %d times; classified again in %s", after.Rows, rows, sightings, d.Round(time.Second))
	if rows != iocRows || sightings != iocSightings {
		t.Errorf("indicators after the restore: %d rows seen %d times, before: %d rows seen %d times", rows, sightings, iocRows, iocSightings)
	}
	if final, err := h.snapshot(ctx); err != nil || !final.diff(after).none() || final.Rows != after.Rows {
		t.Errorf("classification changed the restored events: %+v (%v)", final.diff(after), err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Database restore rehearsal on %s\n\n", opt.instance)
	fmt.Fprintf(&b, "| | Before | After the restore |\n|---|---|---|\n| events | %d | %d |\n| different events | %d | %d |\n| indicators | %d | %d |\n| indicator sightings | %d | %d |\n\n",
		before.Rows, after.Rows, len(before.Events), len(after.Events), iocRows, rows, iocSightings, sightings)
	fmt.Fprintf(&b, "Events missing after the restore %d, restored with another reading's time %d (largest difference %s), changed %d, extra %d.\n\n",
		diff.Missing, diff.Retimed, diff.MaxShift.Round(time.Second), diff.Changed, diff.Extra)
	fmt.Fprintf(&b, "Backup files %d, lines %d, unreadable %d. Restore took %s; classification %s. Database gone at %s.\n",
		rep.Files, rep.Lines, rep.Unreadable, took.Round(time.Second), d.Round(time.Second), lost.Format("15:04:05"))
	_ = os.MkdirAll(opt.reportDir, 0o755)
	_ = os.WriteFile(filepath.Join(opt.reportDir, "restore-"+opt.instance+".md"), []byte(b.String()), 0o644)
	t.Log("\n" + b.String())
}
