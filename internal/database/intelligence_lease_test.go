package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// The in-memory adapter tests the shared capability/WAL boundary, not the
// native SQL/Keeper/Painless atomicity covered by separate integration tests.
type memoryIntelligenceLeaseBackend struct {
	mu          sync.Mutex
	state       *intelligenceLeaseState
	now         time.Time
	checkpoints map[string][]byte
}

func (m *memoryIntelligenceLeaseBackend) intelligenceLeaseRead(context.Context) (*intelligenceLeaseState, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == nil {
		return nil, m.now, nil
	}
	s := *m.state
	return &s, m.now, nil
}
func (m *memoryIntelligenceLeaseBackend) intelligenceLeaseMutate(_ context.Context, op intelligenceLeaseOperation) (intelligenceLeaseState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := applyIntelligenceLeaseOperation(m.state, op, m.now)
	if err == nil {
		m.state = &s
	}
	return s, err
}
func (m *memoryIntelligenceLeaseBackend) intelligenceLeaseStoreCheckpoint(_ context.Context, cp *IntelligenceCheckpoint, digest string) error {
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkpoints[fmt.Sprintf("%d/%s", cp.Revision, digest)] = data
	return nil
}
func (m *memoryIntelligenceLeaseBackend) intelligenceLeaseLoadCheckpoint(_ context.Context, revision uint64, digest string) (*IntelligenceCheckpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data := m.checkpoints[fmt.Sprintf("%d/%s", revision, digest)]
	if len(data) == 0 {
		return nil, errors.New("missing fixture checkpoint")
	}
	var cp IntelligenceCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, err
	}
	return &cp, nil
}

func TestIntelligenceLeaseRequiresIssuedCapabilityAndPreparedSnapshot(t *testing.T) {
	ctx := t.Context()
	b := &memoryIntelligenceLeaseBackend{now: time.Now().UTC(), checkpoints: map[string][]byte{}}
	lease, err := acquireIntelligenceLease(ctx, b, "owner-one-0123456789", 30*time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireIntelligenceLease(ctx, b, "owner-two-0123456789", 30*time.Second, 0); !errors.Is(err, ErrIntelligenceLeaseBusy) {
		t.Fatalf("second owner admitted: %v", err)
	}
	forged := lease
	forged.Fence++
	if _, err := reserveIntelligenceRevision(ctx, b, forged, 0); !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("forged capability admitted: %v", err)
	}
	revision, err := reserveIntelligenceRevision(ctx, b, lease, 0)
	if err != nil {
		t.Fatal(err)
	}
	leased := WithIntelligenceLease(ctx, lease)
	ioc := &IOC{ID: "one", Type: "ip", Value: "203.0.113.8", Honeypot: "cowrie", Count: 3}
	event := &Event{ID: "stored-row", Timestamp: b.now, Honeypot: "cowrie", Classified: true}
	cp := &IntelligenceCheckpoint{Revision: revision, IOCs: []*IOC{ioc}, Events: []*Event{event}, Sessions: []*TTPSession{}}
	if _, err := intelligenceLeaseIOCs(leased, b, revision, cp.IOCs); !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("projection without prepared WAL admitted: %v", err)
	}
	if handled, err := intelligenceLeaseSave(leased, b, cp); !handled || err != nil {
		t.Fatalf("prepared save failed: %v", err)
	}
	if handled, err := intelligenceLeaseSave(ctx, b, cp); !handled || !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("unleased write admitted after activation: %v", err)
	}
	ioc.Count = 19
	if _, err := intelligenceLeaseIOCs(leased, b, revision, cp.IOCs); !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("changed projection admitted: %v", err)
	}
	ioc.Count = 3
	approved, err := intelligenceLeaseIOCs(leased, b, revision, cp.IOCs)
	if err != nil || len(approved) != 1 {
		t.Fatalf("exact projection rejected: %v", err)
	}
	ioc.Count = 21
	if approved[0].Count != 3 {
		t.Fatal("approved projection aliases caller's mutable object")
	}
	if _, err := intelligenceLeaseSessions(leased, b, revision, []*TTPSession{}); err != nil {
		t.Fatalf("empty omitted collection changed semantics: %v", err)
	}
	changed := *event
	changed.ID = "another-row"
	if _, err := intelligenceLeaseEvent(leased, b, &changed); !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("event outside WAL admitted: %v", err)
	}
	if _, err := intelligenceLeaseEvent(leased, b, event); err != nil {
		t.Fatalf("exact event rejected: %v", err)
	}
}

func TestIntelligenceLeaseTakeoverRecoversKnownWALAndReservesGlobally(t *testing.T) {
	ctx := t.Context()
	b := &memoryIntelligenceLeaseBackend{now: time.Now().UTC(), checkpoints: map[string][]byte{}}
	a, err := acquireIntelligenceLease(ctx, b, "owner-one-0123456789", time.Second, 40)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := reserveIntelligenceRevision(ctx, b, a, 0)
	if err != nil || revision != 41 {
		t.Fatalf("initial reservation: %d %v", revision, err)
	}
	ac := WithIntelligenceLease(ctx, a)
	cp := &IntelligenceCheckpoint{Revision: revision, IOCs: []*IOC{{ID: "one", Type: "ip", Value: "203.0.113.8", Honeypot: "cowrie", Count: 1}}}
	if _, err := intelligenceLeaseSave(ac, b, cp); err != nil {
		t.Fatal(err)
	}
	b.now = b.now.Add(2 * time.Second)
	c, err := acquireIntelligenceLease(ctx, b, "owner-two-0123456789", 30*time.Second, 0)
	if err != nil || c.Fence <= a.Fence || c.Namespace != a.Namespace {
		t.Fatalf("takeover: %+v %v", c, err)
	}
	cc := WithIntelligenceLease(ctx, c)
	recovered, handled, err := intelligenceLeaseLoad(cc, b)
	if err != nil || !handled || recovered == nil || recovered.Revision != revision {
		t.Fatalf("recovery: %+v %v", recovered, err)
	}
	if _, err := intelligenceLeaseIOCs(cc, b, revision, recovered.IOCs); err != nil {
		t.Fatalf("successor cannot replay inherited immutable WAL: %v", err)
	}
	for name, check := range map[string]func() error{
		"reserve":    func() error { _, err := reserveIntelligenceRevision(ctx, b, a, 0); return err },
		"renew":      func() error { _, err := renewIntelligenceLease(ctx, b, a, time.Second); return err },
		"release":    func() error { return releaseIntelligenceLease(ctx, b, a) },
		"checkpoint": func() error { _, err := intelligenceLeaseSave(ac, b, cp); return err },
		"projection": func() error { _, err := intelligenceLeaseIOCs(ac, b, revision, cp.IOCs); return err },
	} {
		if err := check(); !errors.Is(err, ErrIntelligenceLeaseLost) {
			t.Fatalf("stale %s admitted: %v", name, err)
		}
	}
	next, err := reserveIntelligenceRevision(ctx, b, c, 0)
	if err != nil || next <= revision {
		t.Fatalf("successor reused revision: %d %v", next, err)
	}
	if err := releaseIntelligenceLease(ctx, b, c); err != nil {
		t.Fatal(err)
	}
	d, err := acquireIntelligenceLease(ctx, b, "owner-three-0123456789", time.Second, 0)
	if err != nil || d.Fence <= c.Fence {
		t.Fatalf("release reset fencing: %+v %v", d, err)
	}
	after, err := reserveIntelligenceRevision(ctx, b, d, 0)
	if err != nil || after <= next {
		t.Fatalf("release reset revisions: %d %v", after, err)
	}
}
