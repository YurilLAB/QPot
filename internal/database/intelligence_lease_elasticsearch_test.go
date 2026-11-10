package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// This server validates the HTTP contract against the shared Go transition
// specification. It deliberately does not claim to execute Elasticsearch's
// Painless engine; the separately gated native test covers that boundary.
type esLeaseWireModel struct {
	mu            sync.Mutex
	now           time.Time
	state         *intelligenceLeaseState
	documents     map[string]esIntelligenceLeaseCheckpointDocument
	version       int
	partial       bool
	missingSource bool
	wrongNonce    bool
	noop          bool
	legacy        *IntelligenceCheckpoint
}

func newESLeaseWireModel(t *testing.T) (*Elasticsearch, *esLeaseWireModel) {
	t.Helper()
	m := &esLeaseWireModel{now: time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC), documents: map[string]esIntelligenceLeaseCheckpointDocument{}, version: 1}
	server := httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(server.Close)
	return &Elasticsearch{client: server.Client(), baseURL: server.URL, config: &config.DatabaseConfig{}}, m
}

func (m *esLeaseWireModel) ack(w http.ResponseWriter, id string, source any, created bool) {
	m.version++
	result, status := "updated", http.StatusOK
	if created {
		result, status = "created", http.StatusCreated
	}
	if m.noop {
		result = "noop"
	}
	ack := map[string]any{"_id": id, "_index": intelligenceCheckpointIndex, "_version": m.version, "result": result,
		"_shards": map[string]int{"total": 2, "successful": 2, "failed": 0}}
	if m.partial {
		ack["_shards"] = map[string]int{"total": 2, "successful": 1, "failed": 0}
	}
	if source != nil && !m.missingSource {
		ack["get"] = map[string]any{"_source": source}
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ack)
}

func (m *esLeaseWireModel) serve(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prefix := "/" + intelligenceCheckpointIndex
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, prefix+"/_doc/") {
		id := strings.TrimPrefix(r.URL.Path, prefix+"/_doc/")
		var source any
		switch id {
		case esIntelligenceLeaseControlID:
			if m.state != nil {
				now := m.now.UnixMilli()
				source = esIntelligenceLeaseRecord{State: m.state, ObservedMS: &now}
			}
		case "worker":
			if m.legacy != nil {
				payload, _ := json.Marshal(m.legacy)
				source = esIntelligenceCheckpoint{Revision: m.legacy.Revision, Payload: string(payload)}
			}
		default:
			if document, found := m.documents[id]; found {
				source = document
			}
		}
		if source == nil {
			w.WriteHeader(404)
			fmt.Fprint(w, `{"found":false}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"_id": id, "_index": intelligenceCheckpointIndex, "found": true, "_source": source})
		return
	}
	if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, prefix+"/_create/") {
		if r.URL.Query().Get("wait_for_active_shards") != "all" {
			http.Error(w, "missing all-shard acknowledgment", 400)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, prefix+"/_create/")
		if _, exists := m.documents[id]; exists {
			w.WriteHeader(409)
			return
		}
		var document esIntelligenceLeaseCheckpointDocument
		if json.NewDecoder(r.Body).Decode(&document) != nil {
			w.WriteHeader(400)
			return
		}
		m.documents[id] = document
		m.ack(w, id, nil, true)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == prefix+"/_delete_by_query" {
		var body struct {
			Query struct {
				Bool struct {
					Filter []map[string]json.RawMessage `json:"filter"`
				} `json:"bool"`
			} `json:"query"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		var before uint64
		marker := false
		for _, filter := range body.Query.Bool.Filter {
			if raw, ok := filter["term"]; ok {
				var term map[string]bool
				_ = json.Unmarshal(raw, &term)
				marker = term["lease_checkpoint"]
			}
			if raw, ok := filter["range"]; ok {
				var ranges map[string]struct {
					LT uint64 `json:"lt"`
				}
				_ = json.Unmarshal(raw, &ranges)
				before = ranges["intelligence_revision"].LT
			}
		}
		if !marker {
			http.Error(w, "unscoped collection", 400)
			return
		}
		for id, document := range m.documents {
			if document.LeaseCheckpoint && document.Revision < before {
				delete(m.documents, id)
			}
		}
		fmt.Fprint(w, `{"deleted":0}`)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != prefix+"/_update/"+esIntelligenceLeaseControlID {
		http.Error(w, "unexpected endpoint", 400)
		return
	}
	if r.URL.Query().Get("_source") != "true" || r.URL.Query().Get("wait_for_active_shards") != "all" || r.URL.Query().Get("retry_on_conflict") != "3" {
		http.Error(w, "incomplete atomic request", 400)
		return
	}
	var body struct {
		Script struct {
			Source string `json:"source"`
			Lang   string `json:"lang"`
			Params struct {
				Operation intelligenceLeaseOperation `json:"operation"`
				Initial   intelligenceLeaseState     `json:"initial"`
				Nonce     string                     `json:"nonce"`
			} `json:"params"`
		} `json:"script"`
		ScriptedUpsert bool `json:"scripted_upsert"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.Script.Lang != "painless" {
		w.WriteHeader(400)
		return
	}
	if body.Script.Source == esIntelligenceLeaseInspectScript {
		if m.state == nil {
			w.WriteHeader(404)
			return
		}
		now := m.now.UnixMilli()
		nonce := body.Script.Params.Nonce
		if m.wrongNonce {
			nonce = "different-inspection"
		}
		m.ack(w, esIntelligenceLeaseControlID, esIntelligenceLeaseRecord{State: m.state, ObservedMS: &now, InspectNonce: nonce}, false)
		return
	}
	if body.Script.Source != esIntelligenceLeaseScript || !body.ScriptedUpsert {
		http.Error(w, "wrong mutation script", 400)
		return
	}
	op := body.Script.Params.Operation
	next, err := applyIntelligenceLeaseOperation(m.state, op, m.now)
	if err != nil {
		reason := "qpot_lease_invalid"
		if errors.Is(err, ErrIntelligenceLeaseBusy) {
			reason = "qpot_lease_busy"
		}
		if errors.Is(err, ErrIntelligenceLeaseLost) {
			reason = "qpot_lease_lost"
		}
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"reason": "runtime error", "caused_by": map[string]any{"reason": reason}}})
		return
	}
	if m.state == nil {
		initial := body.Script.Params.Initial
		next.Reserved = max(next.Reserved, initial.Reserved)
		next.CheckpointRevision, next.CheckpointDigest = initial.CheckpointRevision, initial.CheckpointDigest
	}
	m.state = &next
	copy := next
	if m.wrongNonce {
		copy.Operation = "different-mutation"
	}
	now := m.now.UnixMilli()
	m.ack(w, esIntelligenceLeaseControlID, esIntelligenceLeaseRecord{State: &copy, ObservedMS: &now}, false)
}

func TestElasticsearchLeaseWireContentionExpiryAndFencing(t *testing.T) {
	db, model := newESLeaseWireModel(t)
	ctx := t.Context()
	const ownerA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const ownerB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	first, err := db.AcquireIntelligenceLease(ctx, ownerA, time.Second, 12)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fence != 1 || first.ExpiresAt.Year() != 2031 {
		t.Fatalf("database clock was not used: %+v", first)
	}
	if _, err := db.AcquireIntelligenceLease(ctx, ownerB, time.Second, 0); !errors.Is(err, ErrIntelligenceLeaseBusy) {
		t.Fatalf("competing worker admitted: %v", err)
	}
	revision, err := db.ReserveIntelligenceRevision(ctx, first, 12)
	if err != nil || revision != 13 {
		t.Fatalf("global revision reservation: %d %v", revision, err)
	}
	cp := &IntelligenceCheckpoint{Revision: revision, State: json.RawMessage(`{"active":[]}`)}
	if err := db.SaveIntelligenceCheckpoint(WithIntelligenceLease(ctx, first), cp); err != nil {
		t.Fatal(err)
	}
	model.mu.Lock()
	model.now = model.now.Add(time.Second)
	model.mu.Unlock()
	second, err := db.AcquireIntelligenceLease(ctx, ownerB, time.Second, 0)
	if err != nil || second.Fence != 2 || second.Namespace != first.Namespace {
		t.Fatalf("takeover did not preserve namespace and advance fencing: %+v %v", second, err)
	}
	for name, call := range map[string]func() error{
		"renew":   func() error { _, err := db.RenewIntelligenceLease(ctx, first, time.Second); return err },
		"reserve": func() error { _, err := db.ReserveIntelligenceRevision(ctx, first, 0); return err },
		"release": func() error { return db.ReleaseIntelligenceLease(ctx, first) },
		"publish": func() error { return db.SaveIntelligenceCheckpoint(WithIntelligenceLease(ctx, first), cp) },
	} {
		if err := call(); !errors.Is(err, ErrIntelligenceLeaseLost) {
			t.Errorf("stale %s accepted: %v", name, err)
		}
	}
	loaded, err := db.LoadIntelligenceCheckpoint(WithIntelligenceLease(ctx, second))
	if err != nil || loaded == nil || loaded.Revision != 13 {
		t.Fatalf("takeover lost durable pending checkpoint: %+v %v", loaded, err)
	}
	if err := db.SaveIntelligenceCheckpoint(ctx, cp); !errors.Is(err, ErrIntelligenceLeaseLost) {
		t.Fatalf("unleased checkpoint overwrote active ownership: %v", err)
	}
	if err := db.ReleaseIntelligenceLease(ctx, second); err != nil {
		t.Fatal(err)
	}
	third, err := db.AcquireIntelligenceLease(ctx, ownerA, time.Second, 0)
	if err != nil || third.Fence != 3 {
		t.Fatalf("release reset ownership fence: %+v %v", third, err)
	}
	next, err := db.ReserveIntelligenceRevision(ctx, third, 0)
	if err != nil || next <= revision {
		t.Fatalf("release reset reserved revision: %d %v", next, err)
	}
}

func TestElasticsearchLeaseWireAcknowledgmentsFailClosed(t *testing.T) {
	for _, scenario := range []string{"partial shards", "missing source", "wrong nonce", "noop"} {
		t.Run(scenario, func(t *testing.T) {
			db, model := newESLeaseWireModel(t)
			model.partial = scenario == "partial shards"
			model.missingSource = scenario == "missing source"
			model.wrongNonce = scenario == "wrong nonce"
			model.noop = scenario == "noop"
			if _, err := db.AcquireIntelligenceLease(t.Context(), "owner-aaaaaaaaaaaaaaaa", time.Second, 0); err == nil {
				t.Fatal("incomplete mutation acknowledgment issued a lease")
			}
		})
	}
}

func TestElasticsearchLeaseWireLargeImmutableCheckpointAndConflicts(t *testing.T) {
	db, model := newESLeaseWireModel(t)
	ctx := t.Context()
	lease, err := db.AcquireIntelligenceLease(ctx, "owner-aaaaaaaaaaaaaaaa", time.Minute, 1<<54)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := db.ReserveIntelligenceRevision(ctx, lease, 1<<54)
	if err != nil || revision != (1<<54)+1 {
		t.Fatalf("revision lost integer precision: %d %v", revision, err)
	}
	state, _ := json.Marshal(map[string]string{"padding": strings.Repeat("x", intelligenceCheckpointChunkBytes+211)})
	cp := &IntelligenceCheckpoint{Revision: revision, State: state}
	leased := WithIntelligenceLease(ctx, lease)
	if err := db.SaveIntelligenceCheckpoint(leased, cp); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveIntelligenceCheckpoint(leased, cp); err != nil {
		t.Fatalf("identical immutable retry failed: %v", err)
	}
	loaded, err := db.LoadIntelligenceCheckpoint(leased)
	if err != nil || !sameIntelligenceValue(cp, loaded) {
		t.Fatalf("large checkpoint did not round trip: %v", err)
	}
	changed := &IntelligenceCheckpoint{Revision: revision, State: json.RawMessage(`{"different":true}`)}
	if err := db.SaveIntelligenceCheckpoint(leased, changed); err == nil {
		t.Fatal("same revision accepted conflicting checkpoint bytes")
	}
	loaded, err = db.LoadIntelligenceCheckpoint(leased)
	if err != nil || !sameIntelligenceValue(cp, loaded) {
		t.Fatalf("conflicting publication changed authority: %v", err)
	}
	model.mu.Lock()
	for id, doc := range model.documents {
		if doc.Chunk {
			doc.Payload = "%%%"
			model.documents[id] = doc
			break
		}
	}
	model.mu.Unlock()
	if _, err := db.LoadIntelligenceCheckpoint(leased); err == nil {
		t.Fatal("corrupt immutable chunk was accepted")
	}
}

func TestElasticsearchLeaseWireParallelOwners(t *testing.T) {
	db, _ := newESLeaseWireModel(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for n := 0; n < 24; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := db.AcquireIntelligenceLease(context.Background(), "owner-aaaaaaaa-"+strconv.Itoa(n), time.Minute, 0)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				winners++
			} else if !errors.Is(err, ErrIntelligenceLeaseBusy) {
				t.Errorf("unexpected acquisition error: %v", err)
			}
		}(n)
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("%d competing database workers acquired ownership", winners)
	}
}
