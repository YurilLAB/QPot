package database

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// A real HTTP contract fixture models partial chunks, lost acknowledgments,
// guarded manifest publication, real-time reads, and revision-scoped cleanup.
type checkpointHTTP struct {
	docs        map[string]json.RawMessage
	failChunk   int
	chunks      int
	badAck      bool
	maxBody     int
	gcRevisions []uint64
}

func (s *checkpointHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	if len(data) > s.maxBody {
		s.maxBody = len(data)
	}
	id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	ack := func(result string) {
		if s.badAck {
			fmt.Fprint(w, `{}`)
			return
		}
		fmt.Fprintf(w, `{"result":%q,"_id":%q,"_index":%q,"_version":1,"_shards":{"successful":1,"failed":0}}`, result, id, intelligenceCheckpointIndex)
	}
	if r.Method == http.MethodGet {
		doc, ok := s.docs[id]
		if !ok {
			w.WriteHeader(404)
			return
		}
		fmt.Fprintf(w, `{"found":true,"_id":%q,"_index":%q,"_source":%s}`, id, intelligenceCheckpointIndex, doc)
		return
	}
	if id == "_delete_by_query" {
		var body struct {
			Query struct {
				Bool struct {
					Filter []json.RawMessage `json:"filter"`
				} `json:"bool"`
			} `json:"query"`
		}
		_ = json.Unmarshal(data, &body)
		var threshold struct {
			Range map[string]struct {
				LT uint64 `json:"lt"`
			} `json:"range"`
		}
		_ = json.Unmarshal(body.Query.Bool.Filter[1], &threshold)
		rev := threshold.Range["intelligence_revision"].LT
		s.gcRevisions = append(s.gcRevisions, rev)
		for key, raw := range s.docs {
			var d esIntelligenceCheckpoint
			_ = json.Unmarshal(raw, &d)
			if d.Chunk && d.Revision < rev {
				delete(s.docs, key)
			}
		}
		fmt.Fprint(w, `{"deleted":0}`)
		return
	}
	if r.Method == http.MethodPut {
		s.chunks++
		if s.failChunk != 0 && s.chunks == s.failChunk {
			w.WriteHeader(503)
			return
		}
		s.docs[id] = append([]byte(nil), data...)
		ack("created")
		return
	}
	var body struct {
		Upsert json.RawMessage `json:"upsert"`
	}
	_ = json.Unmarshal(data, &body)
	var next, old esIntelligenceCheckpoint
	_ = json.Unmarshal(body.Upsert, &next)
	_ = json.Unmarshal(s.docs[id], &old)
	if next.Revision >= old.Revision {
		s.docs[id] = body.Upsert
		ack("updated")
	} else {
		ack("noop")
	}
}
func checkpointTestES(t *testing.T, s *checkpointHTTP) *Elasticsearch {
	t.Helper()
	s.docs = make(map[string]json.RawMessage)
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
}
func largeCheckpoint(rev uint64) *IntelligenceCheckpoint {
	state, _ := json.Marshal(map[string]string{"active": strings.Repeat("\"\\\x00é", intelligenceCheckpointChunkBytes/4)})
	return &IntelligenceCheckpoint{Revision: rev, State: state, Complete: true}
}
func TestIntelligenceCheckpointChunksRoundTripAndCleanup(t *testing.T) {
	ctx := context.Background()
	wire := &checkpointHTTP{}
	db := checkpointTestES(t, wire)
	cp := largeCheckpoint(7)
	if err := db.SaveIntelligenceCheckpoint(ctx, cp); err != nil {
		t.Fatal(err)
	}
	got, err := db.LoadIntelligenceCheckpoint(ctx)
	if err != nil || !reflect.DeepEqual(got, cp) {
		t.Fatalf("chunk roundtrip differs: %v", err)
	}
	if wire.chunks < 2 || wire.maxBody > 8<<20 {
		t.Fatalf("unbounded request: chunks=%d max=%d", wire.chunks, wire.maxBody)
	}
	newCP := &IntelligenceCheckpoint{Revision: 8, State: json.RawMessage(`{}`), Complete: true}
	if err := db.SaveIntelligenceCheckpoint(ctx, newCP); err != nil {
		t.Fatal(err)
	}
	if len(wire.docs) != 1 {
		t.Fatalf("old chunks not collected: %d docs", len(wire.docs))
	}
	// A late old prepare cannot replace the newer manifest or delete its data.
	if err := db.SaveIntelligenceCheckpoint(ctx, cp); err != nil {
		t.Fatal(err)
	}
	got, err = db.LoadIntelligenceCheckpoint(ctx)
	if err != nil || !reflect.DeepEqual(got, newCP) {
		t.Fatalf("stale manifest replaced completion: %v", err)
	}
	if err := db.SaveIntelligenceCheckpoint(ctx, newCP); err != nil {
		t.Fatal(err)
	}
	if len(wire.docs) != 1 {
		t.Fatal("late orphan chunks not reclaimed on next save")
	}
}
func TestIntelligenceCheckpointPartialChunksDoNotPublish(t *testing.T) {
	ctx := context.Background()
	wire := &checkpointHTTP{}
	db := checkpointTestES(t, wire)
	old := &IntelligenceCheckpoint{Revision: 1, State: json.RawMessage(`{}`), Complete: true}
	if err := db.SaveIntelligenceCheckpoint(ctx, old); err != nil {
		t.Fatal(err)
	}
	wire.failChunk = 2
	cp := largeCheckpoint(2)
	if err := db.SaveIntelligenceCheckpoint(ctx, cp); err == nil {
		t.Fatal("partial chunks accepted")
	}
	got, err := db.LoadIntelligenceCheckpoint(ctx)
	if err != nil || !reflect.DeepEqual(got, old) {
		t.Fatal("partial save published manifest")
	}
	wire.failChunk = 0
	if err := db.SaveIntelligenceCheckpoint(ctx, cp); err != nil {
		t.Fatal(err)
	}
	got, err = db.LoadIntelligenceCheckpoint(ctx)
	if err != nil || !reflect.DeepEqual(got, cp) {
		t.Fatalf("retry failed: %v", err)
	}
	for id, raw := range wire.docs {
		if id != "worker" {
			var d esIntelligenceCheckpoint
			_ = json.Unmarshal(raw, &d)
			d.Payload = strings.Repeat("A", len(d.Payload))
			wire.docs[id], _ = json.Marshal(d)
			break
		}
	}
	if _, err := db.LoadIntelligenceCheckpoint(ctx); err == nil {
		t.Fatal("corrupted chunk accepted")
	}
}
func TestIntelligenceCheckpointRejectsUncertainAcknowledgments(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprint(chunked), func(t *testing.T) {
			wire := &checkpointHTTP{badAck: true}
			db := checkpointTestES(t, wire)
			cp := &IntelligenceCheckpoint{Revision: 1}
			if chunked {
				cp = largeCheckpoint(1)
			}
			if err := db.SaveIntelligenceCheckpoint(context.Background(), cp); err == nil {
				t.Fatal("empty 2xx acknowledged as durable")
			}
			if len(wire.gcRevisions) != 0 {
				t.Fatal("garbage collected without acknowledged manifest")
			}
			if chunked {
				if _, ok := wire.docs["worker"]; ok {
					t.Fatal("published after uncertain chunk")
				}
			}
		})
	}
}
func TestIntelligenceCheckpointLargeCommandBatchBoundsHTTPRequests(t *testing.T) {
	// This ordinary batch formerly produced a >100 MiB update request from
	// duplicate escaped event/IOC payloads, exceeding Elasticsearch's default.
	cp := &IntelligenceCheckpoint{Revision: 1}
	for n := 0; n < 500; n++ {
		command := fmt.Sprintf("%d-%s", n, strings.Repeat("x", 40000))
		cp.Events = append(cp.Events, &Event{ID: fmt.Sprint(n), Command: command})
		cp.IOCs = append(cp.IOCs, &IOC{ID: "command:" + command + ":test", Value: command, Type: "command", Honeypot: "test", Count: 1})
	}
	maxBody, chunks, published := 0, 0, false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) > maxBody {
			maxBody = len(body)
		}
		if len(body) >= 100<<20 {
			w.WriteHeader(413)
			return
		}
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		if id == "_delete_by_query" {
			fmt.Fprint(w, `{}`)
			return
		}
		if id == "worker" {
			published = true
		} else {
			chunks++
		}
		fmt.Fprintf(w, `{"result":"updated","_id":%q,"_index":%q,"_version":1,"_shards":{"successful":1,"failed":0}}`, id, intelligenceCheckpointIndex)
	}))
	defer srv.Close()
	db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
	if err := db.SaveIntelligenceCheckpoint(context.Background(), cp); err != nil {
		t.Fatal(err)
	}
	if chunks < 50 || !published || maxBody > 8<<20 {
		t.Fatalf("unexpected chunk transport: chunks=%d manifest=%v max=%d", chunks, published, maxBody)
	}
}
