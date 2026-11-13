package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/column"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/qpot/qpot/internal/config"
)

type intelligenceBatch struct {
	driver.Batch
	rows    [][]any
	sendErr error
}

func (b *intelligenceBatch) Append(v ...any) error {
	b.rows = append(b.rows, append([]any(nil), v...))
	return nil
}
func (b *intelligenceBatch) Send() error  { return b.sendErr }
func (b *intelligenceBatch) Abort() error { return nil }

type intelligenceConn struct {
	driver.Conn
	queries []string
	batches []*intelligenceBatch
	sendErr error
}

func (c *intelligenceConn) PrepareBatch(_ context.Context, q string, _ ...driver.PrepareBatchOption) (driver.Batch, error) {
	b := &intelligenceBatch{sendErr: c.sendErr}
	c.queries = append(c.queries, q)
	c.batches = append(c.batches, b)
	return b, nil
}
func TestIntelligenceClickHouseReplayUsesAbsoluteVersionedBatches(t *testing.T) {
	ctx := context.Background()
	conn := &intelligenceConn{}
	db := &ClickHouse{conn: conn}
	now := time.Now().UTC()
	ioc := &IOC{ID: "ip:test:cowrie", Type: "ip", Value: "test", Honeypot: "cowrie", Count: 7, FirstSeen: now, LastSeen: now}
	for n := 0; n < 2; n++ {
		if err := db.replaceLegacyIntelligenceIOCs(ctx, 4, []*IOC{ioc}); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(conn.batches[0].rows, conn.batches[1].rows) {
		t.Fatal("replay changed absolute rows")
	}
	row := conn.batches[0].rows[0]
	if row[0] != uint64(4) || row[9] != uint64(7) {
		t.Fatalf("revision/count not preserved: %v", row)
	}
	if ioc.Count != 7 {
		t.Fatal("projection mutated input")
	}
	cp := &IntelligenceCheckpoint{Revision: 5, State: json.RawMessage(`{"active":[]}`)}
	if err := db.saveLegacyIntelligenceCheckpoint(ctx, cp); err != nil {
		t.Fatal(err)
	}
	var saved IntelligenceCheckpoint
	if err := json.Unmarshal([]byte(conn.batches[2].rows[0][2].(string)), &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 5 {
		t.Fatalf("checkpoint revision %d", saved.Revision)
	}
	conn.sendErr = errors.New("ambiguous send")
	if err := db.replaceLegacyIntelligenceSessions(ctx, 4, []*TTPSession{{SessionID: "one", EventCount: 2}}); err == nil {
		t.Fatal("send failure hidden")
	}
}
func TestIntelligenceElasticsearchRevisionAndCheckpointWire(t *testing.T) {
	var saved map[string]any
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == http.MethodGet {
			if saved == nil {
				w.WriteHeader(404)
				fmt.Fprint(w, `{"found":false}`)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"_source": saved, "_id": "worker", "_index": intelligenceCheckpointIndex, "found": true})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/_delete_by_query") {
			fmt.Fprint(w, `{ "deleted": 0 }`)
			return
		}
		if r.URL.Query().Get("refresh") != "wait_for" {
			t.Error("write not searchable before acknowledgment")
		}
		var body struct {
			Script struct {
				Source string `json:"source"`
				Params struct {
					Revision uint64         `json:"revision"`
					Doc      map[string]any `json:"doc"`
				} `json:"params"`
			} `json:"script"`
			Upsert map[string]any `json:"upsert"`
		}
		decoder := json.NewDecoder(r.Body)
		if r.URL.Path == "/_bulk" {
			var action map[string]any
			if err := decoder.Decode(&action); err != nil {
				t.Error(err)
			}
		}
		if err := decoder.Decode(&body); err != nil {
			t.Error(err)
		}
		if !strings.Contains(body.Script.Source, "intelligence_revision <= params.revision") {
			t.Error("missing stale-write guard")
		}
		if !reflect.DeepEqual(body.Script.Params.Doc, body.Upsert) {
			t.Error("insert and replace payload differ")
		}
		if strings.Contains(r.URL.Path, "checkpoint") {
			saved = body.Upsert
		}
		if r.URL.Path == "/_bulk" {
			fmt.Fprint(w, `{"errors":false,"items":[{"update":{"status":200,"_index":"qpot-iocs","_id":"x","_version":1,"result":"updated","_shards":{"successful":1,"failed":0}}}]}`)
		} else {
			fmt.Fprintf(w, `{"result":"updated","_id":"worker","_index":%q,"_version":1,"_shards":{"successful":1,"failed":0}}`, intelligenceCheckpointIndex)
		}
	}))
	defer srv.Close()
	db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
	ctx := context.Background()
	if cp, err := db.loadLegacyIntelligenceCheckpoint(ctx); err != nil || cp != nil {
		t.Fatalf("empty: %+v %v", cp, err)
	}
	cp := &IntelligenceCheckpoint{Revision: 17, State: json.RawMessage(`{"active":["a"]}`), Complete: true}
	if err := db.saveLegacyIntelligenceCheckpoint(ctx, cp); err != nil {
		t.Fatal(err)
	}
	got, err := db.loadLegacyIntelligenceCheckpoint(ctx)
	if err != nil || !reflect.DeepEqual(got, cp) {
		t.Fatalf("roundtrip %+v %v", got, err)
	}
	if err := db.replaceLegacyIntelligenceIOCs(ctx, 17, []*IOC{{ID: "x", Count: 5}}); err != nil {
		t.Fatal(err)
	}
	if calls != 5 {
		t.Fatalf("requests %d", calls)
	}
}
func TestIntelligenceElasticsearchWriteFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
	if err := db.saveLegacyIntelligenceCheckpoint(context.Background(), &IntelligenceCheckpoint{Revision: 1}); err == nil {
		t.Fatal("checkpoint failure hidden")
	}
	if err := db.replaceLegacyIntelligenceIOCs(context.Background(), 1, []*IOC{{ID: "x"}}); err == nil {
		t.Fatal("projection failure hidden")
	}
}

func checkIntelligenceReplay(t *testing.T, db Database) {
	t.Helper()
	ctx := context.Background()
	store := legacyIntelligenceStoreForTest{db}
	now := time.Now().UTC().Truncate(time.Millisecond)
	key := fmt.Sprintf("replay-%d", now.UnixNano())
	old := &IOC{ID: "domain:" + key + ":test", Type: "domain", Value: key, Honeypot: "test", Count: 3, FirstSeen: now, LastSeen: now, Metadata: map[string]string{}}
	if err := db.InsertIOCs(ctx, []*IOC{old}); err != nil {
		t.Fatal(err)
	}
	baseline, err := store.ReadIntelligenceIOCs(ctx, []*IOC{old})
	if err != nil || len(baseline) != 1 || baseline[0].Count != 3 {
		t.Fatalf("legacy baseline: %+v %v", baseline, err)
	}
	canary := *old
	canary.Honeypot = "canary"
	canary.ID = "domain:" + key + ":canary"
	canary.Count = 2
	if err := db.InsertIOCs(ctx, []*IOC{&canary}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceIntelligenceIOCs(ctx, 2, []*IOC{old}); err != nil {
		t.Fatal(err)
	}
	next := *old
	next.Count = 5 // Equal event timestamps must not choose an older projection.
	for _, write := range []struct {
		rev uint64
		i   *IOC
	}{{4, &next}, {4, &next}, {2, old}} {
		if err := store.ReplaceIntelligenceIOCs(ctx, write.rev, []*IOC{write.i}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.GetIOCs(ctx, IOCFilter{Values: []string{key}, Honeypots: []string{"test"}, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Count != 5 {
		t.Fatalf("replayed count: %+v", rows)
	}
	canaryRows, err := store.ReadIntelligenceIOCs(ctx, []*IOC{&canary})
	if err != nil || len(canaryRows) != 1 || canaryRows[0].Count != 2 {
		t.Fatalf("worker overwrote canary: %+v %v", canaryRows, err)
	}
	session := &TTPSession{SessionID: key, CampaignFingerprint: key, EventCount: 3, FirstSeen: now, LastSeen: now, SourceIPs: []string{}, Techniques: []string{}, KillChainStages: []string{}, IOCIDs: []string{}}
	if err := store.ReplaceIntelligenceSessions(ctx, 4, []*TTPSession{session}); err != nil {
		t.Fatal(err)
	}
	session.EventCount = 1
	if err := store.ReplaceIntelligenceSessions(ctx, 2, []*TTPSession{session}); err != nil {
		t.Fatal(err)
	}
	sessions, err := db.GetTTPSessions(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range sessions {
		if s.SessionID == key {
			found = true
			if s.EventCount != 3 {
				t.Fatalf("stale session: %+v", s)
			}
		}
	}
	if !found {
		t.Fatal("missing projected session")
	}
	// Long values are intentionally not indexed by Elasticsearch, but must
	// still contribute their previous count when preparing the next checkpoint.
	longIOC := *old
	longIOC.Value = strings.Repeat("z", 9000) + key
	longIOC.ID = "command:" + longIOC.Value + ":test"
	longIOC.Type = "command"
	longIOC.Count = 9
	if err := store.ReplaceIntelligenceIOCs(ctx, 4, []*IOC{&longIOC}); err != nil {
		t.Fatal(err)
	}
	baselines, err := store.ReadIntelligenceIOCs(ctx, []*IOC{&longIOC})
	if err != nil || len(baselines) != 1 || baselines[0].Count != 9 {
		t.Fatalf("long baseline: %+v %v", baselines, err)
	}
	previous, err := store.LoadIntelligenceCheckpoint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rev := uint64(10)
	if previous != nil {
		rev = previous.Revision + 10
	}
	// Keep the shared integration database recoverable by subsequent worker
	// tests: an empty active-session accumulator is an object, not a list.
	cp := &IntelligenceCheckpoint{Revision: rev, Complete: true, State: json.RawMessage(`{}`)}
	if err := store.SaveIntelligenceCheckpoint(ctx, cp); err != nil {
		t.Fatal(err)
	}
	stale := *cp
	stale.Revision--
	if err := store.SaveIntelligenceCheckpoint(ctx, &stale); err != nil {
		t.Fatal(err)
	}
	got, err := store.LoadIntelligenceCheckpoint(ctx)
	if err != nil || got == nil || got.Revision != rev {
		t.Fatalf("checkpoint regressed: %+v %v", got, err)
	}
}
func TestCHIntelligenceReplay(t *testing.T) { checkIntelligenceReplay(t, connectCH(t)) }
func TestESIntelligenceReplay(t *testing.T) { checkIntelligenceReplay(t, connectES(t)) }
func TestPGIntelligenceReplay(t *testing.T) {
	db := connectPG(t)
	ctx := context.Background()
	_, err := db.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS ttp_sessions (session_id TEXT PRIMARY KEY,campaign_fingerprint TEXT,source_ips TEXT[],shared_infrastructure BOOLEAN,kill_chain_stages TEXT[],techniques TEXT[],ioc_ids TEXT[],event_count BIGINT,first_seen TIMESTAMPTZ,last_seen TIMESTAMPTZ,confidence DOUBLE PRECISION)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.initializeIntelligenceSchema(ctx); err != nil {
		t.Fatal(err)
	}
	checkIntelligenceReplay(t, db)
}

func TestIntelligenceBulkUncertainRepliesFail(t *testing.T) {
	for _, reply := range []string{`{}`, `not json`, `{"items":[{"update":{"status":429}}]}`, `{"items":[{"update":{"status":200}},{"update":{"status":200}}]}`} {
		t.Run(reply, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, reply) }))
			defer srv.Close()
			db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
			if err := db.replaceLegacyIntelligenceIOCs(context.Background(), 1, []*IOC{{ID: "x"}}); err == nil {
				t.Fatal("uncertain bulk acknowledged")
			}
		})
	}
}

func TestIntelligenceReadLongESIndicatorByIdentity(t *testing.T) {
	value := strings.Repeat("x", 9000)
	ioc := &IOC{ID: "command:" + value + ":cowrie", Type: "command", Value: value, Honeypot: "cowrie", Count: 11, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/qpot-iocs/_mget" {
			t.Errorf("indexed search used: %s", r.URL.Path)
		}
		var body struct {
			IDs []string `json:"ids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.IDs) != 1 || body.IDs[0] != esDocID(ioc.ID) {
			t.Errorf("wrong document identity: %v", body.IDs)
		}
		json.NewEncoder(w).Encode(map[string]any{"docs": []any{map[string]any{"_id": esDocID(ioc.ID), "found": true, "_source": ioc}}})
	}))
	defer srv.Close()
	db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
	rows, err := db.ReadIntelligenceIOCs(context.Background(), []*IOC{ioc})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Count != 11 || rows[0].Value != value {
		t.Fatalf("lost long IOC: %+v", rows)
	}
}
func TestIntelligenceReadESPartialResultFails(t *testing.T) {
	for _, reply := range []string{`{"docs":[]}`, `{"docs":[{"_id":"x"}]}`, `{"docs":[{"_id":"x","error":{"type":"unavailable"}}]}`, `{"docs":[{"_id":"x","found":true}]}`} {
		t.Run(reply, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, reply) }))
			defer srv.Close()
			db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
			if _, err := db.ReadIntelligenceIOCs(context.Background(), []*IOC{{ID: "x"}}); err == nil {
				t.Fatal("partial baseline accepted")
			}
		})
	}
}

func TestIntelligenceLockIdentityUsesStorageNotCredentials(t *testing.T) {
	a := &config.DatabaseConfig{Host: "LOCALHOST.", Database: "qpot", Username: "one", Password: "secret"}
	b := &config.DatabaseConfig{Host: "127.0.0.1", Port: 9000, Database: "qpot", Username: "two", Password: "different"}
	first := (&ClickHouse{config: a}).IntelligenceLockIdentity()
	if first != (&ClickHouse{config: b}).IntelligenceLockIdentity() {
		t.Fatal("same storage has different ownership key")
	}
	b.Database = "other"
	if first == (&ClickHouse{config: b}).IntelligenceLockIdentity() {
		t.Fatal("different storage shares ownership key")
	}
	a.Port = 9200
	b.Port = 9200
	if (&Elasticsearch{config: a}).IntelligenceLockIdentity() != (&Elasticsearch{config: b}).IntelligenceLockIdentity() {
		t.Fatal("ES fixed index namespace depends on unused database setting")
	}
}

func TestIntelligenceESTagRequiresVisibleCompleteAcknowledgment(t *testing.T) {
	cases := []struct {
		name, reply string
		wantErr     bool
	}{
		{"success", `{"timed_out":false,"total":1,"updated":1,"noops":0,"version_conflicts":0,"failures":[]}`, false},
		{"retained event removed", `{"timed_out":false,"total":0,"updated":0,"noops":0,"version_conflicts":0,"failures":[]}`, false},
		{"already applied noop", `{"timed_out":false,"total":1,"updated":0,"noops":1,"version_conflicts":0,"failures":[]}`, false},
		{"timeout", `{"timed_out":true,"total":1,"updated":1,"version_conflicts":0,"failures":[]}`, true},
		{"partial", `{"timed_out":false,"total":2,"updated":1,"version_conflicts":0,"failures":[]}`, true},
		{"conflict", `{"timed_out":false,"total":1,"updated":0,"version_conflicts":1,"failures":[]}`, true},
		{"failure", `{"timed_out":false,"total":1,"updated":0,"version_conflicts":0,"failures":[{"cause":{"type":"unavailable_shards_exception"}}]}`, true},
		{"missing acknowledgment", `{}`, true},
		{"malformed", `not json`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/qpot-events-*/_update_by_query" || r.URL.Query().Get("refresh") != "true" {
					t.Errorf("tag must refresh before checkpoint completion: %s", r.URL)
				}
				var body struct {
					Query struct {
						IDs struct {
							Values []string `json:"values"`
						} `json:"ids"`
					} `json:"query"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if !reflect.DeepEqual(body.Query.IDs.Values, []string{"event-one"}) {
					t.Errorf("wrong identity: %v", body.Query.IDs.Values)
				}
				fmt.Fprint(w, tc.reply)
			}))
			defer srv.Close()
			db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
			err := db.TagEvent(context.Background(), &Event{ID: "event-one", Timestamp: time.Now().UTC()})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v, wantErr=%t", err, tc.wantErr)
			}
		})
	}
}

// Successful HTTP and item statuses alone do not acknowledge durable rows.
// The worker must retain its WAL on missing identity or failed replica shards.
func TestIntelligenceBulkRequiresCompleteDurableAcknowledgment(t *testing.T) {
	cases := []struct {
		name, reply string
		wantErr     bool
	}{
		{"updated", `{"status":200,"_index":"qpot-iocs","_id":"x","_version":2,"result":"updated","_shards":{"successful":1,"failed":0}}`, false},
		{"created", `{"status":201,"_index":"qpot-iocs","_id":"x","_version":1,"result":"created","_shards":{"successful":1,"failed":0}}`, false},
		{"stale replay noop", `{"status":200,"_index":"qpot-iocs","_id":"x","_version":2,"result":"noop"}`, false},
		{"missing evidence", `{"status":200}`, true},
		{"failed replica", `{"status":200,"_index":"qpot-iocs","_id":"x","_version":2,"result":"updated","_shards":{"successful":1,"failed":1}}`, true},
		{"no successful shard", `{"status":200,"_index":"qpot-iocs","_id":"x","_version":2,"result":"updated","_shards":{"successful":0,"failed":0}}`, true},
		{"wrong document", `{"status":200,"_index":"qpot-iocs","_id":"other","_version":2,"result":"updated","_shards":{"successful":1,"failed":0}}`, true},
		{"wrong index", `{"status":200,"_index":"other","_id":"x","_version":2,"result":"updated","_shards":{"successful":1,"failed":0}}`, true},
		{"missing version", `{"status":200,"_index":"qpot-iocs","_id":"x","result":"updated","_shards":{"successful":1,"failed":0}}`, true},
		{"deleted", `{"status":200,"_index":"qpot-iocs","_id":"x","_version":2,"result":"deleted","_shards":{"successful":1,"failed":0}}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `{"errors":false,"items":[{"update":%s}]}`, tc.reply)
			}))
			defer srv.Close()
			db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
			err := db.replaceLegacyIntelligenceIOCs(context.Background(), 2, []*IOC{{ID: "x"}})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v, wantErr=%t", err, tc.wantErr)
			}
		})
	}
}

// The fake batch checks replay behavior; these assertions also execute the
// project's pinned ClickHouse driver's real column conversion for the exact
// production schemas, including nil maps/slices and binary strings.
func TestIntelligenceClickHousePinnedDriverColumnCompatibility(t *testing.T) {
	conn := &intelligenceConn{}
	db := &ClickHouse{conn: conn}
	now := time.Date(2026, 11, 7, 12, 34, 56, 789000000, time.UTC)
	for _, metadata := range []map[string]string{nil, {"binary\xff": "value\x00\xfe"}} {
		if err := db.replaceLegacyIntelligenceIOCs(context.Background(), 31, []*IOC{{ID: "command:test", Type: "command", Value: "test\x00\xff", Honeypot: "cowrie", SourceIP: "2001:db8::1", FirstSeen: now, LastSeen: now, Count: 12, Metadata: metadata}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, shared := range []bool{false, true} {
		if err := db.replaceLegacyIntelligenceSessions(context.Background(), 31, []*TTPSession{{SessionID: "episode", CampaignFingerprint: "campaign", SharedInfrastructure: shared, SourceIPs: []string{"2001:db8::1"}, IOCIDs: []string{"command:test\xff"}, FirstSeen: now, LastSeen: now, EventCount: 12, Confidence: 0.7}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.saveLegacyIntelligenceCheckpoint(context.Background(), &IntelligenceCheckpoint{Revision: 31, Events: []*Event{{Username: "test\xff"}}}); err != nil {
		t.Fatal(err)
	}
	iocTypes := []column.Type{"UInt64", "String", "LowCardinality(String)", "String", "LowCardinality(String)", "String", "String", "DateTime64(3)", "DateTime64(3)", "UInt64", "Map(String, String)"}
	sessionTypes := []column.Type{"UInt64", "String", "String", "Array(String)", "UInt8", "Array(String)", "Array(String)", "Array(String)", "UInt64", "DateTime64(3)", "DateTime64(3)", "Float64"}
	for batch, types := range [][]column.Type{iocTypes, iocTypes, sessionTypes, sessionTypes, {"UInt8", "UInt64", "String"}} {
		row := conn.batches[batch].rows[0]
		if len(row) != len(types) {
			t.Fatalf("batch %d has %d fields for %d columns", batch, len(row), len(types))
		}
		for n, typ := range types {
			col, err := typ.Column(fmt.Sprintf("field%d", n), time.UTC)
			if err != nil {
				t.Fatal(err)
			}
			if err := col.AppendRow(row[n]); err != nil {
				t.Fatalf("batch %d column %d (%s), value %T: %v", batch, n, typ, row[n], err)
			}
			if col.Rows() != 1 {
				t.Fatalf("batch %d column %d produced %d rows", batch, n, col.Rows())
			}
		}
	}
}

type intelligenceQuerySizeConn struct {
	driver.Conn
	queries []string
	args    [][]any
}

func (c *intelligenceQuerySizeConn) Query(_ context.Context, query string, args ...any) (driver.Rows, error) {
	if size := renderedSize(query, args...); size > chMaxQuerySize {
		return nil, fmt.Errorf("query exceeds ClickHouse parser limit: %d", size)
	}
	c.queries = append(c.queries, query)
	c.args = append(c.args, append([]any(nil), args...))
	return &storedRows{}, nil
}

// QueryRow answers the one count a read makes first (is the legacy table
// empty): it is.
func (c *intelligenceQuerySizeConn) QueryRow(context.Context, string, ...any) driver.Row {
	return zeroCountRow{}
}

type zeroCountRow struct{ driver.Row }

func (zeroCountRow) Scan(dest ...any) error { *dest[0].(*uint64) = 0; return nil }
func (zeroCountRow) Err() error             { return nil }

func TestIntelligenceClickHouseExactReadsBoundQuotedKeys(t *testing.T) {
	conn := &intelligenceQuerySizeConn{}
	db := &ClickHouse{conn: conn}
	var wanted []*IOC
	for i := 0; i < 1200; i++ {
		value := fmt.Sprintf("indicator-%d-", i)
		if i < 5 {
			value += strings.Repeat("\\'", 40000)
		}
		wanted = append(wanted, &IOC{ID: value, Type: "command", Value: value, Honeypot: "cowrie"})
	}
	if _, err := db.ReadIntelligenceIOCs(context.Background(), wanted); err != nil {
		t.Fatal(err)
	}
	if len(conn.queries) < 7 {
		t.Fatalf("expected bounded queries for long and numerous keys; got %d", len(conn.queries))
	}
	seen := 0
	for i, q := range conn.queries {
		if strings.Contains(q, " LIMIT ") || strings.Contains(q, " OFFSET ") {
			t.Fatal("exact identity read silently paginates")
		}
		args := conn.args[i]
		if len(args)%3 != 0 || strings.Count(q, "(?, ?, ?)") != len(args)/3 || !strings.Contains(q, "WHERE (type, value, honeypot) IN ((?, ?, ?)") {
			t.Fatal("identity predicates do not cover every key")
		}
		for n := 0; n < len(args); n += 3 {
			key := wanted[seen]
			if args[n] != key.Type || args[n+1] != key.Value || args[n+2] != key.Honeypot {
				t.Fatal("read changed an exact key")
			}
			seen++
		}
	}
	if seen != len(wanted) {
		t.Fatalf("read %d of %d identities", seen, len(wanted))
	}
}

func TestElasticsearchIntelligenceSchemaRejectsUnexpectedIndexErrors(t *testing.T) {
	for _, target := range []string{"qpot-iocs", "qpot-ttp-sessions", "qpot-meta", intelligenceCheckpointIndex} {
		for _, reply := range []string{`{"error":{"type":"mapper_parsing_exception"}}`, `{"error":{"type":"illegal_argument_exception"}}`, `{}`, `not JSON`} {
			t.Run(target+reply, func(t *testing.T) {
				failed := false
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if failed {
						t.Error("schema initialization continued after failed index creation")
					}
					if r.URL.Path == "/"+target {
						failed = true
						w.WriteHeader(http.StatusBadRequest)
						fmt.Fprint(w, reply)
						return
					}
					fmt.Fprint(w, `{"acknowledged":true}`)
				}))
				defer srv.Close()
				db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
				if err := db.InitializeSchema(context.Background()); err == nil {
					t.Fatal("unexpected index creation error hidden")
				}
			})
		}
	}
}

func TestElasticsearchIntelligenceSchemaAllowsExistingIndices(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/_index_template/qpot-events" || r.URL.Path == "/qpot-events-*/_mapping" {
			fmt.Fprint(w, `{"acknowledged":true}`)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":{"type":"resource_already_exists_exception"}}`)
	}))
	defer srv.Close()
	db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
	if err := db.InitializeSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 6 || paths[5] != "/"+intelligenceCheckpointIndex {
		t.Fatalf("not all schemas initialized: %v", paths)
	}
}
