package database

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/qpot/qpot/internal/config"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func successfulBulkIngestItem(operation string) map[string]any {
	result := "created"
	status := 201
	if operation == "update" {
		result = "updated"
		status = 200
	}
	return map[string]any{"status": status, "_index": "qpot-test", "_id": "row-one", "_version": 1, "result": result, "_shards": map[string]int{"successful": 1, "failed": 0}}
}
func TestCheckBulkErrors(t *testing.T) {
	cases := []struct {
		name      string
		operation string
		modify    func(map[string]any)
		errors    bool
		wantErr   bool
	}{
		{"index success", "index", nil, false, false},
		{"update success", "update", nil, false, false},
		{"update noop", "update", func(i map[string]any) { i["result"] = "noop"; delete(i, "_shards") }, false, false},
		{"item failure despite errors false", "index", func(i map[string]any) { i["status"] = 429 }, false, true},
		{"error despite status success", "index", func(i map[string]any) { i["error"] = map[string]string{"reason": "failed to parse field x"} }, false, true},
		{"inconsistent errors flag", "index", nil, true, true},
		{"missing status", "index", func(i map[string]any) { delete(i, "status") }, false, true},
		{"missing version", "index", func(i map[string]any) { delete(i, "_version") }, false, true},
		{"missing index", "index", func(i map[string]any) { delete(i, "_index") }, false, true},
		{"missing identity", "index", func(i map[string]any) { delete(i, "_id") }, false, true},
		{"missing shards", "index", func(i map[string]any) { delete(i, "_shards") }, false, true},
		{"failed replica", "index", func(i map[string]any) { i["_shards"] = map[string]int{"successful": 1, "failed": 1} }, false, true},
		{"no successful shard", "index", func(i map[string]any) { i["_shards"] = map[string]int{"successful": 0, "failed": 0} }, false, true},
		{"unexpected result", "index", func(i map[string]any) { i["result"] = "deleted" }, false, true},
		{"index cannot noop", "index", func(i map[string]any) { i["result"] = "noop" }, false, true},
		{"noop with failed shards", "update", func(i map[string]any) { i["result"] = "noop"; i["_shards"] = map[string]int{"failed": 1} }, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			item := successfulBulkIngestItem(tc.operation)
			if tc.modify != nil {
				tc.modify(item)
			}
			body, _ := json.Marshal(map[string]any{"errors": tc.errors, "items": []any{map[string]any{tc.operation: item}}})
			if err := checkBulkErrors(body, []esBulkExpectation{{Operation: tc.operation, Index: "qpot-test", ID: "row-one"}}); (err != nil) != tc.wantErr {
				t.Fatalf("error=%v, wantErr=%t", err, tc.wantErr)
			}
		})
	}
	for _, body := range []string{`not json`, `{}`, `{"errors":false}`, `{"errors":false,"items":[]}`, `{"errors":false,"items":[{}]}`, `{"errors":false,"items":[{"delete":{"status":200}}]}`, `{"errors":false,"items":[{"index":{},"update":{}}]}`, `{"items":[{"index":{}}]}`} {
		if err := checkBulkErrors([]byte(body), []esBulkExpectation{{Operation: "index", Index: "qpot-test", ID: "row-one"}}); err == nil {
			t.Errorf("incomplete bulk acknowledgment accepted: %s", body)
		}
	}
	item := map[string]any{"index": successfulBulkIngestItem("index")}
	for _, total := range []int{0, 2} {
		body, _ := json.Marshal(map[string]any{"errors": false, "items": []any{item}})
		if err := checkBulkErrors(body, make([]esBulkExpectation, total)); err == nil {
			t.Fatalf("wrong cardinality accepted for %d expected rows", total)
		}
	}
	failure := successfulBulkIngestItem("index")
	failure["status"] = 400
	failure["error"] = map[string]string{"reason": "failed to parse field x"}
	body, _ := json.Marshal(map[string]any{"errors": true, "items": []any{item, map[string]any{"index": failure}}})
	if err := checkBulkErrors(body, []esBulkExpectation{{Operation: "index", Index: "qpot-test", ID: "row-one"}, {Operation: "index", Index: "qpot-test", ID: "row-one"}}); err == nil || !strings.Contains(err.Error(), "1/2") || !strings.Contains(err.Error(), "failed to parse field x") {
		t.Fatalf("partial failure not accurately reported: %v", err)
	}
}

func TestElasticsearchEventPayloadEncodingPreservesBytes(t *testing.T) {
	for _, payload := range [][]byte{nil, {}, []byte("plain text"), []byte("SGVsbG8="), []byte("https://example.com/\xff"), {0, 1, 255, 254, 128}} {
		event := &Event{Timestamp: time.Now().UTC(), Honeypot: "dionaea", Payload: payload}
		doc := eventToES(event)
		if payload != nil && doc.PayloadEncoding != "base64-v1" {
			t.Fatal("missing explicit payload encoding marker")
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(doc.Payload)
		if err != nil || !bytes.Equal(decoded, payload) {
			t.Fatalf("payload not valid binary-field base64: %v", err)
		}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		got, err := esDocToEvent(raw)
		if err != nil || !bytes.Equal(got.Payload, payload) {
			t.Fatalf("payload bytes changed after JSON/storage roundtrip: %v", err)
		}
		if !bytes.Equal(event.Payload, payload) {
			t.Fatal("encoding mutated original payload")
		}
	}
}
func TestElasticsearchLegacyPayloadIsNotGuessed(t *testing.T) {
	for _, payload := range []string{"plain text", "SGVsbG8=", "https://example.com/%FF", "café"} {
		raw, _ := json.Marshal(map[string]any{"timestamp": "2026-11-07T00:00:00Z", "payload": payload})
		got, err := esDocToEvent(raw)
		if err != nil || string(got.Payload) != payload {
			t.Fatalf("legacy payload %q changed: %v", payload, err)
		}
	}
}
func TestElasticsearchTaggedPayloadRejectsMalformedData(t *testing.T) {
	for _, tc := range []struct{ encoding, payload string }{
		{"base64-v1", "not base64!"}, {"base64-v1", "Zh=="}, {"base64-v1", "Zg==\n"}, {"base64-v2", "Zg=="},
	} {
		raw, _ := json.Marshal(map[string]any{"qpot_payload_encoding": tc.encoding, "payload": tc.payload})
		if _, err := esDocToEvent(raw); err == nil {
			t.Fatal("malformed or unsupported tagged payload silently accepted")
		}
	}
}

func TestElasticsearchPayloadWritesUseTaggedBase64OnWire(t *testing.T) {
	payload := []byte("https://downloads.example/raw/\x00\xff\xfe")
	for _, bulk := range []bool{false, true} {
		t.Run(fmt.Sprint(bulk), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				decoder := json.NewDecoder(r.Body)
				index := ""
				if bulk {
					var action struct {
						Index struct {
							Name string `json:"_index"`
						} `json:"index"`
					}
					if err := decoder.Decode(&action); err != nil {
						t.Error(err)
					}
					index = action.Index.Name
				}
				var wire struct {
					Payload  string `json:"payload"`
					Encoding string `json:"qpot_payload_encoding"`
				}
				if err := decoder.Decode(&wire); err != nil {
					t.Error(err)
				}
				decoded, err := base64.StdEncoding.Strict().DecodeString(wire.Payload)
				if err != nil || !bytes.Equal(decoded, payload) || wire.Encoding != "base64-v1" {
					t.Errorf("wire payload lost bytes or version marker: %v", err)
				}
				if bulk {
					item := successfulBulkIngestItem("index")
					item["_index"] = index
					_ = json.NewEncoder(w).Encode(map[string]any{"errors": false, "items": []any{map[string]any{"index": item}}})
				} else {
					fmt.Fprint(w, `{"result":"created"}`)
				}
			}))
			defer srv.Close()
			db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
			event := &Event{Timestamp: time.Now().UTC(), Honeypot: "dionaea", Payload: payload}
			var err error
			if bulk {
				err = db.InsertEvents(context.Background(), []*Event{event})
			} else {
				err = db.InsertEvent(context.Background(), event)
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestElasticsearchMalformedTaggedEventIsNotSilentlySkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"hits":{"total":{"value":1},"hits":[{"_id":"bad","_source":{"timestamp":"2026-11-07T00:00:00Z","payload":"invalid!","qpot_payload_encoding":"base64-v1"}}]}}`)
	}))
	defer srv.Close()
	db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
	if _, err := db.GetEvents(context.Background(), EventFilter{Limit: 10}); err == nil {
		t.Fatal("corrupt stored event silently disappeared from query")
	}
	if _, err := db.GetUnclassifiedEvents(context.Background(), 10); err == nil {
		t.Fatal("corrupt unclassified event silently disappeared from worker batch")
	}
}
func TestElasticsearchPayloadMarkerMappingMigratesExistingIndices(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			seen := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/qpot-events-*/_mapping" {
					seen = true
					if r.Method != http.MethodPut || r.URL.Query().Get("allow_no_indices") != "true" || r.URL.Query().Get("ignore_unavailable") != "true" {
						t.Errorf("unsafe mapping migration request: %s %s", r.Method, r.URL)
					}
					var body struct {
						Properties map[string]struct {
							Type string `json:"type"`
						} `json:"properties"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if len(body.Properties) != 1 || body.Properties["qpot_payload_encoding"].Type != "keyword" {
						t.Error("mapping migration changed existing fields")
					}
					if fail {
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprint(w, `{"error":{"type":"security_exception"}}`)
						return
					}
				}
				fmt.Fprint(w, `{"acknowledged":true}`)
			}))
			defer srv.Close()
			db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
			err := db.InitializeSchema(context.Background())
			if !seen || (err != nil) != fail {
				t.Fatalf("mapping migration seen=%t err=%v failure expected=%t", seen, err, fail)
			}
		})
	}
}

func TestElasticsearchSchemaNeedsAcknowledgment(t *testing.T) {
	for _, target := range []string{"/_index_template/qpot-events", "/qpot-events-*/_mapping", "/qpot-iocs", "/qpot-ttp-sessions", "/qpot-meta", "/" + intelligenceCheckpointIndex} {
		for _, reply := range []string{`{"acknowledged":false}`, `{}`, `not JSON`} {
			t.Run(target+reply, func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == target {
						fmt.Fprint(w, reply)
						return
					}
					fmt.Fprint(w, `{"acknowledged":true}`)
				}))
				defer srv.Close()
				db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
				if err := db.InitializeSchema(context.Background()); err == nil {
					t.Fatal("unacknowledged schema mutation accepted")
				}
			})
		}
	}
}

func TestElasticsearchPresentInvalidPayloadMarkerIsNotLegacy(t *testing.T) {
	for _, marker := range []any{nil, "", false, 7, []string{"base64-v1"}, map[string]string{"encoding": "base64-v1"}} {
		raw, _ := json.Marshal(map[string]any{"payload": "SGVsbG8=", "qpot_payload_encoding": marker})
		if _, err := esDocToEvent(raw); err == nil {
			t.Fatalf("present invalid marker %v treated as legacy", marker)
		}
	}
}

func TestElasticsearchTaggedNullPayloadIsRejected(t *testing.T) {
	if _, err := esDocToEvent(json.RawMessage(`{"payload":null,"qpot_payload_encoding":"base64-v1"}`)); err == nil {
		t.Fatal("explicit null tagged payload accepted")
	}
	if got, err := esDocToEvent(json.RawMessage(`{"qpot_payload_encoding":"base64-v1"}`)); err != nil || len(got.Payload) != 0 {
		t.Fatal("writer's omitted empty payload not accepted")
	}
}

func TestElasticsearchBulkAcknowledgmentBindsRequestedRows(t *testing.T) {
	for _, path := range []string{"events", "legacy IOCs", "durable IOCs"} {
		for _, corruption := range []string{"none", "wrong index", "wrong operation", "swapped rows", "duplicate row", "wrong ID"} {
			if path == "events" && corruption == "wrong ID" {
				continue
			} // Server-generated IDs are not known before insert.
			t.Run(path+"/"+corruption, func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					decoder := json.NewDecoder(r.Body)
					var operations []string
					var results []map[string]any
					for {
						var action map[string]struct {
							Index string `json:"_index"`
							ID    string `json:"_id"`
						}
						err := decoder.Decode(&action)
						if err == io.EOF {
							break
						}
						if err != nil {
							t.Error(err)
							return
						}
						var doc json.RawMessage
						if err := decoder.Decode(&doc); err != nil {
							t.Error(err)
							return
						}
						for op, want := range action {
							result := successfulBulkIngestItem(op)
							result["_index"] = want.Index
							if want.ID != "" {
								result["_id"] = want.ID
							} else {
								result["_id"] = fmt.Sprintf("generated-%d", len(results))
							}
							operations = append(operations, op)
							results = append(results, result)
						}
					}
					if len(results) != 2 {
						t.Errorf("expected two request actions, got %d", len(results))
						return
					}
					switch corruption {
					case "wrong index":
						results[0]["_index"] = "unrelated-index"
					case "wrong ID":
						results[0]["_id"] = "unrelated-document"
					case "wrong operation":
						if operations[0] == "index" {
							operations[0] = "update"
						} else {
							operations[0] = "index"
						}
					case "swapped rows":
						results[0], results[1] = results[1], results[0]
					case "duplicate row":
						results[1] = results[0]
					}
					items := []any{map[string]any{operations[0]: results[0]}, map[string]any{operations[1]: results[1]}}
					_ = json.NewEncoder(w).Encode(map[string]any{"errors": false, "items": items})
				}))
				defer srv.Close()
				db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
				ctx := context.Background()
				now := time.Date(2026, 11, 7, 1, 0, 0, 0, time.UTC)
				iocs := []*IOC{{ID: "first", Type: "url", Value: "one", Honeypot: "cowrie"}, {ID: strings.Repeat("long-ID", 100), Type: "url", Value: "two", Honeypot: "cowrie"}}
				var err error
				switch path {
				case "events":
					err = db.InsertEvents(ctx, []*Event{{Timestamp: now}, {Timestamp: now.Add(24 * time.Hour)}})
				case "legacy IOCs":
					err = db.InsertIOCs(ctx, iocs)
				case "durable IOCs":
					err = db.ReplaceIntelligenceIOCs(ctx, 3, iocs)
				}
				if (err != nil) != (corruption != "none") {
					t.Fatalf("error=%v for %s", err, corruption)
				}
			})
		}
	}
}

func TestElasticsearchDurableBulkRejectsContradictoryAcknowledgments(t *testing.T) {
	for _, corruption := range []string{"errors true", "missing errors", "null errors", "extra operation", "noop failed shards"} {
		t.Run(corruption, func(t *testing.T) {
			row := successfulBulkIngestItem("update")
			row["_index"] = "qpot-iocs"
			row["_id"] = "one"
			item := map[string]any{"update": row}
			body := map[string]any{"errors": false, "items": []any{item}}
			switch corruption {
			case "errors true":
				body["errors"] = true
			case "missing errors":
				delete(body, "errors")
			case "null errors":
				body["errors"] = nil
			case "extra operation":
				item["index"] = row
			case "noop failed shards":
				row["result"] = "noop"
				row["_shards"] = map[string]int{"successful": 1, "failed": 1}
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(body) }))
			defer srv.Close()
			db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
			if err := db.ReplaceIntelligenceIOCs(context.Background(), 3, []*IOC{{ID: "one"}}); err == nil {
				t.Fatal("contradictory durable bulk response accepted")
			}
		})
	}
}
func TestElasticsearchNoopCannotHideFailedShards(t *testing.T) {
	row := successfulBulkIngestItem("update")
	row["result"] = "noop"
	row["_shards"] = map[string]int{"successful": 1, "failed": 1}
	raw, _ := json.Marshal(row)
	if err := validateIntelligenceAcknowledgment(raw, "qpot-test", "row-one", true); err == nil {
		t.Fatal("single-document noop accepted failed shards")
	}
}
