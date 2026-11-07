package database

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// Decode the actual wire body, rather than estimating document sizes. Escaping
// and the script/upsert copies both contribute to the HTTP request limit.
func decodeIntelligenceBulkSizeTest(t *testing.T, r *http.Request) ([]string, []map[string]any, int) {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Error(err)
		return nil, nil, 0
	}
	if r.URL.Path != "/_bulk" || r.URL.Query().Get("refresh") != "wait_for" {
		t.Errorf("unexpected bulk URL: %s", r.URL)
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	var ids []string
	var docs []map[string]any
	for decoder.More() {
		var action struct {
			Update struct {
				ID string `json:"_id"`
			} `json:"update"`
		}
		if err := decoder.Decode(&action); err != nil {
			t.Error(err)
			break
		}
		var row struct {
			Script struct {
				Source string `json:"source"`
				Params struct {
					Revision uint64         `json:"revision"`
					Doc      map[string]any `json:"doc"`
				} `json:"params"`
			} `json:"script"`
			Upsert map[string]any `json:"upsert"`
		}
		if err := decoder.Decode(&row); err != nil {
			t.Error(err)
			break
		}
		if row.Script.Source != intelligenceReplaceScript || row.Script.Params.Revision != 29 || row.Upsert["intelligence_revision"] != float64(29) {
			t.Error("bulk replay changed revision or replacement semantics")
		}
		ids = append(ids, action.Update.ID)
		docs = append(docs, row.Script.Params.Doc)
	}
	return ids, docs, len(body)
}
func intelligenceBulkSizeResponse(w http.ResponseWriter, ids []string, status int) {
	items := make([]map[string]any, len(ids))
	for i := range items {
		items[i] = map[string]any{"update": map[string]any{"status": status, "_index": "qpot-iocs", "_id": ids[i], "_version": 1, "result": "updated", "_shards": map[string]int{"successful": 1, "failed": 0}}}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": status >= 300, "items": items})
}
func intelligenceBulkSizeInput() ([]string, []map[string]interface{}) {
	payload := strings.Repeat("x", 1<<20)
	ids := []string{"a", "b", "c", "d", "e", "f", "g"}
	docs := make([]map[string]interface{}, len(ids))
	for i := range ids {
		docs[i] = map[string]interface{}{"value": payload, "count": i + 3}
	}
	return ids, docs
}
func TestIntelligenceBulkSplitsCompleteEncodedRequests(t *testing.T) {
	var seen []string
	var sizes []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ids, _, size := decodeIntelligenceBulkSizeTest(t, r)
		seen = append(seen, ids...)
		sizes = append(sizes, size)
		intelligenceBulkSizeResponse(w, ids, 200)
	}))
	defer srv.Close()
	db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
	ids, docs := intelligenceBulkSizeInput()
	if err := db.replaceIntelligenceDocuments(context.Background(), "qpot-iocs", 29, ids, docs); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, ",") != "a,b,c,d,e,f,g" || len(sizes) != 3 {
		t.Fatalf("incomplete split: IDs=%v sizes=%v", seen, sizes)
	}
	for _, size := range sizes {
		if size > 8<<20 {
			t.Fatalf("normal chunk exceeds target: %d", size)
		}
	}
}
func TestIntelligenceBulkPartialChunkReplayIsAbsolute(t *testing.T) {
	calls := 0
	fail := true
	stored := map[string]float64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		ids, docs, _ := decodeIntelligenceBulkSizeTest(t, r)
		for i, id := range ids {
			stored[id] = docs[i]["count"].(float64)
		}
		// Simulate a partial/uncertain result after earlier writes took effect.
		if fail && calls == 2 {
			intelligenceBulkSizeResponse(w, ids, 429)
			return
		}
		intelligenceBulkSizeResponse(w, ids, 200)
	}))
	defer srv.Close()
	db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
	ids, docs := intelligenceBulkSizeInput()
	if err := db.replaceIntelligenceDocuments(context.Background(), "qpot-iocs", 29, ids, docs); err == nil {
		t.Fatal("partial chunk failure hidden")
	}
	if calls != 2 {
		t.Fatalf("continued after failed chunk: %d requests", calls)
	}
	fail = false
	if err := db.replaceIntelligenceDocuments(context.Background(), "qpot-iocs", 29, ids, docs); err != nil {
		t.Fatal(err)
	}
	if calls != 5 || len(stored) != 7 || stored["a"] != 3 || stored["b"] != 4 || stored["c"] != 5 || stored["g"] != 9 {
		t.Fatalf("replay was not absolute: calls=%d stored=%v", calls, stored)
	}
}
func TestIntelligenceBulkCountsEscapingAndIsolatesLargeRow(t *testing.T) {
	var sizes []int
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ids, _, size := decodeIntelligenceBulkSizeTest(t, r)
		sizes = append(sizes, size)
		seen = append(seen, ids...)
		intelligenceBulkSizeResponse(w, ids, 200)
	}))
	defer srv.Close()
	db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
	ids := []string{"before", "escaped", "after"}
	docs := []map[string]interface{}{{"value": "small"}, {"value": strings.Repeat("<", 720<<10)}, {"value": "small"}}
	if err := db.replaceIntelligenceDocuments(context.Background(), "qpot-iocs", 29, ids, docs); err != nil {
		t.Fatal(err)
	}
	if len(sizes) != 3 || strings.Join(seen, ",") != "before,escaped,after" {
		t.Fatalf("large row not isolated: %v %v", sizes, seen)
	}
	if sizes[1] <= 8<<20 || sizes[1] > 64<<20 {
		t.Fatalf("escaped row size=%d, expected bounded standalone request", sizes[1])
	}
}
func TestIntelligenceBulkChecksEveryChunkCardinality(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		ids, _, _ := decodeIntelligenceBulkSizeTest(t, r)
		if calls == 2 {
			fmt.Fprint(w, `{"items":[]}`)
			return
		}
		intelligenceBulkSizeResponse(w, ids, 200)
	}))
	defer srv.Close()
	db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
	ids, docs := intelligenceBulkSizeInput()
	if err := db.replaceIntelligenceDocuments(context.Background(), "qpot-iocs", 29, ids, docs); err == nil {
		t.Fatal("missing second chunk acknowledgment accepted")
	}
	if calls != 2 {
		t.Fatalf("continued after uncertain chunk: %d requests", calls)
	}
}
