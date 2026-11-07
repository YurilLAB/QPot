package database

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/qpot/qpot/internal/config"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestIntelligenceCheckpointPreservesRawIdentifiers(t *testing.T) {
	cp := &IntelligenceCheckpoint{Revision: 4, Events: []*Event{{ID: "row\xff", Username: "root\xff", Command: "echo \xc0", Metadata: map[string]string{"key\xff": "value\xfe"}}}, IOCs: []*IOC{{ID: "credential:root\xff", Value: "root\xff", Metadata: map[string]string{"a": "\xff", "a�": "b"}}}, Sessions: []*TTPSession{{SessionID: "session\xff", IOCIDs: []string{"credential:root\xff"}}}, State: json.RawMessage(`{}`)}
	encoded, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 5; n++ {
		repeat, err := json.Marshal(cp)
		if err != nil || !bytes.Equal(repeat, encoded) {
			t.Fatal("checkpoint retry bytes changed")
		}
	}
	var decoded IntelligenceCheckpoint
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cp, &decoded) {
		t.Fatalf("checkpoint lost binary identifiers: %+v", decoded)
	}
}

func TestIntelligenceTextEncodingChecksAllIOCFields(t *testing.T) {
	mutations := map[string]func(*IOC, string){
		"id": func(i *IOC, s string) { i.ID = s }, "type": func(i *IOC, s string) { i.Type = s }, "value": func(i *IOC, s string) { i.Value = s }, "honeypot": func(i *IOC, s string) { i.Honeypot = s }, "source_ip": func(i *IOC, s string) { i.SourceIP = s }, "technique_id": func(i *IOC, s string) { i.TechniqueID = s }, "metadata key": func(i *IOC, s string) { i.Metadata = map[string]string{s: "safe"} }, "metadata value": func(i *IOC, s string) { i.Metadata = map[string]string{"safe": s} },
	}
	for field, mutate := range mutations {
		for _, rejectNUL := range []bool{false, true} {
			for _, invalid := range []string{"sensitive-secret\xff", "sensitive-secret\x00"} {
				i := &IOC{}
				mutate(i, invalid)
				err := validateIntelligenceTextIOCs("test", rejectNUL, []*IOC{i})
				wantErr := strings.Contains(invalid, "\xff") || rejectNUL
				if (err != nil) != wantErr {
					t.Fatalf("field %s rejectNUL=%t: error=%v", field, rejectNUL, err)
				}
				if err != nil {
					var encoding *IntelligenceEncodingError
					if !errors.As(err, &encoding) || encoding.Field != "ioc."+field {
						t.Fatalf("wrong typed field error: %v", err)
					}
					if strings.Contains(err.Error(), "sensitive-secret") {
						t.Fatal("error leaked raw indicator data")
					}
				}
			}
		}
	}
}
func TestIntelligenceTextEncodingChecksSessionIdentities(t *testing.T) {
	for _, session := range []*TTPSession{
		{SessionID: "bad\xff"}, {CampaignFingerprint: "bad\xff"}, {SourceIPs: []string{"bad\xff"}}, {KillChainStages: []string{"bad\xff"}}, {Techniques: []string{"bad\xff"}}, {IOCIDs: []string{"bad\xff"}},
	} {
		if err := validateIntelligenceTextSessions("elasticsearch", false, []*TTPSession{session}); err == nil {
			t.Fatal("binary session field accepted")
		}
	}
	if err := validateIntelligenceTextSessions("timescaledb", true, []*TTPSession{{IOCIDs: []string{"nul\x00"}}}); err == nil {
		t.Fatal("PostgreSQL NUL accepted")
	}
}
func TestIntelligenceUnsupportedEncodingFailsBeforeBackendAccess(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; fmt.Fprint(w, `{}`) }))
	defer srv.Close()
	es := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
	pg := &TimescaleDB{} // A typed encoding error must precede any connection use.
	ctx := context.Background()
	iocs := []*IOC{{ID: "raw", Type: "url", Value: "https://example.com/\xff"}}
	sessions := []*TTPSession{{SessionID: "raw", IOCIDs: []string{"url:raw\xff"}}}
	for name, call := range map[string]func() error{
		"ES baseline":       func() error { _, err := es.ReadIntelligenceIOCs(ctx, iocs); return err },
		"PG baseline":       func() error { _, err := pg.ReadIntelligenceIOCs(ctx, iocs); return err },
		"ES projection":     func() error { return es.ReplaceIntelligenceIOCs(ctx, 1, iocs) },
		"PG projection":     func() error { return pg.ReplaceIntelligenceIOCs(ctx, 1, iocs) },
		"ES session":        func() error { return es.ReplaceIntelligenceSessions(ctx, 1, sessions) },
		"PG session":        func() error { return pg.ReplaceIntelligenceSessions(ctx, 1, sessions) },
		"ES legacy IOC":     func() error { return es.InsertIOCs(ctx, iocs) },
		"PG legacy IOC":     func() error { return pg.InsertIOCs(ctx, iocs) },
		"ES legacy session": func() error { return es.UpsertTTPSession(ctx, sessions[0]) },
		"PG legacy session": func() error { return pg.UpsertTTPSession(ctx, sessions[0]) },
	} {
		var encoding *IntelligenceEncodingError
		if err := call(); !errors.As(err, &encoding) {
			t.Fatalf("%s did not fail closed before connection access: %v", name, err)
		}
	}
	if requests != 0 {
		t.Fatalf("rejected indicators sent %d backend requests", requests)
	}
}
func TestIntelligenceTextValidationPreservesDistinctValidIdentities(t *testing.T) {
	for _, value := range []string{"https://example.com/%FF", "https://example.com/�", "https://example.com/café"} {
		ioc := &IOC{ID: "url:" + value, Type: "url", Value: value}
		before := *ioc
		for _, rejectNUL := range []bool{false, true} {
			if err := validateIntelligenceTextIOCs("test", rejectNUL, []*IOC{ioc}); err != nil {
				t.Fatal(err)
			}
		}
		if !reflect.DeepEqual(*ioc, before) {
			t.Fatal("validation changed an observed identity")
		}
	}
}

func TestElasticsearchRejectsLossyEventTextBeforeIngestion(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; fmt.Fprint(w, `{}`) }))
	defer srv.Close()
	db := &Elasticsearch{client: srv.Client(), baseURL: srv.URL, config: &config.DatabaseConfig{}}
	for _, event := range []*Event{
		{Username: "private-user\xff"}, {Password: "private-pass\xff"}, {Command: "private-command\xff"}, {Metadata: map[string]string{"private-key\xff": "x"}}, {Metadata: map[string]string{"key": "private-value\xff"}},
	} {
		for _, err := range []error{db.InsertEvent(context.Background(), event), db.InsertEvents(context.Background(), []*Event{{Honeypot: "valid"}, event})} {
			var encoding *IntelligenceEncodingError
			if !errors.As(err, &encoding) {
				t.Fatalf("malformed event text not rejected: %v", err)
			}
			if strings.Contains(err.Error(), "private-") {
				t.Fatal("error exposed event text")
			}
		}
	}
	if requests != 0 {
		t.Fatalf("malformed event text sent to Elasticsearch: %d requests", requests)
	}
}
