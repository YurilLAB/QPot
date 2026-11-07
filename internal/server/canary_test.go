package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
)

// newCanaryTestServer builds a Server with the canary subsystem and routes
// wired, backed by a fakeDB and a fresh store under a temp dir.
func newCanaryTestServer(t *testing.T, db *fakeDB) *Server {
	t.Helper()
	cs, err := canary.NewStore(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	s := &Server{
		config: &config.Config{
			QPotID: validTestID,
			WebUI:  config.WebUIConfig{QPotIDAuth: true},
			Canary: config.CanaryConfig{Enabled: true, BaseURL: "https://assets.example.com", Decoy: "notfound"},
		},
		mux:      http.NewServeMux(),
		canaries: cs,
	}
	if db != nil {
		s.database = db
	}
	s.setupRoutes()
	return s
}

func authReq(method, path, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("X-QPot-ID", validTestID)
	return r
}

func TestCanaryBeaconRecordsTripAndEmitsEvent(t *testing.T) {
	db := &fakeDB{}
	s := newCanaryTestServer(t, db)

	// Mint a web canary through the management API.
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, authReq(http.MethodPost, "/api/canaries", `{"kind":"web","name":"bookmark","memo":"fake link"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("create: status %d body %s", rec.Code, rec.Body.String())
	}
	var created map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	url, _ := created["url"].(string)
	const want = "https://assets.example.com/c/"
	if !strings.HasPrefix(url, want) {
		t.Fatalf("url = %q, want prefix %q", url, want)
	}
	token := strings.TrimPrefix(url, want)

	// Hit the public beacon — UNauthenticated — and expect the decoy 404.
	beacon := httptest.NewRequest(http.MethodGet, "/c/"+token, nil)
	beacon.RemoteAddr = "203.0.113.9:51000"
	beacon.Header.Set("User-Agent", "curl/8.0")
	brec := httptest.NewRecorder()
	s.mux.ServeHTTP(brec, beacon)
	if brec.Code != http.StatusNotFound {
		t.Fatalf("beacon decoy status = %d, want 404", brec.Code)
	}

	// The trip must be recorded and surfaced via the trips API.
	trec := httptest.NewRecorder()
	s.mux.ServeHTTP(trec, authReq(http.MethodGet, "/api/canaries/trips", ""))
	if trec.Code != http.StatusOK {
		t.Fatalf("trips: status %d", trec.Code)
	}
	var tr map[string]interface{}
	json.Unmarshal(trec.Body.Bytes(), &tr)
	trips, _ := tr["trips"].([]interface{})
	if len(trips) != 1 {
		t.Fatalf("trips = %d, want 1", len(trips))
	}
	first, _ := trips[0].(map[string]interface{})
	if first["source_ip"] != "203.0.113.9" {
		t.Fatalf("trip source_ip = %v", first["source_ip"])
	}
	if first["channel"] != "http" {
		t.Fatalf("trip channel = %v", first["channel"])
	}

	// A canary trip event must have been emitted into the events pipeline.
	evs := db.insertedEvents()
	if len(evs) != 1 {
		t.Fatalf("inserted events = %d, want 1", len(evs))
	}
	if evs[0].Honeypot != "canary" || evs[0].EventType != "canary_trip" {
		t.Fatalf("event = %+v", evs[0])
	}
	if !evs[0].Classified || evs[0].Metadata["severity"] != "critical" {
		t.Fatalf("canary event must be classified critical: %+v", evs[0])
	}
}

func TestCanaryBeaconUnknownTokenIsSilentDecoy(t *testing.T) {
	db := &fakeDB{}
	s := newCanaryTestServer(t, db)

	req := httptest.NewRequest(http.MethodGet, "/c/doesnotexisttoken", nil)
	req.RemoteAddr = "198.51.100.2:40000"
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown-token status = %d, want 404 decoy", rec.Code)
	}
	if len(db.insertedEvents()) != 0 {
		t.Fatal("unknown token must not emit an event")
	}
}

func TestCanaryManagementRequiresAuth(t *testing.T) {
	s := newCanaryTestServer(t, &fakeDB{})
	// No X-QPot-ID header.
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/canaries", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/canaries status = %d, want 401", rec.Code)
	}
}

func TestCanaryCreateRejectsBadKind(t *testing.T) {
	s := newCanaryTestServer(t, &fakeDB{})
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, authReq(http.MethodPost, "/api/canaries", `{"kind":"sql"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad kind status = %d, want 400", rec.Code)
	}
}

func TestCanaryFileArtifactDownload(t *testing.T) {
	s := newCanaryTestServer(t, &fakeDB{})
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, authReq(http.MethodPost, "/api/canaries", `{"kind":"file","name":"Q4 Salaries"}`))
	var created map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &created)
	id, _ := created["id"].(string)

	arec := httptest.NewRecorder()
	s.mux.ServeHTTP(arec, authReq(http.MethodGet, "/api/canaries/artifact?id="+id, ""))
	if arec.Code != http.StatusOK {
		t.Fatalf("artifact status = %d", arec.Code)
	}
	if ct := arec.Header().Get("Content-Disposition"); !strings.Contains(ct, "attachment") {
		t.Fatalf("missing attachment disposition: %q", ct)
	}
	if !strings.Contains(arec.Body.String(), "/c/") {
		t.Fatal("artifact does not embed a beacon URL")
	}
}

// A download without an id is a bad request, not a missing canary; an
// unknown id is.
func TestCanaryArtifactNeedsAnID(t *testing.T) {
	s := newCanaryTestServer(t, &fakeDB{})
	for _, c := range []struct {
		path string
		want int
		msg  string
	}{
		{"/api/canaries/artifact", http.StatusBadRequest, "id required"},
		{"/api/canaries/artifact?id=", http.StatusBadRequest, "id required"},
		{"/api/canaries/artifact?id=cnry_nosuch", http.StatusNotFound, "canary not found"},
	} {
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, authReq(http.MethodGet, c.path, ""))
		var e map[string]string
		if rec.Code != c.want || json.Unmarshal(rec.Body.Bytes(), &e) != nil || e["error"] != c.msg {
			t.Errorf("%s: %d %s, want %d %q", c.path, rec.Code, rec.Body.String(), c.want, c.msg)
		}
	}
}

func TestCanaryMatcherTripsOnCredentialInSession(t *testing.T) {
	db := &fakeDB{}
	s := newCanaryTestServer(t, &fakeDB{})
	s.database = db

	// Mint an AWS canary.
	c, err := s.canaries.Create(canary.KindAWS, "ci", "jenkins")
	if err != nil {
		t.Fatalf("create aws canary: %v", err)
	}

	m := &canaryMatcher{s: s}
	// An attacker session that pastes the stolen access key.
	ev := &database.Event{
		Honeypot: "cowrie",
		SourceIP: "203.0.113.50",
		Command:  "aws s3 ls --access-key " + c.AccessKeyID,
	}
	if !m.MatchEvent(t.Context(), ev) {
		t.Fatal("expected canary match on planted credential")
	}
	// It must have emitted a canary event tagged honeypot=canary, channel=honeypot.
	evs := db.insertedEvents()
	if len(evs) != 1 || evs[0].Honeypot != "canary" {
		t.Fatalf("matcher events = %+v", evs)
	}
	if evs[0].Metadata["channel"] != "honeypot" {
		t.Fatalf("channel = %q, want honeypot", evs[0].Metadata["channel"])
	}
	// A non-canary event must not match.
	if m.MatchEvent(t.Context(), &database.Event{Honeypot: "cowrie", Command: "ls -la"}) {
		t.Fatal("unexpected match on benign session")
	}
}

// Only watched values in collected event fields are observable. A file path or
// a command using credentials implicitly is not evidence that QPot captured them.
func TestCanaryMatcherObservationBoundary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		event func(*canary.Canary) *database.Event
		want  bool
	}{
		{"credential file read", func(c *canary.Canary) *database.Event {
			return &database.Event{Command: "cat /root/.aws/credentials"}
		}, false},
		{"credential file copy", func(c *canary.Canary) *database.Event {
			return &database.Event{Command: "cp /root/.aws/credentials /tmp/credentials"}
		}, false},
		{"AWS command without captured values", func(c *canary.Canary) *database.Event {
			return &database.Event{Command: "aws sts get-caller-identity"}
		}, false},
		{"key in command", func(c *canary.Canary) *database.Event {
			return &database.Event{Command: "export AWS_ACCESS_KEY_ID=" + c.AccessKeyID}
		}, true},
		{"key in username", func(c *canary.Canary) *database.Event {
			return &database.Event{Username: c.AccessKeyID}
		}, true},
		{"secret in password", func(c *canary.Canary) *database.Event {
			return &database.Event{Password: c.SecretAccessKey}
		}, true},
		{"key in payload", func(c *canary.Canary) *database.Event {
			return &database.Event{Payload: []byte("aws_access_key_id=" + c.AccessKeyID)}
		}, true},
		{"key in metadata value", func(c *canary.Canary) *database.Event {
			return &database.Event{Metadata: map[string]string{"captured": c.AccessKeyID}}
		}, true},
		{"authorized test containing key", func(c *canary.Canary) *database.Event {
			return &database.Event{Command: "echo " + c.AccessKeyID + " # authorized canary test"}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &fakeDB{}
			s := newCanaryTestServer(t, db)
			c, err := s.canaries.Create(canary.KindAWS, "ci", "runner")
			if err != nil {
				t.Fatal(err)
			}
			ev := tc.event(c)
			ev.Honeypot = "cowrie"
			ev.SourceIP = "203.0.113.50"
			if got := (&canaryMatcher{s: s}).MatchEvent(t.Context(), ev); got != tc.want {
				t.Fatalf("matched=%v, want %v", got, tc.want)
			}
			wantCount := 0
			if tc.want {
				wantCount = 1
			}
			trips := s.canaries.Trips(0)
			events := db.insertedEvents()
			if len(trips) != wantCount || len(events) != wantCount {
				t.Fatalf("trips=%d events=%d, want %d each", len(trips), len(events), wantCount)
			}
			if tc.want && (trips[0].CanaryID != c.ID || trips[0].Channel != "honeypot" || events[0].Metadata["canary_id"] != c.ID) {
				t.Fatal("observed value did not preserve its canary identity and channel")
			}
		})
	}
}

func TestCanaryArtifactReadNeedsObservedTrigger(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			db := &fakeDB{}
			s := newCanaryTestServer(t, db)
			c, err := s.canaries.Create(canary.KindFile, "report", "share")
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			s.mux.ServeHTTP(rec, authReq(http.MethodGet, "/api/canaries/artifact?id="+c.ID, ""))
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), c.URL(s.config.Canary.BaseURL)) {
				t.Fatal("artifact did not contain the expected beacon")
			}
			// Downloading/reading bytes does not fetch their linked resources.
			if len(s.canaries.Trips(0)) != 0 || len(db.insertedEvents()) != 0 {
				t.Fatal("artifact bytes alone triggered a trip")
			}
			// A link scanner can issue the same request as a malicious reader.
			// QPot records the interaction, not the requester's intent.
			req := httptest.NewRequest(method, "/c/"+c.Token+"?r=img", nil)
			req.Header.Set("User-Agent", "Authorized-Link-Scanner/1.0")
			s.mux.ServeHTTP(httptest.NewRecorder(), req)
			trips := s.canaries.Trips(0)
			if len(trips) != 1 || len(db.insertedEvents()) != 1 {
				t.Fatal("beacon request was not recorded")
			}
			if trips[0].Channel != "http" || trips[0].UserAgent != req.UserAgent() {
				t.Fatalf("beacon observation context lost: %+v", trips[0])
			}
		})
	}
}
