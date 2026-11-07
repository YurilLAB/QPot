package database

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// hostileText is a search term with SQL, LIKE and Lucene syntax in it.
const hostileText = `o'brien"; DROP TABLE events; -- %_*?\ [a-z] AND 1:1`

// TimescaleDB: every filter value is a $n parameter, the placeholders run
// $1..$n with one argument each, and EventTypes filters (GetEvents once
// dropped it, so an event_type filter returned every type).
func TestPGEventsQuery(t *testing.T) {
	types := []string{"login", "command"}
	q, args := pgEventsQuery(EventFilter{EventTypes: types})
	if !strings.Contains(q, "event_type = ANY($1)") || len(args) != 1 || !reflect.DeepEqual(args[0], types) {
		t.Fatalf("EventTypes alone: %s %v", q, args)
	}

	f := EventFilter{
		StartTime: time.Unix(1, 0), EndTime: time.Unix(2, 0),
		Honeypots: []string{"cowrie"}, SourceIPs: []string{"203.0.113.5"}, Countries: []string{"DE"},
		EventTypes: types, Text: hostileText, Limit: 10, Offset: 20,
	}
	q, args = pgEventsQuery(f)
	if strings.Contains(q, "brien") || strings.Contains(q, "DROP") {
		t.Fatalf("the search term is in the SQL: %s", q)
	}
	seen := map[int]bool{}
	for _, m := range regexp.MustCompile(`\$(\d+)`).FindAllStringSubmatch(q, -1) {
		n, _ := strconv.Atoi(m[1])
		seen[n] = true
	}
	if len(seen) != len(args) {
		t.Fatalf("%d placeholders, %d arguments: %s", len(seen), len(args), q)
	}
	for i := 1; i <= len(args); i++ {
		if !seen[i] {
			t.Fatalf("placeholder $%d missing: %s", i, q)
		}
	}
	at := func(re string) interface{} {
		t.Helper()
		m := regexp.MustCompile(re).FindStringSubmatch(q)
		if m == nil {
			t.Fatalf("%s not in %s", re, q)
		}
		n, _ := strconv.Atoi(m[1])
		return args[n-1]
	}
	if got := at(`event_type = ANY\(\$(\d+)\)`); !reflect.DeepEqual(got, types) {
		t.Errorf("event_type bound to %v", got)
	}
	if got := at(`strpos\(lower\(COALESCE\(username, ''\)\), lower\(\$(\d+)\)\)`); got != hostileText {
		t.Errorf("text bound to %v", got)
	}
	if got := at(`LIMIT \$(\d+)`); got != 10 {
		t.Errorf("limit bound to %v", got)
	}
	if got := at(`OFFSET \$(\d+)`); got != 20 {
		t.Errorf("offset bound to %v", got)
	}
	if strings.Contains(q, " LIKE ") || strings.Contains(q, "ILIKE") {
		t.Errorf("the text search uses LIKE, whose %% and _ are wildcards: %s", q)
	}
}

// Elasticsearch: the term reaches the query only as a wildcard value (its
// own * ? \ escaped) and a match_phrase value, never as query syntax.
func TestESEventQueryText(t *testing.T) {
	if got := escapeWildcard(`a*b?c\d`); got != `a\*b\?c\\d` {
		t.Fatalf("escapeWildcard: %q", got)
	}
	body, err := json.Marshal(buildEventQuery(EventFilter{Text: hostileText, EventTypes: []string{"login"}}))
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if strings.Contains(s, "query_string") {
		t.Fatalf("query syntax: %s", s)
	}
	var q struct {
		Bool struct {
			Must []map[string]json.RawMessage `json:"must"`
		} `json:"bool"`
	}
	if err := json.Unmarshal(body, &q); err != nil || len(q.Bool.Must) != 2 {
		t.Fatalf("query: %s (%v)", s, err)
	}
	if string(q.Bool.Must[0]["terms"]) != `{"event_type":["login"]}` {
		t.Errorf("event type filter: %s", s)
	}
	var text struct {
		Should []struct {
			Wildcard map[string]struct {
				Value           string
				CaseInsensitive bool `json:"case_insensitive"`
			} `json:"wildcard"`
			MatchPhrase map[string]string `json:"match_phrase"`
		} `json:"should"`
		Min int `json:"minimum_should_match"`
	}
	if err := json.Unmarshal(q.Bool.Must[1]["bool"], &text); err != nil || text.Min != 1 || len(text.Should) != 4 {
		t.Fatalf("text clause: %s (%v)", s, err)
	}
	want := "*" + escapeWildcard(hostileText) + "*"
	fields := map[string]bool{}
	for _, c := range text.Should {
		for field, w := range c.Wildcard {
			fields[field] = true
			if w.Value != want || !w.CaseInsensitive {
				t.Errorf("%s: wildcard %q (case_insensitive %v), want %q", field, w.Value, w.CaseInsensitive, want)
			}
		}
		for field, v := range c.MatchPhrase {
			fields["phrase:"+field] = true
			if v != hostileText {
				t.Errorf("match_phrase %s: %q", field, v)
			}
		}
	}
	if !fields["username"] || !fields["password"] || !fields["command.keyword"] || !fields["phrase:command"] {
		t.Errorf("fields searched: %v", fields)
	}
}
