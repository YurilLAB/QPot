package database

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// Lists ranked by a count keep one order when counts tie: by name (or
// address), the same on every call. The web UI redraws a list whose order
// changes. Each backend's test skips unless its QPOT_TEST_* switch is set.

func TestClickHouseTieOrder(t *testing.T) { checkTieOrder(t, connectCH(t), nil) }

func TestPGTieOrder(t *testing.T) { checkTieOrder(t, connectPG(t), nil) }

func TestESTieOrder(t *testing.T) {
	es := connectES(t)
	checkTieOrder(t, es, func() { esRefresh(t, es) })
}

// ranked orders keys by count (most first), then by key.
func ranked(counts map[string]int64) []string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

// prefixOf checks that got is the start of want, at least min long (the
// backends cut their lists at different lengths).
func prefixOf(t *testing.T, what string, got, want []string, min int) {
	t.Helper()
	if min > len(want) {
		min = len(want)
	}
	if len(got) < min || len(got) > len(want) || !reflect.DeepEqual(got, want[:len(got)]) {
		t.Errorf("%s: got %v, want the start of %v", what, got, want)
	}
}

// checkTieOrder stores events far in the future (so the lists see only this
// run's rows: an earlier run's rows are earlier), in three one-second windows:
//
//	B  attackers: 198.51.100.19 ten times, .11 to .18 nine times each, each
//	   on three honeypots;
//	C  one honeypot's credentials and commands: one value three times, twelve
//	   values twice each, every event from its own address;
//	A  stats: thirteen countries three times each (one four times), five
//	   honeypots eight times each, all from one address.
//
// Then it asks for each list ten times.
func checkTieOrder(t *testing.T, db Database, refresh func()) {
	t.Helper()
	ctx := context.Background()
	// Ten future seconds per second of now (around 2090): a run's rows (three
	// whole seconds; ClickHouse compares the lists' `since` in whole seconds)
	// come after every earlier run's.
	t0 := time.Unix(2_900_000_000+(time.Now().Unix()-1_700_000_000)*10, 0).UTC()
	tA := t0.Add(2 * time.Second)
	tag := fmt.Sprintf("o%d", time.Now().UnixNano()%1e9)
	var evs []*Event
	at := func(base time.Time) time.Time { return base.Add(time.Duration(len(evs)%100) * time.Millisecond) }

	// B
	attackerCounts := map[string]int64{}
	for ip := 11; ip <= 19; ip++ {
		n := 9
		if ip == 19 {
			n = 10
		}
		addr := fmt.Sprintf("198.51.100.%d", ip)
		for k := 0; k < n; k++ {
			evs = append(evs, &Event{Timestamp: at(t0), Honeypot: fmt.Sprintf("%sb%d", tag, k%3), SourceIP: addr,
				Protocol: "tcp", EventType: "connect", Country: "ZB"})
		}
		attackerCounts[addr] = int64(n)
	}
	// C
	hpC := tag + "c"
	values := map[string]int64{}
	for e := 0; e < 27; e++ {
		v := "zeta"
		if e >= 3 {
			v = fmt.Sprintf("v%02d", (e-3)/2+1)
		}
		values[v]++
		evs = append(evs, &Event{Timestamp: at(t0.Add(time.Second)), Honeypot: hpC,
			SourceIP: fmt.Sprintf("192.0.2.%d", e+1), Protocol: "tcp", EventType: "login",
			Username: "u-" + v, Password: "p-" + v, Command: "c-" + v, Country: "ZC"})
	}
	// A
	countries, honeypots := map[string]int64{}, map[string]int64{}
	for c := 0; c < 13; c++ {
		code := "Q" + string(rune('A'+c))
		n := 3
		if code == "QM" {
			n = 4
		}
		for k := 0; k < n; k++ {
			hp := fmt.Sprintf("%sa%d", tag, len(evs)%5)
			evs = append(evs, &Event{Timestamp: at(tA), Honeypot: hp, SourceIP: "203.0.113.50",
				Protocol: "tcp", EventType: "connect", Country: code})
			countries[code]++
			honeypots[hp]++
		}
	}
	if err := db.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	if refresh != nil {
		refresh()
	}

	wantCountries, wantHoneypots, wantAttackers := ranked(countries), ranked(honeypots), ranked(attackerCounts)
	with := func(prefix string, keys []string) []string {
		out := make([]string, len(keys))
		for i, k := range keys {
			out[i] = prefix + k
		}
		return out
	}
	var first [5][]string
	for call := 0; call < 10; call++ {
		st, err := db.GetStats(ctx, tA)
		if err != nil {
			t.Fatal(err)
		}
		var gotC, gotH []string
		for _, c := range st.TopCountries {
			gotC = append(gotC, c.Country)
		}
		for _, h := range st.TopHoneypots {
			gotH = append(gotH, h.Honeypot)
		}
		top, err := db.GetTopAttackers(ctx, 5, t0)
		if err != nil {
			t.Fatal(err)
		}
		var gotA []string
		for _, a := range top {
			gotA = append(gotA, a.SourceIP)
			if !sort.StringsAreSorted(a.Honeypots) {
				t.Errorf("%s's honeypots %v not in order", a.SourceIP, a.Honeypots)
			}
		}
		hs, err := db.GetHoneypotStats(ctx, hpC, t0)
		if err != nil {
			t.Fatal(err)
		}
		var gotU []string
		for _, u := range hs.TopUsernames {
			gotU = append(gotU, u.Value)
		}
		var gotP []string
		for _, p := range hs.TopPasswords {
			gotP = append(gotP, p.Value)
		}
		var gotCmd []string
		for _, c := range hs.Commands {
			gotCmd = append(gotCmd, c.Command)
		}
		now := [5][]string{gotC, gotH, gotA, append(gotU, gotP...), gotCmd}
		if call == 0 {
			first = now
			prefixOf(t, "top countries", gotC, wantCountries, 10)
			prefixOf(t, "top honeypots", gotH, wantHoneypots, 5)
			prefixOf(t, "top attackers", gotA, wantAttackers, 5)
			prefixOf(t, "top usernames", gotU, with("u-", ranked(values)), 10)
			prefixOf(t, "top passwords", gotP, with("p-", ranked(values)), 10)
			prefixOf(t, "commands", gotCmd, with("c-", ranked(values)), 10)
			continue
		}
		if !reflect.DeepEqual(now, first) {
			t.Fatalf("call %d: %v, first %v", call+1, now, first)
		}
	}
}

// Without an Elasticsearch server: every terms aggregation the ranked lists
// ask for orders by count, then by key.
func TestESTermsOrderTies(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		var b map[string]any
		if json.Unmarshal(data, &b) == nil {
			mu.Lock()
			bodies = append(bodies, b)
			mu.Unlock()
		}
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()
	es := &Elasticsearch{config: &config.DatabaseConfig{}, client: srv.Client(), baseURL: srv.URL}
	ctx := context.Background()
	since := time.Unix(1_800_000_000, 0)
	_, _ = es.GetStats(ctx, since)
	_, _ = es.GetTopAttackers(ctx, 5, since)
	_, _ = es.GetHoneypotStats(ctx, "cowrie", since)

	var aggs int
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch v := v.(type) {
		case map[string]any:
			if terms, ok := v["terms"].(map[string]any); ok {
				if _, isAgg := terms["field"]; isAgg {
					aggs++
					got, _ := json.Marshal(terms["order"])
					if string(got) != `[{"_count":"desc"},{"_key":"asc"}]` {
						t.Errorf("%s: terms on %v ordered %s", path, terms["field"], got)
					}
				}
			}
			for k, c := range v {
				walk(path+"."+k, c)
			}
		case []any:
			for _, c := range v {
				walk(path, c)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, b := range bodies {
		walk("", b)
	}
	if aggs != 8 {
		t.Errorf("found %d terms aggregations in %d requests, want 8", aggs, len(bodies))
	}
}
