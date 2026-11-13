package behaviour

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
)

var t0 = time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)

func at(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }

// sessionsOf builds real sessions: the campaign builder's IDs and
// fingerprints, with the stages given.
func session(t testing.TB, ip string, first, last int, sum string, stages ...string) *database.TTPSession {
	t.Helper()
	b := intelligence.NewTTPBuilder(1000 * time.Hour)
	e := &database.Event{Timestamp: at(first), Honeypot: "cowrie", SourceIP: ip, EventType: "cowrie.session.file_download"}
	if sum != "" {
		e.Metadata = map[string]string{"shasum": sum}
	}
	b.Update(e)
	s := b.GetActiveSessions()[0]
	s.FirstSeen, s.LastSeen, s.KillChainStages = at(first), at(last), stages
	return s
}

func hash(n int) string { return fmt.Sprintf("%064x", n) }

func payload(n int, first int) *database.IOC {
	return &database.IOC{Type: intelligence.IOCTypeHash, Value: hash(n), Honeypot: "cowrie", SourceIP: "203.0.113.5", FirstSeen: at(first), LastSeen: at(first)}
}

func rules(alerts []Alert) string {
	var out []string
	for _, a := range alerts {
		out = append(out, a.Rule)
	}
	return strings.Join(out, ",")
}

// What is there when the feature first runs is remembered, not alerted; what
// comes after alerts once.
func TestBaselineThenEachThingOnce(t *testing.T) {
	var state State
	old := Input{Now: at(0),
		Payloads: []*database.IOC{payload(1, -500)},
		Sessions: []*database.TTPSession{session(t, "198.51.100.1", -60, -50, "", "discovery", "persistence")},
	}
	if got := Evaluate(&state, old); len(got) != 0 || !state.Started.Equal(at(0)) {
		t.Fatalf("the baseline raised %s", rules(got))
	}
	// The same again: still nothing.
	old.Now = at(1)
	if got := Evaluate(&state, old); len(got) != 0 {
		t.Fatalf("what was there before raised %s", rules(got))
	}

	in := Input{Now: at(10),
		Payloads: append(old.Payloads, payload(2, 5)),
		Sessions: append(old.Sessions, session(t, "198.51.100.2", 3, 8, "", "initial-access", "discovery", "execution", "persistence")),
	}
	got := Evaluate(&state, in)
	if rules(got) != RuleNewPayload+","+RuleProgression {
		t.Fatalf("raised %s", rules(got))
	}
	p, s := got[0], got[1]
	if p.Severity != "high" || !strings.Contains(p.Detail, hash(2)) || p.Evidence[0] != "sha256 "+hash(2) || !p.Time.Equal(at(10)) || len(p.ID) != 24 {
		t.Fatalf("payload alert: %+v", p)
	}
	if s.SessionID != in.Sessions[1].SessionID || s.Sources[0] != "198.51.100.2" || !strings.Contains(s.Detail, "discovery, execution, persistence") {
		t.Fatalf("progression alert: %+v", s)
	}
	in.Now = at(11)
	if again := Evaluate(&state, in); len(again) != 0 {
		t.Fatalf("the same things raised again: %s", rules(again))
	}
	if len(state.Alerts) != 2 {
		t.Fatalf("%d alerts kept", len(state.Alerts))
	}
}

func TestProgressionNeedsDiscoveryFirst(t *testing.T) {
	for stages, want := range map[string]bool{
		"discovery,persistence":                  true,
		"initial-access,discovery,x,persistence": true,
		"persistence,discovery":                  false, // it stayed first and looked around after
		"persistence":                            false,
		"discovery,execution":                    false,
		"":                                       false,
	} {
		s := &database.TTPSession{KillChainStages: strings.Split(stages, ",")}
		if progressed(s) != want {
			t.Errorf("stages %q: progressed = %v", stages, !want)
		}
	}
}

// A source that ran commands, left for an hour or more and runs commands
// again is a returning visitor. One that only knocked is not, and neither is
// a session without a source of its own.
func TestReturningVisitor(t *testing.T) {
	var state State
	Evaluate(&state, Input{Now: at(0)})
	first := session(t, "198.51.100.7", 1, 5, "", "discovery")
	cases := []struct {
		name string
		s    *database.TTPSession
		want bool
	}{
		{"back after two hours, hands on", session(t, "198.51.100.7", 125, 130, "", "execution"), true},
		{"back after ten minutes", session(t, "198.51.100.7", 15, 20, "", "execution"), false},
		{"back, only guessing passwords", session(t, "198.51.100.7", 125, 130, "", "credential-access"), false},
		{"another source", session(t, "198.51.100.8", 125, 130, "", "execution"), false},
	}
	for _, tc := range cases {
		st := state
		st.Sessions, st.Payloads, st.Campaigns, st.Trips = nil, nil, nil, nil
		got := Evaluate(&st, Input{Now: at(200), Sessions: []*database.TTPSession{tc.s, first}})
		if has := strings.Contains(rules(got), RuleReturningVisitor); has != tc.want {
			t.Errorf("%s: raised %q", tc.name, rules(got))
		}
		if tc.want && (got[0].SessionID != tc.s.SessionID || got[0].Evidence[0] != "earlier session "+first.SessionID || !strings.Contains(got[0].Detail, "2h0m0s")) {
			t.Errorf("%s: %+v", tc.name, got[0])
		}
	}
	// The earlier visit was only a knock: a later hands-on visit is a first.
	st := State{Started: at(0)}
	knock := session(t, "198.51.100.7", 1, 5, "", "credential-access")
	if got := Evaluate(&st, Input{Now: at(200), Sessions: []*database.TTPSession{knock, cases[0].s}}); len(got) != 0 {
		t.Fatalf("raised %s", rules(got))
	}
	// A session whose address is Docker's lists no source, and is no one.
	st = State{Started: at(0)}
	a, b := *first, *cases[0].s
	a.SourceIPs, b.SourceIPs = nil, nil
	if got := Evaluate(&st, Input{Now: at(200), Sessions: []*database.TTPSession{&a, &b}}); len(got) != 0 {
		t.Fatalf("a shared address returned: %s", rules(got))
	}
}

// A campaign alerts when a second source joins it, and again at five, ten:
// not for every session, and not for one source seen twice.
func TestSharedPlaybookAlertsAsACampaignGrows(t *testing.T) {
	state := State{Started: at(0)}
	var sessions []*database.TTPSession
	add := func(n int) []Alert {
		for len(sessions) < n {
			i := len(sessions)
			sessions = append(sessions, session(t, fmt.Sprintf("198.51.100.%d", i+1), 10+i, 11+i, hash(77), "execution"))
		}
		return Evaluate(&state, Input{Now: at(100 + n), Sessions: sessions})
	}
	// The builder gives each source its own campaign until evidence links
	// them: here they are stored as linked, as the worker would rewrite them.
	link := func() {
		for _, s := range sessions {
			s.CampaignFingerprint = "c0ffee00c0ffee00c0ffee00c0ffee00"
		}
	}
	if got := add(1); len(got) != 0 {
		t.Fatalf("one source: %s", rules(got))
	}
	// The same source again, in a later session: still one source.
	sessions = append(sessions, session(t, "198.51.100.1", 300, 301, hash(77), "execution"))
	link()
	if got := Evaluate(&state, Input{Now: at(400), Sessions: sessions}); strings.Contains(rules(got), RuleSharedPlaybook) {
		t.Fatalf("one source in two sessions: %s", rules(got))
	}
	sessions = sessions[:1]
	want := map[int]string{2: "2 sources", 3: "", 4: "", 5: "5 sources", 6: "", 9: "", 10: "10 sources", 11: ""}
	for _, n := range []int{2, 3, 4, 5, 6, 9, 10, 11} {
		add(n)
		link()
		got := Evaluate(&state, Input{Now: at(500 + n), Sessions: sessions})
		title := ""
		for _, a := range got {
			if a.Rule == RuleSharedPlaybook {
				title = a.Title
				if a.Campaign != "c0ffee00c0ffee00c0ffee00c0ffee00" || len(a.Sources) == 0 || len(a.Sources) > maxSources {
					t.Fatalf("alert: %+v", a)
				}
			}
		}
		if (want[n] == "") != (title == "") || !strings.HasPrefix(title, want[n]) {
			t.Errorf("%d sources: %q", n, title)
		}
	}
}

// A credential planted in one honeypot and captured in another was carried
// over. The same credential used where it was planted is the ordinary trip,
// and an operator's own canary has no home service to differ from.
func TestPlantedCredentialUsedElsewhere(t *testing.T) {
	canaries := []*canary.Canary{
		{ID: "cnry_db", Name: "cowrie bait: shop database password", Memo: "in /root/.pgpass", Planted: true},
		{ID: "cnry_own", Name: "my bait: wiki", Planted: false},
		{ID: "cnry_odd", Name: "unnamed", Planted: true},
	}
	trip := func(id, cn, detail string, min int) *canary.Trip {
		return &canary.Trip{ID: id, CanaryID: cn, Channel: "honeypot", Time: at(min), SourceIP: "203.0.113.9", Detail: detail}
	}
	state := State{Started: at(0)}
	got := Evaluate(&state, Input{Now: at(60), Canaries: canaries, Trips: []*canary.Trip{
		trip("trip_1", "cnry_db", "matched in heralding session", 30),
		trip("trip_2", "cnry_db", "matched in cowrie session", 31),
		trip("trip_3", "cnry_own", "matched in heralding session", 32),
		trip("trip_4", "cnry_odd", "matched in heralding session", 33),
		trip("trip_5", "cnry_db", "", 34),
		trip("trip_6", "cnry_db", "matched in dionaea session", -5), // before the baseline
		nil,
	}})
	if len(got) != 1 || got[0].Rule != RuleCredentialReuse || got[0].Severity != "critical" ||
		got[0].Title != "A credential planted in cowrie was used against heralding" || got[0].Sources[0] != "203.0.113.9" ||
		!strings.Contains(got[0].Detail, "/root/.pgpass") || !reflect.DeepEqual(got[0].Evidence, []string{"canary cnry_db", "trip trip_1"}) {
		t.Fatalf("raised %+v", got)
	}
	if again := Evaluate(&state, Input{Now: at(61), Canaries: canaries, Trips: []*canary.Trip{trip("trip_1", "cnry_db", "matched in heralding session", 30)}}); len(again) != 0 {
		t.Fatalf("one trip raised twice")
	}
}

// A rule that is off raises nothing, and what happened while it was off does
// not alert when it is turned on again.
func TestRuleTurnedOff(t *testing.T) {
	state := State{Started: at(0)}
	in := Input{Now: at(10), Payloads: []*database.IOC{payload(5, 5)}, Off: []string{RuleNewPayload},
		Sessions: []*database.TTPSession{session(t, "198.51.100.2", 3, 8, "", "discovery", "persistence")}}
	if got := Evaluate(&state, in); rules(got) != RuleProgression {
		t.Fatalf("raised %s", rules(got))
	}
	in.Off, in.Now = nil, at(11)
	if got := Evaluate(&state, in); len(got) != 0 {
		t.Fatalf("turned on again, the past raised %s", rules(got))
	}
	for _, r := range Rules {
		if !IsRule(r.Name) || r.Label == "" || r.Description == "" || severityOf(r.Name) != r.Severity {
			t.Fatalf("rule %+v", r)
		}
	}
	if IsRule("volume") || len(Rules) != 5 {
		t.Fatal("rules")
	}
}

// One run raises at most MaxPerRun, the most severe first; the rest follow
// on later runs, none lost and none twice. The kept list is bounded.
func TestManyAtOnce(t *testing.T) {
	state := State{Started: at(0)}
	in := Input{Now: at(10)}
	for i := 0; i < 60; i++ {
		in.Payloads = append(in.Payloads, payload(1000+i, 5))
	}
	in.Canaries = []*canary.Canary{{ID: "c", Name: "cowrie bait: key", Planted: true}}
	in.Trips = []*canary.Trip{{ID: "trip_x", CanaryID: "c", Time: at(5), Detail: "matched in dionaea session"}}
	seen := map[string]int{}
	total := 0
	for run := 0; run < 5; run++ {
		in.Now = at(10 + run)
		got := Evaluate(&state, in)
		if len(got) > MaxPerRun {
			t.Fatalf("run %d raised %d", run, len(got))
		}
		if run == 0 && (len(got) != MaxPerRun || got[0].Rule != RuleCredentialReuse) {
			t.Fatalf("first run: %d alerts, first %s", len(got), got[0].Rule)
		}
		for _, a := range got {
			seen[a.ID]++
			total++
		}
	}
	if total != 61 || len(seen) != 61 {
		t.Fatalf("%d alerts for 61 things (%d distinct)", total, len(seen))
	}
	for i := 0; i < 700; i++ {
		in.Payloads = []*database.IOC{payload(5000+i, 20)}
		in.Now = at(100 + i)
		Evaluate(&state, in)
	}
	if len(state.Alerts) != MaxAlerts || !state.Alerts[MaxAlerts-1].Time.Equal(at(799)) {
		t.Fatalf("%d alerts kept", len(state.Alerts))
	}
}

func TestStateIsSavedWhole(t *testing.T) {
	dir := t.TempDir()
	empty, err := Load(dir)
	if err != nil || !empty.Started.IsZero() {
		t.Fatalf("no file: %v", err)
	}
	state := State{Started: at(0)}
	Evaluate(&state, Input{Now: at(10), Payloads: []*database.IOC{payload(5, 5)}})
	if err := Save(dir, &state); err != nil {
		t.Fatal(err)
	}
	back, err := Load(dir)
	if err != nil || !reflect.DeepEqual(back.Alerts, state.Alerts) || len(back.Payloads) != 1 || !back.Started.Equal(at(0)) {
		t.Fatalf("read back: %v %+v", err, back)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("%d files left", len(entries))
	}
	if info, err := os.Stat(StatePath(dir)); err != nil || (info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/') {
		t.Fatalf("state file mode: %v", err)
	}
	// What was alerted is not alerted again after a restart.
	if got := Evaluate(back, Input{Now: at(11), Payloads: []*database.IOC{payload(5, 5)}}); len(got) != 0 {
		t.Fatal("alerted again after a restart")
	}
	for name, content := range map[string]string{"not JSON": "{", "a newer version": `{"version": 2}`} {
		if err := os.WriteFile(StatePath(dir), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir); err == nil {
			t.Errorf("%s was taken for a state", name)
		}
	}
}

func FuzzEvaluate(f *testing.F) {
	f.Add([]byte("p\x01\x05s\x01\x03\x02\x04t\x01\x02c\x03\x01"), uint8(3))
	f.Add([]byte("ssssssssss\x00\x00\x00\x00pppp"), uint8(1))
	f.Add([]byte{}, uint8(0))
	stageNames := []string{"discovery", "persistence", "execution", "credential-access", "initial-access", ""}
	f.Fuzz(func(t *testing.T, data []byte, runs uint8) {
		var in Input
		in.Canaries = []*canary.Canary{{ID: "c1", Name: "cowrie bait: k", Planted: true}, {ID: "c2", Name: string(data), Planted: true}}
		for i := 0; i+3 < len(data) && i < 400; i += 4 {
			a, b, c := int(data[i+1]), int(data[i+2]), int(data[i+3])
			switch data[i] % 4 {
			case 0:
				in.Payloads = append(in.Payloads, payload(a, b-100))
			case 1:
				s := session(t, fmt.Sprintf("198.51.100.%d", a%8), b, b+c, "", stageNames[a%len(stageNames)], stageNames[c%len(stageNames)])
				if c%3 == 0 {
					s.CampaignFingerprint = fmt.Sprintf("fp%d", c%4)
				}
				if c%11 == 0 {
					s.SourceIPs = nil
				}
				in.Sessions = append(in.Sessions, s)
			case 2:
				in.Trips = append(in.Trips, &canary.Trip{ID: fmt.Sprintf("t%d", a), CanaryID: fmt.Sprintf("c%d", 1+b%2), Time: at(c - 100),
					Detail: "matched in " + []string{"cowrie", "dionaea", "", "x y"}[c%4] + " session"})
			default:
				in.Off = append(in.Off, Rules[a%len(Rules)].Name)
			}
		}
		var state State
		seen := map[string]bool{}
		for run := 0; run <= int(runs%6); run++ {
			in.Now = at(run * 30)
			got := Evaluate(&state, in)
			if run == 0 && len(got) != 0 {
				t.Fatalf("the baseline raised %d", len(got))
			}
			if len(got) > MaxPerRun || len(state.Alerts) > MaxAlerts {
				t.Fatalf("%d raised, %d kept", len(got), len(state.Alerts))
			}
			for _, a := range got {
				if seen[a.ID] {
					t.Fatalf("%s raised twice: %+v", a.Rule, a)
				}
				seen[a.ID] = true
				if !IsRule(a.Rule) || a.Title == "" || a.Detail == "" || a.Severity == "" || len(a.Sources) > maxSources {
					t.Fatalf("alert: %+v", a)
				}
				for _, off := range in.Off {
					if a.Rule == off {
						t.Fatalf("rule %s is off and raised", off)
					}
				}
			}
		}
		// The state survives its file.
		dir := t.TempDir()
		if err := Save(dir, &state); err != nil {
			t.Fatal(err)
		}
		back, err := Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		in.Now = at(1000)
		if a, b := Evaluate(&state, in), Evaluate(back, in); len(a) != len(b) {
			t.Fatalf("after a restart %d alerts, without one %d", len(b), len(a))
		}
	})
}

func FuzzLoadState(f *testing.F) {
	f.Add([]byte(`{"version":1,"started":"2026-11-14T08:00:00Z","alerts":[{"id":"x","rule":"new-payload"}]}`))
	f.Add([]byte(`{"payloads":null,"alerts":null}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(StatePath(dir), data, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Load(dir)
		if err != nil {
			return
		}
		// Whatever was read is a state that can be evaluated and saved.
		Evaluate(s, Input{Now: at(0), Payloads: []*database.IOC{payload(1, 1)}})
		if err := Save(dir, s); err != nil {
			t.Fatal(err)
		}
		if again, err := Load(dir); err != nil || len(again.Alerts) > MaxAlerts {
			t.Fatalf("saved state not read back: %v", err)
		}
		if bytes.Contains(data, []byte("\x00")) && s == nil {
			t.Fatal("nil state without an error")
		}
	})
}
