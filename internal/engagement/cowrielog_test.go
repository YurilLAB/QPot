package engagement

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

// cowrieFixture is a small Cowrie JSON log: one session that logs in, runs a
// command and downloads a file, then lines that are not events.
const cowrieFixture = `{"eventid":"cowrie.session.connect","src_ip":"203.0.113.5","src_port":50022,"dst_ip":"192.0.2.1","dst_port":2222,"session":"a1b2c3d4e5f6","protocol":"ssh","message":"New connection","sensor":"pot","timestamp":"2026-03-01T10:00:00.000000Z"}
{"eventid":"cowrie.client.version","version":"SSH-2.0-Go","session":"a1b2c3d4e5f6","src_ip":"203.0.113.5","timestamp":"2026-03-01T10:00:00.100000Z"}
{"eventid":"cowrie.login.failed","username":"root","password":"123456","session":"a1b2c3d4e5f6","src_ip":"203.0.113.5","timestamp":"2026-03-01T10:00:01.000000Z"}
{"eventid":"cowrie.login.success","username":"root","password":"admin","session":"a1b2c3d4e5f6","src_ip":"203.0.113.5","timestamp":"2026-03-01T10:00:02.000000Z"}
{"eventid":"cowrie.command.input","input":"uname -a","session":"a1b2c3d4e5f6","src_ip":"203.0.113.5","timestamp":"2026-03-01T10:00:03.500000Z"}

{"eventid":"cowrie.session.file_download","url":"http://198.51.100.9/bins/x86","outfile":"var/lib/cowrie/downloads/abc","shasum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","session":"a1b2c3d4e5f6","src_ip":"203.0.113.5","timestamp":"2026-03-01T10:00:05.000000Z"}
{"eventid":"cowrie.session.closed","duration":12.25,"session":"a1b2c3d4e5f6","src_ip":"203.0.113.5","timestamp":"2026-03-01T10:00:12.250000Z"}
not json at all
{"eventid":"cowrie.command.input","input":"broken
{"timestamp":"2026-03-01T10:00:13.000000Z","session":"a1b2c3d4e5f6"}
{"eventid":"cowrie.command.input","timestamp":"yesterday","session":"a1b2c3d4e5f6"}
["cowrie.command.input"]
   ` + "\t" + `
{"eventid":"COWRIE.Command.Input","input":5,"username":["x"],"session":"ffff00001111","src_ip":"203.0.113.6","timestamp":"2026-03-01T12:00:00+0200"}
{"eventid":"cowrie.session.closed","duration":"3.5","session":"ffff00001111","src_ip":"203.0.113.6","timestamp":"2026-03-01T10:00:20.000000Z"}`

func readAll(t *testing.T, r io.Reader) ([]Event, LogStats) {
	t.Helper()
	var events []Event
	st, err := ReadCowrieLog(r, func(e Event) bool {
		events = append(events, e)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	return events, st
}

func TestReadCowrieLog(t *testing.T) {
	events, st := readAll(t, strings.NewReader(cowrieFixture))
	want := LogStats{Lines: 16, Events: 9, Malformed: 5, Blank: 2}
	if st != want {
		t.Fatalf("stats = %+v, want %+v", st, want)
	}
	ts := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if got, want := events[3], (Event{
		Time: ts("2026-03-01T10:00:02Z"), Honeypot: "cowrie", SourceIP: "203.0.113.5", SessionID: "a1b2c3d4e5f6",
		Type: "cowrie.login.success", Username: "root", Password: "admin",
	}); !reflect.DeepEqual(got, want) {
		t.Errorf("login = %+v, want %+v", got, want)
	}
	if got := events[4]; got.Type != "cowrie.command.input" || got.Command != "uname -a" || !got.Time.Equal(ts("2026-03-01T10:00:03.5Z")) {
		t.Errorf("command = %+v", got)
	}
	if got := events[5]; got.URL != "http://198.51.100.9/bins/x86" || got.SHA256 != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Errorf("download = %+v", got)
	}
	if got := events[6]; got.ReportedDuration != 12250*time.Millisecond {
		t.Errorf("closed: duration = %v, want 12.25s", got.ReportedDuration)
	}
	// An event id in another case, fields of the wrong type, a numeric
	// offset without a colon: still an event, with the odd fields empty.
	if got := events[7]; got.Type != "cowrie.command.input" || got.Command != "" || got.Username != "" || !got.Time.Equal(ts("2026-03-01T10:00:00Z")) {
		t.Errorf("odd line = %+v", got)
	}
	// A duration written as a string, and a last line without a newline.
	if got := events[8]; got.ReportedDuration != 3500*time.Millisecond {
		t.Errorf("last line: duration = %v, want 3.5s", got.ReportedDuration)
	}

	r, err := Compute("stock", sliceSource(events), Options{})
	if err != nil {
		t.Fatal(err)
	}
	m := r.Overall
	if m.Sessions != 2 || m.Funnel.LoggedIn.Count != 1 || m.Funnel.Interactive.Count != 1 || m.Funnel.Payload.Count != 1 {
		t.Errorf("funnel = %+v of %d sessions", m.Funnel, m.Sessions)
	}
	// 12.25 s and 3.5 s, both as the honeypot stated them.
	if d := m.Duration; d.Reported != 2 || d.All.MaxSeconds != 12.25 || d.All.TotalSeconds != 15.75 {
		t.Errorf("duration = %+v", d)
	}
	if m.Intelligence.PayloadHashes.Count != 1 || m.Intelligence.DownloadHosts.Count != 1 || m.Intelligence.CredentialPairs.Count != 1 {
		t.Errorf("intelligence = %+v", m.Intelligence)
	}
}

func TestReadCowrieLogLongLines(t *testing.T) {
	event := `{"eventid":"cowrie.session.connect","session":"s","src_ip":"203.0.113.5","timestamp":"2026-03-01T10:00:00Z"}`
	// As long as allowed: an event whose input fills the line to the limit.
	head := `{"eventid":"cowrie.command.input","session":"s","timestamp":"2026-03-01T10:00:01Z","input":"`
	fits := head + strings.Repeat("a", MaxLogLine-len(head)-len(`"}`)-1) + `"}`
	if len(fits)+1 != MaxLogLine {
		t.Fatalf("fixture is %d bytes with its newline, want %d", len(fits)+1, MaxLogLine)
	}
	tooLong := head + strings.Repeat("a", MaxLogLine) + `"}`
	log := strings.Join([]string{event, tooLong, event, fits, tooLong + tooLong, event, tooLong}, "\n")

	for _, name := range []string{"whole", "one byte at a time"} {
		t.Run(name, func(t *testing.T) {
			var r io.Reader = strings.NewReader(log)
			if name != "whole" {
				r = iotest.OneByteReader(r)
			}
			events, st := readAll(t, r)
			want := LogStats{Lines: 7, Events: 4, Oversized: 3}
			if st != want {
				t.Fatalf("stats = %+v, want %+v", st, want)
			}
			if len(events) != 4 || len(events[2].Command) != MaxLogLine-len(head)-len(`"}`)-1 {
				t.Errorf("events = %d", len(events))
			}
		})
	}
}

func TestReadCowrieLogStopsAndFails(t *testing.T) {
	line := `{"eventid":"cowrie.session.connect","session":"s","timestamp":"2026-03-01T10:00:00Z"}` + "\n"
	n := 0
	st, err := ReadCowrieLog(strings.NewReader(strings.Repeat(line, 5)), func(Event) bool {
		n++
		return n < 2
	})
	if err != nil || n != 2 || st.Events != 2 || st.Lines != 2 {
		t.Errorf("stopped after %d events: %+v, %v", n, st, err)
	}

	boom := errors.New("disk gone")
	st, err = ReadCowrieLog(io.MultiReader(strings.NewReader(line+line), iotest.ErrReader(boom)), func(Event) bool { return true })
	if !errors.Is(err, boom) || st.Events != 2 {
		t.Errorf("read error: %+v, %v", st, err)
	}

	if st, err := ReadCowrieLog(strings.NewReader(""), func(Event) bool { return true }); err != nil || st != (LogStats{}) {
		t.Errorf("empty log: %+v, %v", st, err)
	}
}

func TestSecondsToDuration(t *testing.T) {
	cases := map[float64]time.Duration{
		0: 0, -5: 0, 1.5: 1500 * time.Millisecond, 1e300: maxReported, maxReported.Seconds() + 1: maxReported,
	}
	for sec, want := range cases {
		if got := secondsToDuration(sec); got != want {
			t.Errorf("secondsToDuration(%v) = %v, want %v", sec, got, want)
		}
	}
}

func FuzzReadCowrieLog(f *testing.F) {
	f.Add([]byte(cowrieFixture))
	f.Add([]byte("{}\n{\"eventid\":1}\n\n"))
	f.Add([]byte(`{"eventid":"cowrie.session.closed","duration":"NaN","timestamp":"0000-01-01T00:00:00Z","session":"s"}`))
	f.Add([]byte(`{"eventid":"x.command.input","input":"a\u0000b | c > d","timestamp":"9999-12-31T23:59:59.999999999Z","src_ip":"::1"}` + "\r\n"))
	f.Add([]byte(`{"eventid":"x.login.success","timestamp":"2026-03-01T10:00:00+0200","username":null,"duration":1e400}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var events []Event
		st, err := ReadCowrieLog(strings.NewReader(string(data)), func(e Event) bool {
			events = append(events, e)
			return true
		})
		if err != nil {
			t.Fatalf("a bad line must not be an error: %v", err)
		}
		if st.Lines != st.Events+st.Malformed+st.Oversized+st.Blank || st.Events != int64(len(events)) {
			t.Fatalf("stats do not add up: %+v with %d events", st, len(events))
		}
		if lines := int64(strings.Count(string(data), "\n")) + 1; st.Lines > lines {
			t.Fatalf("%d lines counted in input with %d", st.Lines, lines)
		}
		for _, e := range events {
			if e.Type == "" || e.Honeypot != CowrieHoneypot || e.ReportedDuration < 0 || e.ReportedDuration > maxReported {
				t.Fatalf("bad event %+v", e)
			}
		}
		r, err := Compute("fuzz", sliceSource(events), Options{DistinctLimit: 8, StemLimit: 4, SessionCommandLimit: 2, SessionLimit: 6})
		if err != nil {
			t.Fatal(err)
		}
		in := r.Input
		if in.Events != st.Events || in.Used+in.WithoutTime+in.WithoutSessionKey != in.Events {
			t.Fatalf("report input does not add up: %+v for %+v", in, st)
		}
		m := r.Overall
		if m.Sessions < 0 || m.Sessions > in.Used || m.Funnel.LoggedIn.Count > m.Funnel.LoginAttempted.Count ||
			m.Depth.InteractiveSessions > m.Sessions || m.LeftAfterProbe.Count > m.Depth.InteractiveSessions ||
			m.Returning.Returned > m.Returning.InteractiveSources || m.Diversity.DistinctStems > 4 || m.Diversity.DistinctCommands > 8 {
			t.Fatalf("impossible metrics: %+v", m)
		}
		// The same events in reverse give the same report.
		reversed := make([]Event, len(events))
		for i, e := range events {
			reversed[len(events)-1-i] = e
		}
		again, err := Compute("fuzz", sliceSource(reversed), Options{DistinctLimit: 8, StemLimit: 4, SessionCommandLimit: 2, SessionLimit: 6})
		if err != nil || !reflect.DeepEqual(r, again) {
			t.Fatalf("the report changed when the events were reversed")
		}
	})
}
