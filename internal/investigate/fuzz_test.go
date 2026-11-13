package investigate

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/qpot/qpot/internal/canary"
	"github.com/qpot/qpot/internal/database"
)

// fuzzEvents turns bytes into stored events of a few sources: each line is
// one event, its first bytes choosing the source, the kind and the time, the
// rest being attacker text.
func fuzzEvents(data []byte) []*database.Event {
	ips := []string{"192.0.2.1", "192.0.2.2", "2001:db8::1", "2001:db8::2", "172.18.0.1", "", "not-an-address"}
	types := []string{"cowrie.session.connect", "cowrie.login.failed", "cowrie.login.success", "cowrie.command.input", "cowrie.command.failed",
		"cowrie.session.file_download", "cowrie.session.file_upload", "cowrie.session.closed", "cowrie.log.line_discarded",
		"ssh-proxy.command.start", "ssh-proxy.command.finish", "tanner.http.get", "x"}
	var out []*database.Event
	for i, line := range bytes.Split(data, []byte{'\n'}) {
		if len(line) < 3 || len(out) >= 300 {
			continue
		}
		text := string(line[3:])
		e := ev(i*7+int(line[2])*50, "cowrie", ips[int(line[0])%len(ips)], types[int(line[1])%len(types)])
		half := len(text) / 2
		e.Command, e.Username, e.Password = text, text[:half], text[half:]
		e.Payload = line[3:]
		e.Classified = line[2]%2 == 0
		e.Metadata["shasum"], e.Metadata["outfile"], e.Metadata["duration"] = text, text, text
		e.Metadata["capture_id"], e.Metadata["exit_code"], e.Metadata["stdout_file"] = text[:half], text[half:], text
		switch line[2] % 5 {
		case 1:
			e.Metadata["truncated"] = "input"
		case 2:
			e.Metadata["truncated"], e.Metadata["command_truncated"] = "true", "true"
		case 3:
			e.Metadata[database.SharedSourceKey] = "docker"
		case 4:
			e.Metadata["capture_error"] = text
		}
		if strings.HasPrefix(e.EventType, "ssh-proxy") {
			e.Honeypot = "ssh-proxy"
		}
		out = append(out, e)
	}
	return out
}

// Whatever the events are, a case cites only records it carries, its text
// holds nothing a terminal would act on, and its bundle checks out.
func FuzzCase(f *testing.F) {
	f.Add([]byte("\x00\x00\x00\n\x00\x01\x01root\n\x00\x02\x02admin\n\x00\x03\x03wget http://a.example/x\n\x00\x05\x04http://a.example/x\n\x00\x07\x05"), uint16(50))
	f.Add([]byte("\x01\x03\x00uname -a\n\x02\x03\x01uname -a\n\x04\x03\x03id\n\x04\x03\x08ls\n\x05\x03\x00x\n\x06\x0b\x00/\x1b[2J"), uint16(3))
	f.Add([]byte("\x00\x09\x00abcd\n\x00\x0a\x00abcd\n\x00\x0a\x01ab\xffcd\n\x00\x08\x01{\"x\"\n"), uint16(0))
	f.Fuzz(func(t *testing.T, data []byte, limit uint16) {
		events := fuzzEvents(data)
		if len(events) == 0 {
			return
		}
		db := newDB(t, events...)
		trips := []*canary.Trip{{ID: "trip_1", Kind: canary.Kind("web"), Name: string(data[:min(len(data), 20)]), Channel: "http", Time: at(40), SourceIP: "192.0.2.1"}}
		opts := Options{MaxEvents: int(limit), Trips: trips, Output: &HiFiOutput{Cells: t.TempDir(), Slot: func(s string) (string, error) { return s, nil }}}
		check := func(c *Case, err error) {
			if err != nil {
				t.Fatal(err)
			}
			checkCited(t, c)
			var text bytes.Buffer
			if err := WriteText(&text, c); err != nil {
				t.Fatal(err)
			}
			assertPrintable(t, text.String())
			var zipped bytes.Buffer
			if _, err := WriteBundle(&zipped, c); err != nil {
				t.Fatal(err)
			}
			if rep := verify(t, zipped.Bytes()); !rep.OK() {
				t.Fatalf("the bundle of a case does not check out: %v", rep.Problems)
			}
			total := 0
			for _, sc := range c.Sessions {
				total += sc.EventsRead
				if sc.EventsRead > opts.maxEvents() {
					t.Fatalf("%d events read past the limit of %d", sc.EventsRead, opts.maxEvents())
				}
				for i := 1; i < len(sc.Timeline); i++ {
					if sc.Timeline[i].At.Before(sc.Timeline[i-1].At) {
						t.Fatal("the timeline is not in time order")
					}
				}
			}
			if total != c.Summary.EventsRead || len(c.Records) > total {
				t.Fatalf("%d events read, summary %d, %d records", total, c.Summary.EventsRead, len(c.Records))
			}
		}
		seen := map[string]bool{}
		for _, s := range db.sessions {
			check(SessionCaseFor(context.Background(), db, s.SessionID, opts))
			if !seen[s.CampaignFingerprint] {
				seen[s.CampaignFingerprint] = true
				check(CampaignCaseFor(context.Background(), db, s.CampaignFingerprint, opts))
			}
		}
		l, err := List(context.Background(), db, int(limit))
		if err != nil {
			t.Fatal(err)
		}
		var text bytes.Buffer
		if err := WriteListing(&text, l); err != nil {
			t.Fatal(err)
		}
		assertPrintable(t, text.String())
	})
}

// A bundle from anywhere is checked without trusting it.
func FuzzVerifyBundle(f *testing.F) {
	_, whole := bundleCaseOf(f)
	f.Add(whole)
	f.Add(whole[:len(whole)/2])
	f.Add([]byte("PK\x05\x06" + strings.Repeat("\x00", 18)))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		rep, err := VerifyBundle(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		for _, p := range rep.Problems {
			assertPrintable(t, p)
		}
		if rep.OK() && (rep.Files < 4 || rep.Kind == "") {
			t.Fatalf("an archive without a case, records and manifest checked out: %+v", rep)
		}
	})
}

// Clean leaves nothing a terminal acts on, changes nothing that is safe,
// and cleaning twice is cleaning once.
func FuzzClean(f *testing.F) {
	for _, s := range []string{"plain text", "\x1b[31mred\x1b[0m", "a\r\nb\tc", "\xff\xfe", "x" + string(rune(0x202e)) + "y", string([]rune{0x2028, 0x2029, 0x200b, 0xfeff}), "caf" + string(rune(0xe9)), ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := Clean(s)
		if !utf8.ValidString(got) {
			t.Fatalf("%q cleaned is not text", s)
		}
		for _, r := range got {
			if unsafeRune(r) {
				t.Fatalf("%q cleaned still holds %U", s, r)
			}
		}
		if again := Clean(got); again != got {
			t.Fatalf("cleaning %q twice differs", s)
		}
		safe := utf8.ValidString(s)
		for _, r := range s {
			safe = safe && !unsafeRune(r)
		}
		if safe && got != s {
			t.Fatalf("safe text %q was changed", s)
		}
	})
}

// No name in a stored event makes the output reader open a file that is not
// a capture inside the cell's folder.
func FuzzHiFiOutputName(f *testing.F) {
	cells := f.TempDir()
	const good = "20261114T100000Z-000000000000000000000000000000aa.out"
	for rel, body := range map[string]string{
		"slot/current/uid-7/" + good:           "capture",
		"slot/archive-g1-x/logs/uid-7/" + good: "old capture",
		"slot/current/uid-7/notes.out":         "SECRET",
		"slot/secret.out":                      "SECRET",
		"other/current/uid-7/" + good:          "SECRET",
		"secret":                               "SECRET",
	} {
		p := filepath.Join(cells, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			f.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			f.Fatal(err)
		}
	}
	out := &HiFiOutput{Cells: cells, Slot: func(string) (string, error) { return "slot", nil }}
	for _, seed := range [][4]string{{good, "ssh-backend-1", "7", "app"}, {"../secret.out", "ssh-backend-1", "7", ""}, {"notes.out", "ssh-backend-16", "7", "backup"},
		{good, "ssh-backend-1/../../other", "7", "app"}, {good, "ssh-backend-1", "7/../../..", "app"}, {"..\\..\\secret", "ssh-backend-0", "", "database"}} {
		f.Add(seed[0], seed[1], seed[2], seed[3])
	}
	f.Fuzz(func(t *testing.T, name, cell, uid, role string) {
		e := &database.Event{Metadata: map[string]string{"stdout_file": name, "stderr_file": name, "cell": cell, "uid": uid, "role": role}}
		for _, stream := range []string{"stdout", "stderr", "other"} {
			data, _, found, err := out.Output(e, stream)
			if err != nil {
				t.Fatalf("%q: %v", name, err)
			}
			if bytes.Contains(data, []byte("SECRET")) {
				t.Fatalf("stdout_file %q, cell %q, uid %q read a file that is no capture", name, cell, uid)
			}
			if found && (name != good || uid != "7" || stream != "stdout") {
				t.Fatalf("stdout_file %q, uid %q, stream %s was read", name, uid, stream)
			}
		}
	})
}
