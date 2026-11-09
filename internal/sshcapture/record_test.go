package sshcapture

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

const testConn = "0123456789abcdef0123456789abcdef"

func line(fields ...string) []byte { return []byte(strings.Join(fields, " ")) }

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestParseRecordAcceptsEveryKind(t *testing.T) {
	for _, c := range []struct {
		kind    string
		payload string
	}{
		{"c", b64("uname -a")}, {"C", ""}, {"o", b64("time=1 uid=0 pty=0 sub=0 cmd=1 rport=40000 lport=22 rip=10.0.0.2 host=web01 user=root")},
		{"i", b64("ls\r")}, {"O", b64("bin\r\n")}, {"e", b64("oops\n")}, {"t", ""}, {"x", b64("exit=3")}, {"z", ""},
	} {
		r, err := ParseRecord(line(testConn, "7", "12", c.kind, "345", c.payload))
		if err != nil {
			t.Fatalf("kind %s: %v", c.kind, err)
		}
		want, _ := base64.StdEncoding.DecodeString(c.payload)
		if r.Conn != testConn || r.Channel != 7 || r.Seq != 12 || r.Kind != Kind(c.kind[0]) || r.Millis != 345 || !bytes.Equal(r.Payload, want) {
			t.Fatalf("kind %s parsed as %+v", c.kind, r)
		}
	}
}

func TestParseRecordRejectsAnythingElse(t *testing.T) {
	good := []string{testConn, "0", "0", "O", "0", b64("x")}
	if _, err := ParseRecord(line(good...)); err != nil {
		t.Fatalf("control line rejected: %v", err)
	}
	// The largest channel and time are kept as they are.
	r, err := ParseRecord(line(testConn, "1048576", "0", "O", "9007199254740992", b64("x")))
	if err != nil || r.Channel != 1<<20 || r.Millis != 1<<53 {
		t.Fatalf("largest channel and time: %+v %v", r, err)
	}
	mutate := func(i int, v string) []byte {
		f := append([]string(nil), good...)
		f[i] = v
		return line(f...)
	}
	for name, l := range map[string][]byte{
		"upper-case connection":  mutate(0, strings.ToUpper(testConn)),
		"short connection":       mutate(0, testConn[:31]),
		"negative channel":       mutate(1, "-1"),
		"leading-zero channel":   mutate(1, "01"),
		"huge channel":           mutate(1, "99999999999"),
		"channel past the limit": mutate(1, "1048577"),
		"plus channel":           mutate(1, "+1"),
		"plus sequence":          mutate(2, "+1"),
		"time past the limit":    mutate(4, "9007199254740993"),
		"plus time":              mutate(4, "+5"),
		"unknown kind":           mutate(3, "q"),
		"two-letter kind":        mutate(3, "OO"),
		"negative time":          mutate(4, "-5"),
		"unpadded base64":        mutate(5, "eA"),
		"url base64":             mutate(5, "-_8="),
		"data without payload":   mutate(5, ""),
		"too few fields":         line(good[:5]...),
		"too many fields":        line(append(append([]string(nil), good...), "x")...),
		"double space":           []byte(strings.Join(good, "  ")),
		"trailing carriage":      append(line(good...), '\r'),
		"closed with payload":    line(testConn, "0", "0", "z", "0", b64("x")),
		"truncated with payload": line(testConn, "0", "0", "t", "0", b64("x")),
		"oversized payload":      mutate(5, base64.StdEncoding.EncodeToString(make([]byte, maxPayload+1))),
		"oversized line":         append(line(good...), bytes.Repeat([]byte{'A'}, MaxLine)...),
		"empty":                  nil,
	} {
		if _, err := ParseRecord(l); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParseOpen(t *testing.T) {
	o, err := ParseOpen([]byte("time=1731136000123 uid=1000 pty=1 sub=0 cmd=0 rport=41234 lport=22 rip=172.20.0.10 host=web01 user=operator"))
	if err != nil {
		t.Fatal(err)
	}
	want := Open{TimeMillis: 1731136000123, UID: 1000, PTY: true, PeerPort: 41234, LocalPort: 22, PeerIP: "172.20.0.10", Hostname: "web01", Username: "operator"}
	if o != want {
		t.Fatalf("got %+v want %+v", o, want)
	}
	// The largest uid is kept whole, on 32-bit builds too.
	o, err = ParseOpen([]byte("time=9007199254740992 uid=4294967295 pty=0 sub=0 cmd=0 rport=65535 lport=65535 rip=1.2.3.4 host=h user=root"))
	if err != nil || o.UID != 1<<32-1 || o.TimeMillis != 1<<53 || o.PeerPort != 65535 || o.LocalPort != 65535 {
		t.Fatalf("largest values: %+v %v", o, err)
	}
	for name, text := range map[string]string{
		"uid past the limit":   "time=1 uid=4294967296 pty=0 sub=0 cmd=0 rport=1 lport=22 rip=1.2.3.4 host=h user=root",
		"leading-zero uid":     "time=1 uid=01 pty=0 sub=0 cmd=0 rport=1 lport=22 rip=1.2.3.4 host=h user=root",
		"time past the limit":  "time=9007199254740993 uid=0 pty=0 sub=0 cmd=0 rport=1 lport=22 rip=1.2.3.4 host=h user=root",
		"plus port":            "time=1 uid=0 pty=0 sub=0 cmd=0 rport=+1 lport=22 rip=1.2.3.4 host=h user=root",
		"local port too large": "time=1 uid=0 pty=0 sub=0 cmd=0 rport=1 lport=65536 rip=1.2.3.4 host=h user=root",
		"missing user":         "time=1 uid=0 pty=0 sub=0 cmd=0 rport=1 lport=22 rip=1.2.3.4 host=h",
		"missing rip":          "time=1 uid=0 pty=0 sub=0 cmd=0 rport=1 lport=22 host=h user=root",
		"repeated uid":         "time=1 uid=0 uid=1 pty=0 sub=0 cmd=0 rport=1 lport=22 rip=1.2.3.4 host=h user=root",
		"bad flag":             "time=1 uid=0 pty=2 sub=0 cmd=0 rport=1 lport=22 rip=1.2.3.4 host=h user=root",
		"port too large":       "time=1 uid=0 pty=0 sub=0 cmd=0 rport=65536 lport=22 rip=1.2.3.4 host=h user=root",
		"unknown field":        "time=1 uid=0 pty=0 sub=0 cmd=0 rport=1 lport=22 rip=1.2.3.4 host=h x=1 user=root",
		"space in user":        "time=1 uid=0 pty=0 sub=0 cmd=0 rport=1 lport=22 rip=1.2.3.4 host=h user=ro ot",
		"newline in user":      "time=1 uid=0 pty=0 sub=0 cmd=0 rport=1 lport=22 rip=1.2.3.4 host=h user=ro\not",
	} {
		if _, err := ParseOpen([]byte(text)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParseExit(t *testing.T) {
	for text, want := range map[string]Exit{"exit=0": {}, "exit=3": {Code: 3}, "signal=9": {Code: 137, Signal: 9}} {
		got, err := ParseExit([]byte(text))
		if err != nil || got != want {
			t.Fatalf("%s: %+v %v", text, got, err)
		}
	}
	for _, text := range []string{"exit=256", "signal=256", "exit=+1", "exit=01", "exit=-1", "signal=0", "code=1", "exit=", "exit"} {
		if _, err := ParseExit([]byte(text)); err == nil {
			t.Errorf("%q accepted", text)
		}
	}
}

func FuzzParseRecord(f *testing.F) {
	f.Add(line(testConn, "0", "0", "O", "0", b64("x")))
	f.Add(line(testConn, "3", "9", "o", "12", b64("time=1 uid=0 pty=0 sub=0 cmd=1 rport=1 lport=22 rip=1.2.3.4 host=h user=root")))
	f.Add(line(testConn, "1", "2", "z", "3", ""))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseRecord(data)
		if err != nil {
			return
		}
		// Whatever is accepted re-encodes to exactly the input.
		again := line(r.Conn, strconv.Itoa(r.Channel), strconv.FormatUint(r.Seq, 10), string(rune(r.Kind)), strconv.FormatInt(r.Millis, 10), base64.StdEncoding.EncodeToString(r.Payload))
		if !bytes.Equal(again, data) {
			t.Fatalf("accepted %q but it re-encodes as %q", data, again)
		}
		if r.Kind == KindOpen {
			_, _ = ParseOpen(r.Payload)
		}
		if r.Kind == KindExit {
			_, _ = ParseExit(r.Payload)
		}
	})
}
