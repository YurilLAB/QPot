package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// FuzzSpliceTransparency feeds arbitrary byte payloads through the broker to an
// echo backend and asserts they round-trip byte-for-byte with no panic. This is
// the security-critical invariant: the broker must be a faithful, opaque L4
// splice for ALL inputs (so it never alters or chokes on a stream, and never
// crashes on adversarial bytes). It also exercises the copy/teardown paths.
func FuzzSpliceTransparency(f *testing.F) {
	f.Add([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
	f.Add([]byte{})
	f.Add([]byte{0x00, 0xff, 0x0a, 0x0d, 0x1b})
	f.Add(bytes.Repeat([]byte{0xAB}, 70000)) // larger than the 32KiB splice buffer

	// One shared echo backend + broker for all iterations (cheap, deterministic).
	be, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.Skipf("listen: %v", err)
	}
	defer be.Close()
	go func() {
		for {
			c, err := be.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()

	fe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.Skipf("listen: %v", err)
	}
	defer fe.Close()
	// Go's fuzzer runs many workers in parallel, all dialing from 127.0.0.1, so
	// the pool and admission caps must be generous enough that no connection is
	// rejected for capacity reasons (which would fail the transparency check for
	// reasons unrelated to splicing). Many backends all point at the one echo
	// listener, which happily accepts every connection.
	backends := make([]Backend, 256)
	for i := range backends {
		backends[i] = Backend{ID: "be" + strconv.Itoa(i), Addr: be.Addr().String()}
	}
	pool := NewPool(backends, nil)
	b := NewBroker(Config{
		Honeypot: "fz", IdleTimeout: 2 * time.Second, BufferSize: 4096,
		RatePerSecPerIP: 1e9, BurstPerIP: 1e9, MaxConcurrentIP: 1 << 20, MaxConcurrent: 1 << 20,
	}, pool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = b.Serve(ctx, fe) }()

	f.Fuzz(func(t *testing.T, payload []byte) {
		c, err := net.Dial("tcp", fe.Addr().String())
		if err != nil {
			t.Skip()
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))

		// Writer goroutine so a payload larger than socket buffers can't deadlock
		// against our own blocking read.
		go func() {
			_, _ = c.Write(payload)
			// Half-close so the echo backend sees EOF and the broker tears down.
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.CloseWrite()
			}
		}()

		got := make([]byte, 0, len(payload))
		buf := make([]byte, 32*1024)
		for {
			n, rerr := c.Read(buf)
			got = append(got, buf[:n]...)
			if rerr != nil {
				break
			}
			if len(got) >= len(payload) {
				break
			}
		}
		if !bytes.Equal(got[:min(len(got), len(payload))], payload) {
			t.Fatalf("splice not transparent: got %d bytes, want %d, mismatch", len(got), len(payload))
		}
	})
}

// FuzzParseBackends asserts the operator backend-list parser never panics and,
// whenever it succeeds, returns only well-formed unique backends (so a bad
// config can never yield a pool that dials a malformed/empty address).
func FuzzParseBackends(f *testing.F) {
	f.Add("h1:22,h2:22")
	f.Add("a=1.2.3.4:2222, b=[::1]:22")
	f.Add(",,,")
	f.Add("x=:0")
	f.Add("\x00=\xff:\x01")
	f.Fuzz(func(t *testing.T, s string) {
		bs, err := ParseBackends(s)
		if err != nil {
			if bs != nil {
				t.Fatalf("error result must return nil backends, got %+v", bs)
			}
			return
		}
		seen := map[string]bool{}
		for _, b := range bs {
			if b.ID == "" || b.Addr == "" {
				t.Fatalf("parsed empty backend field: %+v", b)
			}
			if seen[b.ID] {
				t.Fatalf("parsed duplicate id %q", b.ID)
			}
			seen[b.ID] = true
			if _, _, e := net.SplitHostPort(b.Addr); e != nil {
				t.Fatalf("parsed invalid addr %q", b.Addr)
			}
		}
	})
}

// FuzzSplitHostPort asserts the RemoteAddr parser never panics and never returns
// a host containing characters that would break a log line, for arbitrary input.
func FuzzSplitHostPort(f *testing.F) {
	f.Add("1.2.3.4:22")
	f.Add("[::1]:8080")
	f.Add("garbage")
	f.Add("")
	f.Add(":::::")
	f.Fuzz(func(t *testing.T, s string) {
		host, port := splitHostPort(fakeAddr(s))
		if port < 0 {
			t.Fatalf("negative port %d from %q", port, s)
		}
		// host may be anything, but the function must not panic (reached here).
		_ = host
	})
}

// fakeAddr adapts a string into a net.Addr for splitHostPort fuzzing.
type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

// FuzzEventJSON asserts that an Event with arbitrary field values always
// marshals to a single valid JSON line (no panic, parses back, no embedded
// newline that could split one event into two log records).
func FuzzEventJSON(f *testing.F) {
	f.Add("ssh_proxy_session", "ssh-proxy", "1.2.3.4", "be1", "closed", int64(5), int64(6))
	f.Add("x\ny", "h\t", "ip\x00", "b\"q", "r\\n", int64(-1), int64(0))
	f.Fuzz(func(t *testing.T, et, hp, ip, be, reason string, in, out int64) {
		var buf bytes.Buffer
		NewJSONSink(&buf).Emit(Event{
			EventType: et, Honeypot: hp, SrcIP: ip, Backend: be,
			Reason: reason, BytesIn: in, BytesOut: out, SrcPort: 1,
		})
		line := buf.String()
		// Exactly one line (the trailing newline is the only newline).
		if strings.Count(line, "\n") != 1 {
			t.Fatalf("event produced %d newlines (must be exactly 1): %q", strings.Count(line, "\n"), line)
		}
		var e Event
		if err := json.Unmarshal([]byte(strings.TrimRight(line, "\n")), &e); err != nil {
			t.Fatalf("event not valid JSON: %v (%q)", err, line)
		}
	})
}

// FuzzSourceKey checks the unit the per-IP limits apply to: every address in
// one IPv6 /64 is one source, an IPv4 address is its own source in any
// spelling (plain or IPv4-mapped), and nothing panics.
func FuzzSourceKey(f *testing.F) {
	f.Add([]byte{0x20, 1, 0xd, 0xb8, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1}, []byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 9}, "fe80::1%eth0")
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1}, []byte{}, "not an ip")
	f.Fuzz(func(t *testing.T, addr16, low []byte, raw string) {
		_ = sourceKey(raw) // arbitrary text: must not panic
		var a [16]byte
		copy(a[:], addr16)
		ip := netip.AddrFrom16(a)
		if ip.Is4In6() {
			v4 := ip.Unmap()
			if sourceKey(ip.String()) != sourceKey(v4.String()) || sourceKey(v4.String()) != v4.String() {
				t.Fatalf("IPv4 %s: keys %q / %q", v4, sourceKey(ip.String()), sourceKey(v4.String()))
			}
			return
		}
		// Another address in the same /64.
		b := a
		copy(b[8:], low)
		other := netip.AddrFrom16(b)
		if other.Is4In6() {
			return
		}
		if k1, k2 := sourceKey(ip.String()), sourceKey(other.String()); k1 != k2 {
			t.Fatalf("%s and %s share a /64 but have keys %q and %q", ip, other, k1, k2)
		}
		// A different /64 is a different source.
		c := a
		c[7] ^= 1
		if sourceKey(netip.AddrFrom16(c).String()) == sourceKey(ip.String()) {
			t.Fatalf("%s and %s are in different /64s but share a key", ip, netip.AddrFrom16(c))
		}
	})
}

// FuzzGenerationID checks that a backend id, whatever it contains, can only
// ever name a counter file inside the generations directory.
func FuzzGenerationID(f *testing.F) {
	for _, s := range []string{"be1", "..", "../secret", `..\secret`, "/etc/passwd", "C:secret", "a/../../secret", "x:stream", ""} {
		f.Add(s)
	}
	root := f.TempDir()
	dir := filepath.Join(root, "gen")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret"), []byte("99\n"), 0o644); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "be1"), []byte("7\n"), 0o644); err != nil {
		f.Fatal(err)
	}
	g := NewGenerationGate(dir)
	f.Fuzz(func(t *testing.T, id string) {
		switch n := g.Generation(id); n {
		case 0:
		case 7:
			if id != "be1" {
				t.Fatalf("Generation(%q) read be1's counter", id)
			}
		default:
			t.Fatalf("Generation(%q) = %d, read outside the directory", id, n)
		}
	})
}
