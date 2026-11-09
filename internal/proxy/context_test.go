package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func contextFixture() ConnectionContext {
	generation := uint64(0)
	return ConnectionContext{SessionID: strings.Repeat("a", 32), SrcIP: "198.51.100.42", SrcPort: 42001,
		StartedAt: "2026-11-08T12:00:00Z", Generation: &generation}
}

func TestConnectionContextAtomicReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows refuses to replace a file another handle has open. The
		// broker and its readers run in Linux containers.
		t.Skip("rename over an open file is Linux semantics")
	}
	dir := t.TempDir()
	first := contextFixture()
	if err := writeConnectionContext(dir, "be1", first); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "be1", "connection.json")
	var reads atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Errorf("read during replacement: %v", err)
				return
			}
			var document ConnectionContext
			if err := json.Unmarshal(data, &document); err != nil || document.SessionID != strings.Repeat("a", 32) && document.SessionID != strings.Repeat("b", 32) {
				t.Errorf("partial context was published: %q %v", data, err)
				return
			}
			reads.Add(1)
		}
	}()
	for index := range 40 {
		next := first
		if index%2 == 0 {
			next.SessionID = strings.Repeat("b", 32)
		}
		if err := writeConnectionContext(dir, "be1", next); err != nil {
			close(stop)
			wg.Wait()
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	if reads.Load() == 0 {
		t.Fatal("concurrent reader never observed published context")
	}
	entries, err := os.ReadDir(filepath.Join(dir, "be1"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "connection.json" {
		t.Fatalf("temporary files remain: %v %v", entries, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || len(fields) != 5 {
		t.Fatalf("unexpected context fields: %s %v", data, err)
	}
	if string(fields["generation"]) != "0" || bytes.Contains(bytes.ToLower(data), []byte("qpot")) || bytes.Contains(data, []byte("198.51.100.43")) {
		t.Fatalf("context leaked identity or lost generation zero: %s", data)
	}
}

func TestConnectionContextRejectsUnsafePathsAndKeepsPreviousFile(t *testing.T) {
	dir := t.TempDir()
	valid := contextFixture()
	if err := writeConnectionContext(dir, "be1", valid); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "be1", "connection.json")
	before, _ := os.ReadFile(path)
	for _, id := range []string{"", ".", "..", "../elsewhere", "be1/child", `be1\child`, "/absolute", "be1.", "be1:stream", "NUL", "COM1", strings.Repeat("x", 65)} {
		if err := writeConnectionContext(dir, id, valid); err == nil {
			t.Errorf("unsafe context id %q accepted", id)
		}
		if _, err := ParseBackends(id + "=127.0.0.1:22"); id != "" && err == nil {
			t.Errorf("unsafe parser id %q accepted", id)
		}
	}
	if _, err := ParseBackends("be1=127.0.0.1:22,BE1=127.0.0.2:22"); err == nil {
		t.Fatal("case-aliasing backend ids accepted")
	}
	for _, invalid := range []ConnectionContext{
		{SessionID: valid.SessionID, SrcIP: valid.SrcIP, SrcPort: valid.SrcPort, StartedAt: valid.StartedAt},
		{SessionID: "../session", SrcIP: valid.SrcIP, SrcPort: valid.SrcPort, StartedAt: valid.StartedAt, Generation: valid.Generation},
		{SessionID: valid.SessionID, SrcIP: "forged-header", SrcPort: valid.SrcPort, StartedAt: valid.StartedAt, Generation: valid.Generation},
		{SessionID: valid.SessionID, SrcIP: valid.SrcIP, SrcPort: 0, StartedAt: valid.StartedAt, Generation: valid.Generation},
		{SessionID: valid.SessionID, SrcIP: valid.SrcIP, SrcPort: 65536, StartedAt: valid.StartedAt, Generation: valid.Generation},
		{SessionID: valid.SessionID, SrcIP: valid.SrcIP, SrcPort: valid.SrcPort, StartedAt: "yesterday", Generation: valid.Generation},
	} {
		if err := writeConnectionContext(dir, "be1", invalid); err == nil {
			t.Errorf("invalid connection context accepted: %+v", invalid)
		}
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid input changed the prior complete context")
	}
	if err := os.Mkdir(filepath.Join(dir, "blocked"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "blocked", "connection.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeConnectionContext(dir, "blocked", valid); err == nil {
		t.Fatal("directory target was replaced as a context file")
	}
}

func TestConnectionContextRejectsSymlinkSlots(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "be1")); err != nil {
		t.Skipf("platform cannot create symlink: %v", err)
	}
	if err := writeConnectionContext(dir, "be1", contextFixture()); err == nil {
		t.Fatal("symlink context slot accepted")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("context escaped its root: %v %v", entries, err)
	}
}

func TestConnectionContextRejectsSymlinkFile(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "unrelated.json")
	if err := os.WriteFile(outside, []byte("keep-original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "be1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "be1", "connection.json")); err != nil {
		t.Skipf("platform cannot create symlink: %v", err)
	}
	if err := writeConnectionContext(dir, "be1", contextFixture()); err == nil {
		t.Fatal("symlink context file accepted")
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "keep-original" {
		t.Fatalf("symlink target changed: %q %v", data, err)
	}
}

func TestBrokerPublishesActualPeerContextBeforeDial(t *testing.T) {
	dir, generations := t.TempDir(), t.TempDir()
	writeGen(t, generations, "be1", 5)
	gate := NewGenerationGate(generations)
	backend, stopBackend := echoBackend(t)
	defer stopBackend()
	pool := NewPool([]Backend{{ID: "be1", Addr: backend}}, nil)
	pool.SetLeaseHook(gate.OnLease)
	sink := &capSink{}
	observed := make(chan ConnectionContext, 1)
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		data, err := os.ReadFile(filepath.Join(dir, "be1", "connection.json"))
		if err != nil {
			return nil, err
		}
		var document ConnectionContext
		if err := json.Unmarshal(data, &document); err != nil {
			return nil, err
		}
		observed <- document
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	addr, stop := startBroker(t, Config{ContextDir: dir, Gate: gate, Dial: dial, Sink: sink}, pool)
	defer stop()
	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	payload := []byte("X-Forwarded-For: 203.0.113.44\r\n")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, make([]byte, len(payload))); err != nil {
		t.Fatal(err)
	}
	local := client.LocalAddr().(*net.TCPAddr)
	_ = client.Close()
	event := sink.wait(t, EventSession, time.Second)
	select {
	case document := <-observed:
		if document.SrcIP != local.IP.String() || document.SrcPort != local.Port ||
			document.Generation == nil || *document.Generation != 5 ||
			!validSessionID(document.SessionID) || document.SessionID != event.SessionID {
			t.Fatalf("context=%+v event=%+v actual peer=%s", document, event, local)
		}
	case <-time.After(time.Second):
		t.Fatal("backend was never dialed with published attribution")
	}
}

func TestBrokerContextFailureQuarantinesBeforeDial(t *testing.T) {
	for _, name := range []string{"missing-root", "missing-generation", "unsafe-id", "private-slot"} {
		t.Run(name, func(t *testing.T) {
			dir, generations := t.TempDir(), t.TempDir()
			id := "be1"
			if name == "missing-root" {
				dir = filepath.Join(dir, "not-present")
			}
			if name == "unsafe-id" {
				id = "../outside"
			}
			if name == "private-slot" {
				if err := os.Mkdir(filepath.Join(dir, id), 0o700); err != nil {
					t.Fatal(err)
				}
				if info, err := os.Stat(filepath.Join(dir, id)); err != nil || info.Mode().Perm()&0o001 != 0 {
					t.Skip("filesystem does not represent private directory traversal permissions")
				}
			}
			writeGen(t, generations, "be1", 5)
			gate := NewGenerationGate(generations)
			pool := NewPool([]Backend{{ID: id, Addr: "127.0.0.1:22"}}, nil)
			if name != "missing-generation" {
				pool.SetLeaseHook(gate.OnLease)
			}
			var calls atomic.Int32
			sink := &capSink{}
			addr, stop := startBroker(t, Config{ContextDir: dir, Gate: gate, Sink: sink,
				Dial: func(context.Context, string, string) (net.Conn, error) {
					calls.Add(1)
					return nil, net.ErrClosed
				}}, pool)
			defer stop()
			client, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := client.Read(make([]byte, 1)); err == nil {
				t.Fatal("capture failure kept a client open")
			}
			event := sink.wait(t, EventBackendError, time.Second)
			if event.Reason != ReasonBackendContextError || calls.Load() != 0 {
				t.Fatalf("context failure reached guest: event=%+v dials=%d", event, calls.Load())
			}
			deadline := time.Now().Add(time.Second)
			for {
				if a, l, q := pool.Stats(); a == 0 && l == 0 && q == 1 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("uncaptured backend was not quarantined")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestTCPSourceParserKeepsActualIPWithoutIPv6Zone(t *testing.T) {
	ip, port := splitHostPort(&net.TCPAddr{IP: net.ParseIP("fe80::42"), Port: 42001, Zone: "eth0"})
	if ip != "fe80::42" || port != 42001 {
		t.Fatalf("kernel TCP source parsed as %s:%d", ip, port)
	}
	var missing *net.TCPAddr
	if ip, port := splitHostPort(missing); ip != "" || port != 0 {
		t.Fatalf("typed nil TCP address parsed as %s:%d", ip, port)
	}
}

func TestConnectionContextOpaqueNamespaceIsConsistentAndRejectsUnsafeInputs(t *testing.T) {
	dir := t.TempDir()
	namespace := strings.Repeat("a", 64)
	slot := ContextStorageName(namespace, "ssh-backend-1")
	if len(slot) != 32 || slot == "ssh-backend-1" || slot == ContextStorageName(namespace, "ssh-backend-2") || slot == ContextStorageName(strings.Repeat("b", 64), "ssh-backend-1") {
		t.Fatal("opaque context slot is not stable and instance scoped")
	}
	if err := writeConnectionContext(dir, "ssh-backend-1", contextFixture(), namespace); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, slot, "connection.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"../outside", ".", strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("A", 64)} {
		if err := writeConnectionContext(dir, "ssh-backend-1", contextFixture(), bad); err == nil {
			t.Fatalf("invalid namespace accepted: %q", bad)
		}
	}
	if err := writeConnectionContext(dir, "../outside", contextFixture(), namespace); err == nil {
		t.Fatal("namespace hid unsafe service identifier")
	}
	after, err := os.ReadFile(filepath.Join(dir, slot, "connection.json"))
	if err != nil || !bytes.Equal(data, after) {
		t.Fatal("invalid namespace changed trusted context")
	}
	if _, err := os.Lstat(filepath.Join(dir, "ssh-backend-1")); !os.IsNotExist(err) {
		t.Fatal("raw service leaf created")
	}
}
