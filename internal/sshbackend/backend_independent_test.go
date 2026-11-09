package sshbackend

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Arbitrary bytes remain data: the only executed program is a fixed local cat.
// Compare the real child's output and the archived inbound stream independently.
func FuzzBinaryInputCapture(f *testing.F) {
	if runtime.GOOS != "linux" {
		f.Skip("the packaged SSH recorder runs on Linux")
	}
	for _, seed := range [][]byte{nil, []byte("plain\n"), {0, 255, 13, 10, 128}, bytes.Repeat([]byte{0, 1, 255}, 1024)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 16<<10 {
			return
		}
		dir := t.TempDir()
		t.Setenv("HOME", dir)
		t.Setenv("BASH_ENV", "")
		command := "/bin/cat"
		var output, diagnostic bytes.Buffer
		code, err := record(recordOptions{LogDir: dir, Command: &command, Stdin: bytes.NewReader(input), Stdout: &output, Stderr: &diagnostic})
		if err != nil || code != 0 || !bytes.Equal(output.Bytes(), input) || diagnostic.Len() != 0 {
			t.Fatalf("binary delivery failed: exit%d error%v input%d output%d diagnostic%q", code, err, len(input), output.Len(), diagnostic.String())
		}
		paths, err := filepath.Glob(filepath.Join(dir, "uid-*", "*.json"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("expected one command capture: %v %v", paths, err)
		}
		data, err := os.ReadFile(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		var start, finish SessionEvent
		if err := decoder.Decode(&start); err != nil {
			t.Fatal(err)
		}
		if err := decoder.Decode(&finish); err != nil {
			t.Fatal(err)
		}
		if start.Phase != "start" || finish.Phase != "finish" || finish.Input != command || !finish.StdinRecorded || finish.InputFile == "" || finish.Truncated || finish.CaptureError != "" {
			t.Fatalf("invalid successful input capture: %+v", finish)
		}
		archived, err := os.ReadFile(filepath.Join(filepath.Dir(paths[0]), finish.InputFile))
		if err != nil || !bytes.Equal(archived, input) {
			t.Fatalf("archived bytes differ: %v input%d archive%d", err, len(input), len(archived))
		}
	})
}

func FuzzParseAccounts(f *testing.F) {
	for _, value := range []string{"", "root:pass", "user:a:b", "same:a,same:b", "user:unicode-π", "bad\nuser:pass", "user:a\x00b", strings.Repeat("a", 32) + ":x"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		accounts, err := ParseAccounts(value)
		if err != nil {
			return
		}
		if len(accounts) < 1 || len(accounts) > 32 {
			t.Fatalf("unbounded accepted account count: %d", len(accounts))
		}
		names := map[string]bool{}
		var serialized []string
		for _, account := range accounts {
			if account.Name == "" || len(account.Name) > 32 || strings.ContainsAny(account.Name, ":,\r\n\x00/") || names[account.Name] {
				t.Fatalf("invalid accepted account: %#v", account)
			}
			if account.Password == "" || len(account.Password) > 128 || strings.ContainsAny(account.Password, ":,\r\n\x00") {
				t.Fatalf("invalid accepted password")
			}
			names[account.Name] = true
			serialized = append(serialized, account.Name+":"+account.Password)
		}
		again, err := ParseAccounts(strings.Join(serialized, ","))
		if err != nil || !reflect.DeepEqual(accounts, again) {
			t.Fatalf("accepted account configuration changed on roundtrip: %v", err)
		}
	})
}

func FuzzConnectionContext(f *testing.F) {
	generation := uint64(7)
	data, _ := json.Marshal(ConnectionContext{SessionID: strings.Repeat("ab", 16), SrcIP: "192.0.2.17", SrcPort: 2222, StartedAt: "2026-01-02T03:04:05.123Z", Generation: &generation})
	for _, seed := range [][]byte{data, []byte("null"), append(append([]byte{}, data...), []byte(" {}")...), []byte(`{"session_id":"ab","src_ip":"127.0.0.1","src_port":0,"generation":0}`)} {
		f.Add(seed)
	}
	dir := f.TempDir()
	name := filepath.Join(dir, "connection.json")
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 17<<10 {
			return
		}
		if err := os.WriteFile(name, data, 0o600); err != nil {
			t.Fatal(err)
		}
		context, err := readContext(dir)
		if err != nil {
			return
		}
		id, err := hex.DecodeString(context.SessionID)
		if err != nil || len(id) != 16 || context.SessionID != strings.ToLower(context.SessionID) || net.ParseIP(context.SrcIP) == nil || context.SrcPort < 1 || context.SrcPort > 65535 || context.Generation == nil {
			t.Fatalf("invalid accepted attribution fields: %#v", context)
		}
		if _, err := time.Parse(time.RFC3339Nano, context.StartedAt); err != nil {
			t.Fatal("invalid accepted timestamp")
		}
		encoded, err := json.Marshal(context)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		again, err := readContext(dir)
		if err != nil || !reflect.DeepEqual(context, again) {
			t.Fatalf("accepted context failed roundtrip: %v", err)
		}
		if err := os.WriteFile(name, append(encoded, []byte(" {}")...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readContext(dir); err == nil {
			t.Fatal("context accepted a second JSON object")
		}
	})
}

func FuzzBootstrapEnvironment(f *testing.F) {
	for _, value := range []string{"BACKEND_USERS=secret\nPATH=/bin", "backend_scene=secret\nLANG=C", "http_proxy=http://local\nUSER=test", "SHELL=/bin/bash\nLC_ALL=C", ""} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 32768 {
			return
		}
		original := strings.Split(value, "\n")
		filtered := FilterEnvironment(original)
		pos := 0
		for _, entry := range filtered {
			name, _, _ := strings.Cut(entry, "=")
			switch strings.ToUpper(name) {
			case "BACKEND_SCENE", "BACKEND_USERS", "SESSION_CONTAINER", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS", "DOCKER_TLS_VERIFY":
				t.Fatalf("bootstrap field survived filter: %s", name)
			}
			for pos < len(original) && original[pos] != entry {
				pos++
			}
			if pos == len(original) {
				t.Fatal("filter changed an unrelated environment entry")
			}
			pos++
		}
		if !reflect.DeepEqual(filtered, FilterEnvironment(filtered)) {
			t.Fatal("environment filter is not idempotent")
		}
		if !bytes.Equal([]byte(strings.Join(original, "\n")), []byte(value)) {
			t.Fatal("filter mutated its input")
		}
	})
}

// This isolated reproducer uses a sparse preexisting record (under 2 MiB of
// actual new capture data) to test admission near the per-user logical quota.
func TestConcurrentRecorderCapacity(t *testing.T) {
	for _, near := range []bool{true, false} {
		t.Run(map[bool]string{true: "near-capacity", false: "parallel-admission"}[near], func(t *testing.T) {
			concurrentRecorderCapacity(t, near)
		})
	}
}
func concurrentRecorderCapacity(t *testing.T, near bool) {
	root := t.TempDir()
	dir := filepath.Join(root, "uid-"+strconvUID())
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	baseline, err := os.Create(filepath.Join(dir, "existing.out"))
	if err != nil {
		t.Fatal(err)
	}
	if near {
		if err := baseline.Truncate(maxUserLogBytes - (640 << 10)); err != nil {
			t.Fatal(err)
		}
	}
	baseline.Close()
	type result struct {
		code int
		err  error
	}
	count := 3
	if near {
		count = 10
	}
	results := make(chan result, count)
	var inputs []*io.PipeWriter
	for range count {
		input, release := io.Pipe()
		inputs = append(inputs, release)
		defer input.Close()
		defer release.Close()
		command := "read -r gate; head -c 131072 /dev/zero"
		go func() {
			defer input.Close()
			code, err := record(recordOptions{LogDir: root, Command: &command, Stdin: input, Stdout: io.Discard, Stderr: io.Discard})
			results <- result{code, err}
		}()
	}
	deadline := time.Now().Add(10 * time.Second)
	rejected := 0
	admitted := 0
	for {
		started := 0
		names, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			data, _ := os.ReadFile(name)
			if bytes.Contains(data, []byte(`"phase":"start"`)) {
				started++
			}
		}
		if started+rejected == count {
			admitted = started
			break
		}
		select {
		case result := <-results:
			if !near || result.code != 126 || result.err == nil || !strings.Contains(result.err.Error(), "capacity") {
				t.Fatalf("unexpected record rejection: code%d %v", result.code, result.err)
			}
			rejected++
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("only%d recorders admitted before deadline", started)
		}
		time.Sleep(5 * time.Millisecond)
	}
	for _, release := range inputs {
		if _, err := release.Write([]byte("ready\n")); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
		release.Close()
	}
	if admitted < 1 || (!near && admitted != count) || (near && rejected < 1) {
		t.Fatalf("admitted%d rejected%d, near=%v", admitted, rejected, near)
	}
	for range count - rejected {
		result := <-results
		if result.code != 0 || result.err != nil {
			t.Fatalf("record: code%d %v", result.code, result.err)
		}
	}
	var used int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				t.Fatal(err)
			}
			used += info.Size()
		}
	}
	t.Logf("concurrent recorder logical usage=%d configured user limit=%d excess=%d", used, maxUserLogBytes, used-maxUserLogBytes)
	if used > maxUserLogBytes {
		t.Fatalf("concurrent sessions exceeded the user record quota by%d bytes", used-maxUserLogBytes)
	}
}

func TestCaptureReservationsIncludePendingFiles(t *testing.T) {
	dir := t.TempDir()
	// 408 completed sessions leave 2040 ordinary files. Two admissions can
	// interleave before either has created its five output/metadata files.
	for i := 0; i < maxLogFiles-8; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("old-%d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, release, err := reserveCapture(dir, "first")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	_, release2, err := reserveCapture(dir, "second")
	if err == nil {
		defer release2()
		t.Fatal("second admission ignored the first claim's five not-yet-created files")
	}
}

func TestAbandonedCaptureClaimRemainsConservative(t *testing.T) {
	dir := t.TempDir()
	existing, err := os.Create(filepath.Join(dir, "existing.out"))
	if err != nil {
		t.Fatal(err)
	}
	if err := existing.Truncate(maxUserLogBytes - (640 << 10)); err != nil {
		t.Fatal(err)
	}
	existing.Close()
	_, release, err := reserveCapture(dir, "abandoned")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// No files or child were created: an admission interrupted at this exact
	// point still owns its budget and future filename slots.
	if _, another, err := reserveCapture(dir, "next"); err == nil {
		another()
		t.Fatal("incomplete admission's budget was reused")
	}
	// A normal completion releases it; a second admission can then proceed.
	release()
	_, next, err := reserveCapture(dir, "after-completion")
	if err != nil {
		t.Fatalf("completed claim was not released: %v", err)
	}
	next()
}
