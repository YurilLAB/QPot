package sshbackend

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testManifest() Manifest {
	return Manifest{Version: 1, Role: "app", Organization: "North service", Directories: []Directory{{Path: "/srv/app", Mode: 0o750, Owner: "operator"}}, Files: []File{{Path: "/srv/app/.env", Content: "DATABASE_HOST=db\n", Mode: 0o640, Owner: "operator"}}}
}

func TestManifestPreflightAndAtomicSeed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership and permissions")
	}
	root := t.TempDir()
	m := testManifest()
	lookup := func(string) (int, int, error) { return os.Getuid(), os.Getgid(), nil }
	if err := Seed(root, m, lookup); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "srv/app/.env")
	data, err := os.ReadFile(file)
	if err != nil || string(data) != m.Files[0].Content {
		t.Fatalf("seeded file: %q %v", data, err)
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("real mode: %v %v", info, err)
	}
	m.Files[0].Content = "DATABASE_HOST=changed\n"
	if err := Seed(root, m, lookup); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(file)
	if string(data) != m.Files[0].Content {
		t.Fatal("replacement did not take effect")
	}
	before, _ := os.ReadFile(file)
	bad := m
	bad.Files = append(append([]File(nil), m.Files...), File{Path: "/etc/passwd", Content: "bad", Mode: 0o644, Owner: "operator"})
	if err := Seed(root, bad, lookup); err == nil {
		t.Fatal("reserved account database accepted")
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid manifest partially changed files")
	}
	if err := Seed(root, m, func(string) (int, int, error) { return 0, 0, errors.New("unknown") }); err == nil {
		t.Fatal("unknown owner accepted")
	}
	after, _ = os.ReadFile(file)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid owner partially changed files")
	}
}

func TestManifestRefusesSymlinkEscapeAndMalformedInputs(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "srv"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "srv/app")); err != nil {
		t.Skip(err)
	}
	if err := Seed(root, testManifest(), func(string) (int, int, error) { return os.Getuid(), os.Getgid(), nil }); err == nil {
		t.Fatal("symlink parent accepted")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatal("wrote outside scene root")
	}
	base, _ := json.Marshal(testManifest())
	if _, err := DecodeManifest(base); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, append(append([]byte(nil), base...), []byte(" {}")...), []byte(`{"version":1,"role":"app","organization":"x","unknown":1}`), bytes.Repeat([]byte(" "), MaxManifestBytes+1)} {
		if _, err := DecodeManifest(data); err == nil {
			t.Fatalf("invalid input accepted: %.80s", data)
		}
	}
	for _, name := range []string{"/srv/app/../../etc/passwd", "/srv//app/file", "/etc/ssh/keys/key", "/proc/1/environ", "/usr/local/bin/rec-shell", "relative/file"} {
		m := testManifest()
		m.Files[0].Path = name
		if err := m.Validate(); err == nil {
			t.Errorf("unsafe path accepted %q", name)
		}
	}
}

func TestAccountsAndEnvironmentAreBounded(t *testing.T) {
	accounts, err := ParseAccounts("root:root123,bkp:operator123")
	if err != nil || len(accounts) != 2 || accounts[1].Name != "bkp" {
		t.Fatalf("parse: %v %v", accounts, err)
	}
	for _, value := range []string{"root:", "../root:a", "-root:a", "root:a,root:b", "root:a\nb", "root:a:b", strings.Repeat("a", 17<<10)} {
		if _, err := ParseAccounts(value); err == nil {
			t.Errorf("malformed account accepted %q", value[:min(len(value), 80)])
		}
	}
	got := FilterEnvironment([]string{"PATH=/usr/bin", "LANG=C.UTF-8", "BACKEND_USERS=secret", "BACKEND_SCENE=secret", "HTTPS_PROXY=outside", "http_proxy=outside", "DOCKER_HOST=outside"})
	if strings.Join(got, "\n") != "PATH=/usr/bin\nLANG=C.UTF-8" {
		t.Fatalf("bootstrap secret/proxy leaked: %v", got)
	}
}

func TestPrivateHostKeyBootstrapParentProtectsPermissiveSources(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native Unix directory permissions")
	}
	standard := t.TempDir()
	bootstrap := filepath.Join(standard, "bootstrap")
	source := filepath.Join(bootstrap, "keys")
	if err := os.MkdirAll(source, 0o777); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{standard, bootstrap, source} {
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(standard, 0o755); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(source, "source-key")
	if err := os.WriteFile(key, []byte("synthetic bootstrap fixture"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0o777); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		root, err := privateHostKeyDirectory(bootstrap)
		if err != nil {
			t.Fatal(err)
		}
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for dir, mode := range map[string]os.FileMode{standard: 0o755, bootstrap: 0o700, source: 0o777, key: 0o777} {
		info, err := os.Stat(dir)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("private bootstrap changed unrelated source/parent permissions: %s %v %v", dir, info, err)
		}
	}
	after, err := os.Stat(key)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("source key was replaced: %v", err)
	}
}

func TestPrivateHostKeyBootstrapRefusesNonordinaryParents(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native Unix directory permissions")
	}
	for _, invalid := range []string{"file", "symlink", "ancestor symlink"} {
		t.Run(invalid, func(t *testing.T) {
			parent, outside := t.TempDir(), t.TempDir()
			if err := os.Chmod(outside, 0o755); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(parent, "bootstrap")
			var err error
			switch invalid {
			case "file":
				err = os.WriteFile(name, []byte("preserved"), 0o600)
			case "symlink":
				err = os.Symlink(outside, name)
			default:
				err = os.Symlink(outside, name)
				name = filepath.Join(name, "child")
			}
			if err != nil {
				t.Fatal(err)
			}
			root, err := privateHostKeyDirectory(name)
			if root != nil {
				root.Close()
			}
			if err == nil {
				t.Fatal("nonordinary bootstrap parent accepted")
			}
			info, err := os.Stat(outside)
			if err != nil || info.Mode().Perm() != 0o755 {
				t.Fatal("bootstrap followed or chmodded the outside directory")
			}
		})
	}
}

func TestPrivateHostKeyCopiesPreservePermissiveSources(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the native SSH daemon is Linux-only")
	}
	source := filepath.Join(t.TempDir(), "source")
	destination := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	before := map[string]os.FileInfo{}
	for _, kind := range []string{"rsa", "ecdsa", "ed25519"} {
		name := "ssh_host_" + kind + "_key"
		file := filepath.Join(source, name)
		if err := os.WriteFile(file, []byte("synthetic-copy-test-"+kind), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, 0o777); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		before[name] = info
	}
	for range 2 {
		if err := copyPrivateHostKeys(source, destination); err != nil {
			t.Fatal(err)
		}
		for name, original := range before {
			actualSource, err := os.Stat(filepath.Join(source, name))
			if err != nil || !os.SameFile(original, actualSource) || actualSource.Mode().Perm() != 0o777 {
				t.Fatalf("source key identity/mode was modified: %v", err)
			}
			sourceBytes, err := os.ReadFile(filepath.Join(source, name))
			if err != nil {
				t.Fatal(err)
			}
			copyBytes, err := os.ReadFile(filepath.Join(destination, name))
			if err != nil || !bytes.Equal(sourceBytes, copyBytes) {
				t.Fatalf("private host key bytes changed: %v", err)
			}
			private, err := os.Stat(filepath.Join(destination, name))
			if err != nil || private.Mode().Perm() != 0o600 || fileUID(private) != os.Geteuid() {
				t.Fatalf("daemon key copy is not private/owned: %v", err)
			}
		}
	}
	directory, err := os.Stat(destination)
	if err != nil || directory.Mode().Perm() != 0o700 || fileUID(directory) != os.Geteuid() {
		t.Fatalf("daemon key directory is not private/owned: %v", err)
	}
	entries, err := os.ReadDir(destination)
	if err != nil || len(entries) != 3 {
		t.Fatalf("private key copying left staging files: %d %v", len(entries), err)
	}
}

func TestPrivateHostKeyCopyValidatesSourcesBeforeWriting(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the native SSH daemon is Linux-only")
	}
	for _, invalid := range []string{"missing", "empty", "oversized", "directory", "symlink"} {
		t.Run(invalid, func(t *testing.T) {
			source := t.TempDir()
			destination := filepath.Join(t.TempDir(), "private")
			for _, kind := range []string{"rsa", "ecdsa"} {
				if err := os.WriteFile(filepath.Join(source, "ssh_host_"+kind+"_key"), []byte("synthetic-copy-test-"+kind), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			name := filepath.Join(source, "ssh_host_ed25519_key")
			var err error
			switch invalid {
			case "empty":
				err = os.WriteFile(name, nil, 0o600)
			case "oversized":
				err = os.WriteFile(name, bytes.Repeat([]byte("x"), (64<<10)+1), 0o600)
			case "directory":
				err = os.Mkdir(name, 0o700)
			case "symlink":
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(outside, []byte("outside fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(outside, name)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := copyPrivateHostKeys(source, destination); err == nil {
				t.Fatal("invalid source was accepted")
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatal("invalid sources partially materialized daemon keys")
			}
		})
	}
}

func TestPrivateHostKeyCopyRefusesDestinationSymlink(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the native SSH daemon is Linux-only")
	}
	source, outside, parent := t.TempDir(), t.TempDir(), t.TempDir()
	for _, kind := range []string{"rsa", "ecdsa", "ed25519"} {
		if err := os.WriteFile(filepath.Join(source, "ssh_host_"+kind+"_key"), []byte("synthetic-copy-test-"+kind), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(parent, "private")); err != nil {
		t.Fatal(err)
	}
	if err := copyPrivateHostKeys(source, filepath.Join(parent, "private")); err == nil {
		t.Fatal("destination symlink was accepted")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("private copying wrote through a symlink")
	}
}

func TestServeRefusesAccidentalHostBootstrap(t *testing.T) {
	t.Setenv("SESSION_CONTAINER", "")
	if err := Serve(); err == nil {
		t.Fatal("unconfigured host bootstrap was accepted")
	}
}

func TestExistingSystemGroupIsReusedForNewAccount(t *testing.T) {
	args, err := newAccountArgs("operator", func(string) (*user.Group, error) { return &user.Group{Name: "operator", Gid: "37"}, nil })
	if err != nil || strings.Join(args, " ") != "-m -s /usr/local/bin/rec-shell -g operator -- operator" {
		t.Fatalf("existing group: %v %v", args, err)
	}
	args, err = newAccountArgs("bkp", func(string) (*user.Group, error) { return nil, user.UnknownGroupError("bkp") })
	if err != nil || strings.Join(args, " ") != "-m -s /usr/local/bin/rec-shell -- bkp" {
		t.Fatalf("new private group: %v %v", args, err)
	}
	if _, err := newAccountArgs("bkp", func(string) (*user.Group, error) { return nil, errors.New("unreadable group database") }); err == nil {
		t.Fatal("group lookup error silently treated as nonexistent")
	}
}

func TestAuthenticationLogIsPrivateAndRefusesSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix private file modes")
	}
	dir := t.TempDir()
	if err := prepareAuthLog(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "sshd.log"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("auth log privacy: %v %v", info, err)
	}
	if err := os.Remove(filepath.Join(dir, "sshd.log")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(other, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "sshd.log")); err != nil {
		t.Fatal(err)
	}
	if err := prepareAuthLog(dir); err == nil {
		t.Fatal("symlink auth log accepted")
	}
	data, _ := os.ReadFile(other)
	if string(data) != "unchanged" {
		t.Fatal("symlink destination changed")
	}
}

func TestRecordPreservesExecStreamsStatusAndPrivateEvidence(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("real Linux shell")
	}
	root := t.TempDir()
	var stdout, stderr bytes.Buffer
	command := `printf 'a\000b\377'; printf 'error\n' >&2; cat; exit 7`
	code, err := record(recordOptions{LogDir: root, Command: &command, Stdin: strings.NewReader("incoming\n"), Stdout: &stdout, Stderr: &stderr})
	if err != nil || code != 7 {
		t.Fatalf("status %d error %v", code, err)
	}
	if !bytes.Equal(stdout.Bytes(), []byte{'a', 0, 'b', 255, 'i', 'n', 'c', 'o', 'm', 'i', 'n', 'g', '\n'}) || stderr.String() != "error\n" {
		t.Fatalf("streams %q %q", stdout.Bytes(), stderr.String())
	}
	var event SessionEvent
	paths, _ := filepath.Glob(filepath.Join(root, "uid-*", "*.json"))
	if len(paths) != 1 {
		t.Fatalf("JSONL records: %v", paths)
	}
	data, err := os.ReadFile(paths[0])
	decoder := json.NewDecoder(bytes.NewReader(data))
	var started SessionEvent
	if err != nil || decoder.Decode(&started) != nil || decoder.Decode(&event) != nil {
		t.Fatalf("record: %q %v", data, err)
	}
	if started.Phase != "start" || started.EventType != "ssh_backend_command_start" || started.ExitCode != nil || started.Input != command {
		t.Fatalf("invalid admission event: %+v", started)
	}
	if event.Input != command || event.ExitCode == nil || *event.ExitCode != 7 || event.EventType != "ssh_backend_command" || event.Phase != "finish" || event.Username == "" {
		t.Fatalf("event: %+v", event)
	}
	base := strings.TrimSuffix(paths[0], ".json")
	if !event.StdinRecorded || event.InputFile != filepath.Base(base)+".in" {
		t.Fatal("non-PTY stdin capture was not identified")
	}
	for suffix, want := range map[string][]byte{"out": stdout.Bytes(), "err": stderr.Bytes(), "in": []byte("incoming\n")} {
		data, err := os.ReadFile(base + "." + suffix)
		if err != nil || !bytes.Equal(data, want) {
			t.Errorf("captured %s: %q %v", suffix, data, err)
		}
	}
	info, _ := os.Stat(paths[0])
	if info.Mode().Perm() != 0o600 {
		t.Fatal("session record is not private")
	}
	info, _ = os.Stat(filepath.Dir(paths[0]))
	if info.Mode().Perm() != 0o700 {
		t.Fatal("user directory is not private")
	}
}

// The helper subprocess receives an inherited, blocking fd0 just like sshd's
// login shell. A Go-created Pipe alone would miss this cancellation regression.
func TestRecordInheritedStdin(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux inherited descriptors")
	}
	if root := os.Getenv("QPOT_RECORD_INPUT_HELPER"); root != "" {
		command := os.Getenv("QPOT_RECORD_INPUT_COMMAND")
		code, err := record(recordOptions{LogDir: root, Command: &command, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(125)
		}
		os.Exit(code)
	}
	for _, command := range []string{"printf early", "head -c 1", "kill -TERM $$"} {
		t.Run(command, func(t *testing.T) {
			root := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestRecordInheritedStdin$")
			cmd.Env = append(os.Environ(), "QPOT_RECORD_INPUT_HELPER="+root, "QPOT_RECORD_INPUT_COMMAND="+command)
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			var out, diagnostic bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &diagnostic
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			if command == "head -c 1" {
				_, _ = in.Write([]byte{0, 255, 1, 2})
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				want := 0
				if command == "kill -TERM $$" {
					want = 143
				}
				if cmd.ProcessState.ExitCode() != want || (err != nil && want == 0) || diagnostic.Len() != 0 {
					t.Fatalf("exit %v stderr %q", err, diagnostic.String())
				}
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
				_ = in.Close()
				<-done
				t.Fatal("recording waited for client EOF after child exit")
			}
			if command == "printf early" && out.String() != "early" || command == "head -c 1" && !bytes.Equal(out.Bytes(), []byte{0}) {
				t.Fatalf("forwarded bytes %q", out.Bytes())
			}
			paths, _ := filepath.Glob(filepath.Join(root, "uid-*", "*.json"))
			if len(paths) != 1 {
				t.Fatalf("records %v", paths)
			}
			data, _ := os.ReadFile(paths[0])
			decoder := json.NewDecoder(bytes.NewReader(data))
			var start, finish SessionEvent
			if decoder.Decode(&start) != nil || decoder.Decode(&finish) != nil || finish.Phase != "finish" || finish.CaptureError != "" || !finish.StdinRecorded {
				t.Fatalf("incomplete capture %q", data)
			}
		})
	}
}

func TestStartRecordIsVisibleBeforeChildCompletesAndSignalsAreReal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("real Linux processes")
	}
	root := t.TempDir()
	command := `sleep 0.3; exit 4`
	type result struct {
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		code, err := record(recordOptions{LogDir: root, Command: &command, Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard})
		done <- result{code, err}
	}()
	var start SessionEvent
	seen := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		paths, _ := filepath.Glob(filepath.Join(root, "uid-*", "*.json"))
		if len(paths) == 1 {
			data, _ := os.ReadFile(paths[0])
			if json.NewDecoder(bytes.NewReader(data)).Decode(&start) == nil {
				seen = true
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !seen || start.Phase != "start" || start.ExitCode != nil || start.Input != command {
		t.Fatalf("missing durable pre-execution event: %+v", start)
	}
	select {
	case result := <-done:
		if result.err != nil || result.code != 4 {
			t.Fatalf("command result: %+v", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("child did not finish")
	}
	command = `kill -KILL $$`
	code, err := record(recordOptions{LogDir: root, Command: &command, Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard})
	if err != nil || code != 137 {
		t.Fatalf("real killed-child status %d %v", code, err)
	}
}

func TestCaptureBudgetDoesNotCorruptForwardedStream(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "capture"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := &captureBudget{remaining: 3}
	w := &captureWriter{budget: b, file: f}
	var forwarded bytes.Buffer
	tee := io.MultiWriter(&forwarded, w)
	if _, err := tee.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	if forwarded.String() != "abcdef" || !b.truncated {
		t.Fatal("capture quota changed delivered output")
	}
	data, _ := os.ReadFile(f.Name())
	if string(data) != "abc" {
		t.Fatalf("capture bound: %q", data)
	}
}

func TestRecordedInputAndOutputShareBudgetWithoutChangingDelivery(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("real Linux stream forwarding")
	}
	root := t.TempDir()
	payload := bytes.Repeat([]byte{0, 255, 13, 10}, (5<<20)/4)
	command := "cat"
	var output bytes.Buffer
	code, err := record(recordOptions{LogDir: root, Command: &command, Stdin: bytes.NewReader(payload), Stdout: &output, Stderr: io.Discard})
	if err != nil || code != 0 || !bytes.Equal(output.Bytes(), payload) {
		t.Fatalf("delivery changed at input/output capture limit: code=%d err=%v bytes=%d", code, err, output.Len())
	}
	paths, _ := filepath.Glob(filepath.Join(root, "uid-*", "*.json"))
	if len(paths) != 1 {
		t.Fatalf("records %v", paths)
	}
	data, _ := os.ReadFile(paths[0])
	decoder := json.NewDecoder(bytes.NewReader(data))
	var start, finish SessionEvent
	if decoder.Decode(&start) != nil || decoder.Decode(&finish) != nil || !finish.Truncated || !finish.StdinRecorded || finish.CaptureError != "" {
		t.Fatalf("capture limit metadata %q", data)
	}
	var captured int64
	for _, suffix := range []string{".in", ".out", ".err", ".timing"} {
		info, err := os.Stat(strings.TrimSuffix(paths[0], ".json") + suffix)
		if err != nil {
			t.Fatal(err)
		}
		captured += info.Size()
	}
	if captured != maxSessionBytes {
		t.Fatalf("combined input/output capture=%d limit=%d", captured, maxSessionBytes)
	}
}

func TestTrustedContextAttributionAndExplicitFallback(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	event := SessionEvent{SrcIP: "172.30.1.2", SrcPort: 23456}
	attribute(&event, missing)
	if event.Attribution != "peer-only" || event.PeerIP != "172.30.1.2" || event.SrcIP != "172.30.1.2" || event.SessionID != "" {
		t.Fatalf("missing context invented attribution: %+v", event)
	}
	dir := t.TempDir()
	generation := uint64(0)
	context := ConnectionContext{SessionID: strings.Repeat("a", 32), SrcIP: "198.51.100.42", SrcPort: 42001, StartedAt: "2026-11-08T12:00:00Z", Generation: &generation}
	data, _ := json.Marshal(context)
	if err := os.WriteFile(filepath.Join(dir, "connection.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	attribute(&event, dir)
	if event.SrcIP != context.SrcIP || event.PeerIP != "172.30.1.2" || event.SessionID != context.SessionID || event.Generation == nil || *event.Generation != 0 || event.Attribution != "broker-cell" {
		t.Fatalf("trusted attribution: %+v", event)
	}
	for _, bad := range []string{`{}`, string(append(data, []byte(" {}")...)), strings.Replace(string(data), `"generation":0`, `"generation":null`, 1), strings.Replace(string(data), `"src_port":42001`, `"src_port":0`, 1)} {
		if err := os.WriteFile(filepath.Join(dir, "connection.json"), []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		fresh := SessionEvent{SrcIP: "172.30.1.2", SrcPort: 23456}
		attribute(&fresh, dir)
		if fresh.Attribution != "context-unavailable" || fresh.SrcIP != "172.30.1.2" || fresh.SessionID != "" {
			t.Fatalf("invalid context invented attribution: %+v", fresh)
		}
	}
}

func TestRecordFailsClosedForWrongDirectoryAndKeepsEmptyExec(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("real Linux shell")
	}
	root := t.TempDir()
	empty := ""
	var out, errOut bytes.Buffer
	code, err := record(recordOptions{LogDir: root, Command: &empty, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errOut})
	if err != nil || code != 0 {
		t.Fatalf("empty exec: %d %v", code, err)
	}
	bad := t.TempDir()
	if err := os.Symlink(root, filepath.Join(bad, "uid-"+strconvUID())); err != nil {
		t.Fatal(err)
	}
	if _, err := record(recordOptions{LogDir: bad, Command: &empty, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errOut}); err == nil {
		t.Fatal("symlink log directory accepted")
	}
}

func TestRecordPTYCapturesInputOutputAndRealStatus(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux PTY recorder")
	}
	if _, err := os.Stat("/usr/bin/script"); err != nil {
		t.Skip(err)
	}
	root := t.TempDir()
	command := `test -t 0 || exit 90; IFS= read -r line; printf 'received:%s\n' "$line"; exit 3`
	var stdout, stderr bytes.Buffer
	code, err := record(recordOptions{LogDir: root, Command: &command, PTY: true, Stdin: strings.NewReader("hello\n"), Stdout: &stdout, Stderr: &stderr})
	if err != nil || code != 3 || !strings.Contains(stdout.String(), "received:hello\r\n") {
		t.Fatalf("PTY status %d err %v stdout %q stderr %q", code, err, stdout.String(), stderr.String())
	}
	paths, _ := filepath.Glob(filepath.Join(root, "uid-*", "*.json"))
	if len(paths) != 1 {
		t.Fatalf("records %v", paths)
	}
	base := strings.TrimSuffix(paths[0], ".json")
	out, _ := os.ReadFile(base + ".out")
	in, _ := os.ReadFile(base + ".in")
	timing, _ := os.ReadFile(base + ".timing")
	if !bytes.Equal(out, stdout.Bytes()) || !bytes.Contains(in, []byte("hello\n")) || len(timing) == 0 {
		t.Fatalf("PTY capture differs: out=%q in=%q timing=%q", out, in, timing)
	}
}

func strconvUID() string { return fmt.Sprint(os.Getuid()) }

func FuzzDecodeManifest(f *testing.F) {
	data, _ := json.Marshal(testManifest())
	f.Add(data)
	f.Add([]byte(`{"version":1,"role":"backup","organization":"x","files":[{"path":"/proc/1/environ","owner":"root","mode":384}]}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := DecodeManifest(data)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		roundtrip, err := DecodeManifest(encoded)
		if err != nil || roundtrip.Role != m.Role || len(roundtrip.Files) != len(m.Files) {
			t.Fatalf("validated manifest does not round-trip: %v", err)
		}
	})
}
