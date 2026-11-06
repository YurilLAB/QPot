package instance

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
)

// TestGetLogsReadsPastALongLine: GetLogs read docker's output with a
// bufio.Scanner, which stops at the first line over 64 KiB. Nothing read the
// pipe after that, so docker blocked writing and the deferred Wait blocked with
// it: `qpot logs` and /api/logs showed one line and hung until their deadline.
// A honeypot's log lines carry what attackers send, so long ones are routine.
func TestGetLogsReadsPastALongLine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker is a shell script")
	}
	dir := t.TempDir()
	script := `#!/bin/sh
case "$*" in *" logs"*)
  head -c 70000 /dev/zero | tr '\0' x; echo
  i=0; while [ $i -lt 20000 ]; do echo "line $i"; i=$((i+1)); done
  printf 'last line without newline' ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil { // #nosec G306 -- test helper must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cfg := config.Default("logs-test")
	cfg.DataPath = t.TempDir()
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	lines, err := m.GetLogs(ctx, "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for line := range lines {
		got = append(got, line)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("GetLogs took %s", elapsed)
	}
	if len(got) != 20002 {
		t.Fatalf("%d lines, want 20002 (the long one, 20000, the last)", len(got))
	}
	if want := strings.Repeat("x", maxLogLine) + " [line truncated]"; got[0] != want {
		t.Errorf("long line: %d bytes, want the first %d and a mark", len(got[0]), maxLogLine)
	}
	if got[1] != "line 0" || got[20000] != "line 19999" || got[20001] != "last line without newline" {
		t.Errorf("lines after the long one: %q %q %q", got[1], got[20000], got[20001])
	}
}

// TestReadLogLine: lines of every length come back whole up to the limit,
// without their line ending, and nothing is merged or lost around a long one.
func TestReadLogLine(t *testing.T) {
	input := "short\r\n" + strings.Repeat("y", 100) + "\n" + strings.Repeat("z", 31) + "\nend"
	r := bufio.NewReaderSize(strings.NewReader(input), 16)
	var got []string
	for {
		line, err := readLogLine(r, 32)
		if err == nil || line != "" {
			got = append(got, line)
		}
		if err != nil {
			break
		}
	}
	want := []string{"short", strings.Repeat("y", 32) + " [line truncated]", strings.Repeat("z", 31), "end"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}
